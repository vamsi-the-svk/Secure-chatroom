// server.js — Secure Chatroom (v2)
//
// ONE Node.js process, ONE port:
//   1. Serves the web page (public/index.html, public/app.js) over HTTP
//   2. Runs the WebSocket relay on the same port
//
// The server NEVER sees plaintext or session keys. It only:
//   - registers users (userId -> socket)
//   - relays signed handshake messages ("hs") and ciphertext ("msg")
//   - tells users when their peer comes online / goes offline

import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer, WebSocket } from "ws";

const PORT = Number(process.env.PORT) || 8080;
const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "public");
const ID_RE = /^[A-Za-z0-9_-]{1,32}$/; // allowed user IDs
const MAX_FRAME_BYTES = 64 * 1024; // reject huge WebSocket frames
const HEARTBEAT_MS = 30_000; // detect dead connections

// Origins allowed to open a WebSocket (same host is always allowed).
// localhost:3000 is kept so "npx serve public" still works if you prefer it.
const EXTRA_ALLOWED_ORIGINS = new Set(["http://localhost:3000", "http://127.0.0.1:3000"]);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

// Browser security headers: block inline scripts, framing and MIME sniffing.
const SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "connect-src 'self' ws: wss:; img-src 'self' data:; object-src 'none'; " +
    "base-uri 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

// ---------------------------------------------------------------------------
// 1. Static file server (replaces "npx serve")
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, SECURITY_HEADERS);
    return res.end("Method not allowed");
  }

  let urlPath;
  try {
    urlPath = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  } catch {
    res.writeHead(400, SECURITY_HEADERS);
    return res.end("Bad request");
  }
  if (urlPath === "/") urlPath = "/index.html";

  // Block path traversal (e.g. /../server.js)
  const filePath = path.normalize(path.join(PUBLIC_DIR, urlPath));
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(404, SECURITY_HEADERS);
    return res.end("Not found");
  }

  try {
    const data = await fs.readFile(filePath);
    const type = MIME[path.extname(filePath).toLowerCase()] || "application/octet-stream";
    res.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": type });
    res.end(req.method === "HEAD" ? undefined : data);
  } catch {
    res.writeHead(404, SECURITY_HEADERS);
    res.end("Not found");
  }
});

// ---------------------------------------------------------------------------
// 2. WebSocket relay (same port)
// ---------------------------------------------------------------------------
const wss = new WebSocketServer({ server, maxPayload: MAX_FRAME_BYTES });

/** userId -> WebSocket (each socket also stores ws.userId and ws.peerId) */
const clients = new Map();

function send(ws, obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function sendError(ws, code, message) {
  send(ws, { type: "error", code, message });
}

/** The peer socket only counts if that peer is also chatting with *us*. */
function pairedPeer(ws) {
  const peer = clients.get(ws.peerId);
  return peer && peer.peerId === ws.userId ? peer : null;
}

function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // non-browser clients (tests, tools)
  try {
    const o = new URL(origin);
    return o.host === req.headers.host || EXTRA_ALLOWED_ORIGINS.has(o.origin);
  } catch {
    return false;
  }
}

function handleRegister(ws, data) {
  if (ws.userId) return sendError(ws, "ALREADY_REGISTERED", "This connection is already registered.");

  const { userId, peerId } = data;
  if (typeof userId !== "string" || !ID_RE.test(userId)) {
    return sendError(ws, "INVALID_USER_ID", "Invalid User ID. Use 1-32 letters, digits, _ or -.");
  }
  if (typeof peerId !== "string" || !ID_RE.test(peerId)) {
    return sendError(ws, "INVALID_PEER_ID", "Invalid Peer ID. Use 1-32 letters, digits, _ or -.");
  }
  if (userId === peerId) {
    return sendError(ws, "INVALID_PEER_ID", "User ID and Peer ID must be different.");
  }
  if (clients.has(userId)) {
    return sendError(ws, "DUPLICATE_ID", `User ID "${userId}" is already online. Choose another ID.`);
  }

  ws.userId = userId;
  ws.peerId = peerId;
  clients.set(userId, ws);
  console.log(`✅ registered ${userId} (wants to chat with ${peerId})`);

  const peer = pairedPeer(ws);
  send(ws, { type: "registered", userId, peerId, peerOnline: Boolean(peer) });
  if (peer) send(peer, { type: "peer-online", peerId: userId });
}

function handleRelay(ws, data) {
  if (!ws.userId) return sendError(ws, "NOT_REGISTERED", "Register before sending messages.");
  if (!data.payload || typeof data.payload !== "object" || Array.isArray(data.payload)) {
    return sendError(ws, "BAD_MESSAGE", "Missing or invalid payload.");
  }

  const peer = pairedPeer(ws);
  if (!peer) {
    return sendError(ws, "PEER_OFFLINE", `Peer "${ws.peerId}" is not online (or not chatting with you).`);
  }

  // "from" is set by the SERVER from the registered socket — clients cannot spoof it.
  // The payload is forwarded untouched; the server cannot read encrypted content.
  send(peer, { type: data.type, from: ws.userId, payload: data.payload });
  console.log(`📨 ${data.type.padEnd(3)} ${ws.userId} → ${peer.userId}`); // metadata only, never content
}

wss.on("connection", (ws, req) => {
  if (!originAllowed(req)) {
    console.log(`⛔ rejected connection from origin ${req.headers.origin}`);
    return ws.close(1008, "Origin not allowed");
  }

  ws.userId = null;
  ws.peerId = null;
  ws.isAlive = true;
  ws.on("pong", () => (ws.isAlive = true));

  ws.on("message", (raw, isBinary) => {
    if (isBinary) return sendError(ws, "BAD_MESSAGE", "Binary frames are not supported.");

    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return sendError(ws, "BAD_MESSAGE", "Message is not valid JSON.");
    }
    if (!data || typeof data !== "object") return sendError(ws, "BAD_MESSAGE", "Invalid message.");

    switch (data.type) {
      case "register":
        return handleRegister(ws, data);
      case "hs": // signed handshake (ephemeral public key)
      case "msg": // encrypted chat message
        return handleRelay(ws, data);
      default:
        return sendError(ws, "BAD_MESSAGE", "Unknown message type.");
    }
  });

  ws.on("close", () => {
    if (ws.userId && clients.get(ws.userId) === ws) {
      const peer = pairedPeer(ws);
      clients.delete(ws.userId);
      console.log(`❎ disconnected ${ws.userId}`);
      if (peer) send(peer, { type: "peer-offline", peerId: ws.userId });
    }
  });

  ws.on("error", (err) => console.error("socket error:", err.message));
});

// Heartbeat: close sockets that stopped answering (e.g. laptop slept, Wi-Fi dropped)
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, HEARTBEAT_MS);
wss.on("close", () => clearInterval(heartbeat));

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`❌ Port ${PORT} is already in use. Stop the other server or run with PORT=8081 npm start`);
  } else {
    console.error("❌ Server error:", err.message);
  }
  process.exit(1);
});

server.listen(PORT, () => {
  console.log(`✅ Secure Chatroom running`);
  console.log(`   Open:      http://localhost:${PORT}  (in two browser tabs/windows)`);
  console.log(`   WebSocket: ws://localhost:${PORT}`);
});
