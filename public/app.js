// app.js — Secure Chatroom (v2) client
//
// All cryptography happens HERE, in the browser, using the native Web Crypto API.
// No libsodium, no CDN — nothing extra to load.
//
//   Identity key   : Ed25519   (signs every ephemeral key)
//   Ephemeral key  : X25519    (fresh for every session and every rotation)
//   Key derivation : HKDF-SHA-256 → two AES-256 keys (one per direction)
//   Encryption     : AES-256-GCM, nonce = round || counter, with AAD
//
// The server only relays signed public keys and ciphertext.

"use strict";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PROTOCOL = "SECURE-CHAT-v2";
const HANDSHAKE_TIMEOUT_MS = 15_000;
const MAX_TEXT_LEN = 2000;
const ID_RE = /^[A-Za-z0-9_-]{1,32}$/;

// Same server serves the page and the WebSocket (npm start → port 8080).
// If the page is opened from file:// or "npx serve" (port 3000), fall back to 8080.
const WS_URL =
  location.protocol === "file:" || location.port === "3000"
    ? "ws://localhost:8080"
    : `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}`;

// ---------------------------------------------------------------------------
// DOM
// ---------------------------------------------------------------------------
const $ = (id) => document.getElementById(id);
const userIdInput = $("userId");
const peerIdInput = $("peerId");
const connectBtn = $("connectBtn");
const rotateBtn = $("rotateBtn");
const sendBtn = $("sendBtn");
const msgInput = $("message");
const statusEl = $("status");
const chatEl = $("chat");
const logEl = $("log");
const myFpEl = $("myFp");
const peerFpEl = $("peerFp");
const safetyEl = $("safetyCode");
const keyCheckEl = $("keyCheck");
const verifyBtn = $("verifyBtn");

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const enc = new TextEncoder();
const dec = new TextDecoder();

let ws = null;
let registered = false;
let myId = null;
let peerId = null;
let peerOnline = false;

let identity = null; // { keyPair, pubRaw }          — my Ed25519 identity
let peerIdentity = null; // { key, pubRaw }          — peer's Ed25519 identity (pinned for this connection)
let pending = null; // { round, keyPair, pubRaw, peerEphRaw, timer } — handshake in progress
let session = null; // { round, sendKey, recvKey, sendCtr, recvCtr, check } — active session
let verified = false;

// ---------------------------------------------------------------------------
// UI helpers (textContent only — never innerHTML → no XSS)
// ---------------------------------------------------------------------------
const STATES = {
  NOT_CONNECTED: ["NOT CONNECTED", "idle"],
  CONNECTING: ["CONNECTING...", "busy"],
  CONNECTED: ["CONNECTED TO SERVER", "busy"],
  WAITING_PEER: ["WAITING FOR PEER", "busy"],
  KEY_EXCHANGE: ["PERFORMING KEY EXCHANGE", "busy"],
  VERIFYING: ["VERIFYING PEER", "busy"],
  SECURE: ["SECURE CHANNEL ESTABLISHED", "ok"],
  ROTATING: ["ROTATING SESSION KEY", "busy"],
  ROTATED: ["SESSION KEY ROTATED", "ok"],
  PEER_DISCONNECTED: ["PEER DISCONNECTED", "warn"],
  ERROR: ["ERROR", "err"],
};

function setStatus(state, detail = "") {
  const [label, kind] = STATES[state];
  statusEl.textContent = detail ? `${label} — ${detail}` : label;
  statusEl.className = `meta status-${kind}`;
  updateControls();
}

function log(text, kind = "info") {
  const div = document.createElement("div");
  div.className = `log-${kind}`;
  div.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  logEl.appendChild(div);
  logEl.scrollTop = logEl.scrollHeight;
}

function chat(text, who) {
  const div = document.createElement("div");
  div.className = `msg msg-${who}`;
  div.textContent = text;
  chatEl.appendChild(div);
  chatEl.scrollTop = chatEl.scrollHeight;
}

function updateControls() {
  const secure = Boolean(session);
  const rotating = Boolean(session && pending);
  sendBtn.disabled = !secure || rotating;
  msgInput.disabled = !secure || rotating;
  rotateBtn.disabled = !secure || rotating;
  verifyBtn.disabled = !secure || verified;
  userIdInput.disabled = Boolean(ws);
  peerIdInput.disabled = Boolean(ws);
  // Start button: full start when offline; "retry handshake" when registered but not secure
  connectBtn.disabled = Boolean(ws) && (!registered || secure || Boolean(pending));
  connectBtn.textContent = ws && registered && !secure ? "Retry handshake" : "Start (generate keys & connect)";
}

function showSecurityInfo() {
  myFpEl.textContent = identity ? identity.fp : "—";
  peerFpEl.textContent = peerIdentity ? peerIdentity.fp : "—";
  safetyEl.textContent = peerIdentity ? peerIdentity.safety : "—";
  keyCheckEl.textContent = session ? `${session.check} (round ${session.round})` : "—";
  verifyBtn.textContent = verified ? "✔ Verified" : "Codes match → mark verified";
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------
function toB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(str, expectedLen) {
  if (typeof str !== "string" || str.length > 100_000) throw new Error("invalid base64 field");
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (expectedLen !== undefined && out.length !== expectedLen) {
    throw new Error(`expected ${expectedLen} bytes, got ${out.length}`);
  }
  return out;
}

function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const groupHex = (hex) => hex.match(/.{1,4}/g).join(" ");

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

// ---------------------------------------------------------------------------
// Crypto: identity (Ed25519)
// ---------------------------------------------------------------------------
async function createIdentity() {
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const fp = groupHex(toHex(await sha256(pubRaw)).slice(0, 32));
  return { keyPair, pubRaw, fp };
}

/** Exactly what gets signed: binds sender, receiver, round, both keys. */
function handshakeTranscript(from, to, round, idPubRaw, ephPubRaw) {
  return enc.encode(`${PROTOCOL}|hs|${from}|${to}|${round}|${toB64(idPubRaw)}|${toB64(ephPubRaw)}`);
}

/** Same code on both screens if (and only if) both see the same two identity keys. */
async function computeSafetyCode(myPub, theirPub) {
  const [lowPub, highPub] = myId < peerId ? [myPub, theirPub] : [theirPub, myPub];
  const [low, high] = myId < peerId ? [myId, peerId] : [peerId, myId];
  const h = await sha256(concat(enc.encode(`${PROTOCOL}|safety|${low}|${high}|`), lowPub, highPub));
  return groupHex(toHex(h).slice(0, 24));
}

// ---------------------------------------------------------------------------
// Crypto: ephemeral key exchange (X25519 + HKDF)
// ---------------------------------------------------------------------------
async function createEphemeral() {
  // extractable=false: the private key can never be exported from the browser.
  const keyPair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  return { keyPair, pubRaw };
}

async function deriveSession(round, myEph, peerEphRaw) {
  // 1) X25519 shared secret (throws on invalid / low-order public keys)
  const peerEphKey = await crypto.subtle.importKey("raw", peerEphRaw, { name: "X25519" }, false, []);
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "X25519", public: peerEphKey }, myEph.keyPair.privateKey, 256)
  );

  // 2) HKDF: salt binds both identities + both ephemeral keys; info binds IDs + round
  const iAmLow = myId < peerId;
  const [low, high] = iAmLow ? [myId, peerId] : [peerId, myId];
  const ids = iAmLow ? [identity.pubRaw, peerIdentity.pubRaw] : [peerIdentity.pubRaw, identity.pubRaw];
  const ephs = iAmLow ? [myEph.pubRaw, peerEphRaw] : [peerEphRaw, myEph.pubRaw];
  const salt = await sha256(concat(...ids, ...ephs));
  const info = enc.encode(`${PROTOCOL}|session-keys|${low}|${high}|round:${round}`);

  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const okm = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, ikm, 512));

  // 3) Two AES-256 keys, one per direction (so the two senders never share a nonce space)
  const lowToHigh = await crypto.subtle.importKey("raw", okm.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
  const highToLow = await crypto.subtle.importKey("raw", okm.slice(32, 64), "AES-GCM", false, ["encrypt", "decrypt"]);

  // Short public check value: both users should see the same one (proves same keys, reveals nothing useful)
  const check = groupHex(toHex(await sha256(concat(enc.encode(`${PROTOCOL}|check|`), okm))).slice(0, 8));

  shared.fill(0); // best-effort wipe of raw secrets from memory
  okm.fill(0);

  return {
    round,
    sendKey: iAmLow ? lowToHigh : highToLow,
    recvKey: iAmLow ? highToLow : lowToHigh,
    sendCtr: 0,
    recvCtr: 0,
    check,
  };
}

// ---------------------------------------------------------------------------
// Crypto: messages (AES-256-GCM)
// ---------------------------------------------------------------------------
/** 12-byte nonce = 4-byte round || 8-byte counter. Unique because keys are per-direction and per-round. */
function makeNonce(round, ctr) {
  const iv = new Uint8Array(12);
  const v = new DataView(iv.buffer);
  v.setUint32(0, round);
  v.setUint32(4, Math.floor(ctr / 2 ** 32));
  v.setUint32(8, ctr >>> 0);
  return iv;
}

/** Authenticated (not encrypted) context: sender, receiver, round, counter. */
function makeAad(from, to, round, ctr) {
  return enc.encode(`${PROTOCOL}|msg|${from}|${to}|${round}|${ctr}`);
}

// ---------------------------------------------------------------------------
// Networking
// ---------------------------------------------------------------------------
function wsSend(obj) {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    log("Not connected to server.", "err");
    return false;
  }
  ws.send(JSON.stringify(obj));
  return true;
}

function resetPeerState() {
  if (pending) clearTimeout(pending.timer);
  pending = null;
  session = null; // old keys dropped → garbage collected
  peerIdentity = null;
  verified = false;
  showSecurityInfo();
}

function resetAll() {
  resetPeerState();
  ws = null;
  registered = false;
  peerOnline = false;
  identity = null;
  showSecurityInfo();
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------
async function startHandshake(round) {
  if (!pending || pending.round !== round) {
    if (pending) clearTimeout(pending.timer);
    const eph = await createEphemeral();
    pending = { round, keyPair: eph.keyPair, pubRaw: eph.pubRaw, peerEphRaw: null, timer: null, sent: false };
    log(`🔑 Generated fresh X25519 ephemeral key pair (round ${round}).`);
  }
  if (!peerOnline) {
    setStatus("WAITING_PEER", `${peerId} is not online yet`);
    log(`⏳ Waiting for ${peerId} to come online…`);
    return;
  }
  await sendHello();
}

async function sendHello() {
  const p = pending;
  const transcript = handshakeTranscript(myId, peerId, p.round, identity.pubRaw, p.pubRaw);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, identity.keyPair.privateKey, transcript));

  const ok = wsSend({
    type: "hs",
    payload: { v: 2, round: p.round, idPub: toB64(identity.pubRaw), ephPub: toB64(p.pubRaw), sig: toB64(sig) },
  });
  if (!ok) return;
  p.sent = true;

  log(`📤 Sent signed ephemeral public key to ${peerId} (round ${p.round}).`);
  setStatus(session ? "ROTATING" : "KEY_EXCHANGE", `waiting for ${peerId}'s key`);

  clearTimeout(p.timer);
  p.timer = setTimeout(() => onHandshakeTimeout(p), HANDSHAKE_TIMEOUT_MS);
}

function onHandshakeTimeout(p) {
  if (pending !== p) return; // already completed
  pending = null;
  if (session) {
    log(`⌛ Key rotation timed out. Still using the previous key (round ${session.round}).`, "err");
    setStatus("SECURE", `rotation failed — still on round ${session.round}`);
  } else {
    log(`⌛ Handshake timed out: no reply from ${peerId}. Click "Retry handshake".`, "err");
    setStatus("ERROR", "handshake timeout");
  }
}

async function onHello(from, p) {
  // --- 1. Validate format ---
  let idPub, ephPub, sig;
  try {
    if (!p || p.v !== 2 || !Number.isInteger(p.round) || p.round < 1 || p.round > 0xffffffff) {
      throw new Error("bad handshake fields");
    }
    idPub = fromB64(p.idPub, 32);
    ephPub = fromB64(p.ephPub, 32);
    sig = fromB64(p.sig, 64);
  } catch (e) {
    log(`❌ Invalid handshake message from ${from} (${e.message}).`, "err");
    return;
  }

  peerOnline = true; // a handshake from the peer proves they are online
  setStatus("VERIFYING", `checking ${from}'s signature`);

  // --- 2. Peer identity: pin it for this connection, reject if it changes ---
  if (peerIdentity && !equalBytes(peerIdentity.pubRaw, idPub)) {
    log(`🚨 ${from}'s IDENTITY KEY CHANGED mid-session! Possible man-in-the-middle. Handshake rejected.`, "err");
    setStatus("ERROR", "peer identity changed — possible attack");
    return;
  }
  if (!peerIdentity) {
    try {
      const key = await crypto.subtle.importKey("raw", idPub, { name: "Ed25519" }, false, ["verify"]);
      peerIdentity = {
        key,
        pubRaw: idPub,
        fp: groupHex(toHex(await sha256(idPub)).slice(0, 32)),
        safety: await computeSafetyCode(identity.pubRaw, idPub),
      };
    } catch {
      log(`❌ ${from} sent an invalid identity public key.`, "err");
      setStatus("ERROR", "invalid peer identity key");
      return;
    }
    log(`🪪 Received ${from}'s identity key. Fingerprint: ${peerIdentity.fp}`);
    showSecurityInfo();
  }

  // --- 3. Verify the signature over (from, to, round, idPub, ephPub) ---
  const transcript = handshakeTranscript(from, myId, p.round, idPub, ephPub);
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, peerIdentity.key, sig, transcript);
  if (!valid) {
    log(`❌ INVALID SIGNATURE on ${from}'s ephemeral key. Message rejected (possible tampering).`, "err");
    setStatus("ERROR", "invalid signature");
    return;
  }
  log(`✅ Signature verified on ${from}'s ephemeral key (round ${p.round}).`);

  // --- 4. Round checks (stops stale / replayed handshakes) ---
  const expected = session ? session.round + 1 : 1;
  if (p.round < expected) {
    log(`↩️ Ignored old handshake (round ${p.round}).`);
    return restoreStatus();
  }
  if (p.round > expected) {
    log(`❌ Out-of-sync handshake (got round ${p.round}, expected ${expected}).`, "err");
    return restoreStatus();
  }

  // --- 5. If the peer started this round, reply with OUR fresh ephemeral key ---
  if (!pending || pending.round !== p.round) {
    if (session) log(`🔁 ${from} requested key rotation.`);
    await startHandshake(p.round);
  } else if (pending.peerEphRaw) {
    if (!equalBytes(pending.peerEphRaw, ephPub)) log(`⚠️ Conflicting key for round ${p.round} ignored.`, "err");
    return;
  } else if (!pending.sent) {
    await sendHello(); // our key was waiting for the peer to come online
  }
  pending.peerEphRaw = ephPub;
  log(`📥 Received ${from}'s ephemeral public key (round ${p.round}).`);

  await completeHandshake();
}

async function completeHandshake() {
  const p = pending;
  const rotation = Boolean(session);
  try {
    const next = await deriveSession(p.round, p, p.peerEphRaw);
    clearTimeout(p.timer);
    pending = null; // ephemeral private key dropped — never reused
    session = next; // old session key replaced; counters reset to 0
  } catch (e) {
    clearTimeout(p.timer);
    pending = null;
    log(`❌ Key derivation failed (${e.message}). Invalid public key?`, "err");
    setStatus("ERROR", rotation ? "key rotation failed" : "key derivation failed");
    return;
  }

  log(`🔐 Shared secret computed (X25519) → HKDF-SHA-256 → AES-256-GCM session keys.`, "ok");
  log(`🧾 Session key check: ${session.check} — should be the SAME on both screens.`, "ok");
  if (rotation) {
    log(`🔁 Session key rotated to round ${session.round}. Old key discarded, counters reset.`, "ok");
    setStatus("ROTATED", `round ${session.round} with ${peerId}${verified ? " · verified" : ""}`);
  } else {
    log(`✅ Secure channel established with ${peerId}.`, "ok");
    log(`👀 Compare the SAFETY CODE with ${peerId} (call/in person). If it matches, click "mark verified".`);
    setStatus("SECURE", `with ${peerId} · ${verified ? "verified" : "safety code not verified yet"}`);
  }
  showSecurityInfo();
}

function restoreStatus() {
  if (session) setStatus("SECURE", `with ${peerId}${verified ? " · verified" : ""}`);
  else if (pending) setStatus("KEY_EXCHANGE");
  else setStatus(peerOnline ? "CONNECTED" : "WAITING_PEER");
}

// ---------------------------------------------------------------------------
// Encrypted messages
// ---------------------------------------------------------------------------
async function sendMessage() {
  const text = msgInput.value.trim();
  if (!text) return;
  if (!session) return log("⚠️ Session not established yet — cannot send.", "err");
  if (pending) return log("⚠️ Key rotation in progress — please wait a moment.", "err");
  if (text.length > MAX_TEXT_LEN) return log(`⚠️ Message too long (max ${MAX_TEXT_LEN} characters).`, "err");

  const s = session;
  const ctr = ++s.sendCtr;
  try {
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: makeNonce(s.round, ctr), additionalData: makeAad(myId, peerId, s.round, ctr) },
        s.sendKey,
        enc.encode(text)
      )
    );
    const ctB64 = toB64(ct);
    if (!wsSend({ type: "msg", payload: { v: 2, round: s.round, ctr, ct: ctB64 } })) return;
    chat(`🧑‍💻 You: ${text}`, "me");
    log(`📦 Sent message #${ctr} (round ${s.round}) as ciphertext: ${ctB64.slice(0, 24)}…`);
    msgInput.value = "";
  } catch (e) {
    log(`❌ Encryption failed (${e.message}).`, "err");
  }
}

async function onEncryptedMessage(from, p) {
  if (!session) return log(`⚠️ Message from ${from} arrived before the secure session — dropped.`, "err");
  const s = session;

  let ct;
  try {
    if (!p || p.v !== 2 || !Number.isInteger(p.round) || !Number.isSafeInteger(p.ctr) || p.ctr < 1) {
      throw new Error("bad fields");
    }
    ct = fromB64(p.ct);
    if (ct.length < 16) throw new Error("too short");
  } catch {
    return log(`❌ Invalid ciphertext format from ${from} — dropped.`, "err");
  }

  if (p.round !== s.round) {
    return log(`⚠️ Message for key round ${p.round} dropped (current round is ${s.round}).`, "err");
  }
  if (p.ctr <= s.recvCtr) {
    return log(`🚫 Replayed / out-of-order message #${p.ctr} rejected (last accepted #${s.recvCtr}).`, "err");
  }

  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: makeNonce(s.round, p.ctr), additionalData: makeAad(from, myId, s.round, p.ctr) },
      s.recvKey,
      ct
    );
    if (p.ctr > s.recvCtr + 1) log(`⚠️ ${p.ctr - s.recvCtr - 1} message(s) from ${from} missing.`, "err");
    s.recvCtr = p.ctr;
    log(`📥 Received ciphertext #${p.ctr} (round ${s.round}) → decrypted OK.`);
    chat(`💬 ${from}: ${dec.decode(pt)}`, "peer");
  } catch {
    log(`❌ Decryption failed for message #${p.ctr} — it was tampered with or keys don't match.`, "err");
  }
}

// ---------------------------------------------------------------------------
// WebSocket events
// ---------------------------------------------------------------------------
async function onServerMessage(event) {
  let data;
  try {
    data = JSON.parse(event.data);
  } catch {
    return log("❌ Received malformed data from server.", "err");
  }

  try {
    switch (data.type) {
      case "registered":
        registered = true;
        peerOnline = data.peerOnline;
        log(`🟢 Connected to server as ${myId}.`);
        setStatus("CONNECTED", `as ${myId}`);
        log(peerOnline ? `👥 ${peerId} is online. Starting key exchange…` : `👤 ${peerId} is not online yet.`);
        await startHandshake(1);
        break;

      case "peer-online":
        peerOnline = true;
        log(`👥 ${peerId} came online.`);
        if (!session) await startHandshake(1);
        break;

      case "peer-offline":
        peerOnline = false;
        resetPeerState();
        log(`🔌 ${peerId} disconnected. Session keys destroyed.`, "err");
        log(`ℹ️ When ${peerId} returns, a NEW handshake runs — re-check the safety code (it will change).`);
        setStatus("PEER_DISCONNECTED", `waiting for ${peerId} to return`);
        break;

      case "hs":
        if (data.from !== peerId) return log(`⚠️ Ignored handshake from unexpected user ${data.from}.`, "err");
        await onHello(data.from, data.payload);
        break;

      case "msg":
        if (data.from !== peerId) return log(`⚠️ Ignored message from unexpected user ${data.from}.`, "err");
        await onEncryptedMessage(data.from, data.payload);
        break;

      case "error":
        handleServerError(data);
        break;

      default:
        log(`⚠️ Unknown message type from server: ${String(data.type).slice(0, 20)}`, "err");
    }
  } catch (e) {
    log(`❌ Unexpected error: ${e.message}`, "err");
  }
}

function handleServerError(data) {
  const message = typeof data.message === "string" ? data.message : "Unknown server error.";
  log(`❌ Server: ${message}`, "err");

  switch (data.code) {
    case "DUPLICATE_ID":
    case "INVALID_USER_ID":
    case "INVALID_PEER_ID":
      setStatus("ERROR", message);
      ws.close(); // fix the IDs, then click Start again
      break;
    case "PEER_OFFLINE":
      peerOnline = false;
      if (pending) clearTimeout(pending.timer);
      if (!session) setStatus("WAITING_PEER", `${peerId} is not online`);
      break;
    default:
      restoreStatus();
  }
}

// ---------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------
connectBtn.onclick = async () => {
  // Already connected but handshake failed → just retry the key exchange
  if (ws && registered && !session) {
    log("🔄 Retrying handshake…");
    pending = null;
    return startHandshake(1);
  }
  if (ws) return;

  const u = userIdInput.value.trim();
  const p = peerIdInput.value.trim();
  if (!ID_RE.test(u)) return setStatus("ERROR", "invalid User ID (1-32 letters, digits, _ or -)");
  if (!ID_RE.test(p)) return setStatus("ERROR", "invalid Peer ID (1-32 letters, digits, _ or -)");
  if (u === p) return setStatus("ERROR", "User ID and Peer ID must be different");
  myId = u;
  peerId = p;

  try {
    identity = await createIdentity();
  } catch (e) {
    return setStatus("ERROR", `could not generate identity key: ${e.message}`);
  }
  log(`🪪 Generated Ed25519 identity key. Your fingerprint: ${identity.fp}`);
  showSecurityInfo();

  setStatus("CONNECTING");
  log(`🌐 Connecting to ${WS_URL}…`);

  let opened = false;
  const socket = new WebSocket(WS_URL);
  ws = socket;
  updateControls();

  socket.onopen = () => {
    opened = true;
    socket.send(JSON.stringify({ type: "register", userId: myId, peerId }));
  };
  socket.onmessage = onServerMessage;
  socket.onclose = () => {
    if (ws !== socket) return;
    const wasError = statusEl.className.includes("status-err");
    resetAll();
    if (!opened) {
      log(`❌ Server unavailable at ${WS_URL}. Is "npm start" running?`, "err");
      setStatus("ERROR", "server unavailable");
    } else if (!wasError) {
      log("🔌 Disconnected from server. All session keys destroyed. Click Start to reconnect.", "err");
      setStatus("NOT_CONNECTED", "disconnected from server");
    } else {
      updateControls();
    }
  };
};

rotateBtn.onclick = async () => {
  if (!session) return log("⚠️ No secure session to rotate.", "err");
  if (pending) return log("⚠️ Rotation already in progress.", "err");
  log(`🔁 Rotating session key (round ${session.round} → ${session.round + 1})…`);
  setStatus("ROTATING");
  try {
    await startHandshake(session.round + 1);
  } catch (e) {
    pending = null;
    log(`❌ Key rotation failed (${e.message}).`, "err");
    restoreStatus();
  }
};

verifyBtn.onclick = () => {
  if (!session) return;
  verified = true;
  log(`🛡️ You confirmed the safety code matches ${peerId}. Peer identity verified.`, "ok");
  showSecurityInfo();
  restoreStatus();
};

sendBtn.onclick = sendMessage;
msgInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendMessage();
});

// ---------------------------------------------------------------------------
// Startup: check the browser supports everything we need
// ---------------------------------------------------------------------------
(async function checkSupport() {
  showSecurityInfo();
  if (!window.crypto?.subtle) {
    setStatus("ERROR", "Web Crypto unavailable — open the app via http://localhost:8080");
    connectBtn.disabled = true;
    return;
  }
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  } catch {
    setStatus("ERROR", "this browser lacks Ed25519/X25519 — update Chrome, Edge, Firefox or Safari");
    log("❌ Your browser does not support Ed25519/X25519 in Web Crypto. Please update it.", "err");
    connectBtn.disabled = true;
    return;
  }
  setStatus("NOT_CONNECTED");
  log("ℹ️ Ready. Enter your ID and your peer's ID, then click Start.");
})();
