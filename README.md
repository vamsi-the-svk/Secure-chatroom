# 🔐 Secure Chatroom (Prototype)

A secure two-user chat. Messages are encrypted **in the browser**; the server only relays ciphertext.

## Run it (one command)

```bash
npm install
npm start
```

Open **http://localhost:8080** in two browser windows.

- Window 1: User ID `alice`, Peer ID `bob` → click **Start**
- Window 2: User ID `bob`, Peer ID `alice` → click **Start**

`npm run dev` restarts the server automatically when you edit `server.js`.

Use an up-to-date Chrome, Edge, Firefox or Safari (needed for Ed25519/X25519 in Web Crypto).

## Project structure

```
secure-chatroom/
├── package.json
├── server.js          # serves the page + WebSocket relay (one port: 8080)
└── public/
    ├── index.html     # UI
    └── app.js         # all cryptography + chat logic
```

## Cryptography

| Step | Algorithm |
|---|---|
| Identity key | Ed25519 (signs every ephemeral key) |
| Key exchange | X25519 (fresh ephemeral key every session and every rotation) |
| Key derivation | HKDF-SHA-256 → two AES-256 keys (one per direction) |
| Encryption | AES-256-GCM, nonce = round ‖ counter, AAD = sender ‖ receiver ‖ round ‖ counter |

## Flow

1. **Start**: generate the Ed25519 identity key, connect, and register with the server.
2. Generate an X25519 ephemeral key, **sign it**, and send it to the peer.
3. The peer **verifies the signature**, replies with its own signed ephemeral key.
4. Both sides compute the X25519 shared secret → HKDF → session keys.
5. Both screens show the same **session key check** and **safety code**.
6. Messages are encrypted with AES-GCM; the server only sees ciphertext.
7. **Rotate**: both sides make NEW ephemeral keys → new session keys, old ones discarded, counters reset.

## Security properties

| Property | Status |
|---|---|
| Server never sees plaintext or keys | ✅ Implemented |
| Signed ephemeral keys (tampering detected) | ✅ Implemented |
| Identity-key change detected mid-session | ✅ Implemented |
| Replay / reordering rejected (counters) | ✅ Implemented |
| Unique nonces (per-direction keys + counter) | ✅ Implemented |
| Key rotation with fresh keys on both sides | ✅ Implemented |
| Forward secrecy per session / rotation | ✅ Implemented (ephemeral keys, never stored) |
| Server cannot spoof sender / duplicate IDs blocked | ✅ Implemented |
| Peer identity verification | ⚠️ Partial — users must compare the safety code manually |
| Identity persists across page reloads | ❌ Not implemented (new identity each load) |
| Transport encryption (wss:// / HTTPS) | ❌ Recommended for production |
| User accounts / authentication | ❌ Recommended for production |
| Offline messages, groups, Double Ratchet | ❌ Out of scope |

This is a **prototype for learning**. It is not equivalent to Signal or WhatsApp.
