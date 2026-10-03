// fx.js — visual effects only (no crypto, no networking).
//
// 1. Matrix-style "hex rain" on a background canvas.
// 2. Watches the #status badge and copies its state (idle / busy / ok / warn / err)
//    onto <body data-state="…">, so the whole page changes colour smoothly.
//
// It does NOT touch app.js logic. If this file is removed, the chat still works.

"use strict";

(function () {
  const STATE_COLORS = {
    idle: "#00e5ff",
    busy: "#ffb020",
    ok: "#00ff9c",
    warn: "#ff7a1a",
    err: "#ff3b5c",
  };
  let rainColor = STATE_COLORS.idle;

  // -------------------------------------------------------------------------
  // State sync: #status class → body[data-state]
  // -------------------------------------------------------------------------
  function syncState() {
    const status = document.getElementById("status");
    if (!status) return;
    const match = status.className.match(/status-(idle|busy|ok|warn|err)/);
    const state = match ? match[1] : "idle";
    if (document.body.dataset.state !== state) {
      document.body.dataset.state = state;
      rainColor = STATE_COLORS[state];
    }
  }

  function watchStatus() {
    const status = document.getElementById("status");
    if (!status) return;
    syncState();
    new MutationObserver(syncState).observe(status, { attributes: true, attributeFilter: ["class"] });
  }

  // -------------------------------------------------------------------------
  // Hex rain
  // -------------------------------------------------------------------------
  function startRain() {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const canvas = document.getElementById("matrix");
    if (!canvas || !canvas.getContext) return;
    const ctx = canvas.getContext("2d");

    const CHARS = "0123456789ABCDEF";
    const FONT_SIZE = 15;
    const FRAME_MS = 55; // ~18 fps — light on CPU
    let columns = 0;
    let drops = [];
    let last = 0;

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      columns = Math.ceil(window.innerWidth / FONT_SIZE);
      drops = Array.from({ length: columns }, () => Math.random() * -60);
    }

    function draw(now) {
      requestAnimationFrame(draw);
      if (document.hidden || now - last < FRAME_MS) return;
      last = now;

      // fade previous frame → trails
      ctx.fillStyle = "rgba(4, 6, 12, 0.14)";
      ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);

      ctx.font = `${FONT_SIZE}px Consolas, "Courier New", monospace`;
      for (let i = 0; i < columns; i++) {
        const y = drops[i] * FONT_SIZE;
        if (y > 0) {
          const ch = CHARS[(Math.random() * CHARS.length) | 0];
          // bright head, coloured body
          ctx.fillStyle = Math.random() < 0.08 ? "#ffffff" : rainColor;
          ctx.fillText(ch, i * FONT_SIZE, y);
        }
        if (y > window.innerHeight && Math.random() > 0.975) drops[i] = Math.random() * -20;
        drops[i] += 1;
      }
    }

    resize();
    window.addEventListener("resize", resize);
    requestAnimationFrame(draw);
  }

  function init() {
    watchStatus();
    startRain();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
