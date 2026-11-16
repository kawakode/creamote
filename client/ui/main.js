// Interface du client Creamote. Aucune dépendance : API Tauri globale
// (withGlobalTauri) et WebCodecs quand la WebView le propose.
import { HID_USAGE } from "./keymap.js";

const { invoke, Channel } = window.__TAURI__.core;
const $ = (id) => document.getElementById(id);

const FIELDS = ["target", "server", "server-pin", "api-url"];
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* stockage indisponible */ } },
};

let session = null;

async function webCodecsAvailable() {
  if (typeof VideoDecoder === "undefined") return false;
  try {
    const r = await VideoDecoder.isConfigSupported({ codec: "avc1.42E01F" });
    return r.supported === true;
  } catch {
    return false;
  }
}

function setStatus(text, error = false) {
  $("status").textContent = text;
  $("status").classList.toggle("error", error);
}

async function init() {
  for (const f of FIELDS) {
    const v = store.get(`creamote.${f}`);
    if (v) $(f).value = v;
  }
  try {
    const me = await invoke("identity");
    $("my-id").textContent = me.device_id;
    $("my-fp").textContent = `(${me.fingerprint})`;
  } catch (e) {
    setStatus(String(e), true);
  }
  $("connect-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    connect();
  });
  $("disconnect").addEventListener("click", () => invoke("disconnect").finally(() => end("Session fermée.")));
  $("displays").addEventListener("change", (ev) =>
    invoke("select_display", { displayId: Number(ev.target.value) }).catch(console.error));
  setupInput();
}

async function connect() {
  for (const f of FIELDS) store.set(`creamote.${f}`, $(f).value);
  const useWebCodecs = await webCodecsAvailable();
  session = new Session(useWebCodecs);
  const events = new Channel();
  events.onmessage = (m) => session && session.onEvent(m);
  const frames = new Channel();
  frames.onmessage = (m) => session && session.onFrame(m);

  $("connect-btn").disabled = true;
  setStatus("Connexion…");
  try {
    await invoke("connect", {
      args: {
        server: $("server").value.trim(),
        serverPin: $("server-pin").value.trim(),
        target: $("target").value.trim(),
        apiUrl: $("api-url").value.trim() || null,
        apiToken: $("api-token").value || null,
        viewOnly: $("view-only").checked,
        decodeInRust: !useWebCodecs,
      },
      events,
      frames,
    });
    $("home").hidden = true;
    $("session").hidden = false;
    $("waiting").hidden = false;
    $("peer").textContent = $("target").value.trim();
    $("screen").focus();
  } catch (e) {
    session = null;
    setStatus(String(e), true);
  } finally {
    $("connect-btn").disabled = false;
  }
}

function end(message, error = false) {
  if (session) session.close();
  session = null;
  $("session").hidden = true;
  $("home").hidden = false;
  setStatus(message, error);
}

const END_MESSAGES = {
  Declined: "L'utilisateur distant a refusé la connexion.",
  ConsentTimeout: "Pas de réponse de l'utilisateur distant.",
  Forbidden: "Vos droits ne permettent pas d'afficher cet écran.",
  Closed: "Session terminée.",
};

// Codec WebCodecs à partir du SPS (profil, contraintes, niveau).
function codecFromSps(data) {
  for (let i = 0; i + 4 < data.length; i++) {
    if (data[i] === 0 && data[i + 1] === 0 && data[i + 2] === 1 && (data[i + 3] & 0x1f) === 7) {
      const hex = (b) => b.toString(16).padStart(2, "0");
      return `avc1.${hex(data[i + 4])}${hex(data[i + 5])}${hex(data[i + 6])}`;
    }
  }
  return null;
}

class Session {
  constructor(useWebCodecs) {
    this.useWebCodecs = useWebCodecs;
    this.decoder = null;
    this.canvas = $("screen");
    this.ctx = this.canvas.getContext("2d");
    this.control = false;
    this.displayId = 0;
    this.frames = 0;
    this.lastStats = performance.now();
    this.keyframeAsked = false;
  }

  onEvent(ev) {
    switch (ev.type) {
      case "connected":
        $("code").textContent = ev.code;
        break;
      case "accepted":
        this.control = ev.granted.includes("control");
        this.showDisplays(ev.displays, (d) => d.primary);
        $("peer").textContent += this.control ? " · contrôle" : " · vue seule";
        break;
      case "displays":
        // Écran branché ou débranché chez le host.
        this.showDisplays(ev.displays, (d) => d.id === this.displayId);
        break;
      case "video":
        this.displayId = ev.displayId;
        $("displays").value = ev.displayId;
        this.encoder = ev.encoder;
        $("waiting").hidden = true;
        break;
      case "ended":
        end(END_MESSAGES[ev.reason] || ev.message || "Session terminée.", ev.reason !== "Closed");
        break;
    }
  }

  showDisplays(displays, isSelected) {
    const sel = $("displays");
    sel.replaceChildren(...displays.map((d) => {
      const o = document.createElement("option");
      o.value = d.id;
      o.textContent = `${d.name} (${d.width}×${d.height})`;
      o.selected = isSelected(d);
      return o;
    }));
    sel.hidden = displays.length < 2;
  }

  onFrame(msg) {
    const buf = msg instanceof ArrayBuffer ? msg : new Uint8Array(msg).buffer;
    const dv = new DataView(buf);
    const kind = dv.getUint8(0);
    const key = dv.getUint8(1) === 1;
    const id = dv.getUint32(12, true);
    if (kind === 1) {
      const w = dv.getUint32(4, true);
      const h = dv.getUint32(8, true);
      this.resize(w, h);
      this.ctx.putImageData(new ImageData(new Uint8ClampedArray(buf, 16, w * h * 4), w, h), 0, 0);
      this.stats();
      return;
    }
    this.decode(new Uint8Array(buf, 16), key, id);
  }

  decode(data, key, id) {
    if (key) {
      const codec = codecFromSps(data);
      if (codec && (!this.decoder || this.codec !== codec || this.decoder.state !== "configured")) {
        this.resetDecoder();
        this.codec = codec;
        this.decoder = new VideoDecoder({
          output: (frame) => this.draw(frame),
          error: (e) => {
            console.warn("décodeur", e);
            this.resetDecoder();
            this.askKeyframe();
          },
        });
        this.decoder.configure({ codec, optimizeForLatency: true });
      }
      this.keyframeAsked = false;
    }
    if (!this.decoder || this.decoder.state !== "configured") {
      // Pas de décodeur prêt : on attend une image clé, sans bloquer le host.
      this.ack(id);
      this.askKeyframe();
      return;
    }
    this.decoder.decode(new EncodedVideoChunk({
      type: key ? "key" : "delta",
      timestamp: id * 1000,
      data,
    }));
  }

  draw(frame) {
    this.resize(frame.displayWidth, frame.displayHeight);
    this.ctx.drawImage(frame, 0, 0);
    this.ack(Math.round(frame.timestamp / 1000));
    frame.close();
    this.stats();
  }

  resize(w, h) {
    if (this.canvas.width !== w || this.canvas.height !== h) {
      this.canvas.width = w;
      this.canvas.height = h;
    }
  }

  stats() {
    this.frames++;
    const now = performance.now();
    if (now - this.lastStats > 1000) {
      const fps = (this.frames * 1000) / (now - this.lastStats);
      const dec = this.useWebCodecs ? "WebCodecs" : "openh264";
      $("stats").textContent = `${fps.toFixed(0)} i/s · ${this.encoder || ""} → ${dec}`;
      this.frames = 0;
      this.lastStats = now;
    }
  }

  ack(id) {
    invoke("ack", { frameId: id }).catch(() => {});
  }

  askKeyframe() {
    if (this.keyframeAsked) return;
    this.keyframeAsked = true;
    invoke("request_keyframe").catch(() => {});
  }

  resetDecoder() {
    if (this.decoder && this.decoder.state !== "closed") this.decoder.close();
    this.decoder = null;
  }

  close() {
    this.resetDecoder();
    releaseKeys();
  }
}

// ----- Entrées -----

const pressed = new Set();
let pendingMove = null;
let wheel = { dx: 0, dy: 0 };

// Position normalisée dans l'image affichée (object-fit: contain).
function normalized(ev) {
  const c = $("screen");
  const r = c.getBoundingClientRect();
  if (!c.width || !c.height) return null;
  const scale = Math.min(r.width / c.width, r.height / c.height);
  const w = c.width * scale;
  const h = c.height * scale;
  const x = (ev.clientX - r.left - (r.width - w) / 2) / w;
  const y = (ev.clientY - r.top - (r.height - h) / 2) / h;
  return { x: Math.min(Math.max(x, 0), 1), y: Math.min(Math.max(y, 0), 1) };
}

function sendPointer(ev, wheelDx = 0, wheelDy = 0) {
  if (!session || !session.control) return;
  const p = normalized(ev);
  if (!p) return;
  invoke("pointer", {
    displayId: session.displayId,
    x: p.x,
    y: p.y,
    buttons: ev.buttons,
    wheelDx,
    wheelDy,
  }).catch(() => {});
}

function releaseKeys() {
  for (const hid of pressed) invoke("key", { hid, pressed: false }).catch(() => {});
  pressed.clear();
}

function setupInput() {
  const c = $("screen");
  c.addEventListener("pointermove", (ev) => {
    // Un événement par image affichée au plus.
    if (!pendingMove) requestAnimationFrame(() => {
      sendPointer(pendingMove);
      pendingMove = null;
    });
    pendingMove = ev;
  });
  c.addEventListener("pointerdown", (ev) => {
    c.focus();
    c.setPointerCapture(ev.pointerId);
    sendPointer(ev);
  });
  c.addEventListener("pointerup", (ev) => sendPointer(ev));
  c.addEventListener("contextmenu", (ev) => ev.preventDefault());
  c.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    // Crans : ~100 px ou 3 lignes par cran.
    const unit = ev.deltaMode === 0 ? 100 : ev.deltaMode === 1 ? 3 : 1;
    wheel.dx += ev.deltaX / unit;
    wheel.dy += ev.deltaY / unit;
    if (Math.abs(wheel.dx) >= 0.1 || Math.abs(wheel.dy) >= 0.1) {
      sendPointer(ev, wheel.dx, wheel.dy);
      wheel = { dx: 0, dy: 0 };
    }
  }, { passive: false });

  const onKey = (down) => (ev) => {
    if (!session || !session.control) return;
    const hid = HID_USAGE[ev.code];
    if (hid === undefined) return;
    ev.preventDefault();
    // Le système du host gère lui-même la répétition d'une touche tenue.
    if (down && ev.repeat) return;
    if (down) pressed.add(hid); else pressed.delete(hid);
    invoke("key", { hid, pressed: down }).catch(() => {});
  };
  c.addEventListener("keydown", onKey(true));
  c.addEventListener("keyup", onKey(false));
  // Fenêtre quittée (Alt+Tab…) : ne rien laisser enfoncé chez le host.
  window.addEventListener("blur", releaseKeys);
  c.addEventListener("blur", releaseKeys);
}

init();
