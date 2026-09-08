// Secure Chat — minimal shell. Gate: QR only until scanned + connected, then chat UI.
// Flows unchanged: opaque ticket → approve → burn → JWT → WSS.
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

// API base: same-origin by default (Worker-served). Pages sets window.__API_BASE__ via /config.js.
const API_BASE = (typeof window !== "undefined" && window.__API_BASE__ ? window.__API_BASE__ : "").replace(/\/$/, "");
const api = (p) => `${API_BASE}${p}`;
const wsBase = () => (API_BASE ? API_BASE.replace(/^http/, "ws") : `${location.protocol}//${location.host}`);

const statusEl = $("#status");
const timerText = $("#timerText");
const ringFg = $("#ringFg");
const ringNum = $("#ringNum");
const qrEl = $("#qr");
const linkEl = $("#link");
const linkWrap = $("#linkWrap");
const debugEl = $("#debug");
const msgsEl = $("#msgs");
const meEl = $("#me");
const meSub = $("#meSub");
const avatarEl = $("#avatar");
const presenceEl = $("#presence");
const inputEl = $("#msgInput");
const sendBtn = $("#send");
const heroEl = $("#hero");
const scrollEl = $("#scroll");
const modal = $("#qrModal");
const toastsEl = $("#toasts");
const roomNameEl = $("#roomName");
const RING_C = 97.4;

let pollTimer = null, countdownTimer = null, ws = null, chatWs = null;
let currentToken = null, expiresAt = 0;
let gated = true;
let jwt = localStorage.getItem("chat_jwt") || "";
let identity = null;
try { identity = JSON.parse(localStorage.getItem("chat_identity") || "null"); } catch { identity = null; }
let currentRoom = "general";
const debugMode = new URLSearchParams(location.search).has("debug");

function toast(t) {
  if (!toastsEl) return;
  const d = document.createElement("div");
  d.className = "toast"; d.textContent = t;
  toastsEl.appendChild(d);
  setTimeout(() => d.remove(), 2600);
}
function log(...a) {
  if (debugMode && debugEl) {
    debugEl.style.display = "block";
    debugEl.textContent += a.map((x) => typeof x === "string" ? x : JSON.stringify(x)).join(" ") + "\n";
  }
  console.log(...a);
}
function setGated(on) {
  gated = on;
  document.body.classList.toggle("gated", on);
}
function setStatus(t) { if (statusEl) statusEl.textContent = t; }
function setTimer() {
  const s = expiresAt ? Math.max(0, Math.round((expiresAt - Date.now()) / 1000)) : -1;
  if (s < 0) {
    if (timerText) timerText.textContent = "No active ticket";
    if (ringNum) ringNum.textContent = "–";
    if (ringFg) ringFg.style.strokeDashoffset = "0";
    return;
  }
  if (timerText) timerText.textContent = s > 0 ? `${s}s left` : "Expired";
  if (ringNum) ringNum.textContent = String(s);
  if (ringFg) ringFg.style.strokeDashoffset = String(RING_C * (1 - s / 90));
  if (s === 0) setStatus("Expired");
}
function renderMe() {
  const name = jwt && identity ? identity.userId : null;
  if (meEl) meEl.textContent = name || "Not linked";
  if (meSub) meSub.textContent = name ? "pass · 1h" : "ticket required";
  if (avatarEl) avatarEl.textContent = name ? name.slice(0, 1).toUpperCase() : "?";
  updateSend();
}
function updateSend() {
  if (sendBtn && inputEl) sendBtn.disabled = !(chatWs && chatWs.readyState === 1 && inputEl.value.trim());
}
function openModal() { modal?.classList.add("open"); }
function closeModal() {
  if (gated) return; // gate is non-dismissable: scan + connect first
  modal?.classList.remove("open");
}
function updateHero() {
  if (heroEl && msgsEl) heroEl.style.display = msgsEl.querySelector(".row") ? "none" : "";
}

function renderQr(el, text) {
  // Vendored qrcode-generator (same-origin /client/qrcode.min.js) — primary path.
  try {
    if (typeof qrcode !== "undefined") {
      const qr = qrcode(0, "M");
      qr.addData(text);
      qr.make();
      el.innerHTML = qr.createSvgTag({ cellSize: 6, margin: 0, scalable: true });
      const svg = el.querySelector("svg");
      if (svg) {
        svg.style.width = "216px";
        svg.style.height = "216px";
        svg.style.display = "block";
        svg.style.borderRadius = "8px";
      }
      return Promise.resolve(true);
    }
  } catch (e) { console.warn("qrcode render failed", e); }
  // Secondary: node-qrcode UMD if ever present.
  try {
    if (typeof QRCode !== "undefined" && QRCode && QRCode.toCanvas) {
      const c = document.createElement("canvas");
      el.innerHTML = "";
      el.appendChild(c);
      const p = QRCode.toCanvas(c, text, { width: 216, margin: 1 });
      if (p && typeof p.then === "function") return p.then(() => true, () => false);
      return Promise.resolve(true);
    }
  } catch (e) { console.warn("QRCode.toCanvas failed", e); }
  return Promise.resolve(false);
}

async function gen() {
  setStatus("Issuing…");
  if (qrEl) qrEl.innerHTML = '<div class="empty">Creating…</div>';
  if (pollTimer) clearInterval(pollTimer);
  if (countdownTimer) clearInterval(countdownTimer);
  if (ws) try { ws.close(); } catch {}
  openModal();
  let res;
  try {
    res = await fetch(api("/api/auth/qr/create"), { method: "POST" });
  } catch {
    setStatus("Offline");
    if (qrEl) qrEl.innerHTML = '<div class="empty">Network error — retry</div>';
    return;
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    log("create failed", data);
    setStatus("Failed");
    if (qrEl) qrEl.innerHTML = `<div class="empty">Failed — try again</div>`;
    return;
  }
  currentToken = data.token; expiresAt = data.expiresAt;
  // QR encodes Pages origin (so phone lands on Pages /mobile, not Worker). data.url is Worker origin when called via API_BASE.
  const qrText = API_BASE ? `${location.origin}/mobile?token=${encodeURIComponent(data.token)}` : data.url;
  setStatus("Scan with mobile");
  setTimer();
  countdownTimer = setInterval(setTimer, 400);
  if (qrEl) {
    qrEl.innerHTML = "";
    const ok = await renderQr(qrEl, qrText);
    if (!ok) {
      const d = document.createElement("div");
      d.className = "qr-fallback";
      d.textContent = qrText;
      qrEl.appendChild(d);
    }
  }
  if (linkEl && linkWrap) { linkEl.textContent = qrText; linkWrap.style.display = "block"; }
  tryWs(data.token);
  startPolling(data.token);
}
function tryWs(token) {
  try {
    ws = new WebSocket(`${wsBase()}/api/auth/qr/ws?token=${encodeURIComponent(token)}`);
    ws.onmessage = (e) => {
      try {
        const m = JSON.parse(e.data);
        if (m.status === "approved") { setStatus("Approved"); claim(token); }
        if (m.status === "denied") { setStatus("Denied"); cleanup(); }
        if (m.status === "expired") { setStatus("Expired"); cleanup(); }
      } catch {}
    };
  } catch {}
}
function startPolling(token) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    let res;
    try { res = await fetch(api(`/api/auth/qr/status?token=${encodeURIComponent(token)}`)); }
    catch { return; }
    const data = await res.json().catch(() => ({}));
    if (data.status === "approved") { setStatus("Approved"); claim(token); }
    if (data.status === "denied") { setStatus("Denied"); cleanup(); }
    if (data.status === "expired") { setStatus("Expired"); cleanup(); }
  }, 1500);
}
async function claim(token) {
  cleanup();
  let res;
  try {
    res = await fetch(api("/api/auth/qr/claim"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
  } catch { setStatus("Offline"); return; }
  const data = await res.json().catch(() => ({}));
  if (res.ok && data.token) {
    jwt = data.token; identity = data.identity;
    localStorage.setItem("chat_jwt", jwt);
    localStorage.setItem("chat_identity", JSON.stringify(identity));
    renderMe();
    setStatus("Linked");
    if (timerText) timerText.textContent = "Burned";
    toast(`Linked as ${identity.userId}`);
    setGated(false); // reveal the UI — scanned + connected
    modal?.classList.remove("open");
    connectChat(currentRoom);
  } else setStatus("Claim failed");
}
function cleanup() {
  if (pollTimer) clearInterval(pollTimer); pollTimer = null;
  if (countdownTimer) clearInterval(countdownTimer); countdownTimer = null;
  if (ws) try { ws.close(); } catch {} ws = null;
}

function connectChat(roomId = "general") {
  currentRoom = roomId;
  if (roomNameEl) roomNameEl.textContent = roomId;
  if (inputEl) inputEl.placeholder = `Message #${roomId}`;
  $$(".room").forEach((b) => b.classList.toggle("active", b.dataset.room === roomId));
  if (chatWs) try { chatWs.close(); } catch {}
  msgsEl.innerHTML = "";
  updateHero();
  if (!jwt) { setGated(true); openModal(); gen(); return; }
  chatWs = new WebSocket(`${wsBase()}/api/room/${encodeURIComponent(roomId)}/ws?token=${encodeURIComponent(jwt)}`);
  chatWs.onopen = () => renderMe();
  chatWs.onmessage = (e) => {
    try {
      const d = JSON.parse(e.data);
      if (d.type === "welcome") { if (d.history?.length) d.history.forEach(appendMsg); updateHero(); }
      else if (d.type === "message") appendMsg(d.message);
      else if (d.type === "presence" && presenceEl) {
        presenceEl.style.display = "block";
        presenceEl.textContent = `● ${d.userId} ${d.event}ed`;
        clearTimeout(presenceEl._t);
        presenceEl._t = setTimeout(() => (presenceEl.style.display = "none"), 3500);
      }
      else if (d.type === "moderation") { appendSystem("Blocked by moderation."); toast("Blocked"); }
      else if (d.type === "error") appendSystem("Error — try again.");
    } catch {}
  };
  chatWs.onclose = () => { appendSystem("Disconnected — reload to reconnect."); renderMe(); };
  renderMe();
}
function appendMsg(m) {
  const mine = identity && m.userId === identity.userId;
  const div = document.createElement("div");
  div.className = "row " + (mine ? "me" : "peer");
  const who = m.displayName || m.userId;
  const time = new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (mine) {
    div.innerHTML = `<div class="bubble"><div class="body"></div></div>`;
    div.querySelector(".body").textContent = m.body;
  } else {
    div.innerHTML = `<div class="ava"></div><div class="bubble"><div class="meta"><b></b><time>${time}</time></div><div class="body"></div></div>`;
    div.querySelector(".ava").textContent = who.slice(0, 1).toUpperCase();
    div.querySelector("b").textContent = who;
    div.querySelector(".body").textContent = m.body;
  }
  msgsEl.appendChild(div);
  scrollEl.scrollTop = scrollEl.scrollHeight;
  updateHero();
}
function appendSystem(t) {
  const d = document.createElement("div");
  d.className = "sys"; d.textContent = "— " + t;
  msgsEl.appendChild(d);
}
function send() {
  const body = inputEl.value.trim();
  if (!body) return;
  if (!chatWs || chatWs.readyState !== 1) { toast("Link this device first"); openModal(); return; }
  chatWs.send(JSON.stringify({ type: "message", roomId: currentRoom, body }));
  inputEl.value = "";
  autogrow(); updateSend();
}
function autogrow() {
  inputEl.style.height = "auto";
  inputEl.style.height = Math.min(160, inputEl.scrollHeight) + "px";
}

$("#gen")?.addEventListener("click", gen);
$("#openQrBtn")?.addEventListener("click", () => { openModal(); if (!currentToken || Date.now() > expiresAt) gen(); });
$("#linkDeviceBtn")?.addEventListener("click", () => { openModal(); if (!currentToken || Date.now() > expiresAt) gen(); });
$("#heroLinkBtn")?.addEventListener("click", gen);
$("#qrClose")?.addEventListener("click", closeModal);
modal?.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { closeModal(); $("#sidebar")?.classList.remove("open"); }
});
$("#copyLinkBtn")?.addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(linkEl.textContent); toast("Copied"); } catch { toast("Copy failed"); }
});
$("#send")?.addEventListener("click", send);
inputEl?.addEventListener("input", () => { autogrow(); updateSend(); });
inputEl?.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } });
$("#newChatBtn")?.addEventListener("click", () => { msgsEl.innerHTML = ""; updateHero(); inputEl?.focus(); });
$("#menuBtn")?.addEventListener("click", () => $("#sidebar")?.classList.add("open"));
$$(".room").forEach((b) => b.addEventListener("click", () => { connectChat(b.dataset.room); $("#sidebar")?.classList.remove("open"); }));

// Boot: linked sessions go straight to chat; everyone else sees ONLY the QR gate.
renderMe();
setTimer();
if (jwt && identity) {
  setGated(false);
  setTimeout(() => connectChat(currentRoom), 400);
} else {
  setGated(true);
  appendSystem("Link this device to join.");
  gen();
}
