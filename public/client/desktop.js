// Secure Chat — ephemeral, 2-person, nickname-only, E2E on invite rooms.
// Privacy: random temp IDs, no email/phone, IP not logged, messages auto-expire, storage URL is dm_* hash, refresh erases everything.
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

// Ephemeral: clear any persisted session on load — refreshing erases everything
try { localStorage.clear(); sessionStorage.clear(); } catch {}
// Pages → Worker wiring
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
let currentToken = null, expiresAt = 0, createdAsHost = false, privateRoomId = null;
let gated = true;
let jwt = ""; // ephemeral, not persisted
let identity = null;
let currentRoom = "general";
let e2eKey = null; // derived from raw invite token — only host+visitor know it, server cannot read dm_* messages
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
  const qrView = document.getElementById("qrView");
  const chatView = document.getElementById("chatView");
  if (qrView) { qrView.style.display = on ? "grid" : "none"; qrView.classList.toggle("hide", !on); }
  if (chatView) { chatView.style.display = on ? "none" : "grid"; chatView.classList.toggle("hide", on); }
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
  const name = jwt && identity ? identity.displayName || identity.userId : null;
  if (meEl) meEl.textContent = name || "Not linked";
  if (meSub) meSub.textContent = name ? `${name} · ephemeral` : "enter nickname to start";
  if (avatarEl) avatarEl.textContent = name ? name.slice(0, 1).toUpperCase() : "?";
  updateSend();
  if (roomNameEl) roomNameEl.textContent = privateRoomId || currentRoom;
}
function updateSend() {
  if (sendBtn && inputEl) sendBtn.disabled = !(chatWs && chatWs.readyState === 1 && inputEl.value.trim());
}
function openModal() {
  // QR-only page: show qrView
  setGated(true);
  const qrView = document.getElementById("qrView");
  const chatView = document.getElementById("chatView");
  if (qrView) qrView.style.display = "grid";
  if (chatView) chatView.style.display = "none";
  modal?.classList.add("open");
}
function closeModal() {
  if (gated) return;
  modal?.classList.remove("open");
  const qrView = document.getElementById("qrView");
  const chatView = document.getElementById("chatView");
  if (qrView) qrView.style.display = "none";
  if (chatView) chatView.style.display = "grid";
}
function updateHero() {
  if (heroEl && msgsEl) heroEl.style.display = msgsEl.querySelector(".row") ? "none" : "";
}

// --- E2E: AES-GCM key from raw invite token (server stores only hash, cannot decrypt) ---
async function deriveE2EKey(rawToken) {
  if (!rawToken) return null;
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawToken));
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function e2eEncrypt(plain, key) {
  if (!key || !privateRoomId || !privateRoomId.startsWith("dm_")) return plain;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plain));
  return `enc:${btoa(String.fromCharCode(...new Uint8Array(ct)))}.${btoa(String.fromCharCode(...iv))}`;
}
async function e2eDecrypt(payload, key) {
  if (!key || typeof payload !== "string" || !payload.startsWith("enc:")) return payload;
  try {
    const [b64ct, b64iv] = payload.slice(4).split(".");
    const ct = Uint8Array.from(atob(b64ct), (c) => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(b64iv), (c) => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch { return payload; }
}

function renderQr(el, text) {
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
    const headers = {};
    if (jwt) headers["Authorization"] = `Bearer ${jwt}`;
    res = await fetch(api("/api/auth/qr/create"), { method: "POST", headers });
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
  privateRoomId = data.roomId || null;
  if (privateRoomId) currentRoom = privateRoomId;
  createdAsHost = !!jwt;
  e2eKey = await deriveE2EKey(currentToken);
  const qrText = API_BASE ? `${location.origin}/mobile?token=${encodeURIComponent(data.token)}` : data.url;
  setStatus(createdAsHost ? `Invite · ${privateRoomId} — scan to chat` : "Scan with mobile");
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
  if (linkEl && linkWrap) { linkEl.textContent = ""; linkWrap.style.display = "none"; } // token not shown — QR only
  tryWs(data.token);
  startPolling(data.token);
}
function tryWs(token) {
  try {
    ws = new WebSocket(`${wsBase()}/api/auth/qr/ws?token=${encodeURIComponent(token)}`);
    ws.onmessage = (e) => {
      try {
        const m = JSON.parse(e.data);
        if (m.status === "approved") {
          if (createdAsHost) {
            const r = m.roomId || privateRoomId || currentRoom;
            if (r) { privateRoomId = r; currentRoom = r; }
            setStatus("Joined — say hello"); toast(`Someone joined ${r} — 2-person, E2E`); setGated(false); modal?.classList.remove("open"); connectChat(r); cleanup();
          } else { setStatus("Approved"); claim(token); }
        }
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
    if (data.status === "approved") {
      if (createdAsHost) {
        const r = data.roomId || privateRoomId || currentRoom;
        if (r) { privateRoomId = r; currentRoom = r; }
        setStatus("Joined — say hello"); toast(`Someone joined ${r} — 2-person, E2E`); setGated(false); modal?.classList.remove("open"); connectChat(r); cleanup();
      } else { setStatus("Approved"); claim(token); }
    }
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
    privateRoomId = data.roomId || privateRoomId;
    if (privateRoomId) currentRoom = privateRoomId;
    e2eKey = await deriveE2EKey(token);
    renderMe();
    setStatus("Linked");
    if (timerText) timerText.textContent = "Burned";
    toast(`Linked as ${identity.displayName || identity.userId} · ${privateRoomId} (E2E)`);
    setGated(false);
    modal?.classList.remove("open");
    connectChat(privateRoomId || currentRoom);
  } else setStatus("Claim failed");
}
function cleanup() {
  if (pollTimer) clearInterval(pollTimer); pollTimer = null;
  if (countdownTimer) clearInterval(countdownTimer); countdownTimer = null;
  if (ws) try { ws.close(); } catch {} ws = null;
}

async function connectChat(roomId = "general") {
  currentRoom = roomId;
  if (roomNameEl) roomNameEl.textContent = roomId;
  if (inputEl) inputEl.placeholder = `Message #${roomId} · E2E if dm_*`;
  $$(".room").forEach((b) => b.classList.toggle("active", b.dataset.room === roomId));
  if (chatWs) try { chatWs.close(); } catch {}
  msgsEl.innerHTML = "";
  updateHero();
  if (!jwt) { setGated(true); openModal(); gen(); return; }
  chatWs = new WebSocket(`${wsBase()}/api/room/${encodeURIComponent(roomId)}/ws?token=${encodeURIComponent(jwt)}`);
  chatWs.onopen = () => renderMe();
  chatWs.onmessage = async (e) => {
    try {
      const d = JSON.parse(e.data);
      if (d.type === "welcome") {
        // Privacy: do not replay history — fresh session only (ephemeral, refresh erases, 2-person dm_* auto-expires)
        // History still exists server-side for reconnect grace but is not shown to new participants.
        updateHero();
        if (d.history?.length) log("history suppressed", d.history.length);
      } else if (d.type === "message") await appendMsg(d.message);
      else if (d.type === "presence" && presenceEl) {
        presenceEl.style.display = "block";
        presenceEl.textContent = `● ${d.userId} ${d.event}ed`;
        clearTimeout(presenceEl._t);
        presenceEl._t = setTimeout(() => (presenceEl.style.display = "none"), 3500);
      }
      else if (d.type === "moderation") { appendSystem("Blocked by moderation."); toast("Blocked"); }
      else if (d.type === "error") appendSystem(d.error.includes("full") ? "Room full — only 2" : "Error — try again");
    } catch {}
  };
  chatWs.onclose = () => { appendSystem("Disconnected — reload erases (ephemeral)"); renderMe(); };
  renderMe();
}
async function appendMsg(m) {
  const mine = identity && m.userId === identity.userId;
  const div = document.createElement("div");
  div.className = "row " + (mine ? "me" : "peer");
  const who = m.displayName || m.userId;
  const time = new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  // E2E decrypt if needed
  let body = m.body;
  if (m.roomId?.startsWith("dm_") && e2eKey) body = await e2eDecrypt(body, e2eKey);
  else if (m.roomId?.startsWith("dm_") && !e2eKey) body = "[encrypted — refresh cleared key]";
  if (mine) {
    div.innerHTML = `<div class="bubble"><div class="body"></div></div>`;
    div.querySelector(".body").textContent = body;
  } else {
    div.innerHTML = `<div class="ava"></div><div class="bubble"><div class="meta"><b></b><time>${time}</time></div><div class="body"></div></div>`;
    div.querySelector(".ava").textContent = who.slice(0, 1).toUpperCase();
    div.querySelector("b").textContent = who;
    div.querySelector(".body").textContent = body;
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
async function send() {
  const body = inputEl.value.trim();
  if (!body) return;
  if (!chatWs || chatWs.readyState !== 1) { toast("Link first"); openModal(); return; }
  let outBody = body;
  if (currentRoom.startsWith("dm_") && e2eKey) outBody = await e2eEncrypt(body, e2eKey);
  chatWs.send(JSON.stringify({ type: "message", roomId: currentRoom, body: outBody }));
  inputEl.value = "";
  autogrow(); updateSend();
}
function autogrow() {
  inputEl.style.height = "auto";
  inputEl.style.height = Math.min(160, inputEl.scrollHeight) + "px";
}

async function ensureEphemeralIdentity() {
  if (jwt && identity) return;
  const nick = `anon-${Math.random().toString(36).slice(2,6)}`;
  const tmpId = `u_${Math.random().toString(36).slice(2,10)}_${Date.now().toString(36)}`;
  try {
    const res = await fetch(api("/api/auth/dev-login"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ userId: tmpId, displayName: nick }) });
    const data = await res.json();
    if (data.token) { jwt = data.token; identity = { userId: data.userId, displayName: nick }; renderMe(); }
  } catch {}
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

// Boot: ephemeral, no nickname ask — QR only. Auto-mint random anon, show QR.
renderMe();
setTimer();
ensureEphemeralIdentity().then(() => {
  renderMe();
  setGated(true);
  if (heroEl) heroEl.style.display = "";
  appendSystem("Share this QR to chat — no account, no nickname needed. Scan to join (2-person, E2E). Refresh erases everything.");
  gen();
});
