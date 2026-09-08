// Secure Chat — Grok-like shell. Security flows unchanged: opaque ticket → approve → burn → JWT → WSS.
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const statusEl = $("#status");
const timerText = $("#timerText");
const ringFg = $("#ringFg");
const ringNum = $("#ringNum");
const ringSub = $("#ringSub");
const qrEl = $("#qr");
const linkEl = $("#link");
const linkWrap = $("#linkWrap");
const debugEl = $("#debug");
const msgsEl = $("#msgs");
const meEl = $("#me");
const meSub = $("#meSub");
const avatarEl = $("#avatar");
const presenceEl = $("#presence");
const presenceDot = $("#presenceDot");
const sessionRow = $("#sessionRow");
const inputEl = $("#msgInput");
const sendBtn = $("#send");
const heroEl = $("#hero");
const scrollEl = $("#scroll");
const modal = $("#qrModal");
const toastsEl = $("#toasts");
const secureBadge = $("#secureBadge");
const secureText = $("#secureText");
const roomNameEl = $("#roomName");
const kvRoom = $("#kvRoom");
const unreadEl = $("#unreadGeneral");
const RING_C = 97.4;

let pollTimer = null;
let countdownTimer = null;
let ws = null;
let chatWs = null;
let currentToken = null;
let expiresAt = 0;
let jwt = localStorage.getItem("chat_jwt") || "";
let identity = null;
try { identity = JSON.parse(localStorage.getItem("chat_identity") || "null"); } catch { identity = null; }
let currentRoom = "general";
let verbose = false;
let unread = 0;

function toast(text) {
  if (!toastsEl) return;
  const d = document.createElement("div");
  d.className = "toast";
  d.textContent = text;
  toastsEl.appendChild(d);
  setTimeout(() => { d.style.opacity = "0"; setTimeout(() => d.remove(), 250); }, 2600);
}
function log(...a) {
  const line = a.map((x) => (typeof x === "string" ? x : JSON.stringify(x, null, 2))).join(" ");
  if (debugEl && (verbose || /failed|error|claim|poll|recv|open/i.test(line))) {
    debugEl.textContent += line + "\n";
    debugEl.scrollTop = debugEl.scrollHeight;
  }
  console.log(...a);
}
function setStatus(text, tone) {
  if (!statusEl) return;
  statusEl.textContent = text;
  statusEl.className = tone === "ok" ? "ok" : tone === "bad" ? "bad" : tone === "warn" ? "warn" : "";
  statusEl.id = "status";
  const s1 = $("#step1"), s2 = $("#step2"), s3 = $("#step3");
  if (s1 && s2 && s3) {
    s1.className = "done";
    s2.className = text.toLowerCase().includes("approv") || text.toLowerCase().includes("linked") || text.toLowerCase().includes("burn") ? "done" : "";
    s3.className = text.toLowerCase().includes("linked") || text.toLowerCase().includes("burn") ? "done" : "";
  }
}
function setTimer() {
  const s = expiresAt ? Math.max(0, Math.round((expiresAt - Date.now()) / 1000)) : -1;
  if (s < 0) {
    if (timerText) timerText.textContent = "No active ticket";
    if (ringNum) ringNum.textContent = "–";
    if (ringFg) ringFg.style.strokeDashoffset = "0";
    return;
  }
  if (timerText) timerText.textContent = s > 0 ? `${s}s left · burns on claim` : "Expired";
  if (ringNum) ringNum.textContent = String(s);
  if (ringFg) ringFg.style.strokeDashoffset = String(RING_C * (1 - s / 90));
  if (ringSub) ringSub.textContent = s > 0 ? "opaque · SHA-256 at rest · 256-bit" : "expired · generate a new ticket";
  if (s === 0) setStatus("Expired", "bad");
}
function renderMe() {
  const name = jwt && identity ? identity.userId : null;
  if (meEl) meEl.textContent = name || "Not linked";
  if (meSub) meSub.textContent = name ? `${identity.displayName || name} · pass 1h` : "generate a ticket to start";
  if (avatarEl) avatarEl.textContent = name ? name.slice(0, 1).toUpperCase() : "?";
  if (sessionRow) sessionRow.textContent = name ? `●  Linked as ${name} — transcript is live` : "○  Not linked — ticket required";
  if (presenceDot) presenceDot.classList.toggle("on", !!(chatWs && chatWs.readyState === 1));
  if (secureBadge) secureBadge.classList.toggle("off", !name);
  if (secureText) secureText.textContent = name ? "secured · WSS" : "unlinked";
  updateSend();
}
function updateSend() {
  if (!sendBtn || !inputEl) return;
  const ok = !!(chatWs && chatWs.readyState === 1) && inputEl.value.trim().length > 0;
  sendBtn.disabled = !ok;
}
function openModal() {
  modal?.classList.add("open");
  document.body.style.overflow = "hidden";
}
function closeModal() {
  modal?.classList.remove("open");
  document.body.style.overflow = "";
}
function updateHero() {
  if (!heroEl || !msgsEl) return;
  const has = msgsEl.querySelector(".row");
  heroEl.style.display = has ? "none" : "";
}

// ---------- QR ticket flow (unchanged security) ----------
async function gen() {
  setStatus("Issuing…");
  if (qrEl) qrEl.innerHTML = '<div class="empty">Creating ticket…</div>';
  if (pollTimer) clearInterval(pollTimer);
  if (countdownTimer) clearInterval(countdownTimer);
  if (ws) try { ws.close(); } catch {}
  openModal();
  const res = await fetch("/api/auth/qr/create", { method: "POST" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    log("create failed", data);
    setStatus("Failed: " + (data.error || res.status), "bad");
    if (qrEl) qrEl.innerHTML = `<div class="empty">Failed — ${escapeHtml(data.error || String(res.status))}</div>`;
    toast("Could not create ticket — try again");
    return;
  }
  currentToken = data.token;
  expiresAt = data.expiresAt;
  log("QR created", { expiresAt: new Date(data.expiresAt).toISOString(), ttlMs: data.ttlMs });
  setStatus("Scan with mobile", "warn");
  setTimer();
  countdownTimer = setInterval(setTimer, 400);
  if (qrEl) {
    qrEl.innerHTML = "";
    const canvas = document.createElement("canvas");
    qrEl.appendChild(canvas);
    if (typeof QRCode !== "undefined") await QRCode.toCanvas(canvas, data.url, { width: 216, margin: 1, color: { dark: "#000000", light: "#FFFFFF" } });
    else qrEl.textContent = data.url;
  }
  if (linkEl && linkWrap) { linkEl.textContent = data.url; linkWrap.style.display = "block"; }
  tryWs(data.token);
  startPolling(data.token);
}
function tryWs(token) {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  try {
    ws = new WebSocket(`${proto}//${location.host}/api/auth/qr/ws?token=${encodeURIComponent(token)}`);
    ws.onopen = () => log("waiter open");
    ws.onmessage = (e) => {
      log("waiter", e.data);
      try {
        const msg = JSON.parse(e.data);
        if (msg.status === "approved") { setStatus("Approved — burning…", "ok"); claim(token); }
        if (msg.status === "denied") { setStatus("Denied", "bad"); cleanup(); }
        if (msg.status === "expired") { setStatus("Expired", "bad"); cleanup(); }
      } catch {}
    };
    ws.onerror = () => log("waiter error — poll still active");
  } catch (e) { log("waiter failed", String(e)); }
}
function startPolling(token) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const res = await fetch(`/api/auth/qr/status?token=${encodeURIComponent(token)}`);
    const data = await res.json().catch(() => ({}));
    log("poll", res.status, data);
    if (data.status === "approved") { setStatus("Approved — burning…", "ok"); claim(token); }
    if (data.status === "denied") { setStatus("Denied", "bad"); cleanup(); }
    if (data.status === "expired") { setStatus("Expired", "bad"); cleanup(); }
  }, 1500);
}
async function claim(token) {
  cleanup();
  const res = await fetch("/api/auth/qr/claim", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
  const data = await res.json().catch(() => ({}));
  log("claim", res.status, data);
  if (res.ok && data.token) {
    jwt = data.token; identity = data.identity;
    localStorage.setItem("chat_jwt", jwt);
    localStorage.setItem("chat_identity", JSON.stringify(identity));
    renderMe();
    setStatus("Linked · burned", "ok");
    if (timerText) timerText.textContent = "Burned · single-use";
    toast(`Linked as ${identity.userId}`);
    setTimeout(closeModal, 600);
    connectChat(currentRoom);
  } else {
    setStatus("Claim failed: " + (data.error || res.status), "bad");
  }
}
function cleanup() {
  if (pollTimer) clearInterval(pollTimer); pollTimer = null;
  if (countdownTimer) clearInterval(countdownTimer); countdownTimer = null;
  if (ws) try { ws.close(); } catch {} ws = null;
}

// ---------- Chat (Grok messaging component) ----------
function connectChat(roomId = "general") {
  currentRoom = roomId;
  if (roomNameEl) roomNameEl.textContent = roomId;
  if (kvRoom) kvRoom.textContent = "#" + roomId;
  if (inputEl) inputEl.placeholder = `Message #${roomId} — Enter to send, Shift+Enter for a new line`;
  $$(".room").forEach((b) => b.classList.toggle("active", b.dataset.room === roomId));
  if (chatWs) try { chatWs.close(); } catch {}
  msgsEl.innerHTML = "";
  unread = 0; if (unreadEl) unreadEl.style.display = "none";
  updateHero();
  if (!jwt) { appendSystem("Link this device to join the transcript."); renderMe(); return; }
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  chatWs = new WebSocket(`${proto}//${location.host}/api/room/${encodeURIComponent(roomId)}/ws?token=${encodeURIComponent(jwt)}`);
  chatWs.onopen = () => { log("chat open", roomId, identity?.userId); appendPresence(`Live in #${roomId} as ${identity?.userId}`); renderMe(); };
  chatWs.onmessage = (e) => {
    try {
      const d = JSON.parse(e.data);
      log("chat recv", d);
      if (d.type === "welcome") {
        if (d.history?.length) d.history.forEach(appendMsg);
        updateHero();
      } else if (d.type === "message") {
        appendMsg(d.message);
        if (document.hidden && d.message.userId !== identity?.userId) {
          unread++; if (unreadEl) { unreadEl.textContent = String(unread); unreadEl.style.display = ""; }
        }
      }
      else if (d.type === "presence") appendPresence(`${d.userId} ${d.event}ed`);
      else if (d.type === "moderation") { appendSystem(`Blocked: ${d.reason}`, true); toast("Message blocked by moderation"); }
      else if (d.type === "error") appendSystem(`Error: ${d.error}`, true);
    } catch { log("chat raw", e.data); }
  };
  chatWs.onclose = () => { appendSystem("Disconnected — reload to reconnect.", true); renderMe(); };
  chatWs.onerror = () => appendSystem("Socket error.", true);
  renderMe();
}
function appendMsg(m) {
  if (!msgsEl) return;
  const mine = identity && m.userId === identity.userId;
  const div = document.createElement("div");
  div.className = "row " + (mine ? "me" : "peer");
  div.dataset.body = (m.body || "").toLowerCase();
  const who = m.displayName || m.userId;
  const time = new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (mine) {
    div.innerHTML = `<div class="bubble"><div class="body"></div></div>`;
    div.querySelector(".body").textContent = m.body;
  } else {
    div.innerHTML = `<div class="ava">${escapeHtml(who.slice(0, 1).toUpperCase())}</div><div class="bubble"><div class="meta"><b></b><time>${time}</time>${m.flagged ? `<span class="flag">flagged · ${escapeHtml(m.flagReason || "")}</span>` : ""}</div><div class="body"></div></div>`;
    div.querySelector("b").textContent = who;
    div.querySelector(".body").textContent = m.body;
  }
  msgsEl.appendChild(div);
  scrollEl.scrollTop = scrollEl.scrollHeight;
  updateHero();
}
function appendSystem(text, bad) {
  if (!msgsEl) return;
  const div = document.createElement("div");
  div.className = "sys";
  div.textContent = "— " + text;
  if (bad) div.style.color = "#FF8585";
  msgsEl.appendChild(div);
  scrollEl.scrollTop = scrollEl.scrollHeight;
}
function appendPresence(text) {
  if (!presenceEl) return;
  presenceEl.style.display = "flex";
  presenceEl.textContent = "● " + text;
  clearTimeout(appendPresence._t);
  appendPresence._t = setTimeout(() => { presenceEl.style.display = "none"; }, 4000);
}
function escapeHtml(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function send() {
  if (!inputEl) return;
  const body = inputEl.value.trim();
  if (!body) return;
  if (!chatWs || chatWs.readyState !== 1) { toast("Link this device first"); openModal(); return; }
  chatWs.send(JSON.stringify({ type: "message", roomId: currentRoom, body }));
  inputEl.value = "";
  autogrow();
  updateSend();
}
function autogrow() {
  if (!inputEl) return;
  inputEl.style.height = "auto";
  inputEl.style.height = Math.min(160, inputEl.scrollHeight) + "px";
}

// ---------- wiring ----------
$("#gen")?.addEventListener("click", gen);
$("#openQrBtn")?.addEventListener("click", () => { openModal(); if (!currentToken || Date.now() > expiresAt) gen(); });
$("#linkDeviceBtn")?.addEventListener("click", () => { openModal(); if (!currentToken || Date.now() > expiresAt) gen(); });
$("#heroLinkBtn")?.addEventListener("click", gen);
$("#howBtn")?.addEventListener("click", () => toast("Create ticket → scan on /mobile → approve → ticket burns → 1-hour pass"));
$("#qrClose")?.addEventListener("click", closeModal);
modal?.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { closeModal(); $("#sidebar")?.classList.remove("open"); }
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); $("#searchInput")?.focus(); }
});
$("#copyLinkBtn")?.addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(linkEl.textContent); toast("Link copied"); }
  catch { toast("Copy failed"); }
});
$("#send")?.addEventListener("click", send);
inputEl?.addEventListener("input", () => { autogrow(); updateSend(); });
inputEl?.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } });
$("#historyBtn")?.addEventListener("click", async () => {
  if (!jwt) { toast("Link this device first"); openModal(); return; }
  const res = await fetch(`/api/room/${encodeURIComponent(currentRoom)}/history?token=${encodeURIComponent(jwt)}`, { headers: { Authorization: `Bearer ${jwt}` } });
  const data = await res.json().catch(() => ({}));
  log("history", data);
  if (data.messages) { msgsEl.innerHTML = ""; data.messages.forEach(appendMsg); if (!data.messages.length) appendSystem("No messages yet — say hello."); }
});
$("#exportBtn")?.addEventListener("click", async () => {
  const lines = [...msgsEl.querySelectorAll(".row")].map((el) => el.textContent.trim()).join("\n");
  try { await navigator.clipboard.writeText(lines || "(empty)"); toast("Transcript copied"); } catch { toast("Copy failed"); }
});
$("#clearBtn")?.addEventListener("click", () => { msgsEl.innerHTML = ""; updateHero(); });
$("#debugToggle")?.addEventListener("click", () => { verbose = !verbose; debugEl?.classList.toggle("open", verbose); $("#thinkBtn")?.setAttribute("aria-pressed", String(verbose)); toast(verbose ? "Verbose log on" : "Verbose log off"); });
$("#thinkBtn")?.addEventListener("click", () => { verbose = !verbose; debugEl?.classList.toggle("open", verbose); $("#thinkBtn").setAttribute("aria-pressed", String(verbose)); });
$("#attachBtn")?.addEventListener("click", () => toast("Attachments are disabled in this build"));
$("#newChatBtn")?.addEventListener("click", () => { msgsEl.innerHTML = ""; updateHero(); inputEl?.focus(); toast("Started a fresh view — history stays on the server"); });
$("#menuBtn")?.addEventListener("click", () => $("#sidebar")?.classList.add("open"));
$("#collapseBtn")?.addEventListener("click", () => $("#sidebar")?.classList.remove("open"));
$$(".room").forEach((b) => b.addEventListener("click", () => { connectChat(b.dataset.room); $("#sidebar")?.classList.remove("open"); }));
$$("#chips .chip").forEach((c) => c.addEventListener("click", () => {
  if (!jwt) { openModal(); gen(); return; }
  inputEl.value = c.dataset.prompt; autogrow(); updateSend(); inputEl.focus();
}));
$("#searchInput")?.addEventListener("input", (e) => {
  const q = e.target.value.trim().toLowerCase();
  msgsEl.querySelectorAll(".row").forEach((r) => { r.style.display = !q || (r.dataset.body || "").includes(q) ? "" : "none"; });
});

renderMe();
setTimer();
if (jwt && identity) setTimeout(() => connectChat(currentRoom), 400);
else appendSystem("Link this device to join the transcript.");
log("Ready. Grok-like shell. Mobile key at /mobile");
