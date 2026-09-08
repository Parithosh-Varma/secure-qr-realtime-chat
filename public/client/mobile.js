// Mobile — scan to chat directly, nickname-only, ephemeral, E2E on dm_*.
try { localStorage.clear(); sessionStorage.clear(); } catch {}
const API_BASE2 = (typeof window !== "undefined" && window.__API_BASE__ ? window.__API_BASE__ : "").replace(/\/$/, "");
const api2 = (p) => `${API_BASE2}${p}`;
const wsBase2 = () => (API_BASE2 ? API_BASE2.replace(/^http/, "ws") : `${location.protocol}//${location.host}`);
const $ = (s) => document.querySelector(s);
const loginOut = $("#loginOut");
const previewOut = $("#previewOut");
const details = $("#details");
const confirm = $("#confirm");
const dock = $("#dock");
let mobileJwt = ""; // ephemeral
let mobileDisplay = "";
let privateRoomM = null;
let e2eKeyM = null;

function showConfirm(open) {
  if (confirm) confirm.classList.toggle("open", open);
  if (confirm) confirm.style.display = open ? "block" : "none";
  if (dock) dock.style.display = open ? "block" : "none";
}
showConfirm(false);

async function deriveE2EKeyM(rawToken) {
  if (!rawToken) return null;
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawToken));
  return crypto.subtle.importKey("raw", h, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function e2eEncryptM(plain, key) {
  if (!key || !privateRoomM || !privateRoomM.startsWith("dm_")) return plain;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plain));
  return `enc:${btoa(String.fromCharCode(...new Uint8Array(ct)))}.${btoa(String.fromCharCode(...iv))}`;
}
async function e2eDecryptM(payload, key) {
  if (!key || typeof payload !== "string" || !payload.startsWith("enc:")) return payload;
  try {
    const [b64ct, b64iv] = payload.slice(4).split(".");
    const ct = Uint8Array.from(atob(b64ct), (c) => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(b64iv), (c) => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch { return payload; }
}
let mWs = null;
function mAppend(text, mine) {
  const wrap = $("#mmsgs");
  if (!wrap) return;
  const d = document.createElement("div");
  d.className = "mrow" + (mine ? " me" : "");
  if (mine) d.innerHTML = `<div class="mbub"></div>`;
  else d.innerHTML = `<div class="ava"></div><div class="mbub"></div>`;
  const b = d.querySelector(".mbub");
  if (b) b.textContent = text;
  if (!mine) { const a = d.querySelector(".ava"); if (a) a.textContent = text.slice(0,1).toUpperCase() || "•"; }
  wrap.appendChild(d);
  wrap.scrollTop = wrap.scrollHeight;
}
function mSystem(t) {
  const wrap = $("#mmsgs");
  if (!wrap) return;
  const d = document.createElement("div");
  d.className = "msys"; d.textContent = "— " + t;
  wrap.appendChild(d);
  wrap.scrollTop = wrap.scrollHeight;
}
async function joinChatM() {
  const wrap = $("#chatWrap"), st = $("#chatState"), inp = $("#mInput"), btn = $("#mSend");
  const room = privateRoomM || "general";
  if (wrap) wrap.classList.add("open");
  if (st) st.textContent = `connected · ${room} (2-person, E2E)`;
  if (!mobileJwt) { mSystem("Mint a nickname first"); return; }
  if (mWs) try { mWs.close(); } catch {}
  const url = `${wsBase2()}/api/room/${encodeURIComponent(room)}/ws?token=${encodeURIComponent(mobileJwt)}`;
  mWs = new WebSocket(url);
  mWs.onopen = () => { mSystem(`You joined ${room} as ${mobileDisplay || "anon"} — E2E on`); if (btn) btn.disabled = false; if (inp) inp.focus(); };
  mWs.onmessage = async (e) => {
    try {
      const d = JSON.parse(e.data);
      if (d.type === "welcome") {
        // Privacy: suppress history — fresh 1:1 only
        if (d.history?.length) console.log("history suppressed", d.history.length);
      } else if (d.type === "message") {
        const body = await e2eDecryptM(d.message.body, e2eKeyM);
        const mine = d.message.userId === (JSON.parse(atob(mobileJwt.split(".")[1]))?.userId);
        mAppend(`${d.message.displayName || d.message.userId}: ${body}`, mine);
      } else if (d.type === "presence") mSystem(`${d.userId} ${d.event}ed`);
    } catch {}
  };
  mWs.onclose = () => { mSystem("Disconnected — refresh erases (ephemeral)"); const b = $("#mSend"); if (b) b.disabled = true; };
  const send = async () => {
    const v = inp?.value.trim();
    if (!v || !mWs || mWs.readyState !== 1) return;
    const out = await e2eEncryptM(v, e2eKeyM);
    mWs.send(JSON.stringify({ type: "message", roomId: room, body: out }));
    if (inp) inp.value = "";
  };
  btn?.addEventListener("click", send);
  inp?.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } });
}

$("#login")?.addEventListener("click", async () => {
  const nick = ($("#userId")?.value || "").trim() || `anon-${Math.random().toString(36).slice(2,6)}`;
  if (nick.length < 2 || nick.length > 24) return alert("Nickname 2–24 chars");
  const tmpId = `u_${Math.random().toString(36).slice(2,10)}_${Date.now().toString(36)}`;
  const res = await fetch(api2("/api/auth/dev-login"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ userId: tmpId, displayName: nick }) });
  const data = await res.json().catch(() => ({}));
  if (data.token) {
    mobileJwt = data.token; mobileDisplay = nick;
    privateRoomM = `dm_${Math.random().toString(36).slice(2,10)}${Date.now().toString(36).slice(-4)}`;
    if (loginOut) loginOut.textContent = `Ready as ${nick} · private ${privateRoomM} (2-person, refresh erases)`;
  } else if (loginOut) loginOut.textContent = "Could not mint — try again";
});
async function doPreview(t) {
  if (previewOut) previewOut.textContent = "Checking…";
  const res = await fetch(api2(`/api/auth/qr/preview?token=${encodeURIComponent(t)}`));
  const data = await res.json().catch(() => ({}));
  if (data.status === "pending" || (res.ok && data.status)) {
    const left = data.expiresAt ? Math.max(0, Math.round((data.expiresAt - Date.now()) / 1000)) : "?";
    const host = data.host ? `${data.host.displayName || data.host.userId}` : "Host";
    privateRoomM = data.roomId || privateRoomM;
    e2eKeyM = await deriveE2EKeyM(t);
    if (previewOut) previewOut.textContent = `${host} invited you — 1:1 E2E · ${left}s left`;
    if (details) {
      details.innerHTML = "";
      [ `Private room — only 2`, `Expires in ${left}s` ]
        .forEach((x) => { const li = document.createElement("li"); li.textContent = x; details.appendChild(li); });
    }
    const ack = $("#ack"), approve = $("#approve");
    if (ack) ack.checked = false;
    if (approve) approve.disabled = true;
    showConfirm(true);
    return true;
  } else {
    showConfirm(false);
    if (previewOut) previewOut.textContent = "Invite expired — ask for a new QR.";
    return false;
  }
}
$("#preview")?.addEventListener("click", async () => {
  const raw = ($("#token")?.value || "").trim();
  if (!raw) return;
  let t = raw;
  try { const u = new URL(raw); const p = u.searchParams.get("token"); if (p) t = p; } catch {}
  $("#token").value = t;
  await doPreview(t);
});
$("#ack")?.addEventListener("change", (e) => { const a = $("#approve"); if (a) a.disabled = !e.target.checked; });
$("#approve")?.addEventListener("click", async () => {
  const token = ($("#token")?.value || "").trim();
  if (!mobileJwt) return alert("Mint a nickname first (enter above)");
  if (!token) return alert("Paste token");
  e2eKeyM = await deriveE2EKeyM(token);
  privateRoomM = privateRoomM || `dm_${token.slice(0,12)}`; // fallback derive
  const res = await fetch(api2("/api/auth/mobile/approve"), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: "approve" }) });
  if (res.ok) {
    showConfirm(false);
    if (previewOut) previewOut.textContent = "Approved — opening E2E chat…";
    // Directly able to chat with host now (no extra step)
    joinChatM();
  } else {
    const d = await res.json().catch(()=>({}));
    alert("Approve failed: " + (d.error || res.status));
  }
});
$("#deny")?.addEventListener("click", async () => {
  const token = ($("#token")?.value || "").trim();
  if (!mobileJwt) return alert("Mint first");
  const res = await fetch(api2("/api/auth/mobile/approve"), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: "deny" }) });
  if (res.ok) { showConfirm(false); if (previewOut) previewOut.textContent = "Denied."; }
  else alert("Deny failed");
});
$("#paste")?.addEventListener("click", async () => {
  try { $("#token").value = (await navigator.clipboard.readText()).trim(); } catch { alert("Paste manually"); }
});
async function ensureMobileSession() {
  if (mobileJwt) return true;
  const nick = `anon-${Math.random().toString(36).slice(2,6)}`;
  const tmpId = `u_${Math.random().toString(36).slice(2,10)}_${Date.now().toString(36)}`;
  const res = await fetch(api2("/api/auth/dev-login"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ userId: tmpId, displayName: nick }) });
  const data = await res.json().catch(() => ({}));
  if (data.token) { mobileJwt = data.token; mobileDisplay = nick; if (loginOut) loginOut.textContent = `Joined as ${nick} — ephemeral`; return true; }
  return false;
}
try {
  const p = new URL(location.href).searchParams.get("token");
  if (p) {
    $("#token").value = p;
    e2eKeyM = await deriveE2EKeyM(p);
    privateRoomM = `dm_${p.slice(0,12)}`;
    // Hide token from address bar immediately (privacy) — keep it only in memory
    history.replaceState(null, "", location.pathname);
    // Direct chat after scan — no approve/permission, just join
    await ensureMobileSession();
    const ok = await doPreview(p);
    if (ok) {
      // auto-approve without UI
      const resA = await fetch(api2("/api/auth/mobile/approve"), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token: p, action: "approve" }) });
      if (resA.ok) {
        const ic = document.getElementById("inviteCard");
        if (ic) ic.style.display = "none";
        showConfirm(false);
        if (previewOut) previewOut.textContent = "";
        // Hide nickname card as well
        const nickCard = document.querySelector(".card");
        if (nickCard) nickCard.style.display = "none";
        const h1 = document.querySelector("h1");
        if (h1) h1.innerHTML = "Chat<br><em>with me</em>";
        const sub = document.querySelector(".sub");
        if (sub) sub.textContent = "Connected via QR — just chat.";
        joinChatM();
      }
    }
  }
} catch {}
// Refresh erases: no restore from storage — always start fresh

