// Mobile — scan → chat directly with host. Contract: preview → ack → approve → auto-join #general.
const API_BASE2 = (typeof window !== "undefined" && window.__API_BASE__ ? window.__API_BASE__ : "").replace(/\/$/, "");
const api2 = (p) => `${API_BASE2}${p}`;
const wsBase2 = () => (API_BASE2 ? API_BASE2.replace(/^http/, "ws") : `${location.protocol}//${location.host}`);
const $ = (s) => document.querySelector(s);
const loginOut = $("#loginOut");
const previewOut = $("#previewOut");
const details = $("#details");
const confirm = $("#confirm");
const dock = $("#dock");
let mobileJwt = localStorage.getItem("mobile_jwt") || "";

function showConfirm(open) {
  if (confirm) confirm.classList.toggle("open", open);
  if (confirm) confirm.style.display = open ? "block" : "none";
  if (dock) dock.style.display = open ? "block" : "none";
}
showConfirm(false);

$("#login")?.addEventListener("click", async () => {
  const userId = ($("#userId")?.value || "").trim() || "alice";
  const res = await fetch(api2("/api/auth/dev-login"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ userId, displayName: userId }) });
  const data = await res.json().catch(() => ({}));
  if (data.token) {
    mobileJwt = data.token;
    localStorage.setItem("mobile_jwt", mobileJwt);
    if (loginOut) loginOut.textContent = `Session ready as ${data.userId}.`;
  } else if (loginOut) loginOut.textContent = "Could not mint session.";
});
$("#preview")?.addEventListener("click", async () => {
  const raw = ($("#token")?.value || "").trim();
  if (!raw) return alert("Paste token");
  let t = raw;
  try { const u = new URL(raw); const p = u.searchParams.get("token"); if (p) t = p; } catch {}
  $("#token").value = t;
  if (previewOut) previewOut.textContent = "Checking…";
  const res = await fetch(api2(`/api/auth/qr/preview?token=${encodeURIComponent(t)}`));
  const data = await res.json().catch(() => ({}));
  if (data.status === "pending" || (res.ok && data.status)) {
    const left = data.expiresAt ? Math.max(0, Math.round((data.expiresAt - Date.now()) / 1000)) : "?";
    const host = data.host ? `Host ${data.host.displayName || data.host.userId}` : "Host (ticket)";
    if (previewOut) previewOut.textContent = `${host} · Pending · ${left}s left.`;
    if (details) {
      details.innerHTML = "";
      [host, `Created ${data.createdAt ? new Date(data.createdAt).toLocaleTimeString() : "?"}`, `Expires in ${left}s`, `Token ${data.tokenPreview || t.slice(0, 8) + "…"}`]
        .forEach((x) => { const li = document.createElement("li"); li.textContent = x; details.appendChild(li); });
    }
    const ack = $("#ack"), approve = $("#approve");
    if (ack) ack.checked = false;
    if (approve) approve.disabled = true;
    showConfirm(true);
  } else {
    showConfirm(false);
    if (previewOut) previewOut.textContent = "Not pending — cannot approve.";
  }
});
$("#ack")?.addEventListener("change", (e) => { const a = $("#approve"); if (a) a.disabled = !e.target.checked; });
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
function joinChat() {
  const wrap = $("#chatWrap"), st = $("#chatState"), inp = $("#mInput"), btn = $("#mSend");
  if (wrap) wrap.classList.add("open");
  if (st) st.textContent = "connected · #general";
  if (!mobileJwt) { mSystem("Mint a session first"); return; }
  if (mWs) try { mWs.close(); } catch {}
  // Direct chat with host — same #general room as desktop (short domain Pages + Worker WSS)
  const url = `${wsBase2()}/api/room/general/ws?token=${encodeURIComponent(mobileJwt)}`;
  mWs = new WebSocket(url);
  mWs.onopen = () => { mSystem("You joined — say hello to host"); if (btn) btn.disabled = false; if (inp) inp.focus(); };
  mWs.onmessage = (e) => {
    try {
      const d = JSON.parse(e.data);
      if (d.type === "welcome" && d.history?.length) d.history.forEach((m) => mAppend(`${m.displayName || m.userId}: ${m.body}`, false));
      else if (d.type === "message") {
        const mine = d.message.userId === (JSON.parse(atob(mobileJwt.split(".")[1]))?.userId);
        mAppend(`${d.message.displayName || d.message.userId}: ${d.message.body}`, mine);
      }
      else if (d.type === "presence") mSystem(`${d.userId} ${d.event}ed`);
    } catch {}
  };
  mWs.onclose = () => { mSystem("Disconnected"); const b = $("#mSend"); if (b) b.disabled = true; };
  const send = () => {
    const v = inp?.value.trim();
    if (!v || !mWs || mWs.readyState !== 1) return;
    mWs.send(JSON.stringify({ type: "message", roomId: "general", body: v }));
    if (inp) inp.value = "";
  };
  btn?.addEventListener("click", send);
  inp?.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } });
}

$("#approve")?.addEventListener("click", async () => {
  const token = ($("#token")?.value || "").trim();
  if (!mobileJwt) return alert("Mint a session first");
  const res = await fetch(api2("/api/auth/mobile/approve"), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: "approve" }) });
  if (res.ok) {
    showConfirm(false);
    if (previewOut) previewOut.textContent = "Approved — opening chat…";
    // Directly able to chat with host now (no extra step)
    joinChat();
  } else alert("Approve failed");
});
$("#deny")?.addEventListener("click", async () => {
  const token = ($("#token")?.value || "").trim();
  if (!mobileJwt) return alert("Mint a session first");
  const res = await fetch(api2("/api/auth/mobile/approve"), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: "deny" }) });
  if (res.ok) { showConfirm(false); if (previewOut) previewOut.textContent = "Denied."; }
  else alert("Deny failed");
});
$("#paste")?.addEventListener("click", async () => {
  try { $("#token").value = (await navigator.clipboard.readText()).trim(); } catch { alert("Paste manually"); }
});
try {
  const p = new URL(location.href).searchParams.get("token");
  if (p) $("#token").value = p;
} catch {}
