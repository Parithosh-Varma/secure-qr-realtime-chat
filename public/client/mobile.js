// Mobile — scan to chat directly, ephemeral, E2E on dm_*. No nickname anywhere.
// A reload is only terminal once inside the chat: pre-auth reloads boot fresh
// and must never land on about:blank.
try {
  const nav = performance.getEntriesByType && performance.getEntriesByType("navigation")[0];
  const isReload = (nav && nav.type === "reload") || (performance.navigation && performance.navigation.type === 1);
  let wasInChat = false;
  try { wasInChat = sessionStorage.getItem("qrchat.m.inchat") === "1"; } catch {}
  if (isReload && wasInChat) {
    try { localStorage.clear(); sessionStorage.clear(); } catch {}
    try { history.replaceState(null, "", "about:blank"); } catch {}
    location.href = "about:blank";
    try { window.close(); } catch {}
    throw new Error("reload closing");
  }
} catch (e) { if (e && e.message === "reload closing") throw e; }
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
let privateRoomM = null; // ALWAYS server-provided via preview — never derived locally
let e2eSecretM = null; // raw QR e2eSecret; per-epoch keys derived on demand
let currentAuthTokenM = null;

function showConfirm(open) {
  if (confirm) confirm.classList.toggle("open", open);
  if (confirm) confirm.style.display = open ? "block" : "none";
  if (dock) dock.style.display = open ? "block" : "none";
}
showConfirm(false);

function secureSuffixM(len){
  const bytes=new Uint8Array(Math.ceil(len*3/4));
  crypto.getRandomValues(bytes);
  let s=btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  return s.slice(0,len);
}
function getInviteFromUrl(){
  // New format: #a=<authToken>&e=<e2eSecret> (fragment never hits network).
  // Legacy: #token=<authToken> or ?token=<authToken> (no E2E secret).
  try{
    const frag=(location.hash||"").replace(/^#/,"");
    const fp=new URLSearchParams(frag);
    const a=fp.get("a"), e=fp.get("e"), t=fp.get("token");
    if(a) return {authToken:decodeURIComponent(a), e2eSecret:e?decodeURIComponent(e):null};
    if(t) return {authToken:decodeURIComponent(t), e2eSecret:null};
    const qs=new URL(location.href).searchParams.get("token");
    if(qs) return {authToken:qs, e2eSecret:null};
  }catch{}
  return null;
}
function getTokenFromUrl(){
  // Backwards-compat shim — returns authToken only. New code uses getInviteFromUrl().
  const inv=getInviteFromUrl();
  return inv?inv.authToken:null;
}
const E2E_EPOCH_MS = 900000; // 15-min key rotation window (forward secrecy)
const e2eKeyCacheM = new Map(); // "v1" | "v2:<epoch>" -> CryptoKey (capped)
async function deriveE2EKeyM(e2eSecret) {
  // v1 legacy derive — kept so messages from older clients still decrypt.
  // E2E key from the QR e2eSecret ONLY — never from the auth token the
  // server sees. Domain-separated so legacy authToken-derived keys differ.
  if (!e2eSecret) return null;
  try{
    const enc=new TextEncoder();
    const ikm=await crypto.subtle.importKey("raw", enc.encode("qrchat-e2e-v1:"+e2eSecret), {name:"HKDF"}, false, ["deriveKey"]);
    return await crypto.subtle.deriveKey({name:"HKDF", hash:"SHA-256", salt:new Uint8Array(0), info:enc.encode("qrchat-e2e-v1")}, ikm, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  }catch{
    const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("qrchat-e2e-v1:"+e2eSecret));
    return crypto.subtle.importKey("raw", h, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }
}
async function deriveE2EKeyMV2(e2eSecret, epoch) {
  // Per-epoch data key: compromise of one window's key decrypts at most that
  // window. Epoch rides in the envelope, so no clock sync is needed.
  if (!e2eSecret || !Number.isSafeInteger(epoch) || epoch < 0) return null;
  const tag="qrchat-e2e-v2:"+e2eSecret+":"+epoch;
  try{
    const enc=new TextEncoder();
    const ikm=await crypto.subtle.importKey("raw", enc.encode(tag), {name:"HKDF"}, false, ["deriveKey"]);
    return await crypto.subtle.deriveKey({name:"HKDF", hash:"SHA-256", salt:new Uint8Array(0), info:enc.encode("qrchat-e2e-v2")}, ikm, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  }catch{
    const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(tag));
    return crypto.subtle.importKey("raw", h, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }
}
async function e2eKeyForM(secret, epoch){
  // Cache id includes a secret prefix: one tab can cycle secrets across QR
  // regenerations, and same-epoch keys for different secrets must never mix.
  const stag=String(secret||"").slice(0,12);
  const id=(epoch==null?"v1":"v2:"+epoch)+":"+stag;
  let k=e2eKeyCacheM.get(id);
  if(k) return k;
  k=epoch==null?await deriveE2EKeyM(secret):await deriveE2EKeyMV2(secret,epoch);
  if(k){
    e2eKeyCacheM.set(id,k);
    if(e2eKeyCacheM.size>8) e2eKeyCacheM.delete(e2eKeyCacheM.keys().next().value);
  }
  return k;
}
function sanitizeDecryptedM(s){
  if(typeof s!=="string") return "";
  s=s.replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00AD]/g, "");
  // eslint-disable-next-line no-control-regex
  s=s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  return s.slice(0,2000);
}
async function e2eEncryptM(plain, secret) {
  if (!secret || !privateRoomM || !privateRoomM.startsWith("dm_")) return plain;
  const epoch=Math.floor(Date.now()/E2E_EPOCH_MS);
  const key=await e2eKeyForM(secret,epoch);
  if(!key) return plain;
  // AAD binds ciphertext to this room + epoch (no cross-room/time replay).
  const aad=new TextEncoder().encode(`${privateRoomM}:${epoch}`);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, new TextEncoder().encode(plain));
  return `enc2:${epoch}.${btoa(String.fromCharCode(...new Uint8Array(ct)))}.${btoa(String.fromCharCode(...iv))}`;
}
async function e2eDecryptM(payload, secret, roomId) {
  if (!secret || typeof payload !== "string") return payload;
  if (payload.startsWith("enc2:")) {
    try {
      const [epochS, b64ct, b64iv] = payload.slice(5).split(".");
      const epoch=parseInt(epochS,10);
      if(!Number.isSafeInteger(epoch)||epoch<0||!b64ct||!b64iv) return payload;
      const key=await e2eKeyForM(secret,epoch);
      if(!key) return payload;
      const aad=new TextEncoder().encode(`${roomId||privateRoomM}:${epoch}`);
      const ct = Uint8Array.from(atob(b64ct), (c) => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(b64iv), (c) => c.charCodeAt(0));
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, ct);
      return new TextDecoder().decode(pt);
    } catch { return payload; }
  }
  if (!payload.startsWith("enc:")) return payload;
  try {
    const key=await e2eKeyForM(secret,null);
    if(!key) return payload;
    const [b64ct, b64iv] = payload.slice(4).split(".");
    const ct = Uint8Array.from(atob(b64ct), (c) => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(b64iv), (c) => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch { return payload; }
}
let mWs = null;
function mAppend(text, mine, cid) {
  if (mine && cid) mSettlePending(cid);
  const wrap = $("#mmsgs");
  if (!wrap) return;
  const d = document.createElement("div");
  d.className = "mrow" + (mine ? " me" : "");
  if (mine) d.innerHTML = `<div class="mbub"></div><div class="mpstat tick">✓✓</div>`;
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
  if (st) st.textContent = `connecting…`;
  if (!mobileJwt) { mSystem("No session yet — reload to retry"); return; }
  try { sessionStorage.setItem("qrchat.m.inchat", "1"); } catch {}
  if (mWs) try { mWs.close(); } catch {}
  if (btn) btn.disabled = true;
  mTypingSent=false; clearTimeout(mTypingIdle); mHideTyping();
  // Prefer Sec-WebSocket-Protocol for the JWT (no URL leakage). If the
  // handshake fails before opening, retry once with ?token=.
  openChatWsM(room, true);
  function openChatWsM(room, useProto){
    const base=`${wsBase2()}/api/room/${encodeURIComponent(room)}/ws`;
    const w=useProto
      ? new WebSocket(base, ["bearer", mobileJwt])
      : new WebSocket(`${base}?token=${encodeURIComponent(mobileJwt)}`);
    mWs=w;
    let opened=false;
    const retryQuery=()=>{
      if(!useProto || opened || mWs!==w) return;
      try{ w.close(); }catch{}
      try{ openChatWsM(room, false); }catch{ mSystem("Connection failed — retry"); }
    };
    w.onopen = () => { opened=true; if (st) st.textContent = `connected · ${room} (2-person, E2E)`; mSystem(`You joined ${room} as ${mobileDisplay || "anon"} — E2E on`); if (btn) btn.disabled = false; if (inp) inp.focus(); };
    w.onerror = () => { retryQuery(); };
    w.onmessage = async (e) => {
    try {
      const d = JSON.parse(e.data);
      if (d.type === "welcome") {
        // Privacy: suppress history — fresh 1:1 only
        if (d.history?.length) console.log("history suppressed", d.history.length);
      } else if (d.type === "message") {
        const raw = await e2eDecryptM(d.message.body, e2eSecretM, d.message.roomId);
        const body = sanitizeDecryptedM(raw);
        const mine = d.message.userId === (JSON.parse(atob(mobileJwt.split(".")[1]))?.userId);
        mAppend(`${d.message.displayName || d.message.userId}: ${body}`, mine, d.cid);
      } else if (d.type === "ack" && d.cid) {
        const p = mPending.get(d.cid);
        if (p) { clearTimeout(p.timer); const st = p.el.querySelector(".mpstat"); if (st) st.textContent = "✓✓ delivered"; }
      } else if (d.type === "presence") mSystem(`${d.userId} ${d.event}ed`);
      else if (d.type === "typing") { const who=d.displayName||d.userId||"Peer"; if(d.typing) mShowTyping(who); else mHideTyping(); }
      else if (d.type === "peer_closed") { mSystem("Peer refreshed — closing tab…"); setTimeout(()=>{ try{ window.close(); }catch{} location.href="about:blank"; }, 800); try{ mWs.close(); }catch{} }
    } catch {}
  };
  w.onclose = (e) => {
    if(mWs!==w) return;
    if(!opened && useProto){ retryQuery(); return; }
    if (e && e.code === 4000) { mSystem("Peer refreshed — closing tab…"); setTimeout(()=>{ try{ window.close(); }catch{} location.href="about:blank"; }, 500); return; }
    mSystem("Disconnected — refresh erases (ephemeral)"); const b = $("#mSend"); if (b) b.disabled = true;
  };
  }
  const send = async () => { await mSendCurrent(); };
  // Bound once: re-joining must not stack duplicate listeners (that caused
  // double-sends). mSendCurrent reads live module state.
  if (btn && !btn.dataset.tbound) { btn.dataset.tbound = "1"; btn.addEventListener("click", () => mSendCurrent()); }
  if (inp && !inp.dataset.tbound) {
    inp.dataset.tbound = "1";
    inp.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); mSendCurrent(); } });
    inp.addEventListener("input", () => { mSendTyping(!!inp.value.trim()); });
    inp.addEventListener("blur", () => mSendTyping(false));
  }
}
// Module-scope send: always uses the CURRENT room/socket (no stale closures).
async function mSendCurrent(){
  const inpEl = $("#mInput");
  const v = inpEl?.value.trim();
  if (!v || !mWs || mWs.readyState !== 1) return;
  mSendTyping(false);
  const out = await e2eEncryptM(v, e2eSecretM);
  const cid = crypto.randomUUID();
  mRenderPending(v, cid);
  try { mWs.send(JSON.stringify({ type: "message", roomId: privateRoomM || "general", body: out, cid })); }
  catch { mFailPending(cid); }
  if (inpEl) inpEl.value = "";
}
// Pending bubbles: "sending…" until the server ack or our own echo lands.
const mPending = new Map(); // cid -> {el, timer}
function mRenderPending(bodyText, cid){
  const wrap = $("#mmsgs");
  if (!wrap) return;
  const d = document.createElement("div");
  d.className = "mrow me pending"; d.dataset.cid = cid;
  d.innerHTML = `<div class="mbub"></div><div class="mpstat"><span class="spin"></span>sending…</div>`;
  const b = d.querySelector(".mbub");
  if (b) b.textContent = bodyText;
  wrap.appendChild(d);
  wrap.scrollTop = wrap.scrollHeight;
  const timer = setTimeout(() => mFailPending(cid), 8000);
  mPending.set(cid, { el: d, timer });
}
function mFailPending(cid){
  const p = cid && mPending.get(cid);
  if (!p) return;
  clearTimeout(p.timer); mPending.delete(cid);
  const st = p.el.querySelector(".mpstat");
  if (st) st.textContent = "not delivered — retry";
  p.el.classList.add("failed");
}
function mSettlePending(cid){
  const p = cid && mPending.get(cid);
  if (!p) return;
  clearTimeout(p.timer); mPending.delete(cid);
  p.el.remove();
}
// --- typing indicator (loading animation while peer types) ---
let mTypingSent=false, mTypingIdle=null, mTypingThrottle=0, mTypingHideT=null;
function mSendTyping(state){
  if(!mWs||mWs.readyState!==1||!privateRoomM) return;
  const now=Date.now();
  if(state===mTypingSent){ if(state){ clearTimeout(mTypingIdle); mTypingIdle=setTimeout(()=>mSendTyping(false),4000); } return; }
  if(state && now-mTypingThrottle<3000 && mTypingSent) return;
  mTypingSent=state; if(state) mTypingThrottle=now;
  try{ mWs.send(JSON.stringify({type:"typing", roomId:privateRoomM, typing:state})); }catch{}
  if(state){ clearTimeout(mTypingIdle); mTypingIdle=setTimeout(()=>mSendTyping(false),4000); }
  else clearTimeout(mTypingIdle);
}
function mShowTyping(name){
  const el=$("#mtyping"); if(!el) return;
  el.innerHTML=""; const b=document.createElement("b"); b.textContent=name;
  const dots=document.createElement("span"); dots.className="dots"; dots.setAttribute("aria-hidden","true");
  el.append(b, document.createTextNode(" is typing "), dots);
  el.style.display="block";
  clearTimeout(mTypingHideT); mTypingHideT=setTimeout(mHideTyping,5000);
}
function mHideTyping(){ const el=$("#mtyping"); if(el) el.style.display="none"; clearTimeout(mTypingHideT); }

// No nickname UI — a silent ephemeral guest session is minted automatically
// on boot (direct visits) or on scan. Identity is random anon + server
// userId; refresh erases.
if (!getInviteFromUrl()) {
  ensureMobileSession().then((ok) => {
    if (loginOut) loginOut.textContent = ok ? `Ready — ephemeral${mobileDisplay ? ` · ${mobileDisplay}` : ""}` : "Could not mint — reload to retry";
  });
}
async function doPreview(authToken) {
  if (previewOut) {
    previewOut.innerHTML = "";
    const s = document.createElement("span"); s.className = "spin"; s.setAttribute("aria-hidden", "true");
    previewOut.append(s, document.createTextNode("Checking…"));
  }
  // Token via header (no URL leakage). Server returns fingerprint/location
  // for the explicit consent screen.
  const res = await fetch(api2(`/api/auth/qr/preview`),{headers:{"X-QR-Token":authToken}});
  const data = await res.json().catch(() => ({}));
  if (data.status === "pending" || (res.ok && data.status)) {
    const left = data.expiresAt ? Math.max(0, Math.round((data.expiresAt - Date.now()) / 1000)) : "?";
    const host = data.host ? `${data.host.displayName || data.host.userId}` : "Host";
    // SERVER-authoritative roomId — never derive locally (old bug used 12-hex).
    privateRoomM = data.roomId || null;
    currentAuthTokenM = authToken;
    if (previewOut) previewOut.textContent = `${host} invited you — 1:1 E2E · ${left}s left`;
    if (details) {
      details.innerHTML = "";
      const fp=data.fingerprint||{};
      const rows=[ `Private room — only 2`, `Expires in ${left}s` ];
      if(fp.city||fp.country) rows.push(`Login from: ${[fp.city,fp.country].filter(Boolean).join(", ")}`);
      if(fp.userAgent) rows.push(`Device: ${String(fp.userAgent).slice(0,80)}`);
      if(fp.acceptLanguage) rows.push(`Lang: ${fp.acceptLanguage}`);
      rows.forEach((x) => { const li = document.createElement("li"); li.textContent = x; details.appendChild(li); });
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
  // Accept pasted invite URLs in new (#a=&e=) or legacy (#token=/?token=) form
  let authToken = raw, e2eSecret = null;
  try {
    const hashMatch = raw.match(/[#&][ae]=([^&]+)/);
    if (raw.includes("#a=") || raw.includes("&e=") || raw.includes("#token=")) {
      const frag = raw.slice(raw.indexOf("#")+1);
      const fp = new URLSearchParams(frag);
      if (fp.get("a")) { authToken = decodeURIComponent(fp.get("a")); e2eSecret = fp.get("e") ? decodeURIComponent(fp.get("e")) : null; }
      else if (fp.get("token")) { authToken = decodeURIComponent(fp.get("token")); }
    } else if (hashMatch) authToken = decodeURIComponent(hashMatch[1]);
    else { const u = new URL(raw); const p = u.searchParams.get("token") || (u.hash.match(/token=([^&]+)/)?.[1] ? decodeURIComponent(u.hash.match(/token=([^&]+)/)[1]) : null); if (p) authToken = p; }
  } catch {}
  if (e2eSecret) e2eSecretM = e2eSecret;
  $("#token").value = authToken;
  await doPreview(authToken);
});
$("#ack")?.addEventListener("change", (e) => { const a = $("#approve"); if (a) a.disabled = !e.target.checked; });
$("#approve")?.addEventListener("click", async () => {
  const token = ($("#token")?.value || "").trim();
  if (!mobileJwt) return alert("Session not ready — reload and retry");
  if (!token) return alert("Paste token");
  if (!$("#ack")?.checked) return alert("Please confirm you checked the login details first");
  if (!privateRoomM) return alert("Preview the invite first so we know the correct room");
  const approveBtn = $("#approve"), denyBtn = $("#deny");
  if (approveBtn) { approveBtn.disabled = true; approveBtn.textContent = "Approving…"; }
  if (denyBtn) denyBtn.disabled = true;
  let res;
  try{ res = await fetch(api2("/api/auth/mobile/approve"), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: "approve", confirmedFingerprint: true }) }); }
  catch{ if (approveBtn) { approveBtn.disabled = false; approveBtn.textContent = "Approve & chat"; } if (denyBtn) denyBtn.disabled = false; return alert("Network error — retry"); }
  if (approveBtn) approveBtn.textContent = "Approve & chat";
  if (res.ok) {
    showConfirm(false);
    if (previewOut) previewOut.textContent = "Approved — opening E2E chat…";
    // Directly able to chat with host now (no extra step)
    joinChatM();
  } else {
    if (approveBtn) approveBtn.disabled = false;
    if (denyBtn) denyBtn.disabled = false;
    const d = await res.json().catch(()=>({}));
    alert("Approve failed: " + (d.error || res.status));
  }
});
$("#deny")?.addEventListener("click", async () => {
  const token = ($("#token")?.value || "").trim();
  if (!mobileJwt) return alert("Session not ready — reload and retry");
  const denyBtn = $("#deny"), approveBtn = $("#approve");
  if (denyBtn) { denyBtn.disabled = true; denyBtn.textContent = "Denying…"; }
  if (approveBtn) approveBtn.disabled = true;
  let res;
  try{ res = await fetch(api2("/api/auth/mobile/approve"), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: "deny", confirmedFingerprint: true }) }); }
  catch{ if (denyBtn) { denyBtn.disabled = false; denyBtn.textContent = "Deny"; } if (approveBtn) approveBtn.disabled = !$("#ack")?.checked; return alert("Network error — retry"); }
  if (denyBtn) denyBtn.textContent = "Deny";
  if (res.ok) { showConfirm(false); if (previewOut) previewOut.textContent = "Denied."; }
  else { if (denyBtn) denyBtn.disabled = false; if (approveBtn) approveBtn.disabled = !$("#ack")?.checked; alert("Deny failed"); }
});
$("#paste")?.addEventListener("click", async () => {
  try { $("#token").value = (await navigator.clipboard.readText()).trim(); } catch { alert("Paste manually"); }
});
async function ensureMobileSession() {
  if (mobileJwt) return true;
  const nick = `anon-${(crypto.randomUUID ? crypto.randomUUID().slice(0,4) : secureSuffixM(4))}`;
  let res=await fetch(api2("/api/auth/guest-login"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ displayName: nick }) });
  if(res.status===404) res=await fetch(api2("/api/auth/dev-login"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ displayName: nick }) });
  const data = await res.json().catch(() => ({}));
  if (data.token) { mobileJwt = data.token; mobileDisplay = nick; if (loginOut) loginOut.textContent = `Joined as ${nick} — ephemeral`; return true; }
  return false;
}
// Scan = acceptance: the presenter showing the QR opted the session into
// auto-join, so scanning drops you straight into the chat — no nickname, no
// approve tap. A silent guest identity is minted automatically. Who you joined
// (host + device/location) is shown as the first system message instead of a
// blocking gate, so a swapped QR is still visible. Any failure falls back to
// the manual preview + Approve UI below.
async function autoJoinFromScan(authToken){
  try{
    if(!await ensureMobileSession()) return false;
    const prev=await fetch(api2("/api/auth/qr/preview"),{headers:{"X-QR-Token":authToken}});
    const data=await prev.json().catch(()=>({}));
    if(!prev.ok || (data.status!=="pending" && data.status!=="approved")) return false;
    // SERVER-authoritative roomId — never derive locally.
    privateRoomM=data.roomId||null;
    if(!privateRoomM) return false;
    if(data.status!=="approved"){
      const appr=await fetch(api2("/api/auth/mobile/approve"),{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${mobileJwt}`},body:JSON.stringify({token:authToken,action:"approve",auto:true})});
      if(!appr.ok) return false;
    }
    showConfirm(false);
    const fp=data.fingerprint||{};
    const host=data.host?`${data.host.displayName||data.host.userId}`:"Host";
    const loc=[fp.city,fp.country].filter(Boolean).join(", ");
    if(previewOut) previewOut.textContent=`Connected — E2E chat…`;
    joinChatM();
    mSystem(`Joined ${host} — 1:1 E2E on${loc?` · ${loc}`:""}`);
    return true;
  }catch{ return false; }
}
try {
  const inv = getInviteFromUrl();
  if (inv) {
    $("#token").value = inv.authToken;
    e2eSecretM = inv.e2eSecret || null;
    currentAuthTokenM = inv.authToken;
    // Hide invite from address bar immediately (privacy) — keep only in memory
    try{ history.replaceState(null, "", location.pathname + location.search.replace(/[\?&]token=[^&]+/g,'').replace(/^&/,'?')); }catch{}
    try{ if(location.hash) history.replaceState(null, "", location.pathname + location.search); }catch{}
    if(location.hash) try{ location.hash=""; }catch{}
    // Straight into chat shell — no nickname, no tap.
    const ic = document.getElementById("inviteCard");
    if (ic) ic.style.display = "none";
    const nickCard = document.querySelector(".card");
    if (nickCard) nickCard.style.display = "none";
    const chatWrap = document.getElementById("chatWrap");
    if (chatWrap) chatWrap.classList.add("open");
    mSystem("Connecting…");
    const joined = await autoJoinFromScan(inv.authToken);
    if (!joined) {
      // Fall back to manual consent UI.
      if (ic) ic.style.display = "";
      if (nickCard) nickCard.style.display = "";
      if(inv.e2eSecret===null) mSystem("Legacy invite — no E2E secret. Ask for a new QR for full E2E.");
      await doPreview(inv.authToken);
      mSystem("Auto-join failed — check the login details, tick confirm, then Approve.");
    }
  }
} catch {}
// Refresh on any device closes the other tab (ephemeral 2-person)
window.addEventListener("beforeunload", () => { try { mWs?.close(1000, "refresh"); } catch {} });
window.addEventListener("keydown", (e) => {
  if (e.key === "F5" || (e.ctrlKey && e.key.toLowerCase() === "r") || (e.metaKey && e.key.toLowerCase() === "r")) {
    const inChat = document.getElementById("chatWrap")?.classList.contains("open") || (mWs && mWs.readyState === 1);
    if (!inChat) return;
    e.preventDefault();
    try { mWs?.close(1000, "refresh"); } catch {}
    setTimeout(() => { try { window.close(); } catch {} location.href = "about:blank"; }, 80);
  }
});
// Refresh erases: no restore from storage — always start fresh

