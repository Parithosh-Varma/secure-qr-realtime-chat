// Secure Chat — QR-only, 2-person, E2E. Refresh erases.
// A reload is only terminal once inside the chat: pre-auth (QR stage) reloads
// boot fresh with a new QR and must never land on about:blank.
try {
  const nav = performance.getEntriesByType && performance.getEntriesByType("navigation")[0];
  const isReload = (nav && nav.type === "reload") || (performance.navigation && performance.navigation.type === 1);
  let wasInChat = false;
  try { wasInChat = sessionStorage.getItem("qrchat.inchat") === "1"; } catch {}
  if (isReload && wasInChat) {
    try { localStorage.clear(); sessionStorage.clear(); } catch {}
    // Close own tab on reload (peer already closed via beforeunload WS 4000)
    try { history.replaceState(null, "", "about:blank"); } catch {}
    location.href = "about:blank";
    try { window.close(); } catch {}
    throw new Error("reload closing");
  }
} catch (e) { if (e && e.message === "reload closing") throw e; }
try { localStorage.clear(); sessionStorage.clear(); } catch {}
const API_BASE = (typeof window !== "undefined" && window.__API_BASE__ ? window.__API_BASE__ : "").replace(/\/$/, "");
const api = (p) => `${API_BASE}${p}`;
const wsBase = () => (API_BASE ? API_BASE.replace(/^http/, "ws") : `${location.protocol}//${location.host}`);
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const statusEl = $("#status"), timerText = $("#timerText"), ringFg = $("#ringFg"), ringNum = $("#ringNum"), qrEl = $("#qr"), linkEl = $("#link"), linkWrap = $("#linkWrap"), debugEl = $("#debug"), msgsEl = $("#msgs"), meEl = $("#me"), meSub = $("#meSub"), avatarEl = $("#avatar"), presenceEl = $("#presence"), inputEl = $("#msgInput"), sendBtn = $("#send"), heroEl = $("#hero"), scrollEl = $("#scroll"), modal = $("#qrModal"), toastsEl = $("#toasts"), roomNameEl = $("#roomName");
const RING_C = 97.4;
let pollTimer=null, countdownTimer=null, ws=null, chatWs=null;
let currentAuthToken=null, currentE2ESecret=null, expiresAt=0, createdAsHost=false, privateRoomId=null, lastInviteUrl="";
let gated=true;
let jwt="", identity=null;
let currentRoom="general";
let e2eKey=null;
const debugMode=new URLSearchParams(location.search).has("debug") && (location.hostname === "localhost" || location.hostname === "127.0.0.1");
function toast(t){ if(!toastsEl) return; const d=document.createElement("div"); d.className="toast"; d.textContent=t; toastsEl.appendChild(d); setTimeout(()=>d.remove(),2600); }
function log(...a){ if(debugMode&&debugEl){ debugEl.style.display="block"; debugEl.textContent+=a.map(x=>typeof x==="string"?x:JSON.stringify(x)).join(" ")+"\n"; } if(debugMode) console.log(...a); }
function setGated(on){
  gated=on;
  document.body.classList.toggle("gated",on);
  const qrView=document.getElementById("qrView"), chatView=document.getElementById("chatView");
  if(qrView){ qrView.style.display=on?"grid":"none"; qrView.classList.toggle("hide",!on); }
  if(chatView){ chatView.style.display=on?"none":"grid"; chatView.classList.toggle("hide",on); }
}
function setStatus(t){ if(statusEl) statusEl.textContent=t; }
function setTimer(){
  const s=expiresAt?Math.max(0,Math.round((expiresAt-Date.now())/1000)):-1;
  if(s<0){ if(timerText) timerText.textContent="Scan QR from other device"; if(ringNum) ringNum.textContent="–"; if(ringFg) ringFg.style.strokeDashoffset="0"; return; }
  if(timerText) timerText.textContent=s>0?`${s}s left`:"Expired";
  if(ringNum) ringNum.textContent=String(s);
  if(ringFg) ringFg.style.strokeDashoffset=String(RING_C*(1-s/90));
  if(s===0) setStatus("Expired");
}
function renderMe(){
  const name=jwt&&identity?identity.displayName||identity.userId:null;
  if(meEl) meEl.textContent=name||"—";
  if(meSub) meSub.textContent=name?`${name} · ephemeral`:"ephemeral";
  if(avatarEl) avatarEl.textContent=name?name.slice(0,1).toUpperCase():"?";
  updateSend();
  if(roomNameEl) roomNameEl.textContent=privateRoomId||currentRoom;
}
function updateSend(){ if(sendBtn&&inputEl) sendBtn.disabled=!(chatWs&&chatWs.readyState===1&&inputEl.value.trim()); }
// --- typing indicator (loading animation while peer types) ---
let typingSent=false, typingIdle=null, typingThrottle=0, typingHideT=null;
function sendTyping(state){
  if(!chatWs||chatWs.readyState!==1||!currentRoom) return;
  const now=Date.now();
  if(state===typingSent) { if(state){ clearTimeout(typingIdle); typingIdle=setTimeout(()=>sendTyping(false),4000); } return; }
  if(state && now-typingThrottle<3000 && typingSent) return;
  typingSent=state; if(state) typingThrottle=now;
  try{ chatWs.send(JSON.stringify({type:"typing", roomId:currentRoom, typing:state})); }catch{}
  if(state){ clearTimeout(typingIdle); typingIdle=setTimeout(()=>sendTyping(false),4000); }
  else clearTimeout(typingIdle);
}
function showTyping(name){
  const el=$("#typing"); if(!el) return;
  el.innerHTML=""; const b=document.createElement("b"); b.textContent=name;
  const dots=document.createElement("span"); dots.className="dots"; dots.setAttribute("aria-hidden","true");
  el.append(b, document.createTextNode(" is typing "), dots);
  el.style.display="block";
  clearTimeout(typingHideT); typingHideT=setTimeout(hideTyping,5000);
}
function hideTyping(){ const el=$("#typing"); if(el) el.style.display="none"; clearTimeout(typingHideT); }
function openModal(){ try { sessionStorage.removeItem("qrchat.inchat"); } catch {} setGated(true); }
function closeModal(){ if(gated) return; const qrView=document.getElementById("qrView"), chatView=document.getElementById("chatView"); if(qrView) {qrView.style.display="none"; qrView.classList.add("hide");} if(chatView){chatView.style.display="grid"; chatView.classList.remove("hide");} modal?.classList.remove("open"); }
function updateHero(){ if(heroEl&&msgsEl) heroEl.style.display=msgsEl.querySelector(".row")?"none":""; }
// --- helpers: CSPRNG tokens + true E2E (server never sees e2eSecret) ---
function randomB64Url(bytes){
  const b=new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function secureSuffix(len){
  return randomB64Url(Math.ceil(len*3/4)).slice(0,len);
}
async function sha256HexStr(s){
  const d=await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function deriveE2EKey(e2eSecret){
  // E2E key from the QR-fragment e2eSecret ONLY — never from the auth token
  // the server sees. Server stores only SHA-256(authToken) and never receives
  // e2eSecret, so it cannot decrypt dm_* ciphertext.
  if(!e2eSecret) return null;
  try{
    const enc=new TextEncoder();
    const ikm=await crypto.subtle.importKey("raw", enc.encode("qrchat-e2e-v1:"+e2eSecret), {name:"HKDF"}, false, ["deriveKey"]);
    return await crypto.subtle.deriveKey({name:"HKDF", hash:"SHA-256", salt:new Uint8Array(0), info:enc.encode("qrchat-e2e-v1")}, ikm, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  }catch{
    const h=await crypto.subtle.digest("SHA-256", new TextEncoder().encode("qrchat-e2e-v1:"+e2eSecret));
    return crypto.subtle.importKey("raw", h, {name:"AES-GCM"}, false, ["encrypt","decrypt"]);
  }
}
function sanitizeDecrypted(s){
  // Client-side defense-in-depth: E2E plaintext bypasses server moderation,
  // so strip bidi/zero-width + control chars after decrypt before textContent.
  if(typeof s!=="string") return "";
  s=s.replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00AD]/g, "");
  // eslint-disable-next-line no-control-regex
  s=s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  return s.slice(0,2000);
}
async function e2eEncrypt(plain,key){
  if(!key||!privateRoomId||!privateRoomId.startsWith("dm_")) return plain;
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,new TextEncoder().encode(plain));
  return `enc:${btoa(String.fromCharCode(...new Uint8Array(ct)))}.${btoa(String.fromCharCode(...iv))}`;
}
async function e2eDecrypt(payload,key){
  if(!key||typeof payload!=="string"||!payload.startsWith("enc:")) return payload;
  try{
    const [b64ct,b64iv]=payload.slice(4).split(".");
    const ct=Uint8Array.from(atob(b64ct),c=>c.charCodeAt(0));
    const iv=Uint8Array.from(atob(b64iv),c=>c.charCodeAt(0));
    const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct);
    return new TextDecoder().decode(pt);
  }catch{ return payload; }
}
function renderQr(el,text){
  // Use globalThis for module scope
  try{
    const g=globalThis.qrcode || window.qrcode;
    if(g){
      const qr=g(0,"M"); qr.addData(text); qr.make();
      el.innerHTML=qr.createSvgTag({cellSize:6, margin:0, scalable:true});
      const svg=el.querySelector("svg");
      if(svg){ svg.style.width="216px"; svg.style.height="216px"; svg.style.display="block"; svg.style.borderRadius="8px"; }
      return Promise.resolve(true);
    }
  }catch(e){ console.warn("qrcode render failed",e); }
  try{
    const QRC=globalThis.QRCode || window.QRCode;
    if(QRC&&QRC.toCanvas){
      const c=document.createElement("canvas"); el.innerHTML=""; el.appendChild(c);
      const p=QRC.toCanvas(c,text,{width:216, margin:1});
      if(p&&typeof p.then==="function") return p.then(()=>true,()=>false);
      return Promise.resolve(true);
    }
  }catch(e){ console.warn("QRCode render failed",e); }
  return Promise.resolve(false);
}
async function ensureEphemeralIdentity(){
  if(jwt&&identity) return;
  const nick=`anon-${(crypto.randomUUID ? crypto.randomUUID().slice(0,4) : secureSuffix(4))}`;
  try{
    // Guest login: server generates userId; we send displayName ONLY (no
    // userId/email — those are rejected server-side). Try new endpoint first.
    let res=await fetch(api("/api/auth/guest-login"),{method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({displayName:nick})});
    if(res.status===404) res=await fetch(api("/api/auth/dev-login"),{method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({displayName:nick})});
    const data=await res.json().catch(()=>({}));
    if(data.token){ jwt=data.token; identity={userId:data.userId, displayName:nick}; renderMe(); }
  }catch(e){ console.warn("mint failed",e); }
}
async function gen(){
  setStatus("Issuing…");
  if(qrEl) qrEl.innerHTML='<div class="empty">Creating…</div>';
  if(pollTimer) clearInterval(pollTimer);
  if(countdownTimer) clearInterval(countdownTimer);
  if(ws) try{ ws.close(); }catch{}
  openModal();
  // True-E2E: generate authToken + e2eSecret locally. Only SHA-256(authToken)
  // goes to the server; e2eSecret travels ONLY in the QR fragment (#a=&e=)
  // which browsers never send over the network.
  const authToken=randomB64Url(32);
  const e2eSecret=randomB64Url(32);
  let tokenHash;
  try{ tokenHash=await sha256HexStr(authToken); }catch{ setStatus("Crypto unavailable"); return; }
  let res;
  try{
    const headers={"Content-Type":"application/json"};
    if(jwt) headers["Authorization"]=`Bearer ${jwt}`;
    res=await fetch(api("/api/auth/qr/create"),{method:"POST", headers, body:JSON.stringify({tokenHash, autoJoin:true})});
  }catch{
    setStatus("Offline");
    if(qrEl) qrEl.innerHTML='<div class="empty">Network error — retry</div>';
    return;
  }
  let data;
  try{ data=await res.json(); }catch{ data={}; }
  if(!res.ok){
    log("create failed",data);
    setStatus("Failed");
    if(qrEl){ qrEl.innerHTML=""; const d=document.createElement("div"); d.className="empty"; d.textContent=`Failed — ${data.error||res.status}`; qrEl.appendChild(d); }
    return;
  }
  try{
    // New server returns {roomId, expiresAt} (no token — we generated it).
    // Legacy servers return {token, url, roomId}.
    expiresAt=data.expiresAt;
    privateRoomId=data.roomId||null; // SERVER-authoritative — never derive locally
    if(privateRoomId) currentRoom=privateRoomId;
    createdAsHost=!!jwt;
    if(data.token){
      // Legacy fallback: server generated the token (no separate e2eSecret).
      currentAuthToken=data.token; currentE2ESecret=null;
      try{ e2eKey=await deriveE2EKey("legacy:"+data.token); }catch{}
    }else{
      currentAuthToken=authToken; currentE2ESecret=e2eSecret;
      try{ e2eKey=await deriveE2EKey(e2eSecret); }catch{}
    }
    // Fragment (#a=&e=) so secrets never hit server logs/Referer/history.
    const frag=currentE2ESecret
      ? `#a=${encodeURIComponent(currentAuthToken)}&e=${encodeURIComponent(currentE2ESecret)}`
      : `#token=${encodeURIComponent(currentAuthToken)}`;
    const qrText=`${location.origin}/mobile${frag}`;
    lastInviteUrl=qrText;
    const shareBtn=$("#copyLinkBtn"); if(shareBtn) shareBtn.disabled=false;
    setStatus(createdAsHost?`Invite · ${privateRoomId} — scan to chat`:"Scan with mobile");
    setTimer();
    countdownTimer=setInterval(setTimer,400);
    if(qrEl){
      qrEl.innerHTML="";
      let ok=false;
      try{ ok=await renderQr(qrEl,qrText); }catch(e){ console.warn(e); }
      if(!ok){
        const d=document.createElement("div");
        d.className="qr-fallback";
        d.textContent="QR failed — open /mobile manually (no link shown for privacy)";
        qrEl.appendChild(d);
      }
    }
    if(linkEl&&linkWrap){ linkEl.textContent=""; linkWrap.style.display="none"; }
    tryWs(currentAuthToken);
    startPolling(currentAuthToken);
  }catch(e){
    console.error(e);
    if(qrEl) qrEl.innerHTML='<div class="empty">Render failed</div>';
  }
}
function tryWs(authToken, protoTried=true){
  // Prefer Sec-WebSocket-Protocol over ?token= (no URL leakage). If the
  // handshake fails before opening (e.g. server didn't echo the subprotocol),
  // retry once with the deprecated ?token= query. Polling covers us anyway.
  const openWaiter=(useProto)=>{
    const w=useProto
      ? new WebSocket(`${wsBase()}/api/auth/qr/ws`, ["qr", authToken])
      : new WebSocket(`${wsBase()}/api/auth/qr/ws?token=${encodeURIComponent(authToken)}`);
    let opened=false;
    w.onopen=()=>{ opened=true; };
    w.onerror=()=>{ if(useProto && !opened){ try{w.close();}catch{} openWaiter(false); } else log("waiter error"); };
    w.onmessage=(e)=>{
      try{
        const m=JSON.parse(e.data);
        if(m.status==="approved"){
          if(createdAsHost){
            const r=m.roomId||privateRoomId||currentRoom;
            if(r){ privateRoomId=r; currentRoom=r; }
            setStatus("Joined — say hello"); toast(`Someone joined ${r} — 2-person, E2E`); setGated(false); modal?.classList.remove("open"); connectChat(r); cleanup();
          }else{ setStatus("Approved"); claim(authToken); }
        }
        if(m.status==="denied"){ setStatus("Denied"); cleanup(); }
        if(m.status==="expired"){ setStatus("Expired"); cleanup(); }
      }catch{}
    };
    ws=w;
  };
  try{ openWaiter(protoTried); }catch{ if(protoTried){ try{ openWaiter(false); }catch{} } }
}
let pollGen=0, pollDelay=2500;
function startPolling(authToken){
  // Poll is the fallback behind the waiter WS. Base 2.5s stays under the
  // per-token rate cap; consecutive 429s back off exponentially (stale tab
  // storms must never wedge the host on the QR screen).
  if(pollTimer){ clearInterval(pollTimer); clearTimeout(pollTimer); }
  pollTimer=null;
  const gen=++pollGen;
  pollDelay=2500;
  const tick=async()=>{
    if(gen!==pollGen) return;
    let res;
    try{ res=await fetch(api(`/api/auth/qr/status`),{headers:{"X-QR-Token":authToken}}); }
    catch{ if(gen===pollGen) pollTimer=setTimeout(tick,pollDelay); return; }
    if(res.status===429){ pollDelay=Math.min(8000,pollDelay*2); if(gen===pollGen) pollTimer=setTimeout(tick,pollDelay); return; }
    pollDelay=2500;
    const data=await res.json().catch(()=>({}));
    if(data.status==="approved"){
      if(createdAsHost){
        const r=data.roomId||privateRoomId||currentRoom;
        if(r){ privateRoomId=r; currentRoom=r; }
        setStatus("Joined — say hello"); toast(`Someone joined ${r} — 2-person, E2E`); setGated(false); modal?.classList.remove("open"); connectChat(r); cleanup();
      }else{ setStatus("Approved"); claim(authToken); }
      return;
    }
    if(data.status==="denied"){ setStatus("Denied"); cleanup(); return; }
    if(data.status==="expired"){ setStatus("Expired"); cleanup(); return; }
    if(gen===pollGen) pollTimer=setTimeout(tick,pollDelay);
  };
  pollTimer=setTimeout(tick,pollDelay);
}
async function claim(authToken){
  cleanup();
  let res;
  try{ res=await fetch(api("/api/auth/qr/claim"),{method:"POST", headers:{"Content-Type":"application/json","X-QR-Token":authToken}, body:JSON.stringify({token:authToken})}); }
  catch{ setStatus("Offline"); return; }
  const data=await res.json().catch(()=>({}));
  if(res.ok&&data.token){
    jwt=data.token; identity=data.identity;
    privateRoomId=data.roomId||privateRoomId; // server-authoritative
    if(privateRoomId) currentRoom=privateRoomId;
    try{ e2eKey=await deriveE2EKey(currentE2ESecret ? currentE2ESecret : ("legacy:"+authToken)); }catch{}
    renderMe();
    setStatus("Linked");
    if(timerText) timerText.textContent="Burned";
    toast(`Linked as ${identity.displayName||identity.userId} · ${privateRoomId} (E2E)`);
    setGated(false); modal?.classList.remove("open"); connectChat(privateRoomId||currentRoom);
  }else setStatus("Claim failed");
}
function cleanup(){ pollGen++; if(pollTimer){ clearInterval(pollTimer); clearTimeout(pollTimer); } pollTimer=null; if(countdownTimer) clearInterval(countdownTimer); countdownTimer=null; if(ws) try{ ws.close(); }catch{} ws=null; hideTyping(); lastInviteUrl=""; const sb=$("#copyLinkBtn"); if(sb) sb.disabled=true; }
async function connectChat(roomId="general"){
  currentRoom=roomId;
  if(roomNameEl) roomNameEl.textContent=roomId;
  if(inputEl) inputEl.placeholder=`Message · E2E if dm_*`;
  $$(".room").forEach(b=>b.classList.toggle("active",b.dataset.room===roomId));
  if(chatWs) try{ chatWs.close(); }catch{}
  if(msgsEl) msgsEl.innerHTML="";
  typingSent=false; clearTimeout(typingIdle); hideTyping();
  updateHero();
  if(!jwt){ setGated(true); openModal(); gen(); return; }
  try { sessionStorage.setItem("qrchat.inchat", "1"); } catch {}
  // Prefer Sec-WebSocket-Protocol for the JWT (no URL leakage). If the
  // handshake fails before opening, retry once with ?token=.
  openChatWs(roomId, true);
  renderMe();
}
function openChatWs(roomId, useProto){
  const base=`${wsBase()}/api/room/${encodeURIComponent(roomId)}/ws`;
  const w=useProto
    ? new WebSocket(base, ["bearer", jwt])
    : new WebSocket(`${base}?token=${encodeURIComponent(jwt)}`);
  chatWs=w;
  let opened=false;
  const retryQuery=()=>{
    if(!useProto || opened || chatWs!==w) return;
    try{ w.close(); }catch{}
    try{ openChatWs(roomId, false); }catch{ appendSystem("Connection failed — retry"); }
  };
  w.onopen=()=>{ opened=true; renderMe(); };
  w.onerror=()=>{ retryQuery(); };
  w.onmessage=async(e)=>{
    if(chatWs!==w) return;
    try{
      const d=JSON.parse(e.data);
      if(d.type==="welcome"){ updateHero(); if(d.history?.length) log("history suppressed",d.history.length); }
      else if(d.type==="message") await appendMsg(d.message);
      else if(d.type==="typing"){ const who=d.displayName||d.userId||"Peer"; if(d.typing) showTyping(who); else hideTyping(); }
      else if(d.type==="presence"&&presenceEl){ presenceEl.style.display="block"; presenceEl.textContent=`● ${d.userId} ${d.event}ed`; clearTimeout(presenceEl._t); presenceEl._t=setTimeout(()=>presenceEl.style.display="none",3500); }
      else if(d.type==="peer_closed"){ appendSystem("Peer refreshed — closing"); toast("Peer left — closing tab…"); setTimeout(()=>{ try{ window.close(); }catch{} location.href="about:blank"; },800); try{ chatWs.close(); }catch{} }
      else if(d.type==="moderation"){ appendSystem("Blocked by moderation."); toast("Blocked"); }
      else if(d.type==="error") appendSystem(d.error.includes("full")?"Room full — only 2":"Error — try again");
    }catch{}
  };
  w.onclose=(e)=>{
    if(chatWs!==w) return;
    if(!opened && useProto){ retryQuery(); return; }
    if(e&&e.code===4000){ appendSystem("Peer refreshed — closing tab…"); setTimeout(()=>{ try{ window.close(); }catch{} location.href="about:blank"; },500); return; } appendSystem("Disconnected — reload erases (ephemeral)"); renderMe();
  };
}
async function appendMsg(m){
  const mine=identity&&m.userId===identity.userId;
  const div=document.createElement("div");
  div.className="row "+(mine?"me":"peer");
  const who=m.displayName||m.userId;
  const time=new Date(m.ts).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
  let body=m.body;
  if(m.roomId?.startsWith("dm_")&&e2eKey) body=sanitizeDecrypted(await e2eDecrypt(body,e2eKey));
  else if(m.roomId?.startsWith("dm_")&&!e2eKey) body="[encrypted — refresh cleared key]";
  else body=sanitizeDecrypted(body);
  if(mine){ div.innerHTML=`<div class="bubble"><div class="body"></div></div>`; div.querySelector(".body").textContent=body; }
  else{ div.innerHTML=`<div class="ava"></div><div class="bubble"><div class="meta"><b></b><time>${time}</time></div><div class="body"></div></div>`; div.querySelector(".ava").textContent=who.slice(0,1).toUpperCase(); div.querySelector("b").textContent=who; div.querySelector(".body").textContent=body; }
  if(msgsEl) msgsEl.appendChild(div);
  if(scrollEl) scrollEl.scrollTop=scrollEl.scrollHeight;
  updateHero();
}
function appendSystem(t){ const d=document.createElement("div"); d.className="sys"; d.textContent="— "+t; if(msgsEl) msgsEl.appendChild(d); }
async function send(){
  const body=inputEl.value.trim();
  if(!body) return;
  if(!chatWs||chatWs.readyState!==1){ toast("Link first"); openModal(); return; }
  sendTyping(false);
  let outBody=body;
  if(currentRoom.startsWith("dm_")&&e2eKey) outBody=await e2eEncrypt(body,e2eKey);
  chatWs.send(JSON.stringify({type:"message", roomId:currentRoom, body:outBody}));
  inputEl.value=""; autogrow(); updateSend();
}
function autogrow(){ inputEl.style.height="auto"; inputEl.style.height=Math.min(160,inputEl.scrollHeight)+"px"; }
$("#gen")?.addEventListener("click",gen);
$("#openQrBtn")?.addEventListener("click",()=>{ openModal(); if(!currentAuthToken||Date.now()>expiresAt) gen(); });
$("#linkDeviceBtn")?.addEventListener("click",()=>{ openModal(); if(!currentAuthToken||Date.now()>expiresAt) gen(); });
$("#heroLinkBtn")?.addEventListener("click",gen);
$("#qrClose")?.addEventListener("click",closeModal);
modal?.addEventListener("click",(e)=>{ if(e.target===modal) closeModal(); });
document.addEventListener("keydown",(e)=>{ if(e.key==="Escape"){ closeModal(); $("#sidebar")?.classList.remove("open"); } });
$("#copyLinkBtn")?.addEventListener("click",async()=>{
  if(!lastInviteUrl) return toast("No invite yet — wait for the QR");
  try{
    if(navigator.clipboard?.writeText) await navigator.clipboard.writeText(lastInviteUrl);
    else{ const ta=document.createElement("textarea"); ta.value=lastInviteUrl; ta.style.position="fixed"; ta.style.opacity="0"; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
    toast("Invite link copied — open it on the other desktop");
  }catch{ toast("Copy failed — photograph the QR instead"); }
});
$("#send")?.addEventListener("click",send);
inputEl?.addEventListener("input",()=>{ autogrow(); updateSend(); sendTyping(!!inputEl.value.trim()); });
inputEl?.addEventListener("blur",()=>sendTyping(false));
inputEl?.addEventListener("keydown",(e)=>{ if(e.key==="Enter"&&!e.shiftKey){ e.preventDefault(); send(); } });
$("#newChatBtn")?.addEventListener("click",()=>{ if(msgsEl) msgsEl.innerHTML=""; updateHero(); inputEl?.focus(); });
$("#menuBtn")?.addEventListener("click",()=>$("#sidebar")?.classList.add("open"));
$$(".room").forEach(b=>b.addEventListener("click",()=>{ connectChat(b.dataset.room); $("#sidebar")?.classList.remove("open"); }));
window.addEventListener("beforeunload",()=>{ try{ chatWs?.close(1000,"refresh"); ws?.close(1000,"refresh"); }catch{} });
window.addEventListener("keydown",(e)=>{ if(e.key==="F5"||(e.ctrlKey&&e.key.toLowerCase()==="r")||(e.metaKey&&e.key.toLowerCase()==="r")){ if(gated) return; e.preventDefault(); try{ chatWs?.close(1000,"refresh"); }catch{} setTimeout(()=>{ try{ window.close(); }catch{} location.href="about:blank"; },80); } });
// Boot: QR-only, no nickname ask — auto-mint random anon, show QR
renderMe();
setTimer();
ensureEphemeralIdentity().then(()=>{
  renderMe();
  setGated(true);
  if(heroEl) heroEl.style.display="";
  appendSystem("Share this QR to chat — no account, no nickname needed. Scan to join (2-person, E2E). Refresh erases everything — peer tab will also close.");
  gen();
}).catch(()=>{ setGated(true); gen(); });
