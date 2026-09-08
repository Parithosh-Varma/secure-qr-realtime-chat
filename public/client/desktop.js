// Station client — distinctive ink/chalk design, keeps all security hooks
const $ = (s) => document.querySelector(s);
const statusEl = $("#status");
const timerText = $("#timerText");
const qrEl = $("#qr");
const linkEl = $("#link");
const linkWrap = $("#linkWrap");
const debugEl = $("#debug");
const msgsEl = $("#msgs");
const meEl = $("#me");
const presenceEl = $("#presence");
const inputEl = $("#msgInput");

let pollTimer = null;
let countdownTimer = null;
let ws = null;
let chatWs = null;
let currentToken = null;
let expiresAt = 0;
let jwt = localStorage.getItem("chat_jwt") || "";
let identity = JSON.parse(localStorage.getItem("chat_identity") || "null");

function log(...a){
  const line = a.map(x=> typeof x==="string"? x : JSON.stringify(x,null,2)).join(" ");
  if(debugEl){ debugEl.textContent += line + "\n"; debugEl.scrollTop = debugEl.scrollHeight; }
  console.log(...a);
}
function setStatus(text, tone){
  if(!statusEl) return;
  statusEl.textContent = text;
  // tone: ok|warn|bad → background hint
  statusEl.style.background = tone==="ok" ? "#E6F4EA" : tone==="warn" ? "#FFF7D6" : tone==="bad" ? "#FFE0E6" : "var(--concrete)";
  statusEl.style.color = tone==="ok" ? "#0E7A4C" : tone==="bad" ? "#B42318" : "var(--muted)";
}
function setTimer(){
  if(!timerText) return;
  if(!expiresAt){ timerText.textContent="No active link"; return; }
  const s = Math.max(0, Math.round((expiresAt - Date.now())/1000));
  timerText.textContent = s>0 ? `${s}s left · burns on claim` : "Expired";
  if(s===0) setStatus("Expired","bad");
}
function renderMe(){
  if(!meEl) return;
  if(jwt && identity){
    meEl.textContent = `● ${identity.userId} • pass 1h`;
    meEl.style.background="rgba(45,91,255,0.14)"; meEl.style.borderColor="rgba(45,91,255,0.28)"; meEl.style.color="#fff";
    if(presenceEl){ presenceEl.style.display="flex"; presenceEl.innerHTML=`<span>Station linked as <strong>${identity.displayName||identity.userId}</strong> — transcript is live. WSS enforced.</span>`; }
  } else {
    meEl.textContent="Not linked — generate a stub";
    meEl.style.background=""; meEl.style.borderColor=""; meEl.style.color="";
    if(presenceEl) presenceEl.style.display="none";
  }
}
renderMe();

async function gen(){
  setStatus("Issuing…");
  if(qrEl) qrEl.innerHTML='<div class="empty">Creating stub…</div>';
  if(pollTimer) clearInterval(pollTimer);
  if(countdownTimer) clearInterval(countdownTimer);
  if(ws) try{ ws.close(); }catch{}
  const res = await fetch("/api/auth/qr/create",{method:"POST"});
  const data = await res.json().catch(()=>({}));
  if(!res.ok){
    log("create failed",data);
    setStatus("Failed: "+(data.error||res.status),"bad");
    if(qrEl) qrEl.innerHTML=`<div class="empty">Failed — ${data.error||res.status}</div>`;
    return;
  }
  currentToken=data.token; expiresAt=data.expiresAt;
  log("QR created",{url:data.url, expiresAt:new Date(data.expiresAt).toISOString(), ttlMs:data.ttlMs});
  setStatus("Scan with mobile","ok");
  setTimer();
  countdownTimer=setInterval(setTimer,400);

  if(qrEl){
    qrEl.innerHTML="";
    const canvas=document.createElement("canvas");
    qrEl.appendChild(canvas);
    if(typeof QRCode!=="undefined") await QRCode.toCanvas(canvas, data.url, {width:276, margin:1, color:{dark:"#0E1A24", light:"#FFFFFF"}});
    else { qrEl.textContent=data.url; }
  }
  if(linkEl && linkWrap){ linkEl.textContent=data.url; linkWrap.style.display="block"; }
  tryWs(data.token);
  startPolling(data.token);
}

function tryWs(token){
  const proto = location.protocol==="https:"?"wss:":"ws:";
  const wsUrl = `${proto}//${location.host}/api/auth/qr/ws?token=${encodeURIComponent(token)}`;
  try{
    ws=new WebSocket(wsUrl);
    ws.onopen=()=> log("waiter open");
    ws.onmessage=(e)=>{
      log("waiter",e.data);
      try{
        const msg=JSON.parse(e.data);
        if(msg.status==="approved"){ setStatus("Approved — burning…","ok"); claim(token); }
        if(msg.status==="denied"){ setStatus("Denied","bad"); cleanup(); setTimer(); }
        if(msg.status==="expired"){ setStatus("Expired","bad"); cleanup(); }
      }catch{}
    };
    ws.onerror=()=> log("waiter error — poll still active");
    ws.onclose=()=> log("waiter closed");
  }catch(e){ log("waiter failed",String(e)); }
}

function startPolling(token){
  if(pollTimer) clearInterval(pollTimer);
  pollTimer=setInterval(async()=>{
    const res=await fetch(`/api/auth/qr/status?token=${encodeURIComponent(token)}`);
    const data=await res.json().catch(()=>({}));
    log("poll",res.status,data);
    if(data.status==="approved"){ setStatus("Approved (poll) — burning…","ok"); claim(token); }
    if(data.status==="denied"){ setStatus("Denied","bad"); cleanup(); }
    if(data.status==="expired"){ setStatus("Expired","bad"); cleanup(); }
  },1500);
}

async function claim(token){
  cleanup();
  const res=await fetch("/api/auth/qr/claim",{method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({token})});
  const data=await res.json().catch(()=>({}));
  log("claim",res.status,data);
  if(res.ok && data.token){
    jwt=data.token; identity=data.identity;
    localStorage.setItem("chat_jwt",jwt);
    localStorage.setItem("chat_identity",JSON.stringify(identity));
    renderMe();
    setStatus(`Linked as ${identity.userId}`,"ok");
    if(timerText) timerText.textContent="Burned · single-use";
    connectChat("general");
  } else {
    setStatus("Claim failed: "+(data.error||res.status),"bad");
  }
}

function cleanup(){
  if(pollTimer) clearInterval(pollTimer); pollTimer=null;
  if(countdownTimer) clearInterval(countdownTimer); countdownTimer=null;
  if(ws) try{ ws.close(); }catch{} ws=null;
}

function connectChat(roomId="general"){
  if(chatWs) try{ chatWs.close(); }catch{}
  if(!jwt){ log("cannot connect — no pass"); appendSystem("No pass — generate a stub first","bad"); return; }
  const proto=location.protocol==="https:"?"wss:":"ws:";
  const wsUrl=`${proto}//${location.host}/api/room/${encodeURIComponent(roomId)}/ws?token=${encodeURIComponent(jwt)}`;
  chatWs=new WebSocket(wsUrl);
  chatWs.onopen=()=>{ log("chat open",roomId,identity?.userId); appendSystem(`Linked to #${roomId} as ${identity?.userId}`); };
  chatWs.onmessage=(e)=>{
    try{
      const d=JSON.parse(e.data);
      log("chat recv",d);
      if(d.type==="welcome"){
        if(d.history?.length) d.history.forEach(appendMsg);
        else appendSystem("No history yet — say hello.");
      } else if(d.type==="message"){ appendMsg(d.message); }
      else if(d.type==="presence"){ appendSystem(`${d.userId} ${d.event}ed`); }
      else if(d.type==="moderation"){ appendSystem(`Blocked: ${d.reason}`,"bad"); }
      else if(d.type==="error"){ appendSystem(`Error: ${d.error}`,"bad"); }
    }catch{ log("chat raw",e.data); }
  };
  chatWs.onclose=()=> appendSystem("Disconnected — reload to reconnect","bad");
  chatWs.onerror=()=> appendSystem("Socket error","bad");
}

function appendMsg(m){
  if(!msgsEl) return;
  const div=document.createElement("div");
  div.className="line"+(identity && m.userId===identity.userId? " me":"");
  const who = m.displayName||m.userId;
  const time = new Date(m.ts).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit"});
  div.innerHTML=`<div class="time">${time}</div><div class="body"><span class="who">${escapeHtml(who)}:</span> ${m.body}${m.flagged?'<span class="flag">⚑ '+escapeHtml(m.flagReason||"flagged")+'</span>':''}</div>`;
  msgsEl.appendChild(div);
  msgsEl.scrollTop=msgsEl.scrollHeight;
}
function appendSystem(text, tone){
  if(!msgsEl) return;
  const div=document.createElement("div");
  div.className="line system";
  div.innerHTML=`<div>— ${escapeHtml(text)}</div>`;
  if(tone==="bad") div.style.color="#FF8A8A";
  msgsEl.appendChild(div);
  msgsEl.scrollTop=msgsEl.scrollHeight;
}
function escapeHtml(s){ return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

function send(){
  if(!inputEl) return;
  const body=inputEl.value.trim();
  if(!body) return;
  if(!chatWs || chatWs.readyState!==1){ appendSystem("Not connected — link your station first","bad"); return; }
  chatWs.send(JSON.stringify({type:"message", roomId:"general", body}));
  inputEl.value="";
}

document.getElementById("gen")?.addEventListener("click", gen);
document.getElementById("send")?.addEventListener("click", send);
document.getElementById("historyBtn")?.addEventListener("click", async()=>{
  if(!jwt) return alert("Link your station first");
  const res=await fetch(`/api/room/general/history?token=${encodeURIComponent(jwt)}`,{headers:{Authorization:`Bearer ${jwt}`}});
  const data=await res.json().catch(()=>({}));
  log("history",data);
  if(data.messages){
    msgsEl.innerHTML="";
    data.messages.forEach(appendMsg);
    if(!data.messages.length) appendSystem("No messages yet.");
  }
});
document.getElementById("exportBtn")?.addEventListener("click", async()=>{
  const lines=[...msgsEl.querySelectorAll(".line")].map(el=> el.textContent.trim()).join("\n");
  try{ await navigator.clipboard.writeText(lines); appendSystem("Transcript copied"); }catch{ appendSystem("Copy failed","bad"); }
});
document.getElementById("clearBtn")?.addEventListener("click",()=>{ if(msgsEl) msgsEl.innerHTML='<div class="line system"><div>Cleared.</div></div>'; });
inputEl?.addEventListener("keydown",(e)=>{ if(e.key==="Enter" && !e.shiftKey){ e.preventDefault(); send(); }});

// Auto-connect if already authed
if(jwt && identity){
  log("Found existing pass, auto-connecting…");
  setTimeout(()=> connectChat("general"), 500);
}
log("Station ready. Generate a stub. Mobile key at /mobile");
