const $ = s => document.querySelector(s);
const qrEl = $("#qr"), ringFg = $("#ringFg"), ringNum = $("#ringNum"), timerText = $("#timerText");
const roomLbl = $("#roomLbl"), kvRoom = $("#kvRoom"), kvTok = $("#kvTok"), inviteCode = $("#inviteCode");
const hero = $("#hero"), msgsEl = $("#msgs"), scrollEl = $("#scroll"), presenceEl = $("#presence");
const headAva = $("#headAva"), headName = $("#headName"), headSub = $("#headSub"), dot = $("#dot");
const input = $("#input"), sendBtn = $("#send"), e2eBadge = $("#e2eBadge"), count = $("#count");
const toastsEl = $("#toasts");
let you = { id: "u_" + Math.random().toString(36).slice(2,8), name: "anon-" + Math.random().toString(36).slice(2,6) };
let peer = { id: "u_" + Math.random().toString(36).slice(2,8), name: "anon-" + Math.random().toString(36).slice(2,6) };
let acting = "you";
let roomId = null, rawToken = null, e2eKey = null, joined = false, expiresAt = 0, cd = null, poll = null;
let members = new Set();

const RING_C = 2*Math.PI*46;

function toast(t){ const d=document.createElement("div"); d.className="toast"; d.textContent=t; toastsEl.appendChild(d); setTimeout(()=>d.remove(),2600); }
function uid(){ return Math.random().toString(36).slice(2,8) }
function setPresence(t){ if(!t){presenceEl.style.display="none"; return} presenceEl.textContent="● "+t; presenceEl.style.display="block"; clearTimeout(presenceEl._t); presenceEl._t=setTimeout(()=>presenceEl.style.display="none",3200); }
function updateHeader(){
  const name = joined ? (acting==="you"? you.name : peer.name) : "Not joined";
  const sub = joined ? `${roomId} · 2-person · E2E on` : "scan QR to join · private";
  headAva.textContent = (joined ? (acting==="you"? you.name:peer.name) : "?").slice(0,1).toUpperCase();
  headName.textContent = name;
  headSub.textContent = sub;
  dot.style.display = joined ? "block" : "none";
  e2eBadge.textContent = joined ? "E2E on · dm_ encrypted" : "E2E off — join first";
  e2eBadge.style.color = joined ? "var(--ok)" : "var(--mut)";
  roomLbl.textContent = roomId || "dm_····";
  kvRoom.textContent = roomId || "—";
  kvTok.textContent = rawToken ? rawToken.slice(0,16)+"…" : "—";
}
function updateSend(){ sendBtn.disabled = !joined || !input.value.trim(); count.textContent = `${input.value.length} / 2000`; }
function appendSystem(t, cls){ const d=document.createElement("div"); d.className="sys"+(cls?" "+cls:""); d.textContent="— "+t; msgsEl.appendChild(d); scrollEl.scrollTop=scrollEl.scrollHeight; }
function appendMsg({who, body, mine, ts}) {
  const row=document.createElement("div"); row.className="row"+(mine?" me":"");
  const time=new Date(ts).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
  const initial=who.slice(0,1).toUpperCase();
  if(mine){
    row.innerHTML=`<div class="bubble"><div class="body"></div></div>`;
    row.querySelector(".body").textContent=body;
  } else {
    row.innerHTML=`<div class="ava"></div><div class="bubble"><div class="meta"><b></b><t></t></div><div class="body"></div></div>`;
    row.querySelector(".ava").textContent=initial; row.querySelector("b").textContent=who; row.querySelector("t").textContent=time; row.querySelector(".body").textContent=body;
  }
  msgsEl.appendChild(row); scrollEl.scrollTop=scrollEl.scrollHeight;
  // ephemeral fade demo: fade after 20s
  setTimeout(()=>{ row.style.opacity=".35"; row.style.filter="blur(.3px)"; }, 20000);
}

async function deriveKey(raw){
  try{
    const enc=new TextEncoder();
    const ikm=await crypto.subtle.importKey("raw", enc.encode(raw), {name:"HKDF"}, false, ["deriveKey"]);
    return await crypto.subtle.deriveKey({name:"HKDF", hash:"SHA-256", salt:new Uint8Array(0), info:enc.encode("qrchat-e2e-v1")}, ikm, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  } catch {
    const h=await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
    return crypto.subtle.importKey("raw", h, {name:"AES-GCM"}, false, ["encrypt","decrypt"]);
  }
}
async function enc(plain,key){
  if(!key||!roomId?.startsWith("dm_")) return plain;
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,new TextEncoder().encode(plain));
  return `enc:${btoa(String.fromCharCode(...new Uint8Array(ct)))}.${btoa(String.fromCharCode(...iv))}`;
}
async function dec(payload,key){
  if(!key||typeof payload!=="string"||!payload.startsWith("enc:")) return payload;
  try{
    const [b64ct,b64iv]=payload.slice(4).split(".");
    const ct=Uint8Array.from(atob(b64ct),c=>c.charCodeAt(0));
    const iv=Uint8Array.from(atob(b64iv),c=>c.charCodeAt(0));
    const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct);
    return new TextDecoder().decode(pt);
  } catch { return payload; }
}
function renderQr(text){
  try{
    const g=globalThis.qrcode || window.qrcode;
    if(g){ const qr=g(0,"M"); qr.addData(text); qr.make(); qrEl.innerHTML=qr.createSvgTag({cellSize:6,margin:0,scalable:true}) + qrEl.innerHTML.match(/<div class="ring[\s\S]*/)?.[0] || ""; const svg=qrEl.querySelector("svg"); if(svg){svg.style.width="288px";svg.style.height="288px";svg.style.display="block";svg.style.borderRadius="12px"} // keep ring
      // re-append ring if overwritten
      if(!qrEl.querySelector("#ringFg")){ const ring=document.createElement("div"); ring.className="ring"; ring.innerHTML=`<svg viewBox="0 0 100 100"><circle class="bg" cx="50" cy="50" r="46"/><circle id="ringFg" class="fg" cx="50" cy="50" r="46" stroke-dasharray="289" stroke-dashoffset="0"/></svg>`; qrEl.appendChild(ring); }
      return true; }
  } catch(e){ console.warn(e)}
  try{
    const QRC=globalThis.QRCode || window.QRCode;
    if(QRC&&QRC.toCanvas){ const c=document.createElement("canvas"); qrEl.innerHTML=""; qrEl.appendChild(c); QRC.toCanvas(c,text,{width:288,margin:1}); const ring=document.createElement("div"); ring.className="ring"; ring.innerHTML=`<svg viewBox="0 0 100 100"><circle class="bg" cx="50" cy="50" r="46"/><circle id="ringFg" class="fg" cx="50" cy="50" r="46" stroke-dasharray="289" stroke-dashoffset="0"/></svg>`; qrEl.appendChild(ring); return true; }
  } catch{}
  return false;
}

async function gen(){
  // reset ephemeral
  joined=false; members=new Set(); e2eKey=null;
  msgsEl.innerHTML=""; hero.style.display=""; hero.textContent="Share this QR to chat — no account, no nickname needed. Scan to join (2-person, E2E). Refresh erases everything — peer tab will also close.";
  updateHeader(); updateSend();
  // create mock token + room like Worker: room = dm_${sha256(token).hex.slice(0,12)}
  const bytes=new Uint8Array(32); crypto.getRandomValues(bytes);
  rawToken=btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  const buf=await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawToken));
  const hex=[...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join("");
  roomId=`dm_${hex.slice(0,12)}`;
  e2eKey=await deriveKey(rawToken);
  expiresAt=Date.now()+90_000;
  // QR text uses fragment so token never hits server logs
  const qrText=`${location.origin}/mobile#token=${encodeURIComponent(rawToken)}`;
  inviteCode.textContent=qrText; inviteCode.style.display="none";
  // render QR
  const ok = renderQr(qrText);
  if(!ok){ qrEl.innerHTML=`<div class="empty">QR failed — ${qrText.slice(0,48)}</div>`; }
  // ensure ring exists
  const fg=document.getElementById("ringFg");
  if(fg) { fg.style.strokeDasharray=String(RING_C); fg.style.strokeDashoffset="0"; }
  document.getElementById("qrTitle").textContent="Scan QR from other device";
  document.getElementById("qrSub").textContent="No accounts. No history. The QR is the only key — share it side-channel. 90s expiry, 1-time burn.";
  updateHeader();
  toast(`New invite ${roomId} · E2E`);
  startCountdown();
  // reset presence
  setPresence("");
}

function startCountdown(){
  clearInterval(cd); clearInterval(poll);
  const fg=document.getElementById("ringFg");
  const num=document.getElementById("ringNum");
  function tick(){
    const s=Math.max(0,Math.round((expiresAt-Date.now())/1000));
    timerText.innerHTML=`${s>0? s+"s left":"Expired"} · <b id="ringNum">${s}</b>`;
    if(fg) fg.style.strokeDashoffset=String(RING_C*(1 - s/90));
    if(s===0){ clearInterval(cd); appendSystem("Invite expired — generate new QR", "warn"); toast("Expired"); }
  }
  tick(); cd=setInterval(tick, 300);
}

async function simulateScan(){
  if(!rawToken||Date.now()>expiresAt) return toast("Expired — generate new QR");
  if(members.size>=2) return toast("Room is full — only 2");
  joined=true; members.add(you.id); members.add(peer.id);
  hero.style.display="none";
  appendSystem(`Peer ${peer.name} joined ${roomId} — 2-person, E2E on`);
  appendSystem(`You joined as ${you.name} · ephemeral`);
  setPresence(`${peer.name} joined`);
  updateHeader();
  updateSend();
  toast(`Joined ${roomId} — E2E on`);
  // demo: peer sends hello after scan
  setTimeout(()=>{ mockReceive(peer.name, peer.id, "hey — we’re E2E here 👋"); }, 600);
}

async function mockReceive(displayName, userId, plain){
  // simulate wire: encrypt then decrypt
  const wire=await enc(plain, e2eKey);
  // show raw for demo in console, but UI decrypts
  console.log("wire", wire.slice(0,40));
  const body=await dec(wire, e2eKey);
  const mine = (acting==="you" ? userId===you.id : userId===peer.id);
  // but for mock, we always render as peer vs you based on sender
  // determine if current acting user is sender
  const isMine = (displayName === (acting==="you"? you.name: peer.name));
  appendMsg({who:displayName, body, mine:isMine, ts:Date.now()});
}

async function send(){
  const v=input.value.trim();
  if(!v) return;
  if(!joined) return toast("Scan QR first");
  if(members.size>2) return toast("Room full");
  if(v.length>2000) return toast("2000 char max");
  const sender = acting==="you" ? you : peer;
  const wire=await enc(v, e2eKey);
  const plain=await dec(wire, e2eKey);
  // append as mine for sender
  appendMsg({who:sender.name, body:plain, mine:true, ts:Date.now()});
  // also echo to opposite side as peer bubble (simulate the other client receiving)
  setTimeout(async ()=>{
    const other = acting==="you" ? peer : you;
    // the other side would see it as peer
    const row=document.createElement("div");
    // Instead, just append second bubble as peer view: duplicate logic but not needed because single pane shows both
    // For functional mock, we emit presence
  }, 10);
  // simulate peer reply typing indicator occasionally
  input.value=""; updateSend(); autoresize();
}

function autoresize(){ input.style.height="auto"; input.style.height=Math.min(120,input.scrollHeight)+"px"; }

// events
$("#btnNewQR").addEventListener("click", gen);
$("#btnSimScan").addEventListener("click", simulateScan);
$("#btnCopy").addEventListener("click", async ()=>{
  const t=`${location.origin}/mobile#token=${rawToken}`;
  try{ await navigator.clipboard.writeText(t); toast("Copied invite link"); } catch { inviteCode.style.display="block"; inviteCode.textContent=t; toast("Copied — shown below"); }
});
$("#btnReset").addEventListener("click", ()=>{
  // ephemeral reset: clear and go blank then regen like refresh would close
  msgsEl.innerHTML=""; joined=false; members.clear();
  toast("Reset — ephemeral, history erased");
  gen();
});
document.querySelectorAll(".seg button").forEach(b=>{
  b.addEventListener("click", ()=>{
    document.querySelectorAll(".seg button").forEach(x=>{x.classList.remove("on"); x.setAttribute("aria-selected","false")});
    b.classList.add("on"); b.setAttribute("aria-selected","true");
    acting=b.dataset.role;
    updateHeader();
    appendSystem(`Switched to ${acting==="you"? you.name: peer.name}`, "");
  });
});
$("#send").addEventListener("click", send);
input.addEventListener("input", ()=>{ autoresize(); updateSend(); });
input.addEventListener("keydown", e=>{
  if(e.key==="Enter" && !e.shiftKey){ e.preventDefault(); send(); }
});
window.addEventListener("keydown", e=>{
  if(e.key==="F5" || (e.ctrlKey&&e.key.toLowerCase()==="r") || (e.metaKey&&e.key.toLowerCase()==="r")){
    e.preventDefault();
    msgsEl.innerHTML="";
    appendSystem("You refreshed — closing… (mock → blank)", "warn");
    setTimeout(()=>{ document.body.innerHTML=`<div style="min-height:100dvh;display:grid;place-items:center;background:#0A0A0B;color:#6B6B74;font-family:JetBrains Mono,monospace">closed — ephemeral (about:blank) · <a href="" style="color:#ECECED">reopen mock</a></div>`; }, 600);
  }
});
// boot
updateHeader(); gen();
