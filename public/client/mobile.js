// Mobile key — inspect then approve
const $=s=>document.querySelector(s);
const loginOut=$("#loginOut");
const previewOut=$("#previewOut");
const details=$("#details");
const confirm=$("#confirm");
const sheetStatus=$("#sheetStatus");

let mobileJwt=localStorage.getItem("mobile_jwt")||"";

function renderLoginOut(){
  if(!loginOut) return;
  if(mobileJwt){
    loginOut.textContent=`Stored pass (truncated): ${mobileJwt.slice(0,28)}…\nKeep this on your phone only.`;
    loginOut.style.color="#A7F3D0";
  } else loginOut.textContent="No session yet — mint one below.";
}
renderLoginOut();

$("#login")?.addEventListener("click",async()=>{
  const userId=($("#userId")?.value||"").trim()||"alice";
  const res=await fetch("/api/auth/dev-login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({userId, displayName:userId})});
  const data=await res.json().catch(()=>({}));
  if(loginOut) loginOut.textContent=JSON.stringify(data,null,2);
  if(data.token){ mobileJwt=data.token; localStorage.setItem("mobile_jwt",mobileJwt); renderLoginOut(); }
});
$("#clearSession")?.addEventListener("click",()=>{
  mobileJwt=""; localStorage.removeItem("mobile_jwt"); renderLoginOut();
  if(loginOut) loginOut.textContent="Cleared.";
});

$("#preview")?.addEventListener("click",async()=>{
  const raw=($("#token")?.value||"").trim();
  if(!raw) return alert("Paste token");
  let t=raw;
  try{ const u=new URL(raw); const p=u.searchParams.get("token"); if(p) t=p; }catch{}
  const el=$("#token"); if(el) el.value=t;
  if(previewOut) previewOut.textContent="Inspecting…";
  const res=await fetch(`/api/auth/qr/preview?token=${encodeURIComponent(t)}`);
  const data=await res.json().catch(()=>({}));
  if(previewOut) previewOut.textContent=JSON.stringify(data,null,2);
  if(data.status==="pending" || res.ok && data.status){
    if(confirm && details){
      details.innerHTML="";
      const items=[
        `Status: ${data.status||"unknown"}`,
        `Created: ${data.createdAt? new Date(data.createdAt).toLocaleString():"unknown"}`,
        `Expires: ${data.expiresAt? new Date(data.expiresAt).toLocaleString():"unknown"} (${data.expiresAt? Math.max(0,Math.round((data.expiresAt-Date.now())/1000)):"?"}s left)`,
        `Token: ${data.tokenPreview||t.slice(0,8)+"…"}`,
        `Check that the city/time matches your station. If anything looks off, tap Deny.`,
      ];
      items.forEach(txt=>{ const li=document.createElement("li"); li.textContent=txt; details.appendChild(li); });
      confirm.classList.add("open"); confirm.style.display="block";
      if(sheetStatus) sheetStatus.textContent=data.status||"Pending";
      const ack=$("#ack"); const approve=$("#approve");
      if(ack && approve) approve.disabled=!ack.checked;
    }
  } else {
    if(confirm){ confirm.classList.remove("open"); confirm.style.display="none"; }
    if(previewOut) previewOut.textContent += "\nNot pending — cannot approve.";
  }
});

$("#ack")?.addEventListener("change",e=>{
  const approve=$("#approve");
  if(approve) approve.disabled=!e.target.checked;
});
$("#approve")?.addEventListener("click",async()=>{
  const token=($("#token")?.value||"").trim();
  if(!mobileJwt) return alert("Mint a mobile session first (Step 1)");
  const res=await fetch("/api/auth/mobile/approve",{method:"POST",headers:{"Content-Type":"application/json", Authorization:`Bearer ${mobileJwt}`}, body:JSON.stringify({token, action:"approve"})});
  const data=await res.json().catch(()=>({}));
  alert(`Approved: ${res.status} ${JSON.stringify(data)}`);
  if(previewOut) previewOut.textContent=JSON.stringify(data,null,2);
  if(res.ok && sheetStatus) sheetStatus.textContent="Approved";
});
$("#deny")?.addEventListener("click",async()=>{
  const token=($("#token")?.value||"").trim();
  if(!mobileJwt) return alert("Mint a mobile session first");
  const res=await fetch("/api/auth/mobile/approve",{method:"POST",headers:{"Content-Type":"application/json", Authorization:`Bearer ${mobileJwt}`}, body:JSON.stringify({token, action:"deny"})});
  const data=await res.json().catch(()=>({}));
  alert(`Denied: ${res.status} ${JSON.stringify(data)}`);
  if(previewOut) previewOut.textContent=JSON.stringify(data,null,2);
  if(res.ok && sheetStatus) sheetStatus.textContent="Denied";
});
$("#paste")?.addEventListener("click",async()=>{
  try{ const t=await navigator.clipboard.readText(); const el=$("#token"); if(el) el.value=t.trim(); }
  catch{ alert("Clipboard read failed — paste manually"); }
});
try{
  const u=new URL(location.href);
  const p=u.searchParams.get("token");
  if(p){ const el=$("#token"); if(el) el.value=p; }
}catch{}
