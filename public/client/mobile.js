// Mobile — minimal verify. Contract: preview → ack → approve/deny.
const API_BASE2 = (typeof window !== "undefined" && window.__API_BASE__ ? window.__API_BASE__ : "").replace(/\/$/, "");
const api2 = (p) => `${API_BASE2}${p}`;
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
    if (previewOut) previewOut.textContent = `Pending · ${left}s left.`;
    if (details) {
      details.innerHTML = "";
      [`Created ${data.createdAt ? new Date(data.createdAt).toLocaleTimeString() : "?"}`, `Expires in ${left}s`, `Token ${data.tokenPreview || t.slice(0, 8) + "…"}`]
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
$("#approve")?.addEventListener("click", async () => {
  const token = ($("#token")?.value || "").trim();
  if (!mobileJwt) return alert("Mint a session first");
  const res = await fetch(api2("/api/auth/mobile/approve"), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: "approve" }) });
  if (res.ok) { showConfirm(false); if (previewOut) previewOut.textContent = "Approved."; alert("Approved"); }
  else alert("Approve failed");
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
