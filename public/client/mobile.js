// Mobile approve flow — explicitly requires tap-to-approve with fingerprint confirmation
const $ = (s) => document.querySelector(s);
const loginOut = $("#loginOut");
const previewOut = $("#previewOut");
const details = $("#details");
const confirm = $("#confirm");

let mobileJwt = localStorage.getItem("mobile_jwt") || "";

function renderLoginOut() {
  if (!loginOut) return;
  loginOut.textContent = mobileJwt ? `Stored mobile JWT (truncated): ${mobileJwt.slice(0, 24)}…` : "No session";
}
renderLoginOut();

document.getElementById("login")?.addEventListener("click", async () => {
  const userId = ($("#userId")?.value || "").trim() || "alice";
  const res = await fetch("/api/auth/dev-login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId, displayName: userId }),
  });
  const data = await res.json().catch(() => ({}));
  if (loginOut) loginOut.textContent = JSON.stringify(data, null, 2);
  if (data.token) {
    mobileJwt = data.token;
    localStorage.setItem("mobile_jwt", mobileJwt);
    renderLoginOut();
  }
});

document.getElementById("preview")?.addEventListener("click", async () => {
  const raw = ($("#token")?.value || "").trim();
  if (!raw) return alert("Paste token");
  let t = raw;
  try {
    const u = new URL(raw);
    const p = u.searchParams.get("token");
    if (p) t = p;
  } catch {}
  const tokenEl = $("#token");
  if (tokenEl) tokenEl.value = t;
  if (previewOut) previewOut.textContent = "Loading…";
  const res = await fetch(`/api/auth/qr/preview?token=${encodeURIComponent(t)}`);
  const data = await res.json().catch(() => ({}));
  if (previewOut) previewOut.textContent = JSON.stringify(data, null, 2);
  if (data.status === "pending" || res.ok) {
    if (confirm && details) {
      details.innerHTML = "";
      const items = [
        `Status: ${data.status || "unknown"}`,
        `Created: ${data.createdAt ? new Date(data.createdAt).toLocaleString() : "unknown"}`,
        `Expires: ${data.expiresAt ? new Date(data.expiresAt).toLocaleString() : "unknown"} (${data.expiresAt ? Math.round((data.expiresAt - Date.now()) / 1000) : "?"}s left)`,
        `Token: ${data.tokenPreview || t.slice(0, 8) + "…"}`,
        "Location / fingerprint comes from server (city/country, UA, time). Verify it matches your desktop.",
      ];
      items.forEach((txt) => {
        const li = document.createElement("li");
        li.textContent = txt;
        details.appendChild(li);
      });
      confirm.style.display = "block";
      const ack = $("#ack");
      const approveBtn = $("#approve");
      if (ack && approveBtn) approveBtn.disabled = !ack.checked;
    }
  } else {
    if (confirm) confirm.style.display = "none";
    if (previewOut) previewOut.textContent += "\nNot pending — cannot approve.";
  }
});

document.getElementById("ack")?.addEventListener("change", (e) => {
  const approveBtn = $("#approve");
  if (approveBtn) approveBtn.disabled = !e.target.checked;
});

document.getElementById("approve")?.addEventListener("click", async () => {
  const token = ($("#token")?.value || "").trim();
  if (!mobileJwt) return alert("Mint a mobile session first (Step 1)");
  const res = await fetch("/api/auth/mobile/approve", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` },
    body: JSON.stringify({ token, action: "approve" }),
  });
  const data = await res.json().catch(() => ({}));
  alert(`Approve: ${res.status} ${JSON.stringify(data)}`);
  if (previewOut) previewOut.textContent = JSON.stringify(data, null, 2);
});

document.getElementById("deny")?.addEventListener("click", async () => {
  const token = ($("#token")?.value || "").trim();
  if (!mobileJwt) return alert("Mint a mobile session first");
  const res = await fetch("/api/auth/mobile/approve", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${mobileJwt}` },
    body: JSON.stringify({ token, action: "deny" }),
  });
  const data = await res.json().catch(() => ({}));
  alert(`Deny: ${res.status} ${JSON.stringify(data)}`);
  if (previewOut) previewOut.textContent = JSON.stringify(data, null, 2);
});

document.getElementById("paste")?.addEventListener("click", async () => {
  try {
    const t = await navigator.clipboard.readText();
    const el = $("#token");
    if (el) el.value = t.trim();
  } catch {
    alert("Clipboard read failed — paste manually");
  }
});

// Autofill from ?token= when QR link opened on mobile
try {
  const u = new URL(location.href);
  const p = u.searchParams.get("token");
  if (p) {
    const el = $("#token");
    if (el) el.value = p;
  }
} catch {}
