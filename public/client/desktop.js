// Desktop QR + polling/WS claim flow — example client, not a framework
const $ = (s) => document.querySelector(s);
const statusEl = $("#status");
const qrEl = $("#qr");
const linkEl = $("#link");
const linkWrap = $("#linkWrap");
const debugEl = $("#debug");
const msgsEl = $("#msgs");
const meEl = $("#me");
const inputEl = $("#msgInput");

let pollTimer = null;
let ws = null;
let chatWs = null;
let currentToken = null;
let jwt = localStorage.getItem("chat_jwt") || "";
let identity = JSON.parse(localStorage.getItem("chat_identity") || "null");

function log(...a) {
  const line = a.map((x) => (typeof x === "string" ? x : JSON.stringify(x, null, 2))).join(" ");
  if (debugEl) debugEl.textContent += line + "\n";
  console.log(...a);
}
function setStatus(t, cls) {
  if (!statusEl) return;
  statusEl.textContent = t;
  statusEl.style.color = cls || "";
}

function renderMe() {
  if (!meEl) return;
  if (jwt && identity) meEl.textContent = `Logged in as ${identity.userId} (${identity.displayName || ""}) — JWT valid ~1h`;
  else meEl.textContent = "Not logged in — generate a QR and approve on mobile";
}
renderMe();

async function gen() {
  setStatus("Generating…");
  if (qrEl) qrEl.innerHTML = '<span class="muted">Creating session…</span>';
  if (pollTimer) clearInterval(pollTimer);
  if (ws) try { ws.close(); } catch {}
  const res = await fetch("/api/auth/qr/create", { method: "POST" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    log("create failed", data);
    setStatus("Failed: " + (data.error || res.status), "crimson");
    return;
  }
  currentToken = data.token;
  log("QR created", { url: data.url, expiresAt: new Date(data.expiresAt).toISOString(), ttlMs: data.ttlMs });
  setStatus(`Scan with mobile — expires in ${Math.round(data.ttlMs / 1000)}s`);

  // Render QR
  if (qrEl) {
    qrEl.innerHTML = "";
    const canvas = document.createElement("canvas");
    qrEl.appendChild(canvas);
    // eslint-disable-next-line no-undef
    if (typeof QRCode !== "undefined") await QRCode.toCanvas(canvas, data.url, { width: 280, margin: 2 });
    else qrEl.textContent = data.url;
  }
  if (linkEl && linkWrap) {
    linkEl.textContent = data.url;
    linkWrap.style.display = "block";
  }

  tryWs(data.token);
  startPolling(data.token);
}

function tryWs(token) {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${proto}//${location.host}/api/auth/qr/ws?token=${encodeURIComponent(token)}`;
  try {
    ws = new WebSocket(wsUrl);
    ws.onopen = () => log("WS waiter open");
    ws.onmessage = (e) => {
      log("WS waiter", e.data);
      try {
        const msg = JSON.parse(e.data);
        if (msg.status === "approved") {
          setStatus("Approved! Claiming…", "green");
          claim(token);
        }
        if (msg.status === "denied") {
          setStatus("Denied", "crimson");
          cleanup();
        }
        if (msg.status === "expired") {
          setStatus("Expired", "crimson");
          cleanup();
        }
      } catch {}
    };
    ws.onerror = () => log("WS waiter error — polling still active");
    ws.onclose = () => log("WS waiter closed");
  } catch (e) {
    log("WS waiter failed", String(e));
  }
}

function startPolling(token) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const res = await fetch(`/api/auth/qr/status?token=${encodeURIComponent(token)}`);
    const data = await res.json().catch(() => ({}));
    log("poll", res.status, data);
    if (data.status === "approved") {
      setStatus("Approved (poll) — claiming…", "green");
      claim(token);
    }
    if (data.status === "denied") {
      setStatus("Denied", "crimson");
      cleanup();
    }
    if (data.status === "expired") {
      setStatus("Expired", "crimson");
      cleanup();
    }
  }, 1500);
}

async function claim(token) {
  cleanup();
  const res = await fetch("/api/auth/qr/claim", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  const data = await res.json().catch(() => ({}));
  log("claim", res.status, data);
  if (res.ok && data.token) {
    jwt = data.token;
    identity = data.identity;
    localStorage.setItem("chat_jwt", jwt);
    localStorage.setItem("chat_identity", JSON.stringify(identity));
    renderMe();
    setStatus(`Logged in as ${identity.userId} — JWT issued (1h)`, "green");
    connectChat("general");
  } else {
    setStatus("Claim failed: " + (data.error || res.status), "crimson");
  }
}

function cleanup() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  if (ws) try { ws.close(); } catch {}
  ws = null;
}

function connectChat(roomId = "general") {
  if (chatWs) try { chatWs.close(); } catch {}
  if (!jwt) {
    log("Cannot connect — no JWT");
    return;
  }
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${proto}//${location.host}/api/room/${encodeURIComponent(roomId)}/ws?token=${encodeURIComponent(jwt)}`;
  chatWs = new WebSocket(wsUrl);
  chatWs.onopen = () => {
    log("chat WS open", roomId, identity?.userId);
    appendSystem(`Connected to #${roomId} as ${identity?.userId}`);
  };
  chatWs.onmessage = (e) => {
    try {
      const d = JSON.parse(e.data);
      log("chat recv", d);
      if (d.type === "welcome") {
        if (d.history?.length) d.history.forEach((m) => appendMsg(m));
        else appendSystem("No history yet — say hello!");
      } else if (d.type === "message") {
        appendMsg(d.message);
      } else if (d.type === "presence") {
        appendSystem(`${d.userId} ${d.event}ed`);
      } else if (d.type === "moderation") {
        appendSystem(`Blocked: ${d.reason}`, "bad");
      } else if (d.type === "error") {
        appendSystem(`Error: ${d.error}`, "bad");
      }
    } catch {
      log("chat raw", e.data);
    }
  };
  chatWs.onclose = () => appendSystem("Disconnected — reload to reconnect");
  chatWs.onerror = () => appendSystem("WebSocket error", "bad");
}

function appendMsg(m) {
  if (!msgsEl) return;
  const div = document.createElement("div");
  div.className = "msg";
  const when = new Date(m.ts).toLocaleTimeString();
  const flagged = m.flagged ? " ⚑" : "";
  div.textContent = `[${when}] ${m.displayName || m.userId}: ${m.body}${flagged}`;
  if (m.flagged) div.style.color = "#f59e0b";
  msgsEl.appendChild(div);
  msgsEl.scrollTop = msgsEl.scrollHeight;
}
function appendSystem(text, cls) {
  if (!msgsEl) return;
  const div = document.createElement("div");
  div.className = "muted";
  div.style.padding = ".25rem 0";
  if (cls === "bad") div.style.color = "#ef4444";
  div.textContent = `— ${text}`;
  msgsEl.appendChild(div);
  msgsEl.scrollTop = msgsEl.scrollHeight;
}

function send() {
  if (!inputEl) return;
  const body = inputEl.value.trim();
  if (!body) return;
  if (!chatWs || chatWs.readyState !== 1) {
    appendSystem("Not connected — generate QR and log in first", "bad");
    return;
  }
  chatWs.send(JSON.stringify({ type: "message", roomId: "general", body }));
  inputEl.value = "";
}

// Wiring
document.getElementById("gen")?.addEventListener("click", gen);
document.getElementById("send")?.addEventListener("click", send);
document.getElementById("historyBtn")?.addEventListener("click", async () => {
  if (!jwt) return alert("Log in first");
  const res = await fetch(`/api/room/general/history?token=${encodeURIComponent(jwt)}`, {
    headers: { Authorization: `Bearer ${jwt}` },
  });
  const data = await res.json().catch(() => ({}));
  log("history", data);
  if (data.messages) {
    if (msgsEl) msgsEl.innerHTML = "";
    data.messages.forEach(appendMsg);
  }
});
document.getElementById("clearBtn")?.addEventListener("click", () => {
  if (msgsEl) msgsEl.innerHTML = "";
});
inputEl?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") send();
});

// Auto-connect if already authed
if (jwt && identity) {
  log("Found existing JWT, auto-connecting...");
  setTimeout(() => connectChat("general"), 500);
}

log("Desktop ready. Click Generate QR. Mobile: /mobile");
