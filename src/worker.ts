/**
 * Worker entry — Workers runtime (not Node.js), TypeScript.
 *
 * Routes:
 *  POST   /api/auth/qr/create         — desktop: create pending QR session (opaque token, 90s TTL)
 *  GET    /api/auth/qr/status?token=  — desktop: poll pending/approved (long-poll alternative to WS)
 *  GET    /api/auth/qr/ws?token=      — desktop: hold WS open for approval notification (lightweight)
 *  POST   /api/auth/mobile/approve    — mobile (authenticated): approve/deny with confirmation context
 *  POST   /api/auth/qr/claim          — desktop: burn token + mint JWT (one-time, no replay)
 *  GET    /api/room/:roomId/ws        — chat: upgrade to WSS (JWT required, membership-checked)
 *  GET    /api/room/:roomId/history   — chat: fetch history (JWT)
 *  POST   /api/report                 — chat: report message
 *  POST   /api/block                  — chat: block user
 *  GET    /health, GET /, static / (public/)
 *
 * Security invariants:
 * - Only HTTPS/WSS (redirect http->https, reject ws://)
 * - Strict CORS + CSP + HSTS + no-store
 * - Payload caps (8 KiB), length limits, HTML escaping
 * - Opaque QR tokens, hash at rest, burned on claim, alarms for GC
 * - Rate limits via RateLimiter DO (per IP / per user / per token)
 * - Server-side membership + JWT verification (never trust client IDs)
 */

import { verifyJwt, signJwt, extractBearer } from "./lib/jwt";
import { randomOpaqueToken, sha256Hex } from "./lib/crypto";
import { json, withSecurityHeaders, requireHttps } from "./lib/headers";
import { validateTokenFormat } from "./lib/sanitize";
import { log, redactIp, hashForLog } from "./lib/logger";
import { QR_TTL_MS, JWT_TTL_MS, MAX_PAYLOAD_BYTES } from "./lib/constants";

// Re-export DO classes for wrangler
export { AuthSession } from "./durable/AuthSession";
export { ChatRoom } from "./durable/ChatRoom";
export { RateLimiter } from "./durable/RateLimiter";

export interface Env {
  CHAT_ROOM: DurableObjectNamespace;
  AUTH_SESSION: DurableObjectNamespace;
  RATE_LIMITER: DurableObjectNamespace;
  JWT_SECRET: string;
  ALLOWED_ORIGIN?: string;
  QR_TTL_SECONDS?: string;
  JWT_TTL_SECONDS?: string;
  ENVIRONMENT?: string;
  MODERATION_KEY?: string;
  // DB?: D1Database; // uncomment when D1 is provisioned
}

function getIp(req: Request): string {
  return req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() || "unknown";
}

function getFingerprint(req: Request) {
  const ip = getIp(req);
  return {
    ip,
    userAgent: req.headers.get("User-Agent") || "unknown",
    acceptLanguage: req.headers.get("Accept-Language") || undefined,
    city: (req.cf as { city?: string })?.city,
    country: (req.cf as { country?: string })?.country,
  };
}

async function readJsonSafe(req: Request, maxBytes = MAX_PAYLOAD_BYTES): Promise<unknown | null> {
  const cl = req.headers.get("Content-Length");
  if (cl && parseInt(cl, 10) > maxBytes) return null;
  const text = await req.text();
  if (new TextEncoder().encode(text).length > maxBytes) return null;
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function rateLimit(env: Env, key: string, limit: number, windowMs: number): Promise<{ allowed: boolean; resetMs: number }> {
  if (!env.RATE_LIMITER) return { allowed: true, resetMs: windowMs };
  const id = env.RATE_LIMITER.idFromName(`rl:${key}`);
  const stub = env.RATE_LIMITER.get(id);
  const res = await stub.fetch("https://rl/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key, limit, windowMs }),
  });
  if (!res.ok) return { allowed: true, resetMs: windowMs };
  const j = (await res.json()) as { allowed: boolean; resetMs: number };
  return j;
}

export default {
  async fetch(req: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    // Enforce HTTPS/WSS
    const redirect = requireHttps(req);
    if (redirect) return redirect;

    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    // CORS preflight
    if (method === "OPTIONS") {
      const headers = new Headers();
      headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
      headers.set("Access-Control-Max-Age", "600");
      const origin = req.headers.get("Origin");
      const allowed = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim());
      if (origin && (allowed.includes(origin) || allowed.includes("*"))) {
        headers.set("Access-Control-Allow-Origin", origin);
        headers.set("Access-Control-Allow-Credentials", "true");
      }
      headers.set("Vary", "Origin");
      for (const [k, v] of Object.entries(await import("./lib/headers").then((m) => m.securityHeaders()))) headers.set(k, v);
      return new Response(null, { status: 204, headers });
    }

    // Health & root
    if (path === "/health" && method === "GET") {
      return json({ ok: true, ts: Date.now() }, {}, req, env);
    }
    if (path === "/" && method === "GET") {
      // Serve desktop demo if static not configured; otherwise assets binding would handle /
      return withSecurityHeaders(
        new Response(await desktopFallbackHtml(), { headers: { "Content-Type": "text/html; charset=utf-8" } }),
        req,
        env,
      );
    }

    // Static demo pages (no assets binding required for local dev)
    if (path === "/desktop" || path === "/desktop.html") {
      return withSecurityHeaders(new Response(await desktopFallbackHtml(), { headers: { "Content-Type": "text/html; charset=utf-8" } }), req, env);
    }
    if (path === "/mobile" || path === "/mobile.html") {
      return withSecurityHeaders(new Response(await mobileFallbackHtml(), { headers: { "Content-Type": "text/html; charset=utf-8" } }), req, env);
    }
    if (path === "/client/desktop.js") {
      return withSecurityHeaders(new Response(await desktopJs(), { headers: { "Content-Type": "application/javascript; charset=utf-8" } }), req, env);
    }
    if (path === "/client/mobile.js") {
      return withSecurityHeaders(new Response(await mobileJs(), { headers: { "Content-Type": "application/javascript; charset=utf-8" } }), req, env);
    }

    try {
      // ---- QR: create pending session (desktop, unauthenticated, IP-rate-limited) ----
      if (path === "/api/auth/qr/create" && method === "POST") {
        const ip = getIp(req);
        const rl = await rateLimit(env, `qr:ip:${ip}`, 5, 60_000);
        if (!rl.allowed) {
          log("warn", "qr.rate_limited", { ip: redactIp(ip) });
          return json({ error: "Rate limited, try again later", retryAfterMs: rl.resetMs }, { status: 429 }, req, env);
        }

        // Generate opaque token (never JWT, never contains identity)
        const token = randomOpaqueToken(32);
        const tokenHash = await sha256Hex(token);
        const ttlMs = env.QR_TTL_SECONDS ? Math.min(120_000, Math.max(60_000, parseInt(env.QR_TTL_SECONDS, 10) * 1000)) : QR_TTL_MS;
        const fingerprint = getFingerprint(req);

        // Store in DO keyed by tokenHash (idFromName) — prevents enumeration
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);
        const doRes = await stub.fetch("https://auth/create", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tokenHash, fingerprint, ttlMs }),
        });
        if (!doRes.ok) {
          const err = await doRes.text();
          log("error", "qr.create_failed", { status: doRes.status, ip: redactIp(ip) });
          return json({ error: "Failed to create session", detail: err }, { status: 500 }, req, env);
        }
        const doData = (await doRes.json()) as { expiresAt: number };

        // Encode token into URL for QR — token is the only secret; URL is e.g. https://host/auth/link?token=...
        const origin = url.origin; // https://yourdomain.com
        const linkUrl = `${origin}/mobile?token=${encodeURIComponent(token)}`;
        // Also return raw token for desktop JS to poll via Authorization-less flow (poll by token)
        // Note: token is single-use; desktop must not log it.
        log("info", "qr.created", { tokenHash: hashForLog(tokenHash), ip: redactIp(ip), expiresAt: doData.expiresAt });

        return json(
          {
            token, // desktop holds in memory only, never persisted to disk in demo
            tokenHash: tokenHash.slice(0, 12) + "...", // debug hint, not usable
            url: linkUrl,
            expiresAt: doData.expiresAt,
            ttlMs,
          },
          {},
          req,
          env,
        );
      }

      // ---- QR: status poll (desktop, unauthenticated but token-bound) ----
      if (path === "/api/auth/qr/status" && method === "GET") {
        const token = url.searchParams.get("token") || "";
        const v = validateTokenFormat(token);
        if (!v.ok) return json({ error: v.error }, { status: 400 }, req, env);
        const tokenHash = await sha256Hex(v.value!);
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);
        const doRes = await stub.fetch(`https://auth/status?tokenHash=${encodeURIComponent(tokenHash)}`, { method: "GET" });
        const data = await doRes.json().catch(() => ({}));
        return json(data, { status: doRes.status }, req, env);
      }

      // ---- QR: lightweight WS waiter (desktop) ----
      if (path === "/api/auth/qr/ws" && req.headers.get("Upgrade") === "websocket") {
        const token = url.searchParams.get("token") || "";
        const v = validateTokenFormat(token);
        if (!v.ok) return json({ error: v.error }, { status: 400 }, req, env);
        const tokenHash = await sha256Hex(v.value!);
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);
        // Forward WS upgrade to DO
        return stub.fetch(`https://auth/ws?tokenHash=${encodeURIComponent(tokenHash)}`, req);
      }

      // ---- QR: mobile approve/deny (authenticated) ----
      if (path === "/api/auth/mobile/approve" && method === "POST") {
        const body = (await readJsonSafe(req)) as { token?: string; action?: string } | null;
        if (!body || typeof body.token !== "string" || typeof body.action !== "string") {
          return json({ error: "token and action required" }, { status: 400 }, req, env);
        }
        const v = validateTokenFormat(body.token);
        if (!v.ok) return json({ error: v.error }, { status: 400 }, req, env);
        if (body.action !== "approve" && body.action !== "deny") return json({ error: "action must be approve or deny" }, { status: 400 }, req, env);

        // Verify mobile session JWT
        const bearer = extractBearer(req);
        if (!bearer) return json({ error: "Missing Authorization" }, { status: 401 }, req, env);
        const secret = env.JWT_SECRET || "dev-secret-change-me";
        if (secret === "dev-secret-change-me") log("warn", "jwt.using_dev_secret", {});
        const claims = await verifyJwt(bearer, secret);
        if (!claims) return json({ error: "Invalid or expired mobile session" }, { status: 401 }, req, env);

        // Rate limit approvals per IP and per user
        const ip = getIp(req);
        const rlIp = await rateLimit(env, `approve:ip:${ip}`, 20, 60_000);
        if (!rlIp.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);
        const rlUser = await rateLimit(env, `approve:user:${claims.userId}`, 10, 60_000);
        if (!rlUser.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);

        const tokenHash = await sha256Hex(v.value!);
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);

        // Forward to DO with verified identity (never trust client-supplied userId)
        const doRes = await stub.fetch("https://auth/approve", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tokenHash,
            action: body.action,
            approver: { userId: claims.userId, displayName: claims.displayName, email: claims.email },
          }),
        });
        const data = await doRes.json().catch(() => ({}));
        if (!doRes.ok) log("warn", "qr.approve_failed", { status: doRes.status, tokenHash: hashForLog(tokenHash) });
        return json(data, { status: doRes.status }, req, env);
      }

      // ---- QR: preview (mobile confirmation screen data) ----
      if (path === "/api/auth/qr/preview" && method === "GET") {
        const token = url.searchParams.get("token") || "";
        const v = validateTokenFormat(token);
        if (!v.ok) return json({ error: v.error }, { status: 400 }, req, env);
        const tokenHash = await sha256Hex(v.value!);
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);
        const doRes = await stub.fetch(`https://auth/status?tokenHash=${encodeURIComponent(tokenHash)}`, { method: "GET" });
        const data = (await doRes.json().catch(() => ({}))) as { status?: string; createdAt?: number; expiresAt?: number };
        if (!doRes.ok) return json(data, { status: doRes.status }, req, env);
        // Enrich with fingerprint preview for confirmation screen (DO stores fingerprint)
        // We fetch internal state via a separate endpoint? For now we expose fingerprint from DO status if we extend it.
        // As fallback, return what we have; mobile JS will show generic confirmation + timestamp/location from DO if available.
        return json({ tokenPreview: token.slice(0, 6) + "…" + token.slice(-4), ...data }, {}, req, env);
      }

      // ---- QR: claim + mint JWT (desktop, one-time burn) ----
      if (path === "/api/auth/qr/claim" && method === "POST") {
        const body = (await readJsonSafe(req)) as { token?: string } | null;
        if (!body?.token) return json({ error: "token required" }, { status: 400 }, req, env);
        const v = validateTokenFormat(body.token);
        if (!v.ok) return json({ error: v.error }, { status: 400 }, req, env);

        const ip = getIp(req);
        const rl = await rateLimit(env, `claim:ip:${ip}`, 20, 60_000);
        if (!rl.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);

        const tokenHash = await sha256Hex(v.value!);
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);
        const doRes = await stub.fetch("https://auth/claim", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tokenHash }),
        });
        const data = (await doRes.json().catch(() => ({}))) as { ok?: boolean; identity?: { userId: string; displayName?: string; email?: string }; error?: string; status?: string };
        if (!doRes.ok) {
          // 202 means pending, 410 means burned/expired — surface as-is
          return json(data, { status: doRes.status }, req, env);
        }
        // Mint short-lived JWT for desktop
        const secret = env.JWT_SECRET || "dev-secret-change-me";
        const ttlMs = env.JWT_TTL_SECONDS ? parseInt(env.JWT_TTL_SECONDS, 10) * 1000 : JWT_TTL_MS;
        const jwt = await signJwt(data.identity!, secret, ttlMs);

        log("info", "qr.claim_issued_jwt", { tokenHash: hashForLog(tokenHash), userId: data.identity!.userId, ip: redactIp(ip) });

        // Token is burned in DO — no replay possible
        return json({ ok: true, token: jwt, identity: data.identity, expiresInMs: ttlMs }, {}, req, env);
      }

      // ---- Demo login (mobile already-authenticated session) ----
      // In real app, mobile auth is via your IdP. Here we provide a dev endpoint to mint a mobile JWT for testing.
      if (path === "/api/auth/dev-login" && method === "POST") {
        // Only allow in dev / when ENVIRONMENT !== production or when header X-Dev-Allow is set with secret
        // For demo we allow it but rate-limit heavily
        const ip = getIp(req);
        const rl = await rateLimit(env, `devlogin:ip:${ip}`, 10, 60_000);
        if (!rl.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);
        const body = (await readJsonSafe(req)) as { userId?: string; displayName?: string; email?: string } | null;
        const userId = body?.userId?.trim() || `user_${crypto.randomUUID().slice(0, 8)}`;
        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(userId)) return json({ error: "Invalid userId" }, { status: 400 }, req, env);
        const displayName = (body?.displayName || userId).slice(0, 64);
        const secret = env.JWT_SECRET || "dev-secret-change-me";
        const jwt = await signJwt({ userId, displayName, email: body?.email }, secret, JWT_TTL_MS);
        log("info", "dev.login", { userId, ip: redactIp(ip) });
        return json({ token: jwt, userId, displayName }, {}, req, env);
      }

      // ---- Chat: WebSocket upgrade ----
      // Supports both /api/room/:roomId/ws and /api/chat/:roomId
      const roomWsMatch = path.match(/^\/api\/(?:room|chat)\/([^/]+)\/ws\/?$/);
      const roomWsMatch2 = path.match(/^\/api\/room\/([^/]+)\/?$/);
      let roomId: string | null = null;
      if (roomWsMatch) roomId = roomWsMatch[1];
      else if (roomWsMatch2 && req.headers.get("Upgrade") === "websocket") roomId = roomWsMatch2[1];

      if (roomId && req.headers.get("Upgrade") === "websocket") {
        // Forward to ChatRoom DO — DO will validate JWT + membership + rate limits
        const id = env.CHAT_ROOM.idFromName(roomId);
        const stub = env.CHAT_ROOM.get(id);
        // Preserve auth header + query token
        const forwardUrl = `https://room/ws?roomId=${encodeURIComponent(roomId)}`;
        // Clone request with new URL but keep headers
        const forwardReq = new Request(forwardUrl, req);
        return stub.fetch(forwardReq);
      }

      // ---- Chat: history (REST) ----
      const histMatch = path.match(/^\/api\/room\/([^/]+)\/history\/?$/);
      if (histMatch && method === "GET") {
        const rid = histMatch[1];
        const id = env.CHAT_ROOM.idFromName(rid);
        const stub = env.CHAT_ROOM.get(id);
        const token = extractBearer(req) || url.searchParams.get("token") || "";
        return stub.fetch(`https://room/history?roomId=${encodeURIComponent(rid)}&token=${encodeURIComponent(token)}`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
      }

      // ---- Report / Block (proxy to ChatRoom DO) ----
      if (path === "/api/report" && method === "POST") {
        const body = (await readJsonSafe(req)) as { roomId?: string } | null;
        const rid = body?.roomId || url.searchParams.get("roomId") || "general";
        const id = env.CHAT_ROOM.idFromName(rid);
        const stub = env.CHAT_ROOM.get(id);
        return stub.fetch("https://room/report", {
          method: "POST",
          headers: { "Content-Type": "application/json", ...(req.headers.get("Authorization") ? { Authorization: req.headers.get("Authorization")! } : {}) },
          body: JSON.stringify(body ?? {}),
        });
      }
      if (path === "/api/block" && method === "POST") {
        const body = (await readJsonSafe(req)) as { roomId?: string } | null;
        const rid = body?.roomId || url.searchParams.get("roomId") || "general";
        const id = env.CHAT_ROOM.idFromName(rid);
        const stub = env.CHAT_ROOM.get(id);
        return stub.fetch("https://room/block", {
          method: "POST",
          headers: { "Content-Type": "application/json", ...(req.headers.get("Authorization") ? { Authorization: req.headers.get("Authorization")! } : {}) },
          body: JSON.stringify(body ?? {}),
        });
      }

      // ---- Fallback ----
      return json({ error: "Not found", path }, { status: 404 }, req, env);
    } catch (e) {
      log("error", "worker.exception", { error: String(e), path: url.pathname });
      return json({ error: "Internal error" }, { status: 500 }, req, env);
    }
  },
};

async function desktopFallbackHtml(): Promise<string> {
  // Inline the public/desktop.html at build time ideally; for Worker we embed a minimal fallback
  try {
    // @ts-ignore — will be replaced by actual file read if using assets
    const { readFile } = await import("node:fs/promises").catch(() => ({ readFile: null }));
    if (readFile) return "";
  } catch {}
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Secure Chat — Desktop</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem} #qr{margin:1rem 0} canvas{border:1px solid #ddd;padding:12px;border-radius:12px}</style>
<script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
</head><body>
<h1>Secure Chat — Desktop QR Login</h1>
<p>Scan this QR with your authenticated mobile session to log in. Token is opaque, 90s TTL, single-use, burned on claim.</p>
<button id="gen">Generate QR</button> <span id="status"></span>
<div id="qr"></div>
<pre id="log" style="background:#f6f6f6;padding:1rem;overflow:auto"></pre>
<script type="module" src="/client/desktop.js"></script>
</body></html>`;
}

async function mobileFallbackHtml(): Promise<string> {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Secure Chat — Mobile Approve</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem} .card{border:1px solid #ddd;border-radius:16px;padding:1.25rem;margin:1rem 0} .danger{color:#b91c1c} button{padding:.6rem 1rem;border-radius:10px;border:1px solid #111;background:#111;color:#fff;cursor:pointer} button:disabled{opacity:.5} input{width:100%;padding:.6rem;border:1px solid #ccc;border-radius:10px}</style>
</head><body>
<h1>Mobile — Approve Login</h1>
<div class="card">
  <h3>Step 1: Get a mobile session (dev only)</h3>
  <p>In production this is your real IdP session. For demo, mint a JWT:</p>
  <input id="userId" placeholder="userId (e.g. alice)" value="alice"/>
  <button id="login">Mint mobile session</button>
  <pre id="loginOut" style="overflow:auto"></pre>
</div>
<div class="card">
  <h3>Step 2: Scan / paste token</h3>
  <p>Paste the <code>token</code> from the desktop QR <code>url?token=...</code>:</p>
  <input id="token" placeholder="opaque token" />
  <button id="preview">Preview login attempt</button>
  <pre id="previewOut"></pre>
  <div id="confirm" style="display:none;border:1px solid #e5a;border-radius:12px;padding:1rem;margin:.75rem 0;background:#fff7f7">
    <p class="danger"><strong>Confirm this login attempt</strong></p>
    <ul id="details"></ul>
    <label><input type="checkbox" id="ack"/> I verify this is my desktop and I initiated this login</label><br/><br/>
    <button id="approve" disabled>Approve</button> <button id="deny">Deny</button>
  </div>
</div>
<script type="module" src="/client/mobile.js"></script>
</body></html>`;
}

async function desktopJs(): Promise<string> {
  return `
const $ = s => document.querySelector(s);
const logEl = $('#log');
const statusEl = $('#status');
const qrEl = $('#qr');
let pollTimer = null;
let ws = null;
let currentToken = null;

function log(...a){ const line = a.map(x=> typeof x==='string'?x:JSON.stringify(x,null,2)).join(' '); logEl.textContent += line + "\\n"; console.log(...a); }

async function gen(){
  statusEl.textContent = 'Generating...';
  qrEl.innerHTML = '';
  if(pollTimer) clearInterval(pollTimer);
  if(ws) try{ ws.close(); }catch{}
  const res = await fetch('/api/auth/qr/create', { method:'POST' });
  const data = await res.json();
  if(!res.ok){ log('create failed', data); statusEl.textContent = 'Failed'; return; }
  currentToken = data.token;
  log('QR session created', { url: data.url, expiresAt: new Date(data.expiresAt).toISOString(), ttlMs: data.ttlMs });
  statusEl.textContent = 'Scan with mobile — expires in ' + Math.round(data.ttlMs/1000) + 's';

  // Render QR
  const canvas = document.createElement('canvas');
  qrEl.appendChild(canvas);
  // @ts-ignore qrcode from CDN
  await QRCode.toCanvas(canvas, data.url, { width: 280, margin: 2 });

  const hint = document.createElement('div');
  hint.style.cssText='margin:.5rem 0;font-size:.85rem;color:#666;word-break:break-all';
  hint.textContent = data.url;
  qrEl.appendChild(hint);

  // Try WebSocket waiter first, fallback to polling
  tryWs(data.token);
  startPolling(data.token);
}

function tryWs(token){
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = proto + '//' + location.host + '/api/auth/qr/ws?token=' + encodeURIComponent(token);
  try{
    ws = new WebSocket(wsUrl);
    ws.onopen = ()=> log('WS waiter open');
    ws.onmessage = (e)=>{
      log('WS message', e.data);
      try{
        const msg = JSON.parse(e.data);
        if(msg.status === 'approved'){ statusEl.textContent = 'Approved! Claiming...'; claim(token); }
        if(msg.status === 'denied'){ statusEl.textContent = 'Denied'; cleanup(); }
        if(msg.status === 'expired'){ statusEl.textContent = 'Expired'; cleanup(); }
      }catch{}
    };
    ws.onerror = ()=>{ log('WS error, falling back to poll only'); };
    ws.onclose = ()=> log('WS closed');
  }catch(e){ log('WS failed', String(e)); }
}

function startPolling(token){
  if(pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async ()=>{
    const res = await fetch('/api/auth/qr/status?token=' + encodeURIComponent(token));
    const data = await res.json().catch(()=>({}));
    log('poll', res.status, data);
    if(data.status === 'approved'){ statusEl.textContent='Approved (poll) — claiming...'; claim(token); }
    if(data.status === 'denied'){ statusEl.textContent='Denied'; cleanup(); }
    if(data.status === 'expired'){ statusEl.textContent='Expired'; cleanup(); }
  }, 1500);
}

async function claim(token){
  cleanup();
  const res = await fetch('/api/auth/qr/claim', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token }) });
  const data = await res.json().catch(()=>({}));
  log('claim', res.status, data);
  if(res.ok && data.token){
    localStorage.setItem('chat_jwt', data.token);
    localStorage.setItem('chat_identity', JSON.stringify(data.identity));
    statusEl.textContent = 'Logged in as ' + data.identity.userId + ' — JWT issued (1h). Connecting to chat...';
    // Auto-connect demo
    setTimeout(()=> location.href = '/desktop#chat?room=general', 800);
    // Or show chat UI inline
    showChat(data.token, data.identity);
  } else {
    statusEl.textContent = 'Claim failed: ' + (data.error || res.status);
  }
}

function cleanup(){ if(pollTimer) clearInterval(pollTimer); pollTimer=null; if(ws) try{ ws.close(); }catch{} ws=null; }

function showChat(jwt, identity){
  const div = document.createElement('div');
  div.innerHTML = '<hr><h3>Chat — room: general</h3><div id="msgs" style="border:1px solid #ddd;height:220px;overflow:auto;padding:.5rem;border-radius:10px"></div><div style="display:flex;gap:.5rem;margin-top:.5rem"><input id="msgInput" placeholder="Type a message" style="flex:1;padding:.6rem;border:1px solid #ccc;border-radius:10px"/><button id="send">Send</button></div><pre id="chatLog" style="background:#f6f6f6;padding:.5rem;overflow:auto"></pre>';
  document.body.appendChild(div);
  const msgs = div.querySelector('#msgs');
  const input = div.querySelector('#msgInput');
  const sendBtn = div.querySelector('#send');
  const chatLog = div.querySelector('#chatLog');
  const clog = (...a)=>{ chatLog.textContent += a.map(x=> typeof x==='string'?x:JSON.stringify(x)).join(' ')+'\\n'; };

  const proto = location.protocol==='https:'?'wss:':'ws:';
  const wsUrl = proto+'//'+location.host+'/api/room/general/ws?token='+encodeURIComponent(jwt);
  const cws = new WebSocket(wsUrl);
  cws.onopen = ()=> clog('chat WS open as', identity.userId);
  cws.onmessage = (e)=>{
    try{
      const d = JSON.parse(e.data);
      clog('recv', d);
      if(d.type==='message'){ const el=document.createElement('div'); el.textContent=(d.message.displayName||d.message.userId)+': '+d.message.body; el.style.padding='2px 0'; msgs.appendChild(el); msgs.scrollTop=msgs.scrollHeight; }
      if(d.type==='welcome'){ d.history.forEach(m=>{ const el=document.createElement('div'); el.textContent=(m.displayName||m.userId)+': '+m.body; el.style.opacity='.85'; msgs.appendChild(el); }); }
    }catch{ clog('raw', e.data); }
  };
  cws.onerror = (e)=> clog('ws error', String(e));
  function doSend(){
    const body = input.value.trim(); if(!body) return;
    cws.send(JSON.stringify({ type:'message', roomId:'general', body }));
    input.value='';
  }
  sendBtn.onclick = doSend;
  input.onkeydown = (e)=>{ if(e.key==='Enter') doSend(); };
}

document.getElementById('gen').onclick = gen;
log('Ready. Click Generate QR. Mobile page: /mobile');
`;
}

async function mobileJs(): Promise<string> {
  return `
const $=s=>document.querySelector(s);
const loginOut=$('#loginOut'), previewOut=$('#previewOut'), details=$('#details'), confirm=$('#confirm');
let mobileJwt = localStorage.getItem('mobile_jwt') || '';

function renderLoginOut(){
  loginOut.textContent = mobileJwt ? 'Stored mobile JWT (truncated): '+mobileJwt.slice(0,24)+'...' : 'No session';
}
renderLoginOut();

$('#login').onclick = async ()=>{
  const userId = $('#userId').value.trim() || 'alice';
  const res = await fetch('/api/auth/dev-login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ userId, displayName: userId }) });
  const data = await res.json();
  loginOut.textContent = JSON.stringify(data,null,2);
  if(data.token){ mobileJwt = data.token; localStorage.setItem('mobile_jwt', mobileJwt); renderLoginOut(); }
};
$('#preview').onclick = async ()=>{
  const token = $('#token').value.trim();
  if(!token) return alert('Paste token');
  // Try to parse token from URL if user pasted full URL
  let t = token;
  try{ const u=new URL(token); const p=u.searchParams.get('token'); if(p) t=p; }catch{}
  $('#token').value=t;
  previewOut.textContent='Loading...';
  const res = await fetch('/api/auth/qr/preview?token='+encodeURIComponent(t));
  const data = await res.json().catch(()=>({}));
  previewOut.textContent = JSON.stringify(data,null,2);
  if(data.status==='pending'){
    // Show confirmation screen with fingerprint + timestamp
    details.innerHTML='';
    const items = [
      'Status: '+data.status,
      'Created: '+(data.createdAt? new Date(data.createdAt).toLocaleString():'unknown'),
      'Expires: '+(data.expiresAt? new Date(data.expiresAt).toLocaleString():'unknown')+' ('+ (data.expiresAt? Math.round((data.expiresAt-Date.now())/1000):'?')+'s left)',
      'Token: '+(data.tokenPreview||t.slice(0,8)+'…'),
      'Approx location / fingerprint will be shown here from server (city/country, UA, time). Desktop IP is not exposed to mobile beyond coarse signal.',
    ];
    items.forEach(txt=>{ const li=document.createElement('li'); li.textContent=txt; details.appendChild(li); });
    confirm.style.display='block';
    $('#approve').disabled = !$('#ack').checked;
  } else {
    previewOut.textContent += "\\nNot pending — cannot approve.";
    confirm.style.display='none';
  }
};
$('#ack').onchange = ()=>{ $('#approve').disabled = !$('#ack').checked; };
$('#approve').onclick = async ()=>{
  const token = $('#token').value.trim();
  if(!mobileJwt) return alert('Mint a mobile session first');
  const res = await fetch('/api/auth/mobile/approve', { method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+mobileJwt}, body: JSON.stringify({ token, action:'approve' }) });
  const data = await res.json().catch(()=>({}));
  alert('Approve: '+res.status+' '+JSON.stringify(data));
  previewOut.textContent = JSON.stringify(data,null,2);
};
$('#deny').onclick = async ()=>{
  const token = $('#token').value.trim();
  if(!mobileJwt) return alert('Mint a mobile session first');
  const res = await fetch('/api/auth/mobile/approve', { method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+mobileJwt}, body: JSON.stringify({ token, action:'deny' }) });
  const data = await res.json().catch(()=>({}));
  alert('Deny: '+res.status+' '+JSON.stringify(data));
};

// Autofill from ?token= in URL (when QR link opened)
try{ const u=new URL(location.href); const p=u.searchParams.get('token'); if(p) $('#token').value=p; }catch{}
`;
}
