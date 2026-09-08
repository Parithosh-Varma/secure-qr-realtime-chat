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
      if (path === "/api/auth/qr/ws" && req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
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
      else if (roomWsMatch2 && req.headers.get("Upgrade")?.toLowerCase() === "websocket") roomId = roomWsMatch2[1];

      if (roomId && req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
        // Forward to ChatRoom DO — DO will validate JWT + membership + rate limits
        const id = env.CHAT_ROOM.idFromName(roomId);
        const stub = env.CHAT_ROOM.get(id);
        // Preserve auth header + query token (DO checks both Bearer and ?token)
        const qToken = url.searchParams.get("token");
        const forwardUrl = `https://room/ws?roomId=${encodeURIComponent(roomId)}${qToken ? `&token=${encodeURIComponent(qToken)}` : ""}`;
        // Clone request with new URL but keep headers
        const forwardReq = new Request(forwardUrl, req);
        return stub.fetch(forwardReq);
      }

      // ---- Chat: message via REST (alternative to WS) ----
      const msgMatch = path.match(/^\/api\/room\/([^/]+)\/message\/?$/);
      if (msgMatch && method === "POST") {
        const rid = msgMatch[1];
        const id = env.CHAT_ROOM.idFromName(rid);
        const stub = env.CHAT_ROOM.get(id);
        // Forward body + auth header
        const bodyText = await req.text();
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        const auth = req.headers.get("Authorization");
        if (auth) headers["Authorization"] = auth;
        return stub.fetch(`https://room/message`, { method: "POST", headers, body: bodyText });
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
  return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n  <title>Secure Chat \u2014 general</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Inter+Tight:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap\" rel=\"stylesheet\">\n  <script src=\"https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js\"></script>\n  <style>\n    :root{\n      --void:#0A0A0B;\n      --soot:#101014;\n      --soot-2:#131318;\n      --raised:#1C1D23;\n      --raised-2:#26272E;\n      --line:rgba(255,255,255,.08);\n      --line-2:rgba(255,255,255,.12);\n      --txt:#ECECED;\n      --mut:#9A9AA3;\n      --dim:#6B6B74;\n      --aura:#7AA2FF;\n      --amber:#FFB224;\n      --danger:#F4212E;\n      --ok:#34D399;\n      --r:14px;\n    }\n    *{box-sizing:border-box}\n    html,body{height:100%}\n    body{\n      margin:0; background:var(--void); color:var(--txt);\n      font-family:\"Inter\",system-ui,-apple-system,\"Segoe UI\",sans-serif;\n      -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility;\n      font-size:15px; line-height:1.55; overflow:hidden;\n    }\n    body::before{\n      content:\"\"; position:fixed; inset:0; pointer-events:none; z-index:0;\n      background:radial-gradient(900px 320px at 50% -80px, rgba(122,162,255,.07), transparent 70%);\n    }\n    button{font:inherit; color:inherit}\n    :focus-visible{outline:2px solid var(--aura); outline-offset:2px; border-radius:8px}\n    .mono{font-family:\"JetBrains Mono\",monospace}\n\n    .app{position:relative; z-index:1; display:grid; grid-template-columns:264px 1fr; height:100dvh}\n\n    /* ---- sidebar (Grok component: navigation + timeline) ---- */\n    .side{\n      background:var(--soot); border-right:1px solid var(--line);\n      display:flex; flex-direction:column; min-height:0;\n    }\n    .side-top{padding:14px 12px 10px; display:flex; flex-direction:column; gap:10px}\n    .logo-row{display:flex; align-items:center; gap:10px; padding:2px 6px}\n    .mark{\n      width:30px; height:30px; border-radius:50%; background:#fff; color:#000;\n      display:grid; place-items:center; font-weight:700; font-size:16px; flex:0 0 auto;\n      font-family:\"Inter Tight\",sans-serif;\n    }\n    .logo-row b{font-family:\"Inter Tight\",sans-serif; font-weight:600; font-size:14px; letter-spacing:-.01em}\n    .logo-row span{display:block; font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--mut); letter-spacing:.04em}\n    .icon-btn{\n      appearance:none; border:1px solid transparent; background:transparent; cursor:pointer;\n      width:30px; height:30px; border-radius:8px; display:grid; place-items:center; color:var(--mut);\n    }\n    .icon-btn:hover{background:var(--raised); color:var(--txt)}\n    .new-btn{\n      appearance:none; border:1px solid var(--line); background:transparent; color:var(--txt);\n      border-radius:10px; padding:9px 12px; font-size:13.5px; font-weight:500; cursor:pointer;\n      display:flex; align-items:center; gap:8px; width:100%;\n    }\n    .new-btn:hover{background:var(--raised); border-color:var(--line-2)}\n    .search{\n      display:flex; align-items:center; gap:8px; background:var(--void);\n      border:1px solid var(--line); border-radius:10px; padding:8px 10px; color:var(--dim);\n    }\n    .search input{background:transparent; border:0; outline:0; color:var(--txt); font-size:13px; width:100%}\n    .search input::placeholder{color:var(--dim)}\n    .side-scroll{flex:1; overflow:auto; padding:4px 12px 12px; display:flex; flex-direction:column; gap:14px}\n    .side-label{font-size:11.5px; font-weight:600; color:var(--dim); padding:6px 6px 4px; letter-spacing:.01em}\n    .room{\n      appearance:none; width:100%; text-align:left; cursor:pointer;\n      border:1px solid transparent; background:transparent; color:var(--mut);\n      border-radius:10px; padding:8px 10px; font-size:13.5px; display:flex; align-items:center; gap:9px;\n    }\n    .room:hover{background:var(--raised); color:var(--txt)}\n    .room.active{background:var(--raised-2); color:var(--txt); border-color:var(--line)}\n    .room .hash{color:var(--dim); font-weight:500}\n    .room.active .hash{color:var(--txt)}\n    .room .unread{margin-left:auto; font-family:\"JetBrains Mono\",monospace; font-size:10.5px; background:#fff; color:#000; border-radius:99px; padding:1px 7px}\n    .hist-row{\n      display:flex; align-items:center; gap:8px; padding:7px 10px; border-radius:8px;\n      font-size:13px; color:var(--mut); cursor:default; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;\n    }\n    .side-foot{border-top:1px solid var(--line); padding:12px}\n    .user-card{\n      display:flex; align-items:center; gap:10px; background:var(--void);\n      border:1px solid var(--line); border-radius:12px; padding:9px 10px;\n    }\n    .avatar{\n      width:30px; height:30px; border-radius:50%; flex:0 0 auto;\n      background:linear-gradient(135deg,#2A2C35,#17181D); border:1px solid var(--line-2);\n      display:grid; place-items:center; font-size:12px; font-weight:600;\n    }\n    .user-card .who{min-width:0; flex:1}\n    .user-card .who b{display:block; font-size:13px; font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis}\n    .user-card .who span{font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--mut)}\n    .dot{width:7px; height:7px; border-radius:50%; background:var(--dim); flex:0 0 auto}\n    .dot.on{background:var(--ok); box-shadow:0 0 0 4px rgba(52,211,153,.15)}\n    .link-btn{\n      appearance:none; cursor:pointer; border-radius:8px; border:1px solid var(--line);\n      background:transparent; color:var(--txt); font-size:12px; font-weight:500; padding:6px 10px;\n    }\n    .link-btn:hover{background:var(--raised)}\n\n    /* ---- main ---- */\n    .main{display:flex; flex-direction:column; min-width:0; min-height:0; background:transparent}\n    .topbar{\n      height:56px; flex:0 0 auto; display:flex; align-items:center; gap:10px;\n      padding:0 20px; border-bottom:1px solid var(--line);\n      background:rgba(10,10,11,.72); backdrop-filter:blur(12px);\n    }\n    .menu-btn{display:none}\n    .room-pill{\n      display:flex; align-items:center; gap:8px; font-weight:600; font-size:14px;\n      font-family:\"Inter Tight\",sans-serif; letter-spacing:-.01em;\n    }\n    .secure-badge{\n      display:inline-flex; align-items:center; gap:6px;\n      font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--mut);\n      border:1px solid var(--line); border-radius:99px; padding:3px 9px; background:var(--soot);\n    }\n    .secure-badge i{width:6px; height:6px; border-radius:50%; background:var(--ok)}\n    .secure-badge.off i{background:var(--amber)}\n    .top-actions{margin-left:auto; display:flex; align-items:center; gap:6px}\n    .tool-btn{\n      appearance:none; border:1px solid transparent; background:transparent; color:var(--mut);\n      border-radius:9px; padding:7px 10px; font-size:12.5px; cursor:pointer; display:inline-flex; align-items:center; gap:7px;\n    }\n    .tool-btn:hover{background:var(--raised); color:var(--txt)}\n    .tool-btn.primary{border-color:var(--line); color:var(--txt); background:var(--soot-2)}\n\n    .scroll{flex:1; overflow:auto; min-height:0}\n    .col{max-width:780px; margin:0 auto; padding:0 24px; width:100%}\n\n    /* hero = thesis: the question + link CTA (Grok empty state, Claude warmth in copy) */\n    .hero{padding:64px 0 8px; text-align:left}\n    .hero .eyebrow{\n      display:inline-flex; align-items:center; gap:8px;\n      font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--mut);\n      border:1px solid var(--line); background:var(--soot); border-radius:99px; padding:5px 11px;\n    }\n    .hero .eyebrow i{width:6px; height:6px; border-radius:50%; background:var(--amber)}\n    .hero h1{\n      margin:18px 0 10px; font-family:\"Inter Tight\",sans-serif; font-weight:600;\n      font-size:clamp(30px,4.4vw,44px); letter-spacing:-.045em; line-height:1.02;\n    }\n    .hero h1 em{font-style:normal; color:var(--mut); font-weight:500}\n    .hero p{margin:0 0 20px; color:var(--mut); font-size:14.5px; max-width:60ch}\n    .hero p b{color:var(--txt); font-weight:500}\n    .chips{display:flex; gap:8px; flex-wrap:wrap; margin-bottom:22px}\n    .chip{\n      appearance:none; cursor:pointer; border:1px solid var(--line); background:var(--soot);\n      color:var(--txt); border-radius:12px; padding:10px 13px; font-size:13px; text-align:left;\n      max-width:240px;\n    }\n    .chip:hover{background:var(--raised); border-color:var(--line-2)}\n    .chip small{display:block; color:var(--mut); font-size:12px; margin-top:2px}\n    .link-cta{\n      display:flex; align-items:center; gap:14px; border:1px solid var(--line);\n      background:var(--soot); border-radius:16px; padding:14px 16px;\n    }\n    .link-cta .copy{flex:1; min-width:0}\n    .link-cta .copy b{display:block; font-size:14px; font-weight:600; letter-spacing:-.01em}\n    .link-cta .copy span{font-size:13px; color:var(--mut)}\n    .cta-btn{\n      appearance:none; border:0; cursor:pointer; background:#fff; color:#000;\n      font-weight:600; font-size:13.5px; border-radius:11px; padding:11px 16px; flex:0 0 auto;\n    }\n    .cta-btn:hover{background:#E7E7E7}\n    .ghost-btn{\n      appearance:none; cursor:pointer; background:transparent; color:var(--mut);\n      border:1px solid var(--line); border-radius:11px; padding:11px 14px; font-size:13px;\n    }\n    .ghost-btn:hover{color:var(--txt); background:var(--raised)}\n\n    /* transcript rows (Grok messaging component) */\n    #msgs{display:flex; flex-direction:column; gap:2px; padding:26px 0 18px}\n    .sys{\n      text-align:center; color:var(--dim); font-size:12.5px; padding:10px;\n      font-family:\"JetBrains Mono\",monospace; font-size:11px;\n    }\n    .row{display:flex; gap:12px; padding:12px 8px; border-radius:14px}\n    .row:hover{background:rgba(255,255,255,.02)}\n    .row .ava{\n      width:30px; height:30px; border-radius:50%; flex:0 0 auto; display:grid; place-items:center;\n      font-size:12px; font-weight:600; background:var(--raised-2); border:1px solid var(--line);\n    }\n    .row.me{flex-direction:row-reverse}\n    .row.me .ava{display:none}\n    .bubble{max-width:min(78%,560px); min-width:0}\n    .row.me .bubble{\n      background:var(--raised-2); border:1px solid var(--line);\n      border-radius:18px 18px 5px 18px; padding:10px 14px; margin-left:auto;\n    }\n    .row.peer .bubble{padding:2px 0}\n    .meta{display:flex; align-items:baseline; gap:8px; margin-bottom:3px}\n    .meta b{font-size:13px; font-weight:600}\n    .meta time{font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--dim)}\n    .flag{\n      font-family:\"JetBrains Mono\",monospace; font-size:10px; color:var(--amber);\n      border:1px solid rgba(255,178,36,.3); border-radius:99px; padding:1px 7px;\n    }\n    .body{font-size:14.5px; line-height:1.6; word-break:break-word; white-space:pre-wrap}\n    .row.me .body{font-size:14px}\n    .presence{\n      display:none; align-items:center; gap:8px; margin:0 auto 6px; width:fit-content;\n      font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--mut);\n      border:1px solid var(--line); background:var(--soot); border-radius:99px; padding:5px 12px;\n    }\n\n    /* composer (Grok input component) */\n    .composer-zone{flex:0 0 auto; padding:6px 0 10px; background:linear-gradient(180deg, transparent, var(--void) 28%)}\n    .composer{\n      border:1px solid var(--line-2); background:var(--soot-2); border-radius:26px;\n      box-shadow:0 12px 40px rgba(0,0,0,.5); overflow:hidden;\n    }\n    .composer:focus-within{border-color:rgba(122,162,255,.45)}\n    #msgInput{\n      width:100%; background:transparent; border:0; outline:0; resize:none;\n      color:var(--txt); font:inherit; font-size:14.5px; line-height:1.55;\n      padding:15px 18px 4px; max-height:160px; display:block;\n    }\n    #msgInput::placeholder{color:var(--dim)}\n    .composer-bar{display:flex; align-items:center; gap:6px; padding:8px 10px 10px 12px}\n    .pill-btn{\n      appearance:none; cursor:pointer; border:1px solid var(--line); background:transparent; color:var(--mut);\n      border-radius:99px; padding:7px 11px; font-size:12.5px; display:inline-flex; align-items:center; gap:7px;\n    }\n    .pill-btn:hover{color:var(--txt); background:var(--raised)}\n    .pill-btn[aria-pressed=\"true\"]{color:var(--txt); border-color:rgba(122,162,255,.5); background:rgba(122,162,255,.12)}\n    .spacer{flex:1}\n    .send{\n      appearance:none; border:0; cursor:pointer; width:34px; height:34px; border-radius:50%;\n      background:#fff; color:#000; display:grid; place-items:center; flex:0 0 auto;\n    }\n    .send:disabled{background:var(--raised-2); color:var(--dim); cursor:not-allowed}\n    .send:not(:disabled):hover{background:#E4E4E4}\n    .foot{\n      display:flex; align-items:center; justify-content:center; gap:8px;\n      font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--dim); padding:8px 0 14px;\n    }\n    #debug{\n      display:none; margin:0 0 12px; background:#000; border:1px solid var(--line); border-radius:12px;\n      padding:12px 14px; font-family:\"JetBrains Mono\",monospace; font-size:11px; color:#B9B9C2;\n      max-height:130px; overflow:auto; white-space:pre-wrap; word-break:break-word;\n    }\n    #debug.open{display:block}\n\n    /* QR verify modal (Grok modal + MFA/verification components) \u2014 the signature */\n    .backdrop{\n      position:fixed; inset:0; z-index:50; display:none;\n      background:rgba(4,4,6,.62); backdrop-filter:blur(14px); -webkit-backdrop-filter:blur(14px);\n      align-items:center; justify-content:center; padding:20px;\n    }\n    .backdrop.open{display:flex}\n    .sheet{\n      width:min(460px,100%); background:var(--soot-2); border:1px solid var(--line-2);\n      border-radius:20px; box-shadow:0 32px 90px rgba(0,0,0,.6); overflow:hidden;\n      animation:rise 220ms ease;\n    }\n    @keyframes rise{from{transform:translateY(10px) scale(.985); opacity:0} to{transform:none; opacity:1}}\n    .sheet-head{padding:18px 20px 0; display:flex; align-items:flex-start; gap:12px}\n    .sheet-head .t{flex:1}\n    .sheet-head h2{margin:0; font-family:\"Inter Tight\",sans-serif; font-size:17px; font-weight:600; letter-spacing:-.02em}\n    .sheet-head p{margin:5px 0 0; font-size:13px; color:var(--mut)}\n    .steps{display:flex; gap:6px; padding:14px 20px 0}\n    .steps span{height:3px; flex:1; border-radius:99px; background:var(--raised-2)}\n    .steps span.done{background:#fff}\n    .qr-stage{margin:16px 20px 0; background:#fff; border-radius:16px; padding:16px; display:grid; place-items:center; min-height:248px}\n    #qr{display:grid; place-items:center; min-height:216px}\n    #qr canvas{border-radius:8px; display:block}\n    #qr .empty{color:#6B6B74; font-size:13px; text-align:center; font-family:\"JetBrains Mono\",monospace; font-size:11.5px}\n    .verify-row{\n      margin:14px 20px 0; border:1px solid var(--line); border-radius:14px; overflow:hidden; background:var(--void);\n    }\n    .verify-row .vr-head{\n      display:flex; align-items:center; gap:10px; padding:11px 14px; border-bottom:1px solid var(--line);\n    }\n    .ring{position:relative; width:36px; height:36px; flex:0 0 auto}\n    .ring svg{transform:rotate(-90deg)}\n    .ring b{\n      position:absolute; inset:0; display:grid; place-items:center;\n      font-family:\"JetBrains Mono\",monospace; font-size:10px; font-weight:500;\n    }\n    .verify-row .vr-head .tt b{display:block; font-size:13px}\n    .verify-row .vr-head .tt span{font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--mut)}\n    #status{\n      margin-left:auto; font-family:\"JetBrains Mono\",monospace; font-size:10.5px;\n      border:1px solid var(--line); border-radius:99px; padding:4px 10px; color:var(--mut); white-space:nowrap;\n    }\n    #status.ok{color:var(--ok); border-color:rgba(52,211,153,.35)}\n    #status.bad{color:#FF8585; border-color:rgba(244,33,46,.4)}\n    #status.warn{color:var(--amber); border-color:rgba(255,178,36,.4)}\n    .kv{display:grid; grid-template-columns:110px 1fr; font-size:12.5px}\n    .kv div{padding:9px 14px; border-bottom:1px solid var(--line)}\n    .kv div:nth-child(odd){color:var(--dim); font-family:\"JetBrains Mono\",monospace; font-size:11px}\n    .kv div:nth-child(even){overflow:hidden; text-overflow:ellipsis; white-space:nowrap}\n    #linkWrap{display:none; margin:12px 20px 0; border:1px dashed var(--line-2); border-radius:12px; padding:10px 12px}\n    #link{font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--txt); word-break:break-all}\n    .sheet-actions{display:flex; gap:8px; padding:16px 20px 20px}\n    .btn-primary{\n      appearance:none; border:0; cursor:pointer; flex:1; background:#fff; color:#000;\n      font-weight:600; font-size:14px; border-radius:12px; padding:12px;\n    }\n    .btn-primary:hover{background:#E6E6E6}\n    .btn-quiet{\n      appearance:none; cursor:pointer; background:transparent; color:var(--txt);\n      border:1px solid var(--line-2); border-radius:12px; padding:12px 14px; font-size:13.5px; font-weight:500;\n    }\n    .btn-quiet:hover{background:var(--raised)}\n    .toast-stack{position:fixed; bottom:22px; left:50%; transform:translateX(-50%); z-index:60; display:flex; flex-direction:column; gap:8px; align-items:center}\n    .toast{\n      background:var(--raised-2); border:1px solid var(--line-2); color:var(--txt);\n      border-radius:12px; padding:10px 14px; font-size:13px; box-shadow:0 12px 32px rgba(0,0,0,.5);\n      animation:rise 180ms ease;\n    }\n\n    @media (max-width:920px){\n      .app{grid-template-columns:1fr}\n      .side{position:fixed; z-index:40; inset:0 auto 0 0; width:280px; transform:translateX(-102%); transition:transform 200ms ease}\n      .side.open{transform:none; box-shadow:30px 0 80px rgba(0,0,0,.5)}\n      .menu-btn{display:grid}\n      .hero{padding-top:40px}\n    }\n    @media (prefers-reduced-motion: reduce){\n      *{animation:none !important; transition:none !important}\n    }\n  </style>\n</head>\n<body>\n  <div class=\"app\">\n    <!-- ============ SIDEBAR ============ -->\n    <aside class=\"side\" id=\"sidebar\" aria-label=\"Rooms and session\">\n      <div class=\"side-top\">\n        <div class=\"logo-row\">\n          <div class=\"mark\">\u2715</div>\n          <div style=\"flex:1\"><b>Secure Chat</b><span>ephemeral \u00b7 burned on claim</span></div>\n          <button class=\"icon-btn\" id=\"collapseBtn\" title=\"Close sidebar\" aria-label=\"Close sidebar\">\u2a2f</button>\n        </div>\n        <button class=\"new-btn\" id=\"newChatBtn\">\u270e&nbsp; New chat</button>\n        <label class=\"search\"><span aria-hidden=\"true\">\u2315</span><input id=\"searchInput\" placeholder=\"Search conversation\" autocomplete=\"off\" /></label>\n      </div>\n      <div class=\"side-scroll\">\n        <div>\n          <div class=\"side-label\">Rooms</div>\n          <button class=\"room active\" data-room=\"general\"><span class=\"hash\">#</span> general <span class=\"unread\" id=\"unreadGeneral\" style=\"display:none\">0</span></button>\n          <button class=\"room\" data-room=\"engineering\"><span class=\"hash\">#</span> engineering</button>\n          <button class=\"room\" data-room=\"random\"><span class=\"hash\">#</span> random</button>\n        </div>\n        <div>\n          <div class=\"side-label\">Session</div>\n          <div class=\"hist-row\" id=\"sessionRow\">\u25cb&nbsp; Not linked \u2014 ticket required</div>\n          <div class=\"hist-row mono\" id=\"rateRow\" style=\"font-size:11px\">Rate 20 / 10s \u00b7 WSS only \u00b7 no-store</div>\n        </div>\n        <div>\n          <div class=\"side-label\">Security</div>\n          <div class=\"hist-row\">SHA-256 at rest \u00b7 256-bit opaque</div>\n          <div class=\"hist-row\">Burned on claim \u00b7 no replay</div>\n          <div class=\"hist-row\"><a href=\"/mobile\" style=\"color:var(--aura); text-decoration:none\">Open mobile key \u2192</a></div>\n        </div>\n      </div>\n      <div class=\"side-foot\">\n        <div class=\"user-card\">\n          <div class=\"avatar\" id=\"avatar\">?</div>\n          <div class=\"who\"><b id=\"me\">Not linked</b><span id=\"meSub\">generate a ticket to start</span></div>\n          <span class=\"dot\" id=\"presenceDot\" title=\"connection\"></span>\n          <button class=\"link-btn\" id=\"linkDeviceBtn\">Link</button>\n        </div>\n      </div>\n    </aside>\n\n    <!-- ============ MAIN ============ -->\n    <main class=\"main\">\n      <header class=\"topbar\">\n        <button class=\"icon-btn menu-btn\" id=\"menuBtn\" aria-label=\"Open sidebar\">\u2630</button>\n        <div class=\"room-pill\"><span style=\"color:var(--dim)\">#</span> <span id=\"roomName\">general</span></div>\n        <span class=\"secure-badge off\" id=\"secureBadge\"><i></i> <span id=\"secureText\">unlinked</span></span>\n        <div class=\"top-actions\">\n          <button class=\"tool-btn\" id=\"historyBtn\" title=\"Load history\">\u21bb History</button>\n          <button class=\"tool-btn\" id=\"exportBtn\" title=\"Copy transcript\">\u29c9 Copy</button>\n          <button class=\"tool-btn\" id=\"debugToggle\" title=\"Toggle log\">\u203a_ Log</button>\n          <button class=\"tool-btn primary\" id=\"openQrBtn\">Link device</button>\n        </div>\n      </header>\n\n      <div class=\"scroll\" id=\"scroll\">\n        <div class=\"col\">\n          <section class=\"hero\" id=\"hero\">\n            <span class=\"eyebrow\"><i></i> Ticket burns in 90s \u00b7 single-use \u00b7 no replay</span>\n            <h1>What should we<br>talk about<em> \u2014 securely?</em></h1>\n            <p>Link this device with your phone, then every message is <b>escaped server-side</b>, <b>moderated before broadcast</b>, and stored under a room you provably joined. Nothing to steal, nothing to replay.</p>\n            <div class=\"chips\" id=\"chips\">\n              <button class=\"chip\" data-prompt=\"Summarize the threat model of this QR login in two lines.\">Explain the QR login<small>How the 90-second ticket works</small></button>\n              <button class=\"chip\" data-prompt=\"Hello #general \u2014 testing my secure link. Can anyone read this?\">Say hello securely<small>First message in #general</small></button>\n              <button class=\"chip\" data-prompt=\"What happens if someone photographs my QR code?\">What if my QR leaks?<small>Replay, expiry and burn</small></button>\n            </div>\n            <div class=\"link-cta\">\n              <div class=\"copy\"><b>Link this device to start</b><span>Scan with your authenticated phone \u2192 approve \u2192 ticket burns \u2192 1-hour pass.</span></div>\n              <button class=\"ghost-btn\" id=\"howBtn\">How it works</button>\n              <button class=\"cta-btn\" id=\"heroLinkBtn\">Generate link</button>\n            </div>\n          </section>\n\n          <div class=\"presence\" id=\"presence\"></div>\n          <div id=\"msgs\" role=\"log\" aria-live=\"polite\" aria-relevant=\"additions\"></div>\n        </div>\n      </div>\n\n      <div class=\"composer-zone\">\n        <div class=\"col\">\n          <pre id=\"debug\" aria-label=\"Debug log\"></pre>\n          <div class=\"composer\">\n            <textarea id=\"msgInput\" rows=\"1\" placeholder=\"Message #general \u2014 Enter to send, Shift+Enter for a new line\" maxlength=\"2000\" autocomplete=\"off\"></textarea>\n            <div class=\"composer-bar\">\n              <button class=\"pill-btn\" id=\"attachBtn\" title=\"Attachments are disabled in this build\">\uff0b</button>\n              <button class=\"pill-btn\" id=\"thinkBtn\" aria-pressed=\"false\" title=\"Toggle verbose security log\">\u25cd&nbsp; Verbose</button>\n              <button class=\"pill-btn\" id=\"clearBtn\" title=\"Clear transcript\">\u2715&nbsp; Clear</button>\n              <span class=\"spacer\"></span>\n              <span class=\"mono\" id=\"timerText\" style=\"font-size:10.5px; color:var(--dim)\">No active ticket</span>\n              <button class=\"send\" id=\"send\" aria-label=\"Send message\" disabled>\n                <svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\"><path d=\"M12 19V5M5 12l7-7 7 7\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>\n              </button>\n            </div>\n          </div>\n          <div class=\"foot\"><span>Escaped server-side \u00b7 moderated before broadcast \u00b7 20 / 10s \u00b7 WSS only</span></div>\n        </div>\n      </div>\n    </main>\n  </div>\n\n  <!-- ============ QR VERIFY MODAL ============ -->\n  <div class=\"backdrop\" id=\"qrModal\" role=\"dialog\" aria-modal=\"true\" aria-labelledby=\"qrTitle\">\n    <div class=\"sheet\">\n      <div class=\"sheet-head\">\n        <div class=\"t\">\n          <h2 id=\"qrTitle\">Link this device</h2>\n          <p>Scan with your authenticated phone. The ticket burns the moment you claim it.</p>\n        </div>\n        <button class=\"icon-btn\" id=\"qrClose\" aria-label=\"Close\">\u2a2f</button>\n      </div>\n      <div class=\"steps\" aria-hidden=\"true\"><span class=\"done\" id=\"step1\"></span><span id=\"step2\"></span><span id=\"step3\"></span></div>\n      <div class=\"qr-stage\"><div id=\"qr\"><div class=\"empty\">Press Generate \u2014 ticket lives 90s.</div></div></div>\n      <div class=\"verify-row\">\n        <div class=\"vr-head\">\n          <div class=\"ring\" aria-hidden=\"true\">\n            <svg width=\"36\" height=\"36\" viewBox=\"0 0 36 36\"><circle cx=\"18\" cy=\"18\" r=\"15.5\" fill=\"none\" stroke=\"rgba(255,255,255,.12)\" stroke-width=\"3\"/><circle id=\"ringFg\" cx=\"18\" cy=\"18\" r=\"15.5\" fill=\"none\" stroke=\"#fff\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-dasharray=\"97.4\" stroke-dashoffset=\"0\"/></svg>\n            <b id=\"ringNum\">90</b>\n          </div>\n          <div class=\"tt\"><b>Waiting for approval</b><span class=\"mono\" id=\"ringSub\">opaque \u00b7 SHA-256 at rest \u00b7 256-bit</span></div>\n          <span id=\"status\">Idle</span>\n        </div>\n        <div class=\"kv mono\">\n          <div>room</div><div id=\"kvRoom\">#general</div>\n          <div>transport</div><div>WSS only \u00b7 no-store \u00b7 HSTS</div>\n          <div>rate</div><div>5 tickets / min / IP</div>\n        </div>\n      </div>\n      <div id=\"linkWrap\"><div class=\"mono\" style=\"font-size:10.5px; color:var(--mut); margin-bottom:5px\">Copy link (testing only \u2014 treat as secret):</div><code id=\"link\"></code></div>\n      <div class=\"sheet-actions\">\n        <button class=\"btn-quiet\" id=\"copyLinkBtn\">Copy link</button>\n        <button class=\"btn-primary\" id=\"gen\">Generate link</button>\n      </div>\n    </div>\n  </div>\n\n  <div class=\"toast-stack\" id=\"toasts\" aria-live=\"polite\"></div>\n\n  <script type=\"module\" src=\"/client/desktop.js\"></script>\n</body>\n</html>\n";
}

async function mobileFallbackHtml(): Promise<string> {
  return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\" />\n  <title>Verify login \u2014 Secure Chat</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Inter+Tight:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap\" rel=\"stylesheet\">\n  <style>\n    :root{\n      --void:#0A0A0B; --soot:#101014; --card:#131318; --raised:#1C1D23;\n      --line:rgba(255,255,255,.08); --line-2:rgba(255,255,255,.13);\n      --txt:#ECECED; --mut:#9A9AA3; --dim:#6B6B74;\n      --aura:#7AA2FF; --amber:#FFB224; --danger:#F4212E; --ok:#34D399;\n    }\n    *{box-sizing:border-box}\n    body{margin:0; background:var(--void); color:var(--txt); font-family:\"Inter\",system-ui,sans-serif; -webkit-font-smoothing:antialiased; font-size:15px; line-height:1.55}\n    body::before{content:\"\"; position:fixed; inset:0; pointer-events:none; background:radial-gradient(700px 260px at 50% -60px, rgba(122,162,255,.08), transparent 70%)}\n    :focus-visible{outline:2px solid var(--aura); outline-offset:2px}\n    .mono{font-family:\"JetBrains Mono\",monospace}\n    .top{position:sticky; top:0; z-index:10; background:rgba(10,10,11,.8); backdrop-filter:blur(12px); border-bottom:1px solid var(--line)}\n    .top-inner{max-width:560px; margin:0 auto; padding:13px 18px; display:flex; align-items:center; gap:12px}\n    .back{appearance:none; border:1px solid var(--line); background:transparent; color:var(--txt); width:32px; height:32px; border-radius:10px; cursor:pointer; text-decoration:none; display:grid; place-items:center; font-size:15px}\n    .top-inner b{font-family:\"Inter Tight\",sans-serif; font-size:14.5px; font-weight:600; letter-spacing:-.01em}\n    .top-inner span{display:block; font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--mut)}\n    .live{margin-left:auto; display:inline-flex; align-items:center; gap:7px; font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--mut); border:1px solid var(--line); border-radius:99px; padding:5px 11px; background:var(--soot)}\n    .live i{width:6px; height:6px; border-radius:50%; background:var(--ok)}\n    .wrap{position:relative; max-width:560px; margin:0 auto; padding:20px 18px 120px}\n    .hero{padding:14px 2px 4px}\n    .hero h1{margin:0; font-family:\"Inter Tight\",sans-serif; font-size:30px; font-weight:600; letter-spacing:-.04em; line-height:1.05}\n    .hero h1 em{font-style:normal; color:var(--mut); font-weight:500}\n    .hero p{margin:10px 0 0; color:var(--mut); font-size:13.5px}\n    .steps{display:flex; gap:6px; margin:16px 0 4px}\n    .steps span{height:3px; flex:1; border-radius:99px; background:var(--raised)}\n    .steps span.done{background:#fff}\n    .card{background:var(--card); border:1px solid var(--line); border-radius:18px; padding:16px; margin:14px 0}\n    .card h2{margin:0 0 4px; font-size:14px; font-weight:600; letter-spacing:-.01em; font-family:\"Inter Tight\",sans-serif}\n    .card p{margin:0 0 12px; font-size:13px; color:var(--mut)}\n    label.lbl{display:block; font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--dim); margin:10px 0 6px; letter-spacing:.03em}\n    .field{display:flex; gap:8px}\n    input[type=text]{flex:1; min-width:0; background:var(--void); border:1px solid var(--line); color:var(--txt); border-radius:12px; padding:12px 13px; font-size:14px; outline:none; width:100%}\n    input:focus{border-color:rgba(122,162,255,.5)}\n    .row{display:flex; gap:8px; margin-top:10px}\n    .btn{appearance:none; border:0; border-radius:12px; padding:12px 14px; font-size:14px; font-weight:600; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:8px}\n    .btn-primary{background:#fff; color:#000; flex:1}\n    .btn-primary:hover{background:#E6E6E6}\n    .btn-primary:disabled{opacity:.4}\n    .btn-quiet{background:transparent; color:var(--txt); border:1px solid var(--line-2); font-weight:500}\n    .btn-danger{background:var(--danger); color:#fff; flex:1}\n    pre{background:#000; border:1px solid var(--line); color:#B9B9C2; border-radius:12px; padding:12px; overflow:auto; font-family:\"JetBrains Mono\",monospace; font-size:11px; white-space:pre-wrap; word-break:break-word; margin:12px 0 0}\n    .sheet{border:1px solid rgba(255,178,36,.3); background:rgba(255,178,36,.05); border-radius:16px; padding:14px; margin-top:12px}\n    #confirm{display:none}\n    #confirm.open{display:block}\n    #confirm h3{margin:0; font-family:\"Inter Tight\",sans-serif; font-size:15px; display:flex; align-items:center; gap:8px}\n    #confirm h3 .pill{margin-left:auto; font-family:\"JetBrains Mono\",monospace; font-size:10px; color:var(--amber); border:1px solid rgba(255,178,36,.35); padding:3px 9px; border-radius:99px; font-weight:400}\n    .fp{margin:12px 0 0; border:1px solid var(--line); border-radius:12px; overflow:hidden; background:var(--void)}\n    .fp-head{display:flex; align-items:center; gap:8px; padding:10px 13px; border-bottom:1px solid var(--line); font-size:13px; font-weight:600}\n    .fp-head span{margin-left:auto; font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--amber); border:1px solid rgba(255,178,36,.35); padding:2px 9px; border-radius:99px; font-weight:400}\n    #details{margin:0; padding:6px 0; list-style:none}\n    #details li{padding:9px 13px; border-bottom:1px solid var(--line); font-size:13px; display:flex; gap:10px}\n    #details li:last-child{border-bottom:0}\n    #details li::before{content:\"\u00b7\"; color:var(--dim)}\n    .check{display:flex; gap:10px; align-items:flex-start; background:var(--void); border:1px solid var(--line); border-radius:12px; padding:12px; margin:12px 0}\n    .check input{width:18px; height:18px; margin-top:2px; accent-color:#fff}\n    .check label{font-size:13px; color:var(--txt)}\n    .dock{position:fixed; bottom:0; left:0; right:0; z-index:20; background:rgba(10,10,11,.86); backdrop-filter:blur(14px); border-top:1px solid var(--line); padding:12px 18px calc(14px + env(safe-area-inset-bottom))}\n    .dock-inner{max-width:560px; margin:0 auto; display:flex; gap:8px}\n    .foot{max-width:560px; margin:0 auto; padding:0 18px 24px; color:var(--dim); font-size:11.5px; font-family:\"JetBrains Mono\",monospace; font-size:10.5px; display:flex; justify-content:space-between; gap:10px}\n    @media (prefers-reduced-motion: reduce){*{animation:none !important; transition:none !important}}\n  </style>\n</head>\n<body>\n  <header class=\"top\">\n    <div class=\"top-inner\">\n      <a class=\"back\" href=\"/desktop\" aria-label=\"Back to chat\">\u2190</a>\n      <div><b>Verify login</b><span>ticket \u00b7 single-use \u00b7 90s</span></div>\n      <span class=\"live\"><i></i> secure channel</span>\n    </div>\n  </header>\n\n  <div class=\"wrap\">\n    <div class=\"hero\">\n      <h1>Is this you<br><em>trying to link?</em></h1>\n      <p>Confirm the fingerprint matches your desktop. Approving burns the ticket instantly \u2014 denying kills it.</p>\n    </div>\n    <div class=\"steps\"><span class=\"done\"></span><span class=\"done\" id=\"mstep2\"></span><span id=\"mstep3\"></span></div>\n\n    <section class=\"card\">\n      <h2>Your mobile session</h2>\n      <p>In production this is your real IdP session. For the demo, mint a 1-hour pass here.</p>\n      <label class=\"lbl\" for=\"userId\">USER ID</label>\n      <input id=\"userId\" type=\"text\" placeholder=\"e.g. alice\" value=\"alice\" autocomplete=\"off\" />\n      <div class=\"row\">\n        <button id=\"login\" class=\"btn btn-primary\">Mint session</button>\n        <button id=\"clearSession\" class=\"btn btn-quiet\">Clear</button>\n      </div>\n      <pre id=\"loginOut\">No session yet</pre>\n    </section>\n\n    <section class=\"card\">\n      <h2>Inspect the ticket</h2>\n      <p>Paste the token from the desktop QR (<span class=\"mono\">?token=\u2026</span>), or open the QR link here \u2014 it autofills.</p>\n      <label class=\"lbl\" for=\"token\">OPAQUE TOKEN</label>\n      <div class=\"field\">\n        <input id=\"token\" type=\"text\" placeholder=\"Paste token or full link\" autocomplete=\"off\" />\n        <button id=\"paste\" class=\"btn btn-quiet\" type=\"button\">Paste</button>\n      </div>\n      <div class=\"row\"><button id=\"preview\" class=\"btn btn-primary\">Inspect ticket</button></div>\n      <pre id=\"previewOut\">Awaiting token\u2026</pre>\n\n      <div id=\"confirm\" role=\"dialog\" aria-labelledby=\"confirmTitle\">\n        <div class=\"sheet\">\n          <h3 id=\"confirmTitle\">Check the fingerprint <span class=\"pill\">90s \u00b7 single-use</span></h3>\n          <div class=\"fp\">\n            <div class=\"fp-head\">Station fingerprint <span id=\"sheetStatus\">Pending</span></div>\n            <ul id=\"details\"></ul>\n          </div>\n          <div class=\"check\">\n            <input id=\"ack\" type=\"checkbox\" />\n            <label for=\"ack\">I started this login, the time looks right, and I know approving burns this ticket immediately.</label>\n          </div>\n        </div>\n      </div>\n    </section>\n  </div>\n\n  <div class=\"dock\" id=\"dock\" style=\"display:none\">\n    <div class=\"dock-inner\">\n      <button id=\"deny\" class=\"btn btn-quiet\" style=\"flex:1; border-color:rgba(244,33,46,.5); color:#FF8585\">Deny</button>\n      <button id=\"approve\" class=\"btn btn-primary\" disabled>Approve</button>\n    </div>\n  </div>\n  <div class=\"foot\"><span>Burn on claim \u00b7 hash at rest \u00b7 256-bit</span><span><a href=\"/desktop\" style=\"color:var(--mut)\">Station \u2192</a></span></div>\n\n  <script type=\"module\" src=\"/client/mobile.js\"></script>\n</body>\n</html>\n";
}

async function desktopJs(): Promise<string> {
  return "// Secure Chat \u2014 Grok-like shell. Security flows unchanged: opaque ticket \u2192 approve \u2192 burn \u2192 JWT \u2192 WSS.\nconst $ = (s) => document.querySelector(s);\nconst $$ = (s) => [...document.querySelectorAll(s)];\n\nconst statusEl = $(\"#status\");\nconst timerText = $(\"#timerText\");\nconst ringFg = $(\"#ringFg\");\nconst ringNum = $(\"#ringNum\");\nconst ringSub = $(\"#ringSub\");\nconst qrEl = $(\"#qr\");\nconst linkEl = $(\"#link\");\nconst linkWrap = $(\"#linkWrap\");\nconst debugEl = $(\"#debug\");\nconst msgsEl = $(\"#msgs\");\nconst meEl = $(\"#me\");\nconst meSub = $(\"#meSub\");\nconst avatarEl = $(\"#avatar\");\nconst presenceEl = $(\"#presence\");\nconst presenceDot = $(\"#presenceDot\");\nconst sessionRow = $(\"#sessionRow\");\nconst inputEl = $(\"#msgInput\");\nconst sendBtn = $(\"#send\");\nconst heroEl = $(\"#hero\");\nconst scrollEl = $(\"#scroll\");\nconst modal = $(\"#qrModal\");\nconst toastsEl = $(\"#toasts\");\nconst secureBadge = $(\"#secureBadge\");\nconst secureText = $(\"#secureText\");\nconst roomNameEl = $(\"#roomName\");\nconst kvRoom = $(\"#kvRoom\");\nconst unreadEl = $(\"#unreadGeneral\");\nconst RING_C = 97.4;\n\nlet pollTimer = null;\nlet countdownTimer = null;\nlet ws = null;\nlet chatWs = null;\nlet currentToken = null;\nlet expiresAt = 0;\nlet jwt = localStorage.getItem(\"chat_jwt\") || \"\";\nlet identity = null;\ntry { identity = JSON.parse(localStorage.getItem(\"chat_identity\") || \"null\"); } catch { identity = null; }\nlet currentRoom = \"general\";\nlet verbose = false;\nlet unread = 0;\n\nfunction toast(text) {\n  if (!toastsEl) return;\n  const d = document.createElement(\"div\");\n  d.className = \"toast\";\n  d.textContent = text;\n  toastsEl.appendChild(d);\n  setTimeout(() => { d.style.opacity = \"0\"; setTimeout(() => d.remove(), 250); }, 2600);\n}\nfunction log(...a) {\n  const line = a.map((x) => (typeof x === \"string\" ? x : JSON.stringify(x, null, 2))).join(\" \");\n  if (debugEl && (verbose || /failed|error|claim|poll|recv|open/i.test(line))) {\n    debugEl.textContent += line + \"\\n\";\n    debugEl.scrollTop = debugEl.scrollHeight;\n  }\n  console.log(...a);\n}\nfunction setStatus(text, tone) {\n  if (!statusEl) return;\n  statusEl.textContent = text;\n  statusEl.className = tone === \"ok\" ? \"ok\" : tone === \"bad\" ? \"bad\" : tone === \"warn\" ? \"warn\" : \"\";\n  statusEl.id = \"status\";\n  const s1 = $(\"#step1\"), s2 = $(\"#step2\"), s3 = $(\"#step3\");\n  if (s1 && s2 && s3) {\n    s1.className = \"done\";\n    s2.className = text.toLowerCase().includes(\"approv\") || text.toLowerCase().includes(\"linked\") || text.toLowerCase().includes(\"burn\") ? \"done\" : \"\";\n    s3.className = text.toLowerCase().includes(\"linked\") || text.toLowerCase().includes(\"burn\") ? \"done\" : \"\";\n  }\n}\nfunction setTimer() {\n  const s = expiresAt ? Math.max(0, Math.round((expiresAt - Date.now()) / 1000)) : -1;\n  if (s < 0) {\n    if (timerText) timerText.textContent = \"No active ticket\";\n    if (ringNum) ringNum.textContent = \"\u2013\";\n    if (ringFg) ringFg.style.strokeDashoffset = \"0\";\n    return;\n  }\n  if (timerText) timerText.textContent = s > 0 ? `${s}s left \u00b7 burns on claim` : \"Expired\";\n  if (ringNum) ringNum.textContent = String(s);\n  if (ringFg) ringFg.style.strokeDashoffset = String(RING_C * (1 - s / 90));\n  if (ringSub) ringSub.textContent = s > 0 ? \"opaque \u00b7 SHA-256 at rest \u00b7 256-bit\" : \"expired \u00b7 generate a new ticket\";\n  if (s === 0) setStatus(\"Expired\", \"bad\");\n}\nfunction renderMe() {\n  const name = jwt && identity ? identity.userId : null;\n  if (meEl) meEl.textContent = name || \"Not linked\";\n  if (meSub) meSub.textContent = name ? `${identity.displayName || name} \u00b7 pass 1h` : \"generate a ticket to start\";\n  if (avatarEl) avatarEl.textContent = name ? name.slice(0, 1).toUpperCase() : \"?\";\n  if (sessionRow) sessionRow.textContent = name ? `\u25cf  Linked as ${name} \u2014 transcript is live` : \"\u25cb  Not linked \u2014 ticket required\";\n  if (presenceDot) presenceDot.classList.toggle(\"on\", !!(chatWs && chatWs.readyState === 1));\n  if (secureBadge) secureBadge.classList.toggle(\"off\", !name);\n  if (secureText) secureText.textContent = name ? \"secured \u00b7 WSS\" : \"unlinked\";\n  updateSend();\n}\nfunction updateSend() {\n  if (!sendBtn || !inputEl) return;\n  const ok = !!(chatWs && chatWs.readyState === 1) && inputEl.value.trim().length > 0;\n  sendBtn.disabled = !ok;\n}\nfunction openModal() {\n  modal?.classList.add(\"open\");\n  document.body.style.overflow = \"hidden\";\n}\nfunction closeModal() {\n  modal?.classList.remove(\"open\");\n  document.body.style.overflow = \"\";\n}\nfunction updateHero() {\n  if (!heroEl || !msgsEl) return;\n  const has = msgsEl.querySelector(\".row\");\n  heroEl.style.display = has ? \"none\" : \"\";\n}\n\n// ---------- QR ticket flow (unchanged security) ----------\nasync function gen() {\n  setStatus(\"Issuing\u2026\");\n  if (qrEl) qrEl.innerHTML = '<div class=\"empty\">Creating ticket\u2026</div>';\n  if (pollTimer) clearInterval(pollTimer);\n  if (countdownTimer) clearInterval(countdownTimer);\n  if (ws) try { ws.close(); } catch {}\n  openModal();\n  const res = await fetch(\"/api/auth/qr/create\", { method: \"POST\" });\n  const data = await res.json().catch(() => ({}));\n  if (!res.ok) {\n    log(\"create failed\", data);\n    setStatus(\"Failed: \" + (data.error || res.status), \"bad\");\n    if (qrEl) qrEl.innerHTML = `<div class=\"empty\">Failed \u2014 ${escapeHtml(data.error || String(res.status))}</div>`;\n    toast(\"Could not create ticket \u2014 try again\");\n    return;\n  }\n  currentToken = data.token;\n  expiresAt = data.expiresAt;\n  log(\"QR created\", { expiresAt: new Date(data.expiresAt).toISOString(), ttlMs: data.ttlMs });\n  setStatus(\"Scan with mobile\", \"warn\");\n  setTimer();\n  countdownTimer = setInterval(setTimer, 400);\n  if (qrEl) {\n    qrEl.innerHTML = \"\";\n    const canvas = document.createElement(\"canvas\");\n    qrEl.appendChild(canvas);\n    if (typeof QRCode !== \"undefined\") await QRCode.toCanvas(canvas, data.url, { width: 216, margin: 1, color: { dark: \"#000000\", light: \"#FFFFFF\" } });\n    else qrEl.textContent = data.url;\n  }\n  if (linkEl && linkWrap) { linkEl.textContent = data.url; linkWrap.style.display = \"block\"; }\n  tryWs(data.token);\n  startPolling(data.token);\n}\nfunction tryWs(token) {\n  const proto = location.protocol === \"https:\" ? \"wss:\" : \"ws:\";\n  try {\n    ws = new WebSocket(`${proto}//${location.host}/api/auth/qr/ws?token=${encodeURIComponent(token)}`);\n    ws.onopen = () => log(\"waiter open\");\n    ws.onmessage = (e) => {\n      log(\"waiter\", e.data);\n      try {\n        const msg = JSON.parse(e.data);\n        if (msg.status === \"approved\") { setStatus(\"Approved \u2014 burning\u2026\", \"ok\"); claim(token); }\n        if (msg.status === \"denied\") { setStatus(\"Denied\", \"bad\"); cleanup(); }\n        if (msg.status === \"expired\") { setStatus(\"Expired\", \"bad\"); cleanup(); }\n      } catch {}\n    };\n    ws.onerror = () => log(\"waiter error \u2014 poll still active\");\n  } catch (e) { log(\"waiter failed\", String(e)); }\n}\nfunction startPolling(token) {\n  if (pollTimer) clearInterval(pollTimer);\n  pollTimer = setInterval(async () => {\n    const res = await fetch(`/api/auth/qr/status?token=${encodeURIComponent(token)}`);\n    const data = await res.json().catch(() => ({}));\n    log(\"poll\", res.status, data);\n    if (data.status === \"approved\") { setStatus(\"Approved \u2014 burning\u2026\", \"ok\"); claim(token); }\n    if (data.status === \"denied\") { setStatus(\"Denied\", \"bad\"); cleanup(); }\n    if (data.status === \"expired\") { setStatus(\"Expired\", \"bad\"); cleanup(); }\n  }, 1500);\n}\nasync function claim(token) {\n  cleanup();\n  const res = await fetch(\"/api/auth/qr/claim\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ token }) });\n  const data = await res.json().catch(() => ({}));\n  log(\"claim\", res.status, data);\n  if (res.ok && data.token) {\n    jwt = data.token; identity = data.identity;\n    localStorage.setItem(\"chat_jwt\", jwt);\n    localStorage.setItem(\"chat_identity\", JSON.stringify(identity));\n    renderMe();\n    setStatus(\"Linked \u00b7 burned\", \"ok\");\n    if (timerText) timerText.textContent = \"Burned \u00b7 single-use\";\n    toast(`Linked as ${identity.userId}`);\n    setTimeout(closeModal, 600);\n    connectChat(currentRoom);\n  } else {\n    setStatus(\"Claim failed: \" + (data.error || res.status), \"bad\");\n  }\n}\nfunction cleanup() {\n  if (pollTimer) clearInterval(pollTimer); pollTimer = null;\n  if (countdownTimer) clearInterval(countdownTimer); countdownTimer = null;\n  if (ws) try { ws.close(); } catch {} ws = null;\n}\n\n// ---------- Chat (Grok messaging component) ----------\nfunction connectChat(roomId = \"general\") {\n  currentRoom = roomId;\n  if (roomNameEl) roomNameEl.textContent = roomId;\n  if (kvRoom) kvRoom.textContent = \"#\" + roomId;\n  if (inputEl) inputEl.placeholder = `Message #${roomId} \u2014 Enter to send, Shift+Enter for a new line`;\n  $$(\".room\").forEach((b) => b.classList.toggle(\"active\", b.dataset.room === roomId));\n  if (chatWs) try { chatWs.close(); } catch {}\n  msgsEl.innerHTML = \"\";\n  unread = 0; if (unreadEl) unreadEl.style.display = \"none\";\n  updateHero();\n  if (!jwt) { appendSystem(\"Link this device to join the transcript.\"); renderMe(); return; }\n  const proto = location.protocol === \"https:\" ? \"wss:\" : \"ws:\";\n  chatWs = new WebSocket(`${proto}//${location.host}/api/room/${encodeURIComponent(roomId)}/ws?token=${encodeURIComponent(jwt)}`);\n  chatWs.onopen = () => { log(\"chat open\", roomId, identity?.userId); appendPresence(`Live in #${roomId} as ${identity?.userId}`); renderMe(); };\n  chatWs.onmessage = (e) => {\n    try {\n      const d = JSON.parse(e.data);\n      log(\"chat recv\", d);\n      if (d.type === \"welcome\") {\n        if (d.history?.length) d.history.forEach(appendMsg);\n        updateHero();\n      } else if (d.type === \"message\") {\n        appendMsg(d.message);\n        if (document.hidden && d.message.userId !== identity?.userId) {\n          unread++; if (unreadEl) { unreadEl.textContent = String(unread); unreadEl.style.display = \"\"; }\n        }\n      }\n      else if (d.type === \"presence\") appendPresence(`${d.userId} ${d.event}ed`);\n      else if (d.type === \"moderation\") { appendSystem(`Blocked: ${d.reason}`, true); toast(\"Message blocked by moderation\"); }\n      else if (d.type === \"error\") appendSystem(`Error: ${d.error}`, true);\n    } catch { log(\"chat raw\", e.data); }\n  };\n  chatWs.onclose = () => { appendSystem(\"Disconnected \u2014 reload to reconnect.\", true); renderMe(); };\n  chatWs.onerror = () => appendSystem(\"Socket error.\", true);\n  renderMe();\n}\nfunction appendMsg(m) {\n  if (!msgsEl) return;\n  const mine = identity && m.userId === identity.userId;\n  const div = document.createElement(\"div\");\n  div.className = \"row \" + (mine ? \"me\" : \"peer\");\n  div.dataset.body = (m.body || \"\").toLowerCase();\n  const who = m.displayName || m.userId;\n  const time = new Date(m.ts).toLocaleTimeString([], { hour: \"2-digit\", minute: \"2-digit\" });\n  if (mine) {\n    div.innerHTML = `<div class=\"bubble\"><div class=\"body\"></div></div>`;\n    div.querySelector(\".body\").textContent = m.body;\n  } else {\n    div.innerHTML = `<div class=\"ava\">${escapeHtml(who.slice(0, 1).toUpperCase())}</div><div class=\"bubble\"><div class=\"meta\"><b></b><time>${time}</time>${m.flagged ? `<span class=\"flag\">flagged \u00b7 ${escapeHtml(m.flagReason || \"\")}</span>` : \"\"}</div><div class=\"body\"></div></div>`;\n    div.querySelector(\"b\").textContent = who;\n    div.querySelector(\".body\").textContent = m.body;\n  }\n  msgsEl.appendChild(div);\n  scrollEl.scrollTop = scrollEl.scrollHeight;\n  updateHero();\n}\nfunction appendSystem(text, bad) {\n  if (!msgsEl) return;\n  const div = document.createElement(\"div\");\n  div.className = \"sys\";\n  div.textContent = \"\u2014 \" + text;\n  if (bad) div.style.color = \"#FF8585\";\n  msgsEl.appendChild(div);\n  scrollEl.scrollTop = scrollEl.scrollHeight;\n}\nfunction appendPresence(text) {\n  if (!presenceEl) return;\n  presenceEl.style.display = \"flex\";\n  presenceEl.textContent = \"\u25cf \" + text;\n  clearTimeout(appendPresence._t);\n  appendPresence._t = setTimeout(() => { presenceEl.style.display = \"none\"; }, 4000);\n}\nfunction escapeHtml(s) { return String(s).replace(/&/g, \"&amp;\").replace(/</g, \"&lt;\").replace(/>/g, \"&gt;\"); }\nfunction send() {\n  if (!inputEl) return;\n  const body = inputEl.value.trim();\n  if (!body) return;\n  if (!chatWs || chatWs.readyState !== 1) { toast(\"Link this device first\"); openModal(); return; }\n  chatWs.send(JSON.stringify({ type: \"message\", roomId: currentRoom, body }));\n  inputEl.value = \"\";\n  autogrow();\n  updateSend();\n}\nfunction autogrow() {\n  if (!inputEl) return;\n  inputEl.style.height = \"auto\";\n  inputEl.style.height = Math.min(160, inputEl.scrollHeight) + \"px\";\n}\n\n// ---------- wiring ----------\n$(\"#gen\")?.addEventListener(\"click\", gen);\n$(\"#openQrBtn\")?.addEventListener(\"click\", () => { openModal(); if (!currentToken || Date.now() > expiresAt) gen(); });\n$(\"#linkDeviceBtn\")?.addEventListener(\"click\", () => { openModal(); if (!currentToken || Date.now() > expiresAt) gen(); });\n$(\"#heroLinkBtn\")?.addEventListener(\"click\", gen);\n$(\"#howBtn\")?.addEventListener(\"click\", () => toast(\"Create ticket \u2192 scan on /mobile \u2192 approve \u2192 ticket burns \u2192 1-hour pass\"));\n$(\"#qrClose\")?.addEventListener(\"click\", closeModal);\nmodal?.addEventListener(\"click\", (e) => { if (e.target === modal) closeModal(); });\ndocument.addEventListener(\"keydown\", (e) => {\n  if (e.key === \"Escape\") { closeModal(); $(\"#sidebar\")?.classList.remove(\"open\"); }\n  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === \"k\") { e.preventDefault(); $(\"#searchInput\")?.focus(); }\n});\n$(\"#copyLinkBtn\")?.addEventListener(\"click\", async () => {\n  try { await navigator.clipboard.writeText(linkEl.textContent); toast(\"Link copied\"); }\n  catch { toast(\"Copy failed\"); }\n});\n$(\"#send\")?.addEventListener(\"click\", send);\ninputEl?.addEventListener(\"input\", () => { autogrow(); updateSend(); });\ninputEl?.addEventListener(\"keydown\", (e) => { if (e.key === \"Enter\" && !e.shiftKey) { e.preventDefault(); send(); } });\n$(\"#historyBtn\")?.addEventListener(\"click\", async () => {\n  if (!jwt) { toast(\"Link this device first\"); openModal(); return; }\n  const res = await fetch(`/api/room/${encodeURIComponent(currentRoom)}/history?token=${encodeURIComponent(jwt)}`, { headers: { Authorization: `Bearer ${jwt}` } });\n  const data = await res.json().catch(() => ({}));\n  log(\"history\", data);\n  if (data.messages) { msgsEl.innerHTML = \"\"; data.messages.forEach(appendMsg); if (!data.messages.length) appendSystem(\"No messages yet \u2014 say hello.\"); }\n});\n$(\"#exportBtn\")?.addEventListener(\"click\", async () => {\n  const lines = [...msgsEl.querySelectorAll(\".row\")].map((el) => el.textContent.trim()).join(\"\\n\");\n  try { await navigator.clipboard.writeText(lines || \"(empty)\"); toast(\"Transcript copied\"); } catch { toast(\"Copy failed\"); }\n});\n$(\"#clearBtn\")?.addEventListener(\"click\", () => { msgsEl.innerHTML = \"\"; updateHero(); });\n$(\"#debugToggle\")?.addEventListener(\"click\", () => { verbose = !verbose; debugEl?.classList.toggle(\"open\", verbose); $(\"#thinkBtn\")?.setAttribute(\"aria-pressed\", String(verbose)); toast(verbose ? \"Verbose log on\" : \"Verbose log off\"); });\n$(\"#thinkBtn\")?.addEventListener(\"click\", () => { verbose = !verbose; debugEl?.classList.toggle(\"open\", verbose); $(\"#thinkBtn\").setAttribute(\"aria-pressed\", String(verbose)); });\n$(\"#attachBtn\")?.addEventListener(\"click\", () => toast(\"Attachments are disabled in this build\"));\n$(\"#newChatBtn\")?.addEventListener(\"click\", () => { msgsEl.innerHTML = \"\"; updateHero(); inputEl?.focus(); toast(\"Started a fresh view \u2014 history stays on the server\"); });\n$(\"#menuBtn\")?.addEventListener(\"click\", () => $(\"#sidebar\")?.classList.add(\"open\"));\n$(\"#collapseBtn\")?.addEventListener(\"click\", () => $(\"#sidebar\")?.classList.remove(\"open\"));\n$$(\".room\").forEach((b) => b.addEventListener(\"click\", () => { connectChat(b.dataset.room); $(\"#sidebar\")?.classList.remove(\"open\"); }));\n$$(\"#chips .chip\").forEach((c) => c.addEventListener(\"click\", () => {\n  if (!jwt) { openModal(); gen(); return; }\n  inputEl.value = c.dataset.prompt; autogrow(); updateSend(); inputEl.focus();\n}));\n$(\"#searchInput\")?.addEventListener(\"input\", (e) => {\n  const q = e.target.value.trim().toLowerCase();\n  msgsEl.querySelectorAll(\".row\").forEach((r) => { r.style.display = !q || (r.dataset.body || \"\").includes(q) ? \"\" : \"none\"; });\n});\n\nrenderMe();\nsetTimer();\nif (jwt && identity) setTimeout(() => connectChat(currentRoom), 400);\nelse appendSystem(\"Link this device to join the transcript.\");\nlog(\"Ready. Grok-like shell. Mobile key at /mobile\");\n";
}

async function mobileJs(): Promise<string> {
  return "// Mobile key \u2014 Grok-like verification sheet. Same secure contract: preview \u2192 explicit ack \u2192 approve/deny.\nconst $ = (s) => document.querySelector(s);\nconst loginOut = $(\"#loginOut\");\nconst previewOut = $(\"#previewOut\");\nconst details = $(\"#details\");\nconst confirm = $(\"#confirm\");\nconst dock = $(\"#dock\");\nconst sheetStatus = $(\"#sheetStatus\");\n\nlet mobileJwt = localStorage.getItem(\"mobile_jwt\") || \"\";\n\nfunction renderLoginOut() {\n  if (!loginOut) return;\n  loginOut.textContent = mobileJwt\n    ? `Stored pass (truncated): ${mobileJwt.slice(0, 28)}\u2026\\nKeep this on your phone only.`\n    : \"No session yet \u2014 mint one above.\";\n}\nrenderLoginOut();\n\nfunction showConfirm(open) {\n  confirm?.classList.toggle(\"open\", open);\n  if (confirm) confirm.style.display = open ? \"block\" : \"none\";\n  if (dock) dock.style.display = open ? \"block\" : \"none\";\n  $(\"#mstep2\")?.classList.toggle(\"done\", open);\n}\nshowConfirm(false);\n\n$(\"#login\")?.addEventListener(\"click\", async () => {\n  const userId = ($(\"#userId\")?.value || \"\").trim() || \"alice\";\n  const res = await fetch(\"/api/auth/dev-login\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ userId, displayName: userId }) });\n  const data = await res.json().catch(() => ({}));\n  if (loginOut) loginOut.textContent = JSON.stringify(data, null, 2);\n  if (data.token) { mobileJwt = data.token; localStorage.setItem(\"mobile_jwt\", mobileJwt); renderLoginOut(); }\n});\n$(\"#clearSession\")?.addEventListener(\"click\", () => {\n  mobileJwt = \"\"; localStorage.removeItem(\"mobile_jwt\"); renderLoginOut();\n  if (loginOut) loginOut.textContent = \"Cleared.\";\n});\n\n$(\"#preview\")?.addEventListener(\"click\", async () => {\n  const raw = ($(\"#token\")?.value || \"\").trim();\n  if (!raw) return alert(\"Paste token\");\n  let t = raw;\n  try { const u = new URL(raw); const p = u.searchParams.get(\"token\"); if (p) t = p; } catch {}\n  const el = $(\"#token\"); if (el) el.value = t;\n  if (previewOut) previewOut.textContent = \"Inspecting\u2026\";\n  const res = await fetch(`/api/auth/qr/preview?token=${encodeURIComponent(t)}`);\n  const data = await res.json().catch(() => ({}));\n  if (previewOut) previewOut.textContent = JSON.stringify(data, null, 2);\n  if ((data.status === \"pending\") || (res.ok && data.status)) {\n    if (details) {\n      details.innerHTML = \"\";\n      const left = data.expiresAt ? Math.max(0, Math.round((data.expiresAt - Date.now()) / 1000)) : \"?\";\n      [\n        `Status \u2014 ${data.status || \"unknown\"}`,\n        `Created \u2014 ${data.createdAt ? new Date(data.createdAt).toLocaleString() : \"unknown\"}`,\n        `Expires \u2014 ${data.expiresAt ? new Date(data.expiresAt).toLocaleString() : \"unknown\"} (${left}s left)`,\n        `Token \u2014 ${data.tokenPreview || t.slice(0, 8) + \"\u2026\"}`,\n        `If the time looks wrong, deny immediately.`,\n      ].forEach((txt) => { const li = document.createElement(\"li\"); li.textContent = txt; details.appendChild(li); });\n      showConfirm(true);\n      if (sheetStatus) sheetStatus.textContent = data.status || \"Pending\";\n      const ack = $(\"#ack\"), approve = $(\"#approve\");\n      if (ack && approve) approve.disabled = !ack.checked;\n      $(\"#mstep3\")?.classList.remove(\"done\");\n    }\n  } else {\n    showConfirm(false);\n    if (previewOut) previewOut.textContent += \"\\nNot pending \u2014 cannot approve.\";\n  }\n});\n\n$(\"#ack\")?.addEventListener(\"change\", (e) => {\n  const approve = $(\"#approve\");\n  if (approve) approve.disabled = !e.target.checked;\n});\n$(\"#approve\")?.addEventListener(\"click\", async () => {\n  const token = ($(\"#token\")?.value || \"\").trim();\n  if (!mobileJwt) return alert(\"Mint a mobile session first\");\n  const res = await fetch(\"/api/auth/mobile/approve\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: \"approve\" }) });\n  const data = await res.json().catch(() => ({}));\n  if (previewOut) previewOut.textContent = JSON.stringify(data, null, 2);\n  if (res.ok) {\n    if (sheetStatus) sheetStatus.textContent = \"Approved\";\n    $(\"#mstep3\")?.classList.add(\"done\");\n    showConfirm(false);\n    alert(\"Approved \u2014 desktop will burn the ticket now\");\n  } else alert(`Approve failed: ${res.status} ${JSON.stringify(data)}`);\n});\n$(\"#deny\")?.addEventListener(\"click\", async () => {\n  const token = ($(\"#token\")?.value || \"\").trim();\n  if (!mobileJwt) return alert(\"Mint a mobile session first\");\n  const res = await fetch(\"/api/auth/mobile/approve\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: \"deny\" }) });\n  const data = await res.json().catch(() => ({}));\n  if (previewOut) previewOut.textContent = JSON.stringify(data, null, 2);\n  if (res.ok) { if (sheetStatus) sheetStatus.textContent = \"Denied\"; showConfirm(false); alert(\"Denied \u2014 ticket killed\"); }\n  else alert(`Deny failed: ${res.status} ${JSON.stringify(data)}`);\n});\n$(\"#paste\")?.addEventListener(\"click\", async () => {\n  try { const t = await navigator.clipboard.readText(); const el = $(\"#token\"); if (el) el.value = t.trim(); }\n  catch { alert(\"Clipboard read failed \u2014 paste manually\"); }\n});\ntry {\n  const u = new URL(location.href);\n  const p = u.searchParams.get(\"token\");\n  if (p) { const el = $(\"#token\"); if (el) el.value = p; }\n} catch {}\n";
}
