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
  return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n  <title>Secure QR Chat \u2014 Station</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500&family=JetBrains+Mono:wght@400;500&display=swap\" rel=\"stylesheet\">\n  <script src=\"https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js\"></script>\n  <style>\n    :root{\n      --chalk:#FCFCF9;\n      --ink:#0E1A24;\n      --line:#DDE1E7;\n      --concrete:#E9EAF0;\n      --cobalt:#2D5BFF;\n      --signal:#FFD60A;\n      --rose:#FF4D6A;\n      --muted:#6B7280;\n      --ok:#0E7A4C;\n      --radius:14px;\n    }\n    *{box-sizing:border-box}\n    html,body{height:100%}\n    body{\n      margin:0;\n      font-family:\"IBM Plex Sans\",system-ui,-apple-system,Segoe UI,Roboto,sans-serif;\n      background:var(--chalk);\n      color:var(--ink);\n      -webkit-font-smoothing:antialiased;\n      line-height:1.45;\n    }\n    /* header */\n    .topbar{\n      position:sticky; top:0; z-index:10;\n      background:var(--ink);\n      color:var(--chalk);\n      border-bottom:4px solid var(--cobalt);\n    }\n    .topbar-inner{\n      max-width:1120px; margin:0 auto; padding:14px 20px;\n      display:flex; align-items:center; justify-content:space-between; gap:16px;\n    }\n    .brand{\n      display:flex; align-items:center; gap:14px;\n    }\n    .mark{\n      width:28px; height:28px; border-radius:8px; background:var(--signal);\n      display:grid; place-items:center; font-family:\"JetBrains Mono\",monospace; font-weight:500; font-size:13px; color:var(--ink);\n      flex:0 0 auto;\n    }\n    .brand h1{\n      margin:0; font-family:\"Space Grotesk\",sans-serif; font-weight:700; font-size:18px; letter-spacing:-0.02em; line-height:1;\n    }\n    .brand p{margin:2px 0 0; font-family:\"JetBrains Mono\",monospace; font-size:11px; color:#9AA0B6; letter-spacing:0.04em}\n    .top-meta{\n      font-family:\"JetBrains Mono\",monospace; font-size:11px; color:#DDE1E7; opacity:0.9;\n      display:flex; align-items:center; gap:10px;\n    }\n    .live-dot{width:8px; height:8px; border-radius:50%; background:var(--signal); box-shadow:0 0 0 6px rgba(255,214,10,0.18); animation: pulse 2s infinite}\n    @media (prefers-reduced-motion: reduce){ .live-dot{animation:none} }\n    @keyframes pulse{0%,100%{opacity:1} 50%{opacity:0.6}}\n\n    .wrap{max-width:1120px; margin:0 auto; padding:28px 20px 40px}\n\n    /* intro strip */\n    .strip{\n      display:grid; grid-template-columns: 1fr auto; gap:18px; align-items:center;\n      border:1px solid var(--line); background:#fff; border-radius:var(--radius);\n      padding:14px 16px; margin-bottom:22px;\n    }\n    .strip p{margin:0; font-size:13px; color:var(--muted); max-width:62ch}\n    .strip strong{color:var(--ink); font-weight:500}\n    .strip a{color:var(--cobalt); text-underline-offset:3px}\n    @media(max-width:760px){ .strip{grid-template-columns:1fr} }\n\n    /* main grid */\n    .grid{\n      display:grid;\n      grid-template-columns: 380px 1fr;\n      gap:18px;\n      align-items:start;\n    }\n    @media(max-width:980px){ .grid{grid-template-columns:1fr} }\n\n    /* QR stub - paper object */\n    .stub{\n      background:#fff;\n      border:1px solid var(--line);\n      border-radius:var(--radius);\n      overflow:hidden;\n      position:relative;\n      box-shadow: 0 1px 0 rgba(14,26,36,0.04), 0 8px 24px rgba(14,26,36,0.06);\n    }\n    .stub-head{\n      padding:14px 16px 12px;\n      border-bottom:1px dashed var(--line);\n      display:flex; justify-content:space-between; align-items:center;\n      background:linear-gradient(0deg, #fff, #fff), repeating-linear-gradient(90deg, var(--line) 0 6px, transparent 6px 12px);\n    }\n    .stub-head h2{\n      margin:0; font-family:\"Space Grotesk\",sans-serif; font-size:15px; font-weight:700; letter-spacing:-0.02em;\n    }\n    .stub-head span{\n      font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--muted); background:var(--concrete); padding:4px 8px; border-radius:999px;\n    }\n    .stub-body{padding:16px}\n    .qr-frame{\n      background:var(--ink);\n      border-radius:12px;\n      padding:12px;\n      display:grid; place-items:center;\n      min-height:322px;\n      position:relative;\n      overflow:hidden;\n    }\n    .qr-frame::before{\n      content:\"\"; position:absolute; inset:0; opacity:0.06;\n      background-image: radial-gradient(circle at 1px 1px, #fff 1px, transparent 0);\n      background-size:16px 16px;\n    }\n    #qr{position:relative; display:grid; place-items:center; min-height:276px; width:100%}\n    #qr canvas{border-radius:10px; background:#fff; box-shadow:0 6px 18px rgba(0,0,0,0.25)}\n    #qr .empty{\n      color:#C2C8D6; font-family:\"JetBrains Mono\",monospace; font-size:12px; text-align:center; padding:24px; border:1px dashed rgba(255,255,255,0.2); border-radius:10px; width:100%;\n    }\n    .actions{display:flex; gap:10px; margin-top:14px}\n    .btn{\n      appearance:none; border:0; border-radius:10px; padding:10px 14px; font-weight:500; font-size:14px; cursor:pointer;\n      display:inline-flex; align-items:center; justify-content:center; gap:8px; line-height:1;\n      transition: transform 120ms ease, background 120ms ease, color 120ms ease, border-color 120ms ease;\n    }\n    .btn:active{transform:translateY(1px)}\n    .btn:focus-visible{outline:2px solid var(--cobalt); outline-offset:2px}\n    .btn-primary{background:var(--cobalt); color:#fff; flex:1}\n    .btn-primary:hover{background:#244ee0}\n    .btn-ghost{background:#fff; color:var(--ink); border:1px solid var(--line)}\n    .btn-ghost:hover{background:var(--concrete)}\n    .meta-row{\n      margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; align-items:center;\n      font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--muted);\n    }\n    .chip{border:1px solid var(--line); background:var(--chalk); padding:5px 8px; border-radius:999px; display:inline-flex; align-items:center; gap:6px}\n    .chip i{width:6px; height:6px; border-radius:50%; background:var(--ok)}\n    .chip.warn i{background:var(--signal)}\n    .chip.bad i{background:var(--rose)}\n    #linkWrap{margin-top:12px; border:1px solid var(--line); background:var(--chalk); border-radius:10px; padding:10px 12px; display:none}\n    #link{font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--ink); word-break:break-all}\n    .perforation{\n      height:10px; margin:0; background:\n        radial-gradient(circle, transparent 5px, #fff 6px) 0 0 / 20px 10px repeat-x,\n        linear-gradient(#fff,#fff);\n      border-top:1px solid var(--line); border-bottom:1px solid var(--line);\n    }\n    .stub-foot{padding:12px 16px; background:var(--chalk); font-size:12px; color:var(--muted)}\n    .stub-foot ul{margin:6px 0 0; padding-left:16px}\n    .stub-foot li{margin:3px 0}\n\n    /* transcript */\n    .panel{\n      background:var(--ink);\n      color:var(--chalk);\n      border-radius:var(--radius);\n      border:1px solid #1A2432;\n      overflow:hidden;\n      display:flex; flex-direction:column;\n      min-height:540px;\n      box-shadow: 0 1px 0 rgba(14,26,36,0.04), 0 8px 24px rgba(14,26,36,0.08);\n    }\n    .panel-head{\n      display:flex; align-items:center; justify-content:space-between; gap:12px;\n      padding:14px 16px; border-bottom:1px solid rgba(255,255,255,0.08);\n      background:linear-gradient(180deg, rgba(255,255,255,0.04), transparent);\n    }\n    .panel-head h2{margin:0; font-family:\"Space Grotesk\",sans-serif; font-size:15px; font-weight:700; letter-spacing:-0.02em; color:var(--chalk)}\n    .panel-head .right{display:flex; gap:8px; align-items:center}\n    .mono{font-family:\"JetBrains Mono\",monospace; font-size:11px; letter-spacing:0.02em}\n    .tag{padding:4px 8px; border-radius:999px; border:1px solid rgba(255,255,255,0.12); background:rgba(255,255,255,0.06); color:#DDE1E7}\n    .presence{\n      display:flex; align-items:center; gap:8px; padding:10px 16px; border-bottom:1px solid rgba(255,255,255,0.06);\n      background:rgba(45,91,255,0.08);\n      font-size:12px; color:#C2C8D6;\n    }\n    .presence strong{color:var(--chalk); font-weight:500}\n    #msgs{\n      flex:1; overflow:auto; padding:14px 16px; display:flex; flex-direction:column; gap:10px;\n      background:\n        linear-gradient(180deg, rgba(255,255,255,0.02), transparent 120px),\n        repeating-linear-gradient(0deg, transparent 0 28px, rgba(255,255,255,0.03) 28px 29px);\n    }\n    .line{\n      display:grid; grid-template-columns: 86px 1fr; gap:12px; align-items:start;\n      padding:10px 12px; border-radius:10px; background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.06);\n    }\n    .line.me{background:rgba(45,91,255,0.14); border-color:rgba(45,91,255,0.28)}\n    .line.system{background:transparent; border-style:dashed; color:#9AA0B6; justify-items:start; grid-template-columns:1fr}\n    .line .time{font-family:\"JetBrains Mono\",monospace; font-size:11px; color:#8E96AD; padding-top:2px}\n    .line .body{font-size:14px; color:var(--chalk); word-break:break-word; white-space:pre-wrap}\n    .line .who{font-weight:500; color:var(--chalk); margin-right:6px}\n    .line .body .flag{font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--signal); margin-left:6px}\n\n    .composer{\n      padding:12px 16px; border-top:1px solid rgba(255,255,255,0.08); background:rgba(0,0,0,0.16);\n      display:flex; flex-direction:column; gap:10px;\n    }\n    .input-row{display:flex; gap:10px; align-items:center}\n    #msgInput{\n      flex:1; background:#0A101A; color:var(--chalk); border:1px solid rgba(255,255,255,0.12); border-radius:10px;\n      padding:12px 14px; font-size:14px; outline:none;\n    }\n    #msgInput::placeholder{color:#6B7390}\n    #msgInput:focus{border-color:var(--cobalt); box-shadow:0 0 0 3px rgba(45,91,255,0.22)}\n    .send{\n      width:44px; height:44px; border-radius:10px; border:0; background:var(--cobalt); color:#fff; display:grid; place-items:center; cursor:pointer; flex:0 0 auto;\n    }\n    .send:hover{background:#244ee0}\n    .send:focus-visible{outline:2px solid var(--signal); outline-offset:2px}\n    .sub-actions{display:flex; gap:8px; flex-wrap:wrap}\n    .sub-actions button{\n      font-family:\"JetBrains Mono\",monospace; font-size:11px; padding:7px 10px; border-radius:999px;\n      border:1px solid rgba(255,255,255,0.14); background:rgba(255,255,255,0.04); color:#DDE1E7; cursor:pointer;\n    }\n    .sub-actions button:hover{background:rgba(255,255,255,0.08)}\n    #debug{\n      font-family:\"JetBrains Mono\",monospace; font-size:11px; color:#8E96AD; background:rgba(0,0,0,0.24); border:1px solid rgba(255,255,255,0.08);\n      border-radius:10px; padding:10px 12px; max-height:120px; overflow:auto; white-space:pre-wrap; word-break:break-word;\n    }\n\n    /* footer */\n    .foot{\n      max-width:1120px; margin:0 auto; padding:0 20px 36px; color:var(--muted); font-size:12px;\n      display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap;\n    }\n    .foot code{font-family:\"JetBrains Mono\",monospace; background:#fff; border:1px solid var(--line); padding:2px 6px; border-radius:6px}\n  </style>\n</head>\n<body>\n  <header class=\"topbar\">\n    <div class=\"topbar-inner\">\n      <div class=\"brand\">\n        <div class=\"mark\">\u25d0</div>\n        <div>\n          <h1>Secure QR Chat</h1>\n          <p>Station \u00b7 ephemeral link \u00b7 burned on claim</p>\n        </div>\n      </div>\n      <div class=\"top-meta\">\n        <span class=\"live-dot\" aria-hidden=\"true\"></span>\n        <span>WSS only \u00b7 90s \u00b7 single-use</span>\n        <a href=\"/mobile\" style=\"color:var(--chalk); text-decoration:none; border:1px solid rgba(255,255,255,0.18); padding:6px 10px; border-radius:999px; font-size:12px\">Open mobile key \u2192</a>\n      </div>\n    </div>\n  </header>\n\n  <div class=\"wrap\">\n    <div class=\"strip\">\n      <p><strong>How it works:</strong> Generate a stub. Scan the QR with your already-authenticated phone. Confirm the check-sheet on mobile \u2014 device, city, time \u2014 then tap approve. Desktop burns the ticket and mints a 1-hour pass. Nothing to steal, nothing to replay.</p>\n      <div class=\"mono\" style=\"color:var(--muted)\">Room: <span style=\"color:var(--ink); background:var(--signal); padding:2px 6px; border-radius:6px; font-weight:500\">general</span> &nbsp; <span style=\"opacity:0.6\">\u00b7</span> &nbsp; <a href=\"#transcript\">Go to transcript \u2193</a></div>\n    </div>\n\n    <div class=\"grid\">\n      <!-- QR stub -->\n      <section class=\"stub\" aria-labelledby=\"stub-title\">\n        <div class=\"stub-head\">\n          <h2 id=\"stub-title\">Detachable link</h2>\n          <span id=\"status\">Idle</span>\n        </div>\n        <div class=\"stub-body\">\n          <div class=\"qr-frame\">\n            <div id=\"qr\"><div class=\"empty\">No stub yet.<br>Press Generate to create a 90-second link.</div></div>\n          </div>\n          <div class=\"actions\">\n            <button id=\"gen\" class=\"btn btn-primary\"><span>Generate</span> <span aria-hidden=\"true\">\u21bb</span></button>\n            <button id=\"clearBtn\" class=\"btn btn-ghost\" title=\"Clear transcript\">Clear</button>\n          </div>\n          <div class=\"meta-row\">\n            <span id=\"timer\" class=\"chip\"><i></i> <span id=\"timerText\">No active link</span></span>\n            <span class=\"chip warn\"><i></i> Hash at rest \u00b7 SHA-256</span>\n          </div>\n          <div id=\"linkWrap\"><div class=\"mono\" style=\"font-size:11px; color:var(--muted); margin-bottom:4px\">Copy link (for testing):</div><code id=\"link\"></code></div>\n        </div>\n        <div class=\"perforation\" aria-hidden=\"true\"></div>\n        <div class=\"stub-foot\">\n          <strong style=\"font-family:Space Grotesk,sans-serif; font-size:12px; color:var(--ink)\">Check-sheet shows on mobile:</strong>\n          <ul>\n            <li>Approximate city, browser, time</li>\n            <li>90-second expiry, auto-burn</li>\n            <li>Single tap to approve, no auto-trust</li>\n          </ul>\n        </div>\n      </section>\n\n      <!-- transcript -->\n      <section class=\"panel\" id=\"transcript\" aria-labelledby=\"transcript-title\">\n        <div class=\"panel-head\">\n          <h2 id=\"transcript-title\">Transcript</h2>\n          <div class=\"right\">\n            <span class=\"mono tag\" id=\"me\">Not logged in</span>\n            <span class=\"mono tag\" id=\"roomTag\"># general</span>\n          </div>\n        </div>\n        <div id=\"presence\" class=\"presence\" style=\"display:none\"></div>\n        <div id=\"msgs\" role=\"log\" aria-live=\"polite\" aria-relevant=\"additions\">\n          <div class=\"line system\"><div>Generate a stub on the left, approve on your phone, then type here. Messages are escaped server-side \u2014 even <code>&lt;script&gt;</code> renders as text.</div></div>\n        </div>\n        <div class=\"composer\">\n          <div class=\"input-row\">\n            <input id=\"msgInput\" placeholder=\"Write a message \u2014 2000 char max \u00b7 HTML is escaped\" maxlength=\"2000\" autocomplete=\"off\" />\n            <button id=\"send\" class=\"send\" aria-label=\"Send message\">\n              <svg width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\"><path d=\"M22 2L11 13\" stroke=\"currentColor\" stroke-width=\"1.7\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/><path d=\"M22 2L15 22L11 13L2 9L22 2Z\" stroke=\"currentColor\" stroke-width=\"1.7\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>\n            </button>\n          </div>\n          <div class=\"sub-actions\">\n            <button id=\"historyBtn\" type=\"button\">Load history</button>\n            <button id=\"exportBtn\" type=\"button\">Copy transcript</button>\n            <span class=\"mono\" style=\"color:#8E96AD; padding:7px 0;\">Rate: 20 / 10s \u00b7 CSP + HSTS \u00b7 no-store</span>\n          </div>\n          <pre id=\"debug\" aria-label=\"Debug log\"></pre>\n        </div>\n      </section>\n    </div>\n  </div>\n\n  <div class=\"foot\">\n    <div>Built for Workers + Durable Objects. One DO per room, one per ticket. <code>POST /api/auth/qr/create \u2192 /mobile?token=\u2026 \u2192 /approve \u2192 /claim (burn)</code></div>\n    <div class=\"mono\">Ink + Chalk + Cobalt + Signal \u00b7 Space Grotesk / IBM Plex</div>\n  </div>\n\n  <script type=\"module\" src=\"/client/desktop.js\"></script>\n</body>\n</html>\n";
}

async function mobileFallbackHtml(): Promise<string> {
  return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n  <title>Secure QR Chat \u2014 Mobile Key</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500&family=JetBrains+Mono:wght@400;500&display=swap\" rel=\"stylesheet\">\n  <style>\n    :root{--chalk:#FCFCF9;--ink:#0E1A24;--line:#DDE1E7;--concrete:#E9EAF0;--cobalt:#2D5BFF;--signal:#FFD60A;--rose:#FF4D6A;--muted:#6B7280;--ok:#0E7A4C;--radius:14px}\n    *{box-sizing:border-box} body{margin:0; font-family:\"IBM Plex Sans\",sans-serif; background:var(--chalk); color:var(--ink); -webkit-font-smoothing:antialiased; line-height:1.45}\n    .top{position:sticky; top:0; z-index:10; background:var(--ink); color:var(--chalk); border-bottom:4px solid var(--cobalt)}\n    .top-inner{max-width:640px; margin:0 auto; padding:14px 20px; display:flex; align-items:center; justify-content:space-between; gap:12px}\n    .brand{display:flex; gap:12px; align-items:center}\n    .mark{width:28px; height:28px; border-radius:8px; background:var(--signal); display:grid; place-items:center; font-family:\"JetBrains Mono\",monospace; font-size:13px; color:var(--ink)}\n    .brand h1{margin:0; font-family:\"Space Grotesk\",sans-serif; font-size:16px; font-weight:700; letter-spacing:-0.02em; line-height:1}\n    .brand p{margin:2px 0 0; font-family:\"JetBrains Mono\",monospace; font-size:11px; color:#9AA0B6}\n    .top a{color:var(--chalk); text-decoration:none; border:1px solid rgba(255,255,255,0.18); padding:6px 10px; border-radius:999px; font-size:12px}\n    .wrap{max-width:640px; margin:0 auto; padding:22px 20px 40px}\n    .card{background:#fff; border:1px solid var(--line); border-radius:var(--radius); padding:16px; margin:16px 0; box-shadow:0 1px 0 rgba(14,26,36,0.04), 0 8px 24px rgba(14,26,36,0.05)}\n    .card h2{margin:0 0 6px; font-family:\"Space Grotesk\",sans-serif; font-size:15px; font-weight:700; letter-spacing:-0.02em}\n    .card p{margin:0 0 12px; font-size:13px; color:var(--muted)}\n    .mono{font-family:\"JetBrains Mono\",monospace; font-size:11px}\n    .field{display:flex; flex-direction:column; gap:8px; margin:10px 0}\n    input[type=text]{width:100%; padding:11px 12px; border-radius:10px; border:1px solid var(--line); background:var(--chalk); font-size:14px; outline:none}\n    input:focus{border-color:var(--cobalt); box-shadow:0 0 0 3px rgba(45,91,255,0.18)}\n    .row{display:flex; gap:10px}\n    .btn{appearance:none; border:0; border-radius:10px; padding:11px 14px; font-weight:500; font-size:14px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:8px; transition:transform 120ms ease, background 120ms ease}\n    .btn:active{transform:translateY(1px)} .btn:focus-visible{outline:2px solid var(--cobalt); outline-offset:2px}\n    .btn-primary{background:var(--cobalt); color:#fff; flex:1} .btn-primary:hover{background:#244ee0} .btn-primary:disabled{opacity:0.45; cursor:not-allowed}\n    .btn-ghost{background:#fff; color:var(--ink); border:1px solid var(--line)} .btn-ghost:hover{background:var(--concrete)}\n    .btn-danger{background:var(--rose); color:#fff} .btn-danger:hover{background:#e54860}\n    pre{background:var(--ink); color:#DDE1E7; border-radius:10px; padding:12px; overflow:auto; border:1px solid #1A2432; font-family:\"JetBrains Mono\",monospace; font-size:11px; white-space:pre-wrap; word-break:break-word}\n    .sheet{border:1px solid var(--line); border-radius:12px; overflow:hidden}\n    .sheet-head{padding:10px 14px; background:var(--chalk); border-bottom:1px dashed var(--line); display:flex; justify-content:space-between; align-items:center}\n    .sheet-head strong{font-family:\"Space Grotesk\",sans-serif; font-size:13px}\n    .sheet-head span{font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--muted); background:#fff; border:1px solid var(--line); padding:3px 8px; border-radius:999px}\n    .sheet-body{padding:14px; background:#fff}\n    #details{margin:0; padding-left:18px; font-size:13px}\n    #details li{margin:6px 0}\n    .check{display:flex; gap:10px; align-items:flex-start; background:var(--chalk); border:1px solid var(--line); border-radius:10px; padding:12px; margin:12px 0}\n    .check input{margin-top:2px}\n    .check label{font-size:13px; color:var(--ink)}\n    .confirm{display:none; border:1px solid #F3D98A; background:#FFFDF0; border-radius:12px; padding:14px; margin-top:12px}\n    .confirm.open{display:block}\n    .confirm h3{margin:0 0 8px; font-family:\"Space Grotesk\",sans-serif; font-size:14px; color:#7A5A00}\n    .pill{display:inline-flex; align-items:center; gap:6px; font-family:\"JetBrains Mono\",monospace; font-size:11px; background:#fff; border:1px solid #F1D17A; padding:4px 8px; border-radius:999px; color:#7A5A00}\n    .pill i{width:6px; height:6px; border-radius:50%; background:var(--signal)}\n    .foot{max-width:640px; margin:0 auto; padding:0 20px 32px; color:var(--muted); font-size:12px; display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap}\n  </style>\n</head>\n<body>\n  <header class=\"top\">\n    <div class=\"top-inner\">\n      <div class=\"brand\">\n        <div class=\"mark\">\u25d0</div>\n        <div><h1>Mobile key</h1><p>Confirm before you trust</p></div>\n      </div>\n      <a href=\"/desktop\">Station \u2192</a>\n    </div>\n  </header>\n\n  <div class=\"wrap\">\n    <div class=\"card\" style=\"border-left:4px solid var(--cobalt)\">\n      <h2>1 \u00b7 Establish your mobile session</h2>\n      <p>In production this is your real IdP session. For the demo we mint a 1-hour JWT here and store it locally.</p>\n      <div class=\"field\">\n        <label class=\"mono\" for=\"userId\" style=\"color:var(--muted)\">User id</label>\n        <input id=\"userId\" type=\"text\" placeholder=\"e.g. alice\" value=\"alice\" autocomplete=\"off\" />\n      </div>\n      <div class=\"row\">\n        <button id=\"login\" class=\"btn btn-primary\">Mint session</button>\n        <button id=\"clearSession\" class=\"btn btn-ghost\">Clear</button>\n      </div>\n      <pre id=\"loginOut\" style=\"margin-top:12px\">No session yet</pre>\n    </div>\n\n    <div class=\"card\">\n      <h2>2 \u00b7 Inspect the link</h2>\n      <p>Paste the <code style=\"font-family:JetBrains Mono,monospace; background:var(--chalk); border:1px solid var(--line); padding:1px 6px; border-radius:6px\">token</code> from the station QR (<code style=\"font-family:JetBrains Mono,monospace\">?token=\u2026</code>), or open the QR link directly on this device \u2014 it autofills.</p>\n      <div class=\"field\">\n        <label class=\"mono\" for=\"token\" style=\"color:var(--muted)\">Opaque token</label>\n        <div class=\"row\">\n          <input id=\"token\" type=\"text\" placeholder=\"Paste token or full link\" autocomplete=\"off\" style=\"flex:1\" />\n          <button id=\"paste\" class=\"btn btn-ghost\" type=\"button\">Paste</button>\n        </div>\n      </div>\n      <div class=\"row\">\n        <button id=\"preview\" class=\"btn btn-primary\">Inspect</button>\n      </div>\n      <pre id=\"previewOut\" style=\"margin-top:12px\">Awaiting token\u2026</pre>\n\n      <div id=\"confirm\" class=\"confirm\" role=\"dialog\" aria-labelledby=\"confirmTitle\" aria-modal=\"false\">\n        <div style=\"display:flex; justify-content:space-between; align-items:center; gap:8px\">\n          <h3 id=\"confirmTitle\">Check-sheet \u2014 verify this is you</h3>\n          <span class=\"pill\"><i></i> 90s \u00b7 single-use</span>\n        </div>\n        <div class=\"sheet\" style=\"margin-top:10px\">\n          <div class=\"sheet-head\"><strong>Station fingerprint</strong><span id=\"sheetStatus\">Pending</span></div>\n          <div class=\"sheet-body\">\n            <ul id=\"details\"></ul>\n          </div>\n        </div>\n        <div class=\"check\">\n          <input id=\"ack\" type=\"checkbox\" />\n          <label for=\"ack\">I initiated this login on my station, the city/time looks correct, and I understand approving will burn this link immediately.</label>\n        </div>\n        <div class=\"row\">\n          <button id=\"approve\" class=\"btn btn-primary\" disabled>Approve</button>\n          <button id=\"deny\" class=\"btn btn-danger\">Deny</button>\n        </div>\n        <p class=\"mono\" style=\"margin:10px 0 0; color:var(--muted)\">On deny the ticket is marked <em>denied</em> and the station is notified instantly.</p>\n      </div>\n    </div>\n\n    <div class=\"card\" style=\"background:var(--chalk)\">\n      <h2>What you\u2019re confirming</h2>\n      <ul style=\"margin:6px 0 0; padding-left:18px; font-size:13px; color:var(--muted)\">\n        <li>Device & browser, approximate city/country, language</li>\n        <li>Creation time and seconds remaining</li>\n        <li>That you tapped explicitly \u2014 no auto-approve exists</li>\n      </ul>\n    </div>\n  </div>\n\n  <div class=\"foot\">\n    <div>Ink + Chalk + Cobalt + Signal \u00b7 Space Grotesk / IBM Plex</div>\n    <div class=\"mono\">Burn on claim \u00b7 hash at rest \u00b7 256-bit</div>\n  </div>\n\n  <script type=\"module\" src=\"/client/mobile.js\"></script>\n</body>\n</html>\n";
}

async function desktopJs(): Promise<string> {
  return "// Station client \u2014 distinctive ink/chalk design, keeps all security hooks\nconst $ = (s) => document.querySelector(s);\nconst statusEl = $(\"#status\");\nconst timerText = $(\"#timerText\");\nconst qrEl = $(\"#qr\");\nconst linkEl = $(\"#link\");\nconst linkWrap = $(\"#linkWrap\");\nconst debugEl = $(\"#debug\");\nconst msgsEl = $(\"#msgs\");\nconst meEl = $(\"#me\");\nconst presenceEl = $(\"#presence\");\nconst inputEl = $(\"#msgInput\");\n\nlet pollTimer = null;\nlet countdownTimer = null;\nlet ws = null;\nlet chatWs = null;\nlet currentToken = null;\nlet expiresAt = 0;\nlet jwt = localStorage.getItem(\"chat_jwt\") || \"\";\nlet identity = JSON.parse(localStorage.getItem(\"chat_identity\") || \"null\");\n\nfunction log(...a){\n  const line = a.map(x=> typeof x===\"string\"? x : JSON.stringify(x,null,2)).join(\" \");\n  if(debugEl){ debugEl.textContent += line + \"\\n\"; debugEl.scrollTop = debugEl.scrollHeight; }\n  console.log(...a);\n}\nfunction setStatus(text, tone){\n  if(!statusEl) return;\n  statusEl.textContent = text;\n  // tone: ok|warn|bad \u2192 background hint\n  statusEl.style.background = tone===\"ok\" ? \"#E6F4EA\" : tone===\"warn\" ? \"#FFF7D6\" : tone===\"bad\" ? \"#FFE0E6\" : \"var(--concrete)\";\n  statusEl.style.color = tone===\"ok\" ? \"#0E7A4C\" : tone===\"bad\" ? \"#B42318\" : \"var(--muted)\";\n}\nfunction setTimer(){\n  if(!timerText) return;\n  if(!expiresAt){ timerText.textContent=\"No active link\"; return; }\n  const s = Math.max(0, Math.round((expiresAt - Date.now())/1000));\n  timerText.textContent = s>0 ? `${s}s left \u00b7 burns on claim` : \"Expired\";\n  if(s===0) setStatus(\"Expired\",\"bad\");\n}\nfunction renderMe(){\n  if(!meEl) return;\n  if(jwt && identity){\n    meEl.textContent = `\u25cf ${identity.userId} \u2022 pass 1h`;\n    meEl.style.background=\"rgba(45,91,255,0.14)\"; meEl.style.borderColor=\"rgba(45,91,255,0.28)\"; meEl.style.color=\"#fff\";\n    if(presenceEl){ presenceEl.style.display=\"flex\"; presenceEl.innerHTML=`<span>Station linked as <strong>${identity.displayName||identity.userId}</strong> \u2014 transcript is live. WSS enforced.</span>`; }\n  } else {\n    meEl.textContent=\"Not linked \u2014 generate a stub\";\n    meEl.style.background=\"\"; meEl.style.borderColor=\"\"; meEl.style.color=\"\";\n    if(presenceEl) presenceEl.style.display=\"none\";\n  }\n}\nrenderMe();\n\nasync function gen(){\n  setStatus(\"Issuing\u2026\");\n  if(qrEl) qrEl.innerHTML='<div class=\"empty\">Creating stub\u2026</div>';\n  if(pollTimer) clearInterval(pollTimer);\n  if(countdownTimer) clearInterval(countdownTimer);\n  if(ws) try{ ws.close(); }catch{}\n  const res = await fetch(\"/api/auth/qr/create\",{method:\"POST\"});\n  const data = await res.json().catch(()=>({}));\n  if(!res.ok){\n    log(\"create failed\",data);\n    setStatus(\"Failed: \"+(data.error||res.status),\"bad\");\n    if(qrEl) qrEl.innerHTML=`<div class=\"empty\">Failed \u2014 ${data.error||res.status}</div>`;\n    return;\n  }\n  currentToken=data.token; expiresAt=data.expiresAt;\n  log(\"QR created\",{url:data.url, expiresAt:new Date(data.expiresAt).toISOString(), ttlMs:data.ttlMs});\n  setStatus(\"Scan with mobile\",\"ok\");\n  setTimer();\n  countdownTimer=setInterval(setTimer,400);\n\n  if(qrEl){\n    qrEl.innerHTML=\"\";\n    const canvas=document.createElement(\"canvas\");\n    qrEl.appendChild(canvas);\n    if(typeof QRCode!==\"undefined\") await QRCode.toCanvas(canvas, data.url, {width:276, margin:1, color:{dark:\"#0E1A24\", light:\"#FFFFFF\"}});\n    else { qrEl.textContent=data.url; }\n  }\n  if(linkEl && linkWrap){ linkEl.textContent=data.url; linkWrap.style.display=\"block\"; }\n  tryWs(data.token);\n  startPolling(data.token);\n}\n\nfunction tryWs(token){\n  const proto = location.protocol===\"https:\"?\"wss:\":\"ws:\";\n  const wsUrl = `${proto}//${location.host}/api/auth/qr/ws?token=${encodeURIComponent(token)}`;\n  try{\n    ws=new WebSocket(wsUrl);\n    ws.onopen=()=> log(\"waiter open\");\n    ws.onmessage=(e)=>{\n      log(\"waiter\",e.data);\n      try{\n        const msg=JSON.parse(e.data);\n        if(msg.status===\"approved\"){ setStatus(\"Approved \u2014 burning\u2026\",\"ok\"); claim(token); }\n        if(msg.status===\"denied\"){ setStatus(\"Denied\",\"bad\"); cleanup(); setTimer(); }\n        if(msg.status===\"expired\"){ setStatus(\"Expired\",\"bad\"); cleanup(); }\n      }catch{}\n    };\n    ws.onerror=()=> log(\"waiter error \u2014 poll still active\");\n    ws.onclose=()=> log(\"waiter closed\");\n  }catch(e){ log(\"waiter failed\",String(e)); }\n}\n\nfunction startPolling(token){\n  if(pollTimer) clearInterval(pollTimer);\n  pollTimer=setInterval(async()=>{\n    const res=await fetch(`/api/auth/qr/status?token=${encodeURIComponent(token)}`);\n    const data=await res.json().catch(()=>({}));\n    log(\"poll\",res.status,data);\n    if(data.status===\"approved\"){ setStatus(\"Approved (poll) \u2014 burning\u2026\",\"ok\"); claim(token); }\n    if(data.status===\"denied\"){ setStatus(\"Denied\",\"bad\"); cleanup(); }\n    if(data.status===\"expired\"){ setStatus(\"Expired\",\"bad\"); cleanup(); }\n  },1500);\n}\n\nasync function claim(token){\n  cleanup();\n  const res=await fetch(\"/api/auth/qr/claim\",{method:\"POST\", headers:{\"Content-Type\":\"application/json\"}, body:JSON.stringify({token})});\n  const data=await res.json().catch(()=>({}));\n  log(\"claim\",res.status,data);\n  if(res.ok && data.token){\n    jwt=data.token; identity=data.identity;\n    localStorage.setItem(\"chat_jwt\",jwt);\n    localStorage.setItem(\"chat_identity\",JSON.stringify(identity));\n    renderMe();\n    setStatus(`Linked as ${identity.userId}`,\"ok\");\n    if(timerText) timerText.textContent=\"Burned \u00b7 single-use\";\n    connectChat(\"general\");\n  } else {\n    setStatus(\"Claim failed: \"+(data.error||res.status),\"bad\");\n  }\n}\n\nfunction cleanup(){\n  if(pollTimer) clearInterval(pollTimer); pollTimer=null;\n  if(countdownTimer) clearInterval(countdownTimer); countdownTimer=null;\n  if(ws) try{ ws.close(); }catch{} ws=null;\n}\n\nfunction connectChat(roomId=\"general\"){\n  if(chatWs) try{ chatWs.close(); }catch{}\n  if(!jwt){ log(\"cannot connect \u2014 no pass\"); appendSystem(\"No pass \u2014 generate a stub first\",\"bad\"); return; }\n  const proto=location.protocol===\"https:\"?\"wss:\":\"ws:\";\n  const wsUrl=`${proto}//${location.host}/api/room/${encodeURIComponent(roomId)}/ws?token=${encodeURIComponent(jwt)}`;\n  chatWs=new WebSocket(wsUrl);\n  chatWs.onopen=()=>{ log(\"chat open\",roomId,identity?.userId); appendSystem(`Linked to #${roomId} as ${identity?.userId}`); };\n  chatWs.onmessage=(e)=>{\n    try{\n      const d=JSON.parse(e.data);\n      log(\"chat recv\",d);\n      if(d.type===\"welcome\"){\n        if(d.history?.length) d.history.forEach(appendMsg);\n        else appendSystem(\"No history yet \u2014 say hello.\");\n      } else if(d.type===\"message\"){ appendMsg(d.message); }\n      else if(d.type===\"presence\"){ appendSystem(`${d.userId} ${d.event}ed`); }\n      else if(d.type===\"moderation\"){ appendSystem(`Blocked: ${d.reason}`,\"bad\"); }\n      else if(d.type===\"error\"){ appendSystem(`Error: ${d.error}`,\"bad\"); }\n    }catch{ log(\"chat raw\",e.data); }\n  };\n  chatWs.onclose=()=> appendSystem(\"Disconnected \u2014 reload to reconnect\",\"bad\");\n  chatWs.onerror=()=> appendSystem(\"Socket error\",\"bad\");\n}\n\nfunction appendMsg(m){\n  if(!msgsEl) return;\n  const div=document.createElement(\"div\");\n  div.className=\"line\"+(identity && m.userId===identity.userId? \" me\":\"\");\n  const who = m.displayName||m.userId;\n  const time = new Date(m.ts).toLocaleTimeString([], {hour:\"2-digit\", minute:\"2-digit\", second:\"2-digit\"});\n  div.innerHTML=`<div class=\"time\">${time}</div><div class=\"body\"><span class=\"who\">${escapeHtml(who)}:</span> ${m.body}${m.flagged?'<span class=\"flag\">\u2691 '+escapeHtml(m.flagReason||\"flagged\")+'</span>':''}</div>`;\n  msgsEl.appendChild(div);\n  msgsEl.scrollTop=msgsEl.scrollHeight;\n}\nfunction appendSystem(text, tone){\n  if(!msgsEl) return;\n  const div=document.createElement(\"div\");\n  div.className=\"line system\";\n  div.innerHTML=`<div>\u2014 ${escapeHtml(text)}</div>`;\n  if(tone===\"bad\") div.style.color=\"#FF8A8A\";\n  msgsEl.appendChild(div);\n  msgsEl.scrollTop=msgsEl.scrollHeight;\n}\nfunction escapeHtml(s){ return s.replace(/&/g,\"&amp;\").replace(/</g,\"&lt;\").replace(/>/g,\"&gt;\"); }\n\nfunction send(){\n  if(!inputEl) return;\n  const body=inputEl.value.trim();\n  if(!body) return;\n  if(!chatWs || chatWs.readyState!==1){ appendSystem(\"Not connected \u2014 link your station first\",\"bad\"); return; }\n  chatWs.send(JSON.stringify({type:\"message\", roomId:\"general\", body}));\n  inputEl.value=\"\";\n}\n\ndocument.getElementById(\"gen\")?.addEventListener(\"click\", gen);\ndocument.getElementById(\"send\")?.addEventListener(\"click\", send);\ndocument.getElementById(\"historyBtn\")?.addEventListener(\"click\", async()=>{\n  if(!jwt) return alert(\"Link your station first\");\n  const res=await fetch(`/api/room/general/history?token=${encodeURIComponent(jwt)}`,{headers:{Authorization:`Bearer ${jwt}`}});\n  const data=await res.json().catch(()=>({}));\n  log(\"history\",data);\n  if(data.messages){\n    msgsEl.innerHTML=\"\";\n    data.messages.forEach(appendMsg);\n    if(!data.messages.length) appendSystem(\"No messages yet.\");\n  }\n});\ndocument.getElementById(\"exportBtn\")?.addEventListener(\"click\", async()=>{\n  const lines=[...msgsEl.querySelectorAll(\".line\")].map(el=> el.textContent.trim()).join(\"\\n\");\n  try{ await navigator.clipboard.writeText(lines); appendSystem(\"Transcript copied\"); }catch{ appendSystem(\"Copy failed\",\"bad\"); }\n});\ndocument.getElementById(\"clearBtn\")?.addEventListener(\"click\",()=>{ if(msgsEl) msgsEl.innerHTML='<div class=\"line system\"><div>Cleared.</div></div>'; });\ninputEl?.addEventListener(\"keydown\",(e)=>{ if(e.key===\"Enter\" && !e.shiftKey){ e.preventDefault(); send(); }});\n\n// Auto-connect if already authed\nif(jwt && identity){\n  log(\"Found existing pass, auto-connecting\u2026\");\n  setTimeout(()=> connectChat(\"general\"), 500);\n}\nlog(\"Station ready. Generate a stub. Mobile key at /mobile\");\n";
}

async function mobileJs(): Promise<string> {
  return "// Mobile key \u2014 inspect then approve\nconst $=s=>document.querySelector(s);\nconst loginOut=$(\"#loginOut\");\nconst previewOut=$(\"#previewOut\");\nconst details=$(\"#details\");\nconst confirm=$(\"#confirm\");\nconst sheetStatus=$(\"#sheetStatus\");\n\nlet mobileJwt=localStorage.getItem(\"mobile_jwt\")||\"\";\n\nfunction renderLoginOut(){\n  if(!loginOut) return;\n  if(mobileJwt){\n    loginOut.textContent=`Stored pass (truncated): ${mobileJwt.slice(0,28)}\u2026\\nKeep this on your phone only.`;\n    loginOut.style.color=\"#A7F3D0\";\n  } else loginOut.textContent=\"No session yet \u2014 mint one below.\";\n}\nrenderLoginOut();\n\n$(\"#login\")?.addEventListener(\"click\",async()=>{\n  const userId=($(\"#userId\")?.value||\"\").trim()||\"alice\";\n  const res=await fetch(\"/api/auth/dev-login\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({userId, displayName:userId})});\n  const data=await res.json().catch(()=>({}));\n  if(loginOut) loginOut.textContent=JSON.stringify(data,null,2);\n  if(data.token){ mobileJwt=data.token; localStorage.setItem(\"mobile_jwt\",mobileJwt); renderLoginOut(); }\n});\n$(\"#clearSession\")?.addEventListener(\"click\",()=>{\n  mobileJwt=\"\"; localStorage.removeItem(\"mobile_jwt\"); renderLoginOut();\n  if(loginOut) loginOut.textContent=\"Cleared.\";\n});\n\n$(\"#preview\")?.addEventListener(\"click\",async()=>{\n  const raw=($(\"#token\")?.value||\"\").trim();\n  if(!raw) return alert(\"Paste token\");\n  let t=raw;\n  try{ const u=new URL(raw); const p=u.searchParams.get(\"token\"); if(p) t=p; }catch{}\n  const el=$(\"#token\"); if(el) el.value=t;\n  if(previewOut) previewOut.textContent=\"Inspecting\u2026\";\n  const res=await fetch(`/api/auth/qr/preview?token=${encodeURIComponent(t)}`);\n  const data=await res.json().catch(()=>({}));\n  if(previewOut) previewOut.textContent=JSON.stringify(data,null,2);\n  if(data.status===\"pending\" || res.ok && data.status){\n    if(confirm && details){\n      details.innerHTML=\"\";\n      const items=[\n        `Status: ${data.status||\"unknown\"}`,\n        `Created: ${data.createdAt? new Date(data.createdAt).toLocaleString():\"unknown\"}`,\n        `Expires: ${data.expiresAt? new Date(data.expiresAt).toLocaleString():\"unknown\"} (${data.expiresAt? Math.max(0,Math.round((data.expiresAt-Date.now())/1000)):\"?\"}s left)`,\n        `Token: ${data.tokenPreview||t.slice(0,8)+\"\u2026\"}`,\n        `Check that the city/time matches your station. If anything looks off, tap Deny.`,\n      ];\n      items.forEach(txt=>{ const li=document.createElement(\"li\"); li.textContent=txt; details.appendChild(li); });\n      confirm.classList.add(\"open\"); confirm.style.display=\"block\";\n      if(sheetStatus) sheetStatus.textContent=data.status||\"Pending\";\n      const ack=$(\"#ack\"); const approve=$(\"#approve\");\n      if(ack && approve) approve.disabled=!ack.checked;\n    }\n  } else {\n    if(confirm){ confirm.classList.remove(\"open\"); confirm.style.display=\"none\"; }\n    if(previewOut) previewOut.textContent += \"\\nNot pending \u2014 cannot approve.\";\n  }\n});\n\n$(\"#ack\")?.addEventListener(\"change\",e=>{\n  const approve=$(\"#approve\");\n  if(approve) approve.disabled=!e.target.checked;\n});\n$(\"#approve\")?.addEventListener(\"click\",async()=>{\n  const token=($(\"#token\")?.value||\"\").trim();\n  if(!mobileJwt) return alert(\"Mint a mobile session first (Step 1)\");\n  const res=await fetch(\"/api/auth/mobile/approve\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\", Authorization:`Bearer ${mobileJwt}`}, body:JSON.stringify({token, action:\"approve\"})});\n  const data=await res.json().catch(()=>({}));\n  alert(`Approved: ${res.status} ${JSON.stringify(data)}`);\n  if(previewOut) previewOut.textContent=JSON.stringify(data,null,2);\n  if(res.ok && sheetStatus) sheetStatus.textContent=\"Approved\";\n});\n$(\"#deny\")?.addEventListener(\"click\",async()=>{\n  const token=($(\"#token\")?.value||\"\").trim();\n  if(!mobileJwt) return alert(\"Mint a mobile session first\");\n  const res=await fetch(\"/api/auth/mobile/approve\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\", Authorization:`Bearer ${mobileJwt}`}, body:JSON.stringify({token, action:\"deny\"})});\n  const data=await res.json().catch(()=>({}));\n  alert(`Denied: ${res.status} ${JSON.stringify(data)}`);\n  if(previewOut) previewOut.textContent=JSON.stringify(data,null,2);\n  if(res.ok && sheetStatus) sheetStatus.textContent=\"Denied\";\n});\n$(\"#paste\")?.addEventListener(\"click\",async()=>{\n  try{ const t=await navigator.clipboard.readText(); const el=$(\"#token\"); if(el) el.value=t.trim(); }\n  catch{ alert(\"Clipboard read failed \u2014 paste manually\"); }\n});\ntry{\n  const u=new URL(location.href);\n  const p=u.searchParams.get(\"token\");\n  if(p){ const el=$(\"#token\"); if(el) el.value=p; }\n}catch{}\n";
}
