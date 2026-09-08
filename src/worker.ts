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
  return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n  <title>Secure Chat \u2014 general</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Inter+Tight:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap\" rel=\"stylesheet\">\n  <script src=\"https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js\"></script>\n  <style>\n    :root{\n      --void:#0A0A0B; --soot:#101014; --card:#131318; --raised:#1C1D23; --raised-2:#26272E;\n      --line:rgba(255,255,255,.08); --line-2:rgba(255,255,255,.13);\n      --txt:#ECECED; --mut:#9A9AA3; --dim:#6B6B74; --aura:#7AA2FF;\n    }\n    *{box-sizing:border-box}\n    html,body{height:100%}\n    body{margin:0; background:var(--void); color:var(--txt); font-family:\"Inter\",system-ui,sans-serif; font-size:15px; line-height:1.55; overflow:hidden; -webkit-font-smoothing:antialiased}\n    :focus-visible{outline:2px solid var(--aura); outline-offset:2px}\n    .mono{font-family:\"JetBrains Mono\",monospace}\n    .app{display:grid; grid-template-columns:240px 1fr; height:100dvh}\n    /* sidebar \u2014 rooms + identity only */\n    .side{background:var(--soot); border-right:1px solid var(--line); display:flex; flex-direction:column; min-height:0}\n    .side-top{padding:14px 12px 6px; display:flex; flex-direction:column; gap:10px}\n    .logo{display:flex; align-items:center; gap:10px; padding:2px 6px}\n    .mark{width:30px; height:30px; border-radius:50%; background:#fff; color:#000; display:grid; place-items:center; font-weight:700; font-size:15px; font-family:\"Inter Tight\",sans-serif}\n    .logo b{font-family:\"Inter Tight\",sans-serif; font-size:14px; font-weight:600}\n    .new-btn{border:1px solid var(--line); background:transparent; color:var(--txt); border-radius:10px; padding:9px 12px; font-size:13.5px; font-weight:500; cursor:pointer; display:flex; gap:8px; align-items:center; width:100%}\n    .new-btn:hover{background:var(--raised)}\n    .side-scroll{flex:1; overflow:auto; padding:6px 12px}\n    .side-label{font-size:11.5px; font-weight:600; color:var(--dim); padding:8px 6px 4px}\n    .room{width:100%; text-align:left; border:0; background:transparent; color:var(--mut); border-radius:10px; padding:8px 10px; font-size:13.5px; cursor:pointer; display:flex; gap:9px; align-items:center}\n    .room:hover{background:var(--raised); color:var(--txt)}\n    .room.active{background:var(--raised-2); color:var(--txt)}\n    .room .hash{color:var(--dim)}\n    .side-foot{border-top:1px solid var(--line); padding:12px}\n    .user-card{display:flex; align-items:center; gap:10px; background:var(--void); border:1px solid var(--line); border-radius:12px; padding:9px 10px}\n    .avatar{width:30px; height:30px; border-radius:50%; background:#1E1F26; border:1px solid var(--line-2); display:grid; place-items:center; font-size:12px; font-weight:600; flex:0 0 auto}\n    .who{flex:1; min-width:0}\n    .who b{display:block; font-size:13px; font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis}\n    .who span{font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--mut)}\n    .link-btn{border:1px solid var(--line); background:transparent; color:var(--txt); border-radius:8px; font-size:12px; padding:6px 10px; cursor:pointer}\n    .link-btn:hover{background:var(--raised)}\n    /* main */\n    .main{display:flex; flex-direction:column; min-width:0; min-height:0}\n    .topbar{height:56px; flex:0 0 auto; display:flex; align-items:center; gap:10px; padding:0 20px; border-bottom:1px solid var(--line); background:rgba(10,10,11,.72); backdrop-filter:blur(12px)}\n    .icon-btn{border:0; background:transparent; color:var(--mut); width:30px; height:30px; border-radius:8px; cursor:pointer; display:grid; place-items:center}\n    .icon-btn:hover{background:var(--raised); color:var(--txt)}\n    .menu-btn{display:none}\n    .room-pill{font-family:\"Inter Tight\",sans-serif; font-weight:600; font-size:14px}\n    .room-pill span{color:var(--dim)}\n    .top-actions{margin-left:auto}\n    .primary-btn{border:0; background:#fff; color:#000; font-weight:600; font-size:13.5px; border-radius:11px; padding:9px 15px; cursor:pointer}\n    .primary-btn:hover{background:#E4E4E4}\n    .scroll{flex:1; overflow:auto}\n    .col{max-width:760px; margin:0 auto; padding:0 24px; width:100%}\n    .hero{padding:72px 0 8px}\n    .hero h1{margin:0 0 10px; font-family:\"Inter Tight\",sans-serif; font-weight:600; font-size:clamp(30px,4.4vw,42px); letter-spacing:-.045em; line-height:1.04}\n    .hero h1 em{font-style:normal; color:var(--mut); font-weight:500}\n    .hero p{margin:0 0 22px; color:var(--mut); font-size:14.5px}\n    #msgs{display:flex; flex-direction:column; gap:2px; padding:26px 0 18px}\n    .sys{text-align:center; color:var(--dim); font-family:\"JetBrains Mono\",monospace; font-size:11px; padding:10px}\n    .row{display:flex; gap:12px; padding:11px 8px; border-radius:14px}\n    .row:hover{background:rgba(255,255,255,.02)}\n    .row .ava{width:30px; height:30px; border-radius:50%; flex:0 0 auto; display:grid; place-items:center; font-size:12px; font-weight:600; background:var(--raised-2); border:1px solid var(--line)}\n    .row.me{flex-direction:row-reverse}\n    .row.me .ava{display:none}\n    .bubble{max-width:min(78%,560px)}\n    .row.me .bubble{background:var(--raised-2); border:1px solid var(--line); border-radius:18px 18px 5px 18px; padding:10px 14px; margin-left:auto}\n    .meta{display:flex; gap:8px; align-items:baseline; margin-bottom:2px}\n    .meta b{font-size:13px}\n    .meta time{font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--dim)}\n    .body{font-size:14.5px; line-height:1.6; white-space:pre-wrap; word-break:break-word}\n    .presence{display:none; width:fit-content; margin:0 auto 6px; font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--mut); border:1px solid var(--line); background:var(--soot); border-radius:99px; padding:5px 12px}\n    .composer-zone{flex:0 0 auto; padding:6px 0 10px; background:linear-gradient(180deg, transparent, var(--void) 30%)}\n    .composer{border:1px solid var(--line-2); background:var(--card); border-radius:26px; box-shadow:0 12px 40px rgba(0,0,0,.5)}\n    .composer:focus-within{border-color:rgba(122,162,255,.45)}\n    #msgInput{width:100%; background:transparent; border:0; outline:0; resize:none; color:var(--txt); font:inherit; font-size:14.5px; padding:15px 18px 14px; max-height:160px; display:block}\n    #msgInput::placeholder{color:var(--dim)}\n    .composer-bar{display:flex; align-items:center; padding:0 10px 10px 18px}\n    .hint{font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--dim)}\n    .spacer{flex:1}\n    .send{border:0; width:34px; height:34px; border-radius:50%; background:#fff; color:#000; display:grid; place-items:center; cursor:pointer}\n    .send:disabled{background:var(--raised-2); color:var(--dim); cursor:not-allowed}\n    .foot{text-align:center; font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--dim); padding:8px 0 14px}\n    #debug{display:none; margin:0 0 12px; background:#000; border:1px solid var(--line); border-radius:12px; padding:12px; font-family:\"JetBrains Mono\",monospace; font-size:11px; color:#B9B9C2; max-height:120px; overflow:auto; white-space:pre-wrap}\n    /* modal \u2014 ticket only */\n    .backdrop{position:fixed; inset:0; z-index:50; display:none; background:rgba(4,4,6,.62); backdrop-filter:blur(14px); align-items:center; justify-content:center; padding:20px}\n    .backdrop.open{display:flex}\n    .sheet{width:min(420px,100%); background:var(--card); border:1px solid var(--line-2); border-radius:20px; box-shadow:0 32px 90px rgba(0,0,0,.6); overflow:hidden}\n    .sheet-head{padding:18px 20px 0; display:flex; gap:12px; align-items:flex-start}\n    .sheet-head h2{margin:0; font-family:\"Inter Tight\",sans-serif; font-size:17px; font-weight:600; letter-spacing:-.02em}\n    .sheet-head p{margin:5px 0 0; font-size:13px; color:var(--mut)}\n    .qr-stage{margin:16px 20px 0; background:#fff; border-radius:16px; padding:16px; display:grid; place-items:center; min-height:248px}\n    #qr{display:grid; place-items:center; min-height:216px}\n    #qr canvas{border-radius:8px; display:block}\n    #qr .empty{color:#6B6B74; font-family:\"JetBrains Mono\",monospace; font-size:11.5px; text-align:center}\n    .verify{display:flex; align-items:center; gap:12px; margin:14px 20px 0; border:1px solid var(--line); border-radius:14px; padding:11px 14px; background:var(--void)}\n    .ring{position:relative; width:36px; height:36px; flex:0 0 auto}\n    .ring svg{transform:rotate(-90deg)}\n    .ring b{position:absolute; inset:0; display:grid; place-items:center; font-family:\"JetBrains Mono\",monospace; font-size:10px}\n    .verify .tt{flex:1; min-width:0}\n    .verify .tt b{display:block; font-size:13px}\n    .verify .tt span{font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--mut)}\n    #status{font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--mut); border:1px solid var(--line); border-radius:99px; padding:4px 10px; white-space:nowrap}\n    #linkWrap{display:none; margin:12px 20px 0; border:1px dashed var(--line-2); border-radius:12px; padding:10px 12px}\n    #link{font-family:\"JetBrains Mono\",monospace; font-size:11px; word-break:break-all}\n    .sheet-actions{display:flex; gap:8px; padding:16px 20px 20px}\n    .btn-primary{flex:1; border:0; background:#fff; color:#000; font-weight:600; font-size:14px; border-radius:12px; padding:12px; cursor:pointer}\n    .btn-quiet{background:transparent; color:var(--txt); border:1px solid var(--line-2); border-radius:12px; padding:12px 14px; font-size:13.5px; cursor:pointer}\n    .toast-stack{position:fixed; bottom:22px; left:50%; transform:translateX(-50%); z-index:60; display:flex; flex-direction:column; gap:8px; align-items:center}\n    .toast{background:var(--raised-2); border:1px solid var(--line-2); border-radius:12px; padding:10px 14px; font-size:13px}\n    @media (max-width:920px){\n      .app{grid-template-columns:1fr}\n      .side{position:fixed; z-index:40; inset:0 auto 0 0; width:272px; transform:translateX(-102%); transition:transform 200ms ease}\n      .side.open{transform:none}\n      .menu-btn{display:grid}\n      .hero{padding-top:44px}\n    }\n    @media (prefers-reduced-motion: reduce){*{animation:none !important; transition:none !important}}\n  </style>\n</head>\n<body>\n  <div class=\"app\">\n    <aside class=\"side\" id=\"sidebar\" aria-label=\"Rooms and session\">\n      <div class=\"side-top\">\n        <div class=\"logo\"><div class=\"mark\">\u2715</div><b>Secure Chat</b></div>\n        <button class=\"new-btn\" id=\"newChatBtn\">\u270e&nbsp; New chat</button>\n      </div>\n      <div class=\"side-scroll\">\n        <div class=\"side-label\">Rooms</div>\n        <button class=\"room active\" data-room=\"general\"><span class=\"hash\">#</span> general</button>\n        <button class=\"room\" data-room=\"engineering\"><span class=\"hash\">#</span> engineering</button>\n        <button class=\"room\" data-room=\"random\"><span class=\"hash\">#</span> random</button>\n      </div>\n      <div class=\"side-foot\">\n        <div class=\"user-card\">\n          <div class=\"avatar\" id=\"avatar\">?</div>\n          <div class=\"who\"><b id=\"me\">Not linked</b><span id=\"meSub\">ticket required</span></div>\n          <button class=\"link-btn\" id=\"linkDeviceBtn\">Link</button>\n        </div>\n      </div>\n    </aside>\n\n    <main class=\"main\">\n      <header class=\"topbar\">\n        <button class=\"icon-btn menu-btn\" id=\"menuBtn\" aria-label=\"Open sidebar\">\u2630</button>\n        <div class=\"room-pill\"><span>#</span> <span id=\"roomName\">general</span></div>\n        <div class=\"top-actions\"><button class=\"primary-btn\" id=\"openQrBtn\">Link device</button></div>\n      </header>\n\n      <div class=\"scroll\" id=\"scroll\">\n        <div class=\"col\">\n          <section class=\"hero\" id=\"hero\">\n            <h1>What should we<br>talk about<em> \u2014 securely?</em></h1>\n            <p>Link this device to start. The ticket burns in 90 seconds.</p>\n            <button class=\"primary-btn\" id=\"heroLinkBtn\" style=\"padding:12px 18px\">Generate link</button>\n          </section>\n          <div class=\"presence\" id=\"presence\"></div>\n          <div id=\"msgs\" role=\"log\" aria-live=\"polite\" aria-relevant=\"additions\"></div>\n        </div>\n      </div>\n\n      <div class=\"composer-zone\">\n        <div class=\"col\">\n          <pre id=\"debug\" aria-label=\"Debug log\"></pre>\n          <div class=\"composer\">\n            <textarea id=\"msgInput\" rows=\"1\" placeholder=\"Message #general\" maxlength=\"2000\" autocomplete=\"off\"></textarea>\n            <div class=\"composer-bar\">\n              <span class=\"hint\">Enter to send</span>\n              <span class=\"spacer\"></span>\n              <button class=\"send\" id=\"send\" aria-label=\"Send message\" disabled>\n                <svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\"><path d=\"M12 19V5M5 12l7-7 7 7\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>\n              </button>\n            </div>\n          </div>\n          <div class=\"foot\">Secure \u00b7 WSS \u00b7 burns on claim</div>\n        </div>\n      </div>\n    </main>\n  </div>\n\n  <div class=\"backdrop\" id=\"qrModal\" role=\"dialog\" aria-modal=\"true\" aria-labelledby=\"qrTitle\">\n    <div class=\"sheet\">\n      <div class=\"sheet-head\">\n        <div style=\"flex:1\"><h2 id=\"qrTitle\">Link this device</h2><p>Scan with your phone to approve.</p></div>\n        <button class=\"icon-btn\" id=\"qrClose\" aria-label=\"Close\">\u2a2f</button>\n      </div>\n      <div class=\"qr-stage\"><div id=\"qr\"><div class=\"empty\">Press Generate \u2014 lives 90s.</div></div></div>\n      <div class=\"verify\">\n        <div class=\"ring\" aria-hidden=\"true\">\n          <svg width=\"36\" height=\"36\" viewBox=\"0 0 36 36\"><circle cx=\"18\" cy=\"18\" r=\"15.5\" fill=\"none\" stroke=\"rgba(255,255,255,.12)\" stroke-width=\"3\"/><circle id=\"ringFg\" cx=\"18\" cy=\"18\" r=\"15.5\" fill=\"none\" stroke=\"#fff\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-dasharray=\"97.4\" stroke-dashoffset=\"0\"/></svg>\n          <b id=\"ringNum\">\u2013</b>\n        </div>\n        <div class=\"tt\"><b>Waiting for approval</b><span class=\"mono\" id=\"timerText\">No active ticket</span></div>\n        <span id=\"status\">Idle</span>\n      </div>\n      <div id=\"linkWrap\"><code id=\"link\"></code></div>\n      <div class=\"sheet-actions\">\n        <button class=\"btn-quiet\" id=\"copyLinkBtn\">Copy</button>\n        <button class=\"btn-primary\" id=\"gen\">Generate link</button>\n      </div>\n    </div>\n  </div>\n\n  <div class=\"toast-stack\" id=\"toasts\" aria-live=\"polite\"></div>\n  <script type=\"module\" src=\"/client/desktop.js\"></script>\n</body>\n</html>\n";
}

async function mobileFallbackHtml(): Promise<string> {
  return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\" />\n  <title>Verify login \u2014 Secure Chat</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Inter+Tight:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap\" rel=\"stylesheet\">\n  <style>\n    :root{--void:#0A0A0B; --card:#131318; --raised:#1C1D23; --line:rgba(255,255,255,.08); --line-2:rgba(255,255,255,.13); --txt:#ECECED; --mut:#9A9AA3; --dim:#6B6B74; --aura:#7AA2FF; --danger:#F4212E}\n    *{box-sizing:border-box}\n    body{margin:0; background:var(--void); color:var(--txt); font-family:\"Inter\",system-ui,sans-serif; font-size:15px; line-height:1.55; -webkit-font-smoothing:antialiased}\n    :focus-visible{outline:2px solid var(--aura); outline-offset:2px}\n    .mono{font-family:\"JetBrains Mono\",monospace}\n    .top{position:sticky; top:0; background:rgba(10,10,11,.8); backdrop-filter:blur(12px); border-bottom:1px solid var(--line)}\n    .top-inner{max-width:520px; margin:0 auto; padding:13px 18px; display:flex; align-items:center; gap:12px}\n    .back{border:1px solid var(--line); color:var(--txt); width:32px; height:32px; border-radius:10px; display:grid; place-items:center; text-decoration:none}\n    .top-inner b{font-family:\"Inter Tight\",sans-serif; font-size:14.5px}\n    .wrap{max-width:520px; margin:0 auto; padding:22px 18px 120px}\n    h1{margin:0; font-family:\"Inter Tight\",sans-serif; font-size:30px; font-weight:600; letter-spacing:-.04em; line-height:1.05}\n    h1 em{font-style:normal; color:var(--mut); font-weight:500}\n    .sub{margin:10px 0 0; color:var(--mut); font-size:13.5px}\n    .card{background:var(--card); border:1px solid var(--line); border-radius:18px; padding:16px; margin:14px 0}\n    .card h2{margin:0 0 10px; font-size:14px; font-family:\"Inter Tight\",sans-serif}\n    input[type=text]{width:100%; background:var(--void); border:1px solid var(--line); color:var(--txt); border-radius:12px; padding:12px 13px; font-size:14px; outline:none}\n    input:focus{border-color:rgba(122,162,255,.5)}\n    .row{display:flex; gap:8px; margin-top:10px}\n    .btn{border:0; border-radius:12px; padding:12px 14px; font-size:14px; font-weight:600; cursor:pointer}\n    .btn-primary{background:#fff; color:#000; flex:1}\n    .btn-quiet{background:transparent; color:var(--txt); border:1px solid var(--line-2); font-weight:500}\n    .btn-danger{background:var(--danger); color:#fff; flex:1}\n    .btn:disabled{opacity:.4}\n    .note{font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--mut); margin:10px 0 0; white-space:pre-wrap}\n    #confirm{display:none; border:1px solid rgba(255,255,255,.12); border-radius:14px; padding:14px; margin-top:12px}\n    #confirm.open{display:block}\n    #details{margin:0 0 4px; padding-left:18px; font-size:13px; color:var(--txt)}\n    #details li{margin:5px 0}\n    .check{display:flex; gap:10px; align-items:flex-start; margin:12px 0}\n    .check input{width:18px; height:18px; accent-color:#fff}\n    .check label{font-size:13px}\n    .dock{position:fixed; bottom:0; left:0; right:0; background:rgba(10,10,11,.88); backdrop-filter:blur(14px); border-top:1px solid var(--line); padding:12px 18px calc(14px + env(safe-area-inset-bottom))}\n    .dock-inner{max-width:520px; margin:0 auto; display:flex; gap:8px}\n  </style>\n</head>\n<body>\n  <header class=\"top\"><div class=\"top-inner\"><a class=\"back\" href=\"/desktop\" aria-label=\"Back\">\u2190</a><b>Verify login</b></div></header>\n  <div class=\"wrap\">\n    <h1>Is this you<br><em>trying to link?</em></h1>\n    <p class=\"sub\">Check it matches your desktop, then approve. The ticket burns instantly.</p>\n\n    <section class=\"card\">\n      <h2>1 \u00b7 Your session</h2>\n      <input id=\"userId\" type=\"text\" value=\"alice\" autocomplete=\"off\" aria-label=\"User id\" />\n      <div class=\"row\"><button id=\"login\" class=\"btn btn-primary\">Mint session</button></div>\n      <p class=\"note\" id=\"loginOut\">No session yet.</p>\n    </section>\n\n    <section class=\"card\">\n      <h2>2 \u00b7 The ticket</h2>\n      <input id=\"token\" type=\"text\" placeholder=\"Paste token\" autocomplete=\"off\" aria-label=\"Token\" />\n      <div class=\"row\">\n        <button id=\"paste\" class=\"btn btn-quiet\" type=\"button\">Paste</button>\n        <button id=\"preview\" class=\"btn btn-primary\">Inspect</button>\n      </div>\n      <p class=\"note\" id=\"previewOut\">Awaiting token\u2026</p>\n      <div id=\"confirm\" role=\"dialog\" aria-labelledby=\"confirmTitle\">\n        <ul id=\"details\"></ul>\n        <div class=\"check\"><input id=\"ack\" type=\"checkbox\" /><label for=\"ack\">I started this login and the time looks right.</label></div>\n      </div>\n    </section>\n  </div>\n  <div class=\"dock\" id=\"dock\" style=\"display:none\"><div class=\"dock-inner\">\n    <button id=\"deny\" class=\"btn btn-quiet\" style=\"flex:1; color:#FF8585\">Deny</button>\n    <button id=\"approve\" class=\"btn btn-primary\" disabled>Approve</button>\n  </div></div>\n  <script type=\"module\" src=\"/client/mobile.js\"></script>\n</body>\n</html>\n";
}

async function desktopJs(): Promise<string> {
  return "// Secure Chat \u2014 minimal shell. Flows unchanged: opaque ticket \u2192 approve \u2192 burn \u2192 JWT \u2192 WSS.\nconst $ = (s) => document.querySelector(s);\nconst $$ = (s) => [...document.querySelectorAll(s)];\n\nconst statusEl = $(\"#status\");\nconst timerText = $(\"#timerText\");\nconst ringFg = $(\"#ringFg\");\nconst ringNum = $(\"#ringNum\");\nconst qrEl = $(\"#qr\");\nconst linkEl = $(\"#link\");\nconst linkWrap = $(\"#linkWrap\");\nconst debugEl = $(\"#debug\");\nconst msgsEl = $(\"#msgs\");\nconst meEl = $(\"#me\");\nconst meSub = $(\"#meSub\");\nconst avatarEl = $(\"#avatar\");\nconst presenceEl = $(\"#presence\");\nconst inputEl = $(\"#msgInput\");\nconst sendBtn = $(\"#send\");\nconst heroEl = $(\"#hero\");\nconst scrollEl = $(\"#scroll\");\nconst modal = $(\"#qrModal\");\nconst toastsEl = $(\"#toasts\");\nconst roomNameEl = $(\"#roomName\");\nconst RING_C = 97.4;\n\nlet pollTimer = null, countdownTimer = null, ws = null, chatWs = null;\nlet currentToken = null, expiresAt = 0;\nlet jwt = localStorage.getItem(\"chat_jwt\") || \"\";\nlet identity = null;\ntry { identity = JSON.parse(localStorage.getItem(\"chat_identity\") || \"null\"); } catch { identity = null; }\nlet currentRoom = \"general\";\nconst debugMode = new URLSearchParams(location.search).has(\"debug\");\n\nfunction toast(t) {\n  if (!toastsEl) return;\n  const d = document.createElement(\"div\");\n  d.className = \"toast\"; d.textContent = t;\n  toastsEl.appendChild(d);\n  setTimeout(() => d.remove(), 2600);\n}\nfunction log(...a) {\n  if (debugMode && debugEl) {\n    debugEl.style.display = \"block\";\n    debugEl.textContent += a.map((x) => typeof x === \"string\" ? x : JSON.stringify(x)).join(\" \") + \"\\n\";\n  }\n  console.log(...a);\n}\nfunction setStatus(t) { if (statusEl) statusEl.textContent = t; }\nfunction setTimer() {\n  const s = expiresAt ? Math.max(0, Math.round((expiresAt - Date.now()) / 1000)) : -1;\n  if (s < 0) {\n    if (timerText) timerText.textContent = \"No active ticket\";\n    if (ringNum) ringNum.textContent = \"\u2013\";\n    if (ringFg) ringFg.style.strokeDashoffset = \"0\";\n    return;\n  }\n  if (timerText) timerText.textContent = s > 0 ? `${s}s left` : \"Expired\";\n  if (ringNum) ringNum.textContent = String(s);\n  if (ringFg) ringFg.style.strokeDashoffset = String(RING_C * (1 - s / 90));\n  if (s === 0) setStatus(\"Expired\");\n}\nfunction renderMe() {\n  const name = jwt && identity ? identity.userId : null;\n  if (meEl) meEl.textContent = name || \"Not linked\";\n  if (meSub) meSub.textContent = name ? \"pass \u00b7 1h\" : \"ticket required\";\n  if (avatarEl) avatarEl.textContent = name ? name.slice(0, 1).toUpperCase() : \"?\";\n  updateSend();\n}\nfunction updateSend() {\n  if (sendBtn && inputEl) sendBtn.disabled = !(chatWs && chatWs.readyState === 1 && inputEl.value.trim());\n}\nfunction openModal() { modal?.classList.add(\"open\"); }\nfunction closeModal() { modal?.classList.remove(\"open\"); }\nfunction updateHero() {\n  if (heroEl && msgsEl) heroEl.style.display = msgsEl.querySelector(\".row\") ? \"none\" : \"\";\n}\n\nasync function gen() {\n  setStatus(\"Issuing\u2026\");\n  if (qrEl) qrEl.innerHTML = '<div class=\"empty\">Creating\u2026</div>';\n  if (pollTimer) clearInterval(pollTimer);\n  if (countdownTimer) clearInterval(countdownTimer);\n  if (ws) try { ws.close(); } catch {}\n  openModal();\n  const res = await fetch(\"/api/auth/qr/create\", { method: \"POST\" });\n  const data = await res.json().catch(() => ({}));\n  if (!res.ok) {\n    log(\"create failed\", data);\n    setStatus(\"Failed\");\n    if (qrEl) qrEl.innerHTML = `<div class=\"empty\">Failed \u2014 try again</div>`;\n    return;\n  }\n  currentToken = data.token; expiresAt = data.expiresAt;\n  setStatus(\"Scan with mobile\");\n  setTimer();\n  countdownTimer = setInterval(setTimer, 400);\n  if (qrEl) {\n    qrEl.innerHTML = \"\";\n    const c = document.createElement(\"canvas\");\n    qrEl.appendChild(c);\n    if (typeof QRCode !== \"undefined\") await QRCode.toCanvas(c, data.url, { width: 216, margin: 1 });\n    else qrEl.textContent = data.url;\n  }\n  if (linkEl && linkWrap) { linkEl.textContent = data.url; linkWrap.style.display = \"block\"; }\n  tryWs(data.token);\n  startPolling(data.token);\n}\nfunction tryWs(token) {\n  const proto = location.protocol === \"https:\" ? \"wss:\" : \"ws:\";\n  try {\n    ws = new WebSocket(`${proto}//${location.host}/api/auth/qr/ws?token=${encodeURIComponent(token)}`);\n    ws.onmessage = (e) => {\n      try {\n        const m = JSON.parse(e.data);\n        if (m.status === \"approved\") { setStatus(\"Approved\"); claim(token); }\n        if (m.status === \"denied\") { setStatus(\"Denied\"); cleanup(); }\n        if (m.status === \"expired\") { setStatus(\"Expired\"); cleanup(); }\n      } catch {}\n    };\n  } catch {}\n}\nfunction startPolling(token) {\n  if (pollTimer) clearInterval(pollTimer);\n  pollTimer = setInterval(async () => {\n    const res = await fetch(`/api/auth/qr/status?token=${encodeURIComponent(token)}`);\n    const data = await res.json().catch(() => ({}));\n    if (data.status === \"approved\") { setStatus(\"Approved\"); claim(token); }\n    if (data.status === \"denied\") { setStatus(\"Denied\"); cleanup(); }\n    if (data.status === \"expired\") { setStatus(\"Expired\"); cleanup(); }\n  }, 1500);\n}\nasync function claim(token) {\n  cleanup();\n  const res = await fetch(\"/api/auth/qr/claim\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ token }) });\n  const data = await res.json().catch(() => ({}));\n  if (res.ok && data.token) {\n    jwt = data.token; identity = data.identity;\n    localStorage.setItem(\"chat_jwt\", jwt);\n    localStorage.setItem(\"chat_identity\", JSON.stringify(identity));\n    renderMe();\n    setStatus(\"Linked\");\n    if (timerText) timerText.textContent = \"Burned\";\n    toast(`Linked as ${identity.userId}`);\n    setTimeout(closeModal, 500);\n    connectChat(currentRoom);\n  } else setStatus(\"Claim failed\");\n}\nfunction cleanup() {\n  if (pollTimer) clearInterval(pollTimer); pollTimer = null;\n  if (countdownTimer) clearInterval(countdownTimer); countdownTimer = null;\n  if (ws) try { ws.close(); } catch {} ws = null;\n}\n\nfunction connectChat(roomId = \"general\") {\n  currentRoom = roomId;\n  if (roomNameEl) roomNameEl.textContent = roomId;\n  if (inputEl) inputEl.placeholder = `Message #${roomId}`;\n  $$(\".room\").forEach((b) => b.classList.toggle(\"active\", b.dataset.room === roomId));\n  if (chatWs) try { chatWs.close(); } catch {}\n  msgsEl.innerHTML = \"\";\n  updateHero();\n  if (!jwt) { appendSystem(\"Link this device to join.\"); renderMe(); return; }\n  const proto = location.protocol === \"https:\" ? \"wss:\" : \"ws:\";\n  chatWs = new WebSocket(`${proto}//${location.host}/api/room/${encodeURIComponent(roomId)}/ws?token=${encodeURIComponent(jwt)}`);\n  chatWs.onopen = () => renderMe();\n  chatWs.onmessage = (e) => {\n    try {\n      const d = JSON.parse(e.data);\n      if (d.type === \"welcome\") { if (d.history?.length) d.history.forEach(appendMsg); updateHero(); }\n      else if (d.type === \"message\") appendMsg(d.message);\n      else if (d.type === \"presence\" && presenceEl) {\n        presenceEl.style.display = \"block\";\n        presenceEl.textContent = `\u25cf ${d.userId} ${d.event}ed`;\n        clearTimeout(presenceEl._t);\n        presenceEl._t = setTimeout(() => (presenceEl.style.display = \"none\"), 3500);\n      }\n      else if (d.type === \"moderation\") { appendSystem(\"Blocked by moderation.\"); toast(\"Blocked\"); }\n      else if (d.type === \"error\") appendSystem(\"Error \u2014 try again.\");\n    } catch {}\n  };\n  chatWs.onclose = () => { appendSystem(\"Disconnected \u2014 reload to reconnect.\"); renderMe(); };\n  renderMe();\n}\nfunction appendMsg(m) {\n  const mine = identity && m.userId === identity.userId;\n  const div = document.createElement(\"div\");\n  div.className = \"row \" + (mine ? \"me\" : \"peer\");\n  const who = m.displayName || m.userId;\n  const time = new Date(m.ts).toLocaleTimeString([], { hour: \"2-digit\", minute: \"2-digit\" });\n  if (mine) {\n    div.innerHTML = `<div class=\"bubble\"><div class=\"body\"></div></div>`;\n    div.querySelector(\".body\").textContent = m.body;\n  } else {\n    div.innerHTML = `<div class=\"ava\"></div><div class=\"bubble\"><div class=\"meta\"><b></b><time>${time}</time></div><div class=\"body\"></div></div>`;\n    div.querySelector(\".ava\").textContent = who.slice(0, 1).toUpperCase();\n    div.querySelector(\"b\").textContent = who;\n    div.querySelector(\".body\").textContent = m.body;\n  }\n  msgsEl.appendChild(div);\n  scrollEl.scrollTop = scrollEl.scrollHeight;\n  updateHero();\n}\nfunction appendSystem(t) {\n  const d = document.createElement(\"div\");\n  d.className = \"sys\"; d.textContent = \"\u2014 \" + t;\n  msgsEl.appendChild(d);\n}\nfunction send() {\n  const body = inputEl.value.trim();\n  if (!body) return;\n  if (!chatWs || chatWs.readyState !== 1) { toast(\"Link this device first\"); openModal(); return; }\n  chatWs.send(JSON.stringify({ type: \"message\", roomId: currentRoom, body }));\n  inputEl.value = \"\";\n  autogrow(); updateSend();\n}\nfunction autogrow() {\n  inputEl.style.height = \"auto\";\n  inputEl.style.height = Math.min(160, inputEl.scrollHeight) + \"px\";\n}\n\n$(\"#gen\")?.addEventListener(\"click\", gen);\n$(\"#openQrBtn\")?.addEventListener(\"click\", () => { openModal(); if (!currentToken || Date.now() > expiresAt) gen(); });\n$(\"#linkDeviceBtn\")?.addEventListener(\"click\", () => { openModal(); if (!currentToken || Date.now() > expiresAt) gen(); });\n$(\"#heroLinkBtn\")?.addEventListener(\"click\", gen);\n$(\"#qrClose\")?.addEventListener(\"click\", closeModal);\nmodal?.addEventListener(\"click\", (e) => { if (e.target === modal) closeModal(); });\ndocument.addEventListener(\"keydown\", (e) => {\n  if (e.key === \"Escape\") { closeModal(); $(\"#sidebar\")?.classList.remove(\"open\"); }\n});\n$(\"#copyLinkBtn\")?.addEventListener(\"click\", async () => {\n  try { await navigator.clipboard.writeText(linkEl.textContent); toast(\"Copied\"); } catch { toast(\"Copy failed\"); }\n});\n$(\"#send\")?.addEventListener(\"click\", send);\ninputEl?.addEventListener(\"input\", () => { autogrow(); updateSend(); });\ninputEl?.addEventListener(\"keydown\", (e) => { if (e.key === \"Enter\" && !e.shiftKey) { e.preventDefault(); send(); } });\n$(\"#newChatBtn\")?.addEventListener(\"click\", () => { msgsEl.innerHTML = \"\"; updateHero(); inputEl?.focus(); });\n$(\"#menuBtn\")?.addEventListener(\"click\", () => $(\"#sidebar\")?.classList.add(\"open\"));\n$$(\".room\").forEach((b) => b.addEventListener(\"click\", () => { connectChat(b.dataset.room); $(\"#sidebar\")?.classList.remove(\"open\"); }));\n\nrenderMe();\nsetTimer();\nif (jwt && identity) setTimeout(() => connectChat(currentRoom), 400);\nelse appendSystem(\"Link this device to join.\");\n";
}

async function mobileJs(): Promise<string> {
  return "// Mobile \u2014 minimal verify. Contract: preview \u2192 ack \u2192 approve/deny.\nconst $ = (s) => document.querySelector(s);\nconst loginOut = $(\"#loginOut\");\nconst previewOut = $(\"#previewOut\");\nconst details = $(\"#details\");\nconst confirm = $(\"#confirm\");\nconst dock = $(\"#dock\");\nlet mobileJwt = localStorage.getItem(\"mobile_jwt\") || \"\";\n\nfunction showConfirm(open) {\n  if (confirm) confirm.classList.toggle(\"open\", open);\n  if (confirm) confirm.style.display = open ? \"block\" : \"none\";\n  if (dock) dock.style.display = open ? \"block\" : \"none\";\n}\nshowConfirm(false);\n\n$(\"#login\")?.addEventListener(\"click\", async () => {\n  const userId = ($(\"#userId\")?.value || \"\").trim() || \"alice\";\n  const res = await fetch(\"/api/auth/dev-login\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ userId, displayName: userId }) });\n  const data = await res.json().catch(() => ({}));\n  if (data.token) {\n    mobileJwt = data.token;\n    localStorage.setItem(\"mobile_jwt\", mobileJwt);\n    if (loginOut) loginOut.textContent = `Session ready as ${data.userId}.`;\n  } else if (loginOut) loginOut.textContent = \"Could not mint session.\";\n});\n$(\"#preview\")?.addEventListener(\"click\", async () => {\n  const raw = ($(\"#token\")?.value || \"\").trim();\n  if (!raw) return alert(\"Paste token\");\n  let t = raw;\n  try { const u = new URL(raw); const p = u.searchParams.get(\"token\"); if (p) t = p; } catch {}\n  $(\"#token\").value = t;\n  if (previewOut) previewOut.textContent = \"Checking\u2026\";\n  const res = await fetch(`/api/auth/qr/preview?token=${encodeURIComponent(t)}`);\n  const data = await res.json().catch(() => ({}));\n  if (data.status === \"pending\" || (res.ok && data.status)) {\n    const left = data.expiresAt ? Math.max(0, Math.round((data.expiresAt - Date.now()) / 1000)) : \"?\";\n    if (previewOut) previewOut.textContent = `Pending \u00b7 ${left}s left.`;\n    if (details) {\n      details.innerHTML = \"\";\n      [`Created ${data.createdAt ? new Date(data.createdAt).toLocaleTimeString() : \"?\"}`, `Expires in ${left}s`, `Token ${data.tokenPreview || t.slice(0, 8) + \"\u2026\"}`]\n        .forEach((x) => { const li = document.createElement(\"li\"); li.textContent = x; details.appendChild(li); });\n    }\n    const ack = $(\"#ack\"), approve = $(\"#approve\");\n    if (ack) ack.checked = false;\n    if (approve) approve.disabled = true;\n    showConfirm(true);\n  } else {\n    showConfirm(false);\n    if (previewOut) previewOut.textContent = \"Not pending \u2014 cannot approve.\";\n  }\n});\n$(\"#ack\")?.addEventListener(\"change\", (e) => { const a = $(\"#approve\"); if (a) a.disabled = !e.target.checked; });\n$(\"#approve\")?.addEventListener(\"click\", async () => {\n  const token = ($(\"#token\")?.value || \"\").trim();\n  if (!mobileJwt) return alert(\"Mint a session first\");\n  const res = await fetch(\"/api/auth/mobile/approve\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: \"approve\" }) });\n  if (res.ok) { showConfirm(false); if (previewOut) previewOut.textContent = \"Approved.\"; alert(\"Approved\"); }\n  else alert(\"Approve failed\");\n});\n$(\"#deny\")?.addEventListener(\"click\", async () => {\n  const token = ($(\"#token\")?.value || \"\").trim();\n  if (!mobileJwt) return alert(\"Mint a session first\");\n  const res = await fetch(\"/api/auth/mobile/approve\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: \"deny\" }) });\n  if (res.ok) { showConfirm(false); if (previewOut) previewOut.textContent = \"Denied.\"; }\n  else alert(\"Deny failed\");\n});\n$(\"#paste\")?.addEventListener(\"click\", async () => {\n  try { $(\"#token\").value = (await navigator.clipboard.readText()).trim(); } catch { alert(\"Paste manually\"); }\n});\ntry {\n  const p = new URL(location.href).searchParams.get(\"token\");\n  if (p) $(\"#token\").value = p;\n} catch {}\n";
}
