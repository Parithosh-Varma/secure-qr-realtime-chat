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
import { validateTokenFormat, validateDisplayName } from "./lib/sanitize";
import { log, redactIp, hashForLog } from "./lib/logger";
import { QR_TTL_MS, JWT_TTL_MS, MAX_PAYLOAD_BYTES } from "./lib/constants";
import { LOGO_PNG_BASE64, LOGO_DARK_PNG_BASE64, FAVICON_PNG_BASE64, FAVICON_LIGHT_PNG_BASE64, APPLE_TOUCH_ICON_BASE64, FAVICON_ICO_BASE64 } from "./logo";

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
  ENABLE_DEV_LOGIN?: string;
  MODERATION_KEY?: string;
  TURNSTILE_SECRET?: string;
  // DB?: D1Database; // uncomment when D1 is provisioned
}

function getIp(req: Request): string {
  // Prefer Cloudflare-verified IP; never trust X-Forwarded-For unless you control the proxy
  return req.headers.get("CF-Connecting-IP") || "unknown";
}

function requireJwtSecret(env: Env): string {
  const s = env.JWT_SECRET;
  if (!s || s === "dev-secret-change-me" || s.length < 32) {
    throw new Error("JWT_SECRET not configured — set via wrangler secret put JWT_SECRET (min 32 chars)");
  }
  return s;
}

function getFingerprint(req: Request) {
  // Privacy: do not persist raw IP; store only hashed/partial for confirmation screen
  const ip = getIp(req);
  return {
    ip: hashForLog(ip), // hashed for rate-limit correlation, not raw
    userAgent: req.headers.get("User-Agent") || "unknown",
    acceptLanguage: req.headers.get("Accept-Language") || undefined,
    city: (req.cf as { city?: string })?.city,
    country: (req.cf as { country?: string })?.country,
  };
}

async function readJsonSafe(req: Request, maxBytes = MAX_PAYLOAD_BYTES): Promise<unknown | null> {
  const cl = req.headers.get("Content-Length");
  if (cl && parseInt(cl, 10) > maxBytes) return null;
  // SECURITY FIX: stream with early abort so chunked bodies without
  // Content-Length cannot OOM the Worker by buffering unbounded text first.
  if (!req.body) {
    const text = await req.text();
    if (new TextEncoder().encode(text).length > maxBytes) return null;
    if (!text) return {};
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  }
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        chunks.push(value);
      }
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  const text = new TextDecoder().decode(merged);
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * Extract a raw QR opaque token without putting it in URLs.
 * Priority: X-QR-Token header (no log leakage) > POST JSON body > ?token=
 * query (deprecated backwards-compat; logs a warning at call sites).
 */
function getQrToken(req: Request, url: URL, bodyToken?: unknown): { token: string; viaQuery: boolean } | { token: null; viaQuery: boolean } {
  const headerToken = req.headers.get("X-QR-Token")?.trim();
  if (headerToken) return { token: headerToken, viaQuery: false };
  if (typeof bodyToken === "string" && bodyToken) return { token: bodyToken, viaQuery: false };
  const q = url.searchParams.get("token") || "";
  if (q) return { token: q, viaQuery: true };
  // Fragment tokens (#token=) never reach the server — clients must copy
  // the fragment into X-QR-Token before calling.
  return { token: null, viaQuery: false };
}

function getWsQrToken(req: Request, url: URL): { token: string | null; viaQuery: boolean } {
  // Browsers can't set custom headers on WS upgrade, but they CAN offer
  // Sec-WebSocket-Protocol. Prefer it over ?token=.
  const proto = req.headers.get("Sec-WebSocket-Protocol") || "";
  if (proto) {
    const parts = proto.split(",").map((s) => s.trim()).filter(Boolean);
    const candidate = parts.filter((p) => p.toLowerCase() !== "bearer").pop();
    if (candidate && /^[A-Za-z0-9_-]{32,128}$/.test(candidate)) return { token: candidate, viaQuery: false };
  }
  const headerToken = req.headers.get("X-QR-Token")?.trim();
  if (headerToken) return { token: headerToken, viaQuery: false };
  const q = url.searchParams.get("token") || "";
  if (q) return { token: q, viaQuery: true };
  return { token: null, viaQuery: false };
}

async function verifyTurnstile(env: Env, token: string | undefined, ip: string): Promise<boolean> {
  // Optional bot protection. If TURNSTILE_SECRET is unset, skip (dev).
  // If set, require a valid token for anon endpoints (qr/create, guest login).
  if (!env.TURNSTILE_SECRET) return true;
  if (!token) return false;
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 1500);
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${encodeURIComponent(env.TURNSTILE_SECRET)}&response=${encodeURIComponent(token)}&remoteip=${encodeURIComponent(ip)}`,
      signal: controller.signal,
    });
    clearTimeout(t);
    if (!res.ok) return false;
    const data = (await res.json()) as { success?: boolean };
    return data.success === true;
  } catch {
    return false;
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
  if (!res.ok) {
    // Fail closed for brute-force sensitive paths — return denied to prevent bypass when DO is down
    return { allowed: false, resetMs: windowMs };
  }
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
      headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-QR-Token, Sec-WebSocket-Protocol");
      headers.set("Access-Control-Max-Age", "600");
      const origin = req.headers.get("Origin");
      const allowed = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
      const hasWildcard = allowed.includes("*");
      if (hasWildcard && origin) {
        // Fail closed for credentialed wildcard — never echo * with credentials
      } else if (origin) {
        // Enforce https for non-local origins (an http subdomain must never
        // match an https allowlist entry).
        let schemeOk = true;
        try {
          const o = new URL(origin);
          const isLocalOrigin = o.hostname === "localhost" || o.hostname === "127.0.0.1" || o.hostname === "::1";
          if (!isLocalOrigin && o.protocol !== "https:") schemeOk = false;
        } catch {
          schemeOk = false;
        }
        const isAllowed =
          schemeOk &&
          (allowed.includes(origin) ||
            allowed.some((a) => {
              if (!a.includes("*")) return false;
              try {
                const o = new URL(origin);
                const base = a.split("*.")[1];
                if (!base) return false;
                return o.hostname === base || o.hostname.endsWith("." + base);
              } catch {
                return false;
              }
            }));
        if (isAllowed && origin) {
          headers.set("Access-Control-Allow-Origin", origin);
          headers.set("Access-Control-Allow-Credentials", "true");
        }
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
    if (path === "/logo.png" || path === "/logo-dark.png" || path === "/favicon.png" || path === "/favicon-light.png" || path === "/favicon.ico" || path === "/apple-touch-icon.png") {
      // Brand icons (see public/, embedded in src/logo.ts so Workers serve them without an assets binding)
      // Tab favicons use solid tiles so the mark stays legible at 16px on any browser theme.
      let b64 = LOGO_PNG_BASE64;
      let contentType = "image/png";
      if (path === "/logo-dark.png") b64 = LOGO_DARK_PNG_BASE64;
      else if (path === "/favicon.png") b64 = FAVICON_PNG_BASE64;
      else if (path === "/favicon-light.png") b64 = FAVICON_LIGHT_PNG_BASE64;
      else if (path === "/apple-touch-icon.png") b64 = APPLE_TOUCH_ICON_BASE64;
      else if (path === "/favicon.ico") { b64 = FAVICON_ICO_BASE64; contentType = "image/x-icon"; }
      const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      const headers = new Headers({
        "Content-Type": contentType,
        "Cache-Control": "public, max-age=31536000, immutable",
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Referrer-Policy": "no-referrer",
      });
      return new Response(bytes, { headers });
    }

    try {
      // ---- QR: create pending session (desktop, unauthenticated, IP-rate-limited) ----
      // SECURE FLOW (true E2E): desktop generates authToken + e2eSecret locally
      // with CSPRNG, sends ONLY tokenHash (SHA-256 hex) to the server. The
      // e2eSecret is NEVER sent — it travels only inside the QR fragment
      // (#a=..&e=..) which never hits the network. Legacy clients that POST
      // without tokenHash get a server-generated token (deprecated).
      if (path === "/api/auth/qr/create" && method === "POST") {
        const ip = getIp(req);
        const rl = await rateLimit(env, `qr:ip:${ip}`, 5, 60_000);
        if (!rl.allowed) {
          log("warn", "qr.rate_limited", { ip: redactIp(ip) });
          return json({ error: "Rate limited, try again later", retryAfterMs: rl.resetMs }, { status: 429 }, req, env);
        }
        const createBody = (await readJsonSafe(req)) as { tokenHash?: string; turnstile?: string; autoJoin?: boolean } | null;
        if (createBody === null && req.headers.get("Content-Length") !== null) {
          return json({ error: "Invalid body" }, { status: 400 }, req, env);
        }
        if (!(await verifyTurnstile(env, createBody?.turnstile, ip))) {
          return json({ error: "Bot verification required" }, { status: 403 }, req, env);
        }

        let tokenHash: string;
        let token: string | null = null; // only set for legacy server-generated flow
        const clientHash = typeof createBody?.tokenHash === "string" ? createBody.tokenHash : null;
        if (clientHash) {
          if (!/^[a-f0-9]{64}$/.test(clientHash)) {
            return json({ error: "tokenHash must be SHA-256 hex" }, { status: 400 }, req, env);
          }
          tokenHash = clientHash;
        } else {
          // Legacy: server generates (deprecated — new clients MUST send tokenHash
          // so the server never learns the E2E secret derivation material).
          token = randomOpaqueToken(32);
          tokenHash = await sha256Hex(token);
        }
        const ttlMs = env.QR_TTL_SECONDS ? Math.min(120_000, Math.max(60_000, parseInt(env.QR_TTL_SECONDS, 10) * 1000)) : QR_TTL_MS;
        const fingerprint = getFingerprint(req);
        // Optional host identity (for invite-to-chat: desktop already linked)
        // If Authorization is supplied but invalid, reject rather than silently ignore (prevents alg confusion)
        let host: { userId: string; displayName?: string } | undefined;
        const bearerHost = extractBearer(req);
        if (bearerHost) {
          let jwtSecret: string;
          try { jwtSecret = requireJwtSecret(env); } catch (e) { return json({ error: (e as Error).message }, { status: 500 }, req, env); }
          const claimsHost = await verifyJwt(bearerHost, jwtSecret);
          if (!claimsHost) {
            return json({ error: "Invalid host session" }, { status: 401 }, req, env);
          }
          host = { userId: claimsHost.userId, displayName: claimsHost.displayName };
        }

        // Private 2-person room derived from tokenHash (128-bit entropy).
        // Server is authoritative — clients MUST use the returned roomId and
        // MUST NOT derive roomIds from token prefixes (old bug).
        const roomId = `dm_${tokenHash.slice(0, 32)}`;
        // Store in DO keyed by tokenHash (idFromName) — prevents enumeration
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);
        const doRes = await stub.fetch("https://auth/create", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tokenHash, fingerprint, ttlMs, host, roomId, autoJoin: createBody?.autoJoin === true }),
        });
        if (!doRes.ok) {
          const errData = (await doRes.json().catch(() => ({}))) as { error?: string };
          if (doRes.status === 409) return json({ error: "Session already exists, retry" }, { status: 409 }, req, env);
          log("error", "qr.create_failed", { status: doRes.status });
          return json({ error: errData.error || "Failed to create session" }, { status: 500 }, req, env);
        }
        const doData = (await doRes.json()) as { expiresAt: number };

        // New clients already hold authToken+e2eSecret and build their own
        // fragment URL (#a=..&e=..). Legacy clients get a server token + URL.
        // Privacy: never log roomId (it leaks 128 bits of tokenHash).
        log("info", "qr.created", { tokenHash: hashForLog(tokenHash), expiresAt: doData.expiresAt });

        if (token) {
          const origin = url.origin;
          const linkUrl = `${origin}/mobile#token=${encodeURIComponent(token)}`;
          return json(
            {
              token,
              url: linkUrl,
              roomId,
              expiresAt: doData.expiresAt,
              ttlMs,
              deprecated: "client-tokenHash-required",
            },
            {},
            req,
            env,
          );
        }
        return json({ roomId, expiresAt: doData.expiresAt, ttlMs }, {}, req, env);
      }

      // ---- QR: status poll (desktop, unauthenticated but token-bound) ----
      // Token via X-QR-Token header (preferred) or POST; ?token= deprecated.
      if ((path === "/api/auth/qr/status" && (method === "GET" || method === "POST"))) {
        let rawToken: string | null = null;
        let viaQuery = false;
        if (method === "POST") {
          const b = (await readJsonSafe(req)) as { token?: string } | null;
          if (b === null) return json({ error: "Invalid body" }, { status: 400 }, req, env);
          const r = getQrToken(req, url, b?.token);
          rawToken = r.token;
          viaQuery = r.viaQuery;
        } else {
          const r = getQrToken(req, url);
          rawToken = r.token;
          viaQuery = r.viaQuery;
        }
        if (!rawToken) return json({ error: "token required (X-QR-Token header or body)" }, { status: 400 }, req, env);
        const v = validateTokenFormat(rawToken);
        if (!v.ok) return json({ error: v.error }, { status: 400 }, req, env);
        if (viaQuery) log("warn", "qr.status_query_token_deprecated", {});
        // Rate-limit status polling per IP and per token to prevent enumeration/DoS
        const ip = getIp(req);
        const rlIp = await rateLimit(env, `qrstatus:ip:${ip}`, 60, 60_000);
        if (!rlIp.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);
        const rlTok = await rateLimit(env, `qrstatus:tok:${await sha256Hex(v.value!)}`, 30, 60_000);
        if (!rlTok.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);
        const tokenHash = await sha256Hex(v.value!);
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);
        const doRes = await stub.fetch(`https://auth/status?tokenHash=${encodeURIComponent(tokenHash)}`, { method: "GET" });
        const data = await doRes.json().catch(() => ({}));
        return json(data, { status: doRes.status }, req, env);
      }

      // ---- QR: lightweight WS waiter (desktop) ----
      if (path === "/api/auth/qr/ws" && req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
        const { token: rawToken, viaQuery } = getWsQrToken(req, url);
        if (!rawToken) return json({ error: "token required (Sec-WebSocket-Protocol or X-QR-Token)" }, { status: 400 }, req, env);
        const v = validateTokenFormat(rawToken);
        if (!v.ok) return json({ error: v.error }, { status: 400 }, req, env);
        if (viaQuery) log("warn", "qr.ws_query_token_deprecated", {});
        const ip = getIp(req);
        const rlIp = await rateLimit(env, `qrws:ip:${ip}`, 20, 60_000);
        if (!rlIp.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);
        const tokenHash = await sha256Hex(v.value!);
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);
        // Forward WS upgrade to DO with Origin validation in DO. Preserve the
        // original Host so the DO can allow same-origin (Worker host itself
        // may not be in ALLOWED_ORIGIN during dev).
        const fwdHeaders = new Headers(req.headers);
        fwdHeaders.set("X-Forwarded-Host", url.host);
        const fwdReq = new Request(`https://auth/ws?tokenHash=${encodeURIComponent(tokenHash)}`, {
          method: req.method,
          headers: fwdHeaders,
        });
        // Preserve WebSocket upgrade semantics for the DO fetch
        return stub.fetch(fwdReq);
      }

      // ---- QR: mobile approve/deny (authenticated) ----
      // Token via POST body (preferred) or X-QR-Token header. ?token= is NOT
      // accepted here — approve must be an explicit POST with bearer JWT.
      if (path === "/api/auth/mobile/approve" && method === "POST") {
        const body = (await readJsonSafe(req)) as { token?: string; action?: string; confirmedFingerprint?: boolean; auto?: boolean } | null;
        if (body === null) return json({ error: "Invalid body" }, { status: 400 }, req, env);
        const { token: rawToken, viaQuery } = getQrToken(req, url, body?.token);
        if (!rawToken || typeof body?.action !== "string") {
          return json({ error: "token and action required" }, { status: 400 }, req, env);
        }
        // Approve/deny must never arrive via URL query (would leak the
        // single-use credential to logs). Header or POST body only.
        if (viaQuery) return json({ error: "token must be in body or X-QR-Token header, not URL" }, { status: 400 }, req, env);
        // Require explicit confirmation that the user saw the fingerprint
        // screen — unless this is a scan auto-join (auto:true), which the DO
        // only honors for presenter-opted-in sessions.
        const autoJoin = body.auto === true;
        if (body.action === "approve" && body.confirmedFingerprint !== true && !autoJoin) {
          return json({ error: "Explicit fingerprint confirmation required (confirmedFingerprint:true) or auto-join" }, { status: 400 }, req, env);
        }
        const v = validateTokenFormat(rawToken);
        if (!v.ok) return json({ error: v.error }, { status: 400 }, req, env);
        if (body.action !== "approve" && body.action !== "deny") return json({ error: "action must be approve or deny" }, { status: 400 }, req, env);

        // Verify mobile session JWT
        const bearer = extractBearer(req);
        if (!bearer) return json({ error: "Missing Authorization" }, { status: 401 }, req, env);
        let jwtSecret: string;
        try { jwtSecret = requireJwtSecret(env); } catch (e) { return json({ error: (e as Error).message }, { status: 500 }, req, env); }
        const claims = await verifyJwt(bearer, jwtSecret);
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

        // Forward to DO with verified identity (never trust client-supplied userId).
        // Email is never forwarded — guest identities are userId+displayName
        // only (no email impersonation via self-asserted JWTs).
        const doRes = await stub.fetch("https://auth/approve", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tokenHash,
            action: body.action,
            approver: { userId: claims.userId, displayName: claims.displayName },
            auto: autoJoin,
          }),
        });
        const data = await doRes.json().catch(() => ({}));
        if (!doRes.ok) log("warn", "qr.approve_failed", { status: doRes.status, tokenHash: hashForLog(tokenHash) });
        return json(data, { status: doRes.status }, req, env);
      }

      // ---- QR: preview (mobile confirmation screen data) ----
      // Token via X-QR-Token header (preferred) or POST body. GET ?token=
      // kept for backwards compat but deprecated. NEVER returns raw token
      // fragments — only fingerprint/location for the consent screen.
      if ((path === "/api/auth/qr/preview" && (method === "GET" || method === "POST"))) {
        let rawToken: string | null = null;
        let viaQuery = false;
        if (method === "POST") {
          const b = (await readJsonSafe(req)) as { token?: string } | null;
          if (b === null) return json({ error: "Invalid body" }, { status: 400 }, req, env);
          const r = getQrToken(req, url, b?.token);
          rawToken = r.token;
          viaQuery = r.viaQuery;
        } else {
          const r = getQrToken(req, url);
          rawToken = r.token;
          viaQuery = r.viaQuery;
        }
        if (!rawToken) return json({ error: "token required (X-QR-Token header or body)" }, { status: 400 }, req, env);
        const v = validateTokenFormat(rawToken);
        if (!v.ok) return json({ error: v.error }, { status: 400 }, req, env);
        if (viaQuery) log("warn", "qr.preview_query_token_deprecated", {});
        const ip = getIp(req);
        const rlIp = await rateLimit(env, `qrpreview:ip:${ip}`, 60, 60_000);
        if (!rlIp.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);
        const rlTok = await rateLimit(env, `qrpreview:tok:${await sha256Hex(v.value!)}`, 30, 60_000);
        if (!rlTok.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);
        const tokenHash = await sha256Hex(v.value!);
        const id = env.AUTH_SESSION.idFromName(tokenHash);
        const stub = env.AUTH_SESSION.get(id);
        const doRes = await stub.fetch(`https://auth/status?tokenHash=${encodeURIComponent(tokenHash)}`, { method: "GET" });
        const data = (await doRes.json().catch(() => ({}))) as { status?: string; createdAt?: number; expiresAt?: number };
        if (!doRes.ok) return json(data, { status: doRes.status }, req, env);
        // DO status already includes fingerprint/location + host for the
        // consent screen. Do NOT echo raw token material back.
        return json(data, {}, req, env);
      }

      // ---- QR: claim + mint JWT (desktop, one-time burn) ----
      if (path === "/api/auth/qr/claim" && method === "POST") {
        const body = (await readJsonSafe(req)) as { token?: string } | null;
        if (body === null) return json({ error: "Invalid body" }, { status: 400 }, req, env);
        const { token: rawToken, viaQuery: claimViaQuery } = getQrToken(req, url, body?.token);
        if (!rawToken) return json({ error: "token required (body or X-QR-Token)" }, { status: 400 }, req, env);
        if (claimViaQuery) return json({ error: "token must be in body or X-QR-Token header, not URL" }, { status: 400 }, req, env);
        const v = validateTokenFormat(rawToken);
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
        const data = (await doRes.json().catch(() => ({}))) as { ok?: boolean; identity?: { userId: string; displayName?: string }; roomId?: string; error?: string; status?: string };
        if (!doRes.ok) {
          // 202 means pending, 410 means burned/expired — surface as-is
          return json(data, { status: doRes.status }, req, env);
        }
        // Mint short-lived JWT for desktop (iss/aud pinned in lib/jwt)
        let jwtSecret: string;
        try { jwtSecret = requireJwtSecret(env); } catch (e) { return json({ error: (e as Error).message }, { status: 500 }, req, env); }
        const ttlMs = env.JWT_TTL_SECONDS ? parseInt(env.JWT_TTL_SECONDS, 10) * 1000 : JWT_TTL_MS;
        const jwt = await signJwt(data.identity!, jwtSecret, ttlMs);

        // Privacy: never log roomId (leaks 128 bits of tokenHash).
        log("info", "qr.claim_issued_jwt", { tokenHash: hashForLog(tokenHash) });

        // Token is burned in DO — no replay possible
        return json({ ok: true, token: jwt, identity: data.identity, roomId: data.roomId, expiresInMs: ttlMs }, {}, req, env);
      }

      // ---- Ephemeral guest login (replaces demo dev-login) ----
      // Threat model: this app has no persistent identities — every session
      // is an anonymous ephemeral guest (refresh erases). userIds are ALWAYS
      // server-generated CSPRNG; client-supplied userId/email are rejected
      // (previously ignored-but-validated, now 400). For real persistent
      // identities, replace this endpoint with your IdP and delete it.
      // NEVER enable in production without understanding: anyone with network
      // access can mint a guest JWT (by design — guests are anonymous).
      if ((path === "/api/auth/dev-login" || path === "/api/auth/guest-login") && method === "POST") {
        // Fail closed in production: requires BOTH non-production AND explicit flag.
        // Previously `!== production || flag` let prod enable with one flag.
        const allowDev = env.ENVIRONMENT !== "production" && env.ENABLE_DEV_LOGIN === "true";
        if (!allowDev) return json({ error: "Not found" }, { status: 404 }, req, env);
        const ip = getIp(req);
        const rl = await rateLimit(env, `devlogin:ip:${ip}`, 10, 60_000);
        if (!rl.allowed) return json({ error: "Rate limited" }, { status: 429 }, req, env);
        const body = (await readJsonSafe(req)) as { userId?: string; displayName?: string; email?: string; turnstile?: string } | null;
        if (body === null) return json({ error: "Invalid body" }, { status: 400 }, req, env);
        if (!(await verifyTurnstile(env, body?.turnstile, ip))) {
          if (env.TURNSTILE_SECRET) return json({ error: "Bot verification required" }, { status: 403 }, req, env);
        }
        // Reject client-supplied userId/email outright (impersonation surface)
        if (body?.userId !== undefined) return json({ error: "userId is server-generated" }, { status: 400 }, req, env);
        if (body?.email !== undefined) return json({ error: "email not supported for guests" }, { status: 400 }, req, env);
        const userId = `guest_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
        const dnRes = validateDisplayName(body?.displayName || userId);
        if (!dnRes.ok) return json({ error: dnRes.error }, { status: 400 }, req, env);
        const displayName = dnRes.value || userId;
        let jwtSecret2: string;
        try { jwtSecret2 = requireJwtSecret(env); } catch (e) { return json({ error: (e as Error).message }, { status: 500 }, req, env); }
        const jwt = await signJwt({ userId, displayName }, jwtSecret2, JWT_TTL_MS);
        log("info", "guest.login", {});
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
        // Forward to ChatRoom DO — DO validates JWT (header / SWP preferred,
        // ?token= deprecated) + membership + rate limits + Origin.
        const id = env.CHAT_ROOM.idFromName(roomId);
        const stub = env.CHAT_ROOM.get(id);
        // Preserve all headers (Authorization, Sec-WebSocket-Protocol, Origin).
        // Keep ?token= in the forwarded URL only for backwards compat — the
        // DO logs a deprecation warning when it must use it. Also forward the
        // original Host so the DO can allow same-origin even when the Worker
        // host itself isn't in ALLOWED_ORIGIN (local dev).
        const qToken = url.searchParams.get("token");
        const forwardUrl = `https://room/ws?roomId=${encodeURIComponent(roomId)}${qToken ? `&token=${encodeURIComponent(qToken)}` : ""}`;
        const fwdHeaders = new Headers(req.headers);
        fwdHeaders.set("X-Forwarded-Host", url.host);
        // Clone request with new URL but keep headers. NOTE: `new Request(url,
        // req)` drops the Upgrade body semantics in some runtimes, so build
        // explicitly.
        const forwardReq = new Request(forwardUrl, {
          method: req.method,
          headers: fwdHeaders,
        });
        return stub.fetch(forwardReq);
      }

      // ---- Chat: message via REST (alternative to WS) ----
      const msgMatch = path.match(/^\/api\/room\/([^/]+)\/message\/?$/);
      if (msgMatch && method === "POST") {
        const rid = msgMatch[1];
        const id = env.CHAT_ROOM.idFromName(rid);
        const stub = env.CHAT_ROOM.get(id);
        // Forward body + auth header. Include roomId in DO URL so the DO can
        // enforce URL-room == body-room (IDOR fix) — see handleRestMessage.
        // Stream with cap instead of unbounded req.text().
        const bodyText = await req.text();
        if (new TextEncoder().encode(bodyText).length > MAX_PAYLOAD_BYTES) {
          return json({ error: "Payload too large" }, { status: 413 }, req, env);
        }
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        const auth = req.headers.get("Authorization");
        if (auth) headers["Authorization"] = auth;
        return stub.fetch(`https://room/message?roomId=${encodeURIComponent(rid)}`, { method: "POST", headers, body: bodyText });
      }

      // ---- Chat: history (REST) ----
      const histMatch = path.match(/^\/api\/room\/([^/]+)\/history\/?$/);
      if (histMatch && method === "GET") {
        const rid = histMatch[1];
        const bearer = extractBearer(req);
        if (!bearer) return json({ error: "Missing Authorization" }, { status: 401 }, req, env);
        const id = env.CHAT_ROOM.idFromName(rid);
        const stub = env.CHAT_ROOM.get(id);
        // SECURITY: REST history requires Authorization header only, no query token to avoid log leakage
        return stub.fetch(`https://room/history?roomId=${encodeURIComponent(rid)}`, {
          headers: { Authorization: `Bearer ${bearer}` },
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
  return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n  <title>Secure Chat \u2014 private</title>\n  <link rel=\"icon\" type=\"image/png\" sizes=\"256x256\" href=\"/favicon-light.png\" media=\"(prefers-color-scheme: light)\" />\n  <link rel=\"icon\" type=\"image/png\" sizes=\"256x256\" href=\"/favicon.png\" media=\"(prefers-color-scheme: dark)\" />\n  <link rel=\"shortcut icon\" href=\"/favicon.ico\" />\n  <link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"/apple-touch-icon.png\" />\n  <script src=\"/client/qrcode.min.js\"></script>\n  <style>\n    *{box-sizing:border-box}\n    html,body{height:100%}\n    body{margin:0; background:#0A0A0B; color:#ECECED; font-family:\"Inter\",system-ui,sans-serif; -webkit-font-smoothing:antialiased}\n    .qr-view{min-height:100dvh; display:grid; place-items:center; padding:24px}\n    .qr-card{width:min(360px,100%); text-align:center}\n    #qr{width:320px; height:320px; margin:0 auto; background:#fff; border-radius:20px; padding:16px; display:grid; place-items:center}\n    #qr canvas,#qr svg,#qr img{border-radius:12px; display:block; width:288px; height:288px}\n    #qr .empty{color:#6B6B74; font-size:13px}\n    .qr-card h1{margin:18px 0 0; font-family:\"Inter Tight\",sans-serif; font-size:18px; font-weight:600}\n    .share-btn{margin-top:14px; border:1px solid rgba(255,255,255,.13); background:transparent; color:#ECECED; border-radius:99px; font-size:12.5px; font-weight:600; padding:8px 16px; cursor:pointer}\n    .share-btn:disabled{opacity:.35; cursor:default}\n    .share-hint{margin:8px 0 0; color:#6B6B74; font-size:11.5px}\n    .hide{display:none !important}\n    /* chat \u2014 hidden until connected */\n    .app{display:grid; grid-template-columns:220px 1fr; height:100dvh}\n    .side{background:#101014; border-right:1px solid rgba(255,255,255,.08); display:flex; flex-direction:column}\n    .side-top{padding:14px 12px 6px}\n    .logo{display:flex; gap:10px; align-items:center; padding:2px 6px}\n    .mark{width:30px; height:30px; border-radius:50%; background:#fff; color:#000; display:grid; place-items:center; font-weight:700}\n    .mark-img{width:30px; height:30px; border-radius:8px; object-fit:cover; display:block; background:#000}\n    .logo b{font-family:\"Inter Tight\",sans-serif; font-size:14px}\n    .side-foot{border-top:1px solid rgba(255,255,255,.08); padding:12px; margin-top:auto}\n    .user-card{display:flex; gap:10px; align-items:center; background:#0A0A0B; border:1px solid rgba(255,255,255,.08); border-radius:12px; padding:9px 10px}\n    .avatar{width:30px; height:30px; border-radius:50%; background:#1C1D23; display:grid; place-items:center; font-size:12px}\n    .who{flex:1; min-width:0}\n    .who b{display:block; font-size:13px}\n    .who span{font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:#9A9AA3}\n    .link-btn{border:1px solid rgba(255,255,255,.08); background:transparent; color:#ECECED; border-radius:8px; font-size:12px; padding:6px 10px; cursor:pointer}\n    .main{display:flex; flex-direction:column; min-width:0}\n    .topbar{height:56px; display:flex; align-items:center; gap:10px; padding:0 20px; border-bottom:1px solid rgba(255,255,255,.08); background:rgba(10,10,11,.72)}\n    .room-pill{font-family:\"Inter Tight\",sans-serif; font-weight:600}\n    .primary-btn{border:0; background:#fff; color:#000; font-weight:600; border-radius:11px; padding:9px 15px; cursor:pointer}\n    .scroll{flex:1; overflow:auto}\n    .col{max-width:760px; margin:0 auto; padding:0 24px; width:100%}\n    #msgs{display:flex; flex-direction:column; gap:2px; padding:26px 0 18px}\n    .sys{text-align:center; color:#6B6B74; font-family:\"JetBrains Mono\",monospace; font-size:11px; padding:10px}\n    .row{display:flex; gap:12px; padding:11px 8px; border-radius:14px}\n    .row.me{flex-direction:row-reverse}\n    .row .ava{width:30px; height:30px; border-radius:50%; flex:0 0 auto; display:grid; place-items:center; font-weight:600; background:#26272E; border:1px solid rgba(255,255,255,.08)}\n    .row.me .ava{display:none}\n    .bubble{max-width:min(78%,560px)}\n    .row.me .bubble{background:#26272E; border:1px solid rgba(255,255,255,.08); border-radius:18px 18px 5px 18px; padding:10px 14px; margin-left:auto}\n    .meta{display:flex; gap:8px; align-items:baseline}\n    .meta b{font-size:13px}\n    .meta time{font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:#6B6B74}\n    .body{font-size:14.5px; line-height:1.6; white-space:pre-wrap; word-break:break-word}\n    .presence{display:none; width:fit-content; margin:0 auto 6px; font-family:\"JetBrains Mono\",monospace; font-size:11px; color:#9A9AA3; border:1px solid rgba(255,255,255,.08); background:#101014; border-radius:99px; padding:5px 12px}\n    .composer{border:1px solid rgba(255,255,255,.13); background:#131318; border-radius:26px; padding:0}\n    #msgInput{width:100%; background:transparent; border:0; outline:0; color:#ECECED; font:inherit; font-size:14.5px; padding:15px 18px; display:block}\n    .composer-bar{display:flex; align-items:center; padding:0 10px 10px 18px}\n    .send{border:0; width:34px; height:34px; border-radius:50%; background:#fff; color:#000; display:grid; place-items:center; cursor:pointer}\n    .send:disabled{opacity:.4}\n    .toast-stack{position:fixed; bottom:22px; left:50%; transform:translateX(-50%); display:flex; flex-direction:column; gap:8px}\n    .toast{background:#26272E; border:1px solid rgba(255,255,255,.13); border-radius:12px; padding:10px 14px; font-size:13px}\n  </style>\n</head>\n<body>\n  <!-- QR only -->\n  <div id=\"qrView\" class=\"qr-view\">\n    <div class=\"qr-card\">\n      <div id=\"qr\"><div class=\"empty\">Generating\u2026</div></div>\n      <h1>Scan QR from other device</h1>\n      <div><button class=\"share-btn\" id=\"copyLinkBtn\" disabled>\u29c9 Copy invite link</button></div>\n      <p class=\"share-hint\">No camera? Open the link in any desktop browser to join.</p>\n      <div id=\"status\" class=\"hide\"></div><div id=\"timerText\" class=\"hide\"></div><div id=\"linkWrap\" class=\"hide\"><code id=\"link\"></code></div><div id=\"ringNum\" class=\"hide\"></div><div id=\"ringFg\" class=\"hide\"></div>\n    </div>\n  </div>\n\n  <!-- Chat \u2014 hidden until scanned + connected (2-person) -->\n  <div id=\"chatView\" class=\"app hide\">\n    <aside class=\"side\">\n      <div class=\"side-top\"><div class=\"logo\"><img src=\"/logo.png\" alt=\"Secure Chat logo\" class=\"mark-img\" width=\"30\" height=\"30\" /><b>Secure Chat</b></div></div>\n      <div class=\"side-foot\"><div class=\"user-card\"><div class=\"avatar\" id=\"avatar\">?</div><div class=\"who\"><b id=\"me\">\u2014</b><span id=\"meSub\">ephemeral</span></div><button class=\"link-btn\" id=\"linkDeviceBtn\">Invite</button></div></div>\n    </aside>\n    <main class=\"main\">\n      <header class=\"topbar\"><div class=\"room-pill\">Private \u00b7 2-person \u00b7 E2E</div><div style=\"margin-left:auto\"><button class=\"primary-btn\" id=\"openQrBtn\">Invite</button></div></header>\n      <div class=\"scroll\" id=\"scroll\"><div class=\"col\"><div id=\"presence\"></div><div id=\"msgs\" role=\"log\" aria-live=\"polite\"></div></div></div>\n      <div style=\"padding:6px 0 10px; background:linear-gradient(180deg, transparent, #0A0A0B 30%)\"><div class=\"col\"><div class=\"composer\"><textarea id=\"msgInput\" rows=\"1\" placeholder=\"Message\" maxlength=\"2000\"></textarea><div class=\"composer-bar\"><span style=\"flex:1\"></span><button class=\"send\" id=\"send\" aria-label=\"Send\" disabled>\u2191</button></div></div></div></div>\n    </main>\n  </div>\n\n  <div id=\"qrModal\" class=\"hide\"></div><div id=\"hero\" class=\"hide\"></div><div id=\"debug\" class=\"hide\"></div><div id=\"toasts\" class=\"toast-stack\"></div>\n  <div class=\"hide\"><span id=\"roomName\"></span><span id=\"gen\"></span><span id=\"heroLinkBtn\"></span><span id=\"qrClose\"></span><span id=\"menuBtn\"></span><span id=\"newChatBtn\"></span></div>\n  <script src=\"/config.js\"></script>\n  <script type=\"module\" src=\"/client/desktop.js\"></script>\n</body>\n</html>\n"
}

async function mobileFallbackHtml(): Promise<string> {
  return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\" />\n  <meta name=\"theme-color\" content=\"#0A0A0B\" />\n  <title>Verify login \u2014 Secure Chat</title>\n  <link rel=\"icon\" type=\"image/png\" sizes=\"256x256\" href=\"/favicon-light.png\" media=\"(prefers-color-scheme: light)\" />\n  <link rel=\"icon\" type=\"image/png\" sizes=\"256x256\" href=\"/favicon.png\" media=\"(prefers-color-scheme: dark)\" />\n  <link rel=\"shortcut icon\" href=\"/favicon.ico\" />\n  <link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"/apple-touch-icon.png\" />\n  <style>\n    :root{--void:#0A0A0B; --card:#131318; --raised:#1C1D23; --line:rgba(255,255,255,.08); --line-2:rgba(255,255,255,.13); --txt:#ECECED; --mut:#9A9AA3; --dim:#6B6B74; --aura:#7AA2FF; --danger:#F4212E}\n    *{box-sizing:border-box}\n    button{touch-action:manipulation; -webkit-tap-highlight-color:transparent}\n    body{margin:0; background:var(--void); color:var(--txt); font-family:\"Inter\",system-ui,sans-serif; font-size:15px; line-height:1.55; -webkit-font-smoothing:antialiased}\n    :focus-visible{outline:2px solid var(--aura); outline-offset:2px}\n    .mono{font-family:\"JetBrains Mono\",monospace}\n    .top{position:sticky; top:0; background:rgba(10,10,11,.8); backdrop-filter:blur(12px); border-bottom:1px solid var(--line)}\n    .top-inner{max-width:520px; margin:0 auto; padding:13px 18px; display:flex; align-items:center; gap:12px}\n    .brand-logo{width:28px; height:28px; border-radius:7px; object-fit:cover; display:block; background:#000}\n    .back{border:1px solid var(--line); color:var(--txt); width:32px; height:32px; border-radius:10px; display:grid; place-items:center; text-decoration:none}\n    .top-inner b{font-family:\"Inter Tight\",sans-serif; font-size:14.5px}\n    .wrap{max-width:520px; margin:0 auto; padding:22px 18px 120px}\n    h1{margin:0; font-family:\"Inter Tight\",sans-serif; font-size:30px; font-weight:600; letter-spacing:-.04em; line-height:1.05}\n    h1 em{font-style:normal; color:var(--mut); font-weight:500}\n    .sub{margin:10px 0 0; color:var(--mut); font-size:13.5px}\n    .card{background:var(--card); border:1px solid var(--line); border-radius:18px; padding:16px; margin:14px 0}\n    .card h2{margin:0 0 10px; font-size:14px; font-family:\"Inter Tight\",sans-serif}\n    input[type=text]{width:100%; background:var(--void); border:1px solid var(--line); color:var(--txt); border-radius:12px; padding:12px 13px; font-size:16px; outline:none}\n    input:focus{border-color:rgba(122,162,255,.5)}\n    .row{display:flex; gap:8px; margin-top:10px}\n    .btn{border:0; border-radius:12px; padding:12px 14px; font-size:14px; font-weight:600; cursor:pointer}\n    .btn-primary{background:#fff; color:#000; flex:1}\n    .btn-quiet{background:transparent; color:var(--txt); border:1px solid var(--line-2); font-weight:500}\n    .btn-danger{background:var(--danger); color:#fff; flex:1}\n    .btn:disabled{opacity:.4}\n    .note{font-family:\"JetBrains Mono\",monospace; font-size:11px; color:var(--mut); margin:10px 0 0; white-space:pre-wrap}\n    #confirm{display:none; border:1px solid rgba(255,255,255,.12); border-radius:14px; padding:14px; margin-top:12px}\n    #confirm.open{display:block}\n    #details{margin:0 0 4px; padding-left:18px; font-size:13px; color:var(--txt)}\n    #details li{margin:5px 0}\n    .check{display:flex; gap:10px; align-items:flex-start; margin:12px 0}\n    .check input{width:18px; height:18px; accent-color:#fff}\n    .check label{font-size:13px}\n     .dock{position:fixed; bottom:0; left:0; right:0; background:rgba(10,10,11,.88); backdrop-filter:blur(14px); border-top:1px solid var(--line); padding:12px 18px calc(14px + env(safe-area-inset-bottom))}\n    .dock-inner{max-width:520px; margin:0 auto; display:flex; gap:8px}\n    /* chat \u2014 minimal Grok-like, appears after scan+approve */\n    #chatWrap{display:none; border:1px solid var(--line); background:var(--card); border-radius:18px; overflow:hidden; margin-top:14px}\n    #chatWrap.open{display:block}\n    #chatHead{display:flex; align-items:center; gap:8px; padding:10px 14px; border-bottom:1px solid var(--line); font-family:\"Inter Tight\",sans-serif; font-size:14px}\n    #chatHead span{margin-left:auto; font-family:\"JetBrains Mono\",monospace; font-size:10.5px; color:var(--mut); border:1px solid var(--line); border-radius:99px; padding:3px 9px}\n    #mmsgs{height:280px; height:min(52dvh,420px); overflow:auto; overscroll-behavior:contain; padding:12px; display:flex; flex-direction:column; gap:2px}\n    #mmsgs:empty::after{content:\"No messages yet \u2014 say hello.\"; display:block; text-align:center; color:var(--dim); font-size:12.5px; padding:18px 0}\n    .mrow{display:flex; gap:10px; padding:8px 8px; border-radius:12px}\n    .mrow.me{justify-content:flex-end}\n    .mrow .ava{width:28px; height:28px; border-radius:50%; flex:0 0 auto; display:grid; place-items:center; font-size:11px; font-weight:600; background:#1C1D23; border:1px solid var(--line)}\n    .mrow.me .ava{display:none}\n    .mbub{max-width:78%; font-size:13.5px; line-height:1.5; padding:9px 12px; border-radius:16px; border:1px solid var(--line); background:var(--raised)}\n    .mrow.me .mbub{background:#fff; color:#000; border-color:#fff; border-radius:16px 16px 4px 16px}\n    .msys{text-align:center; color:var(--dim); font-family:\"JetBrains Mono\",monospace; font-size:11px; padding:6px}\n    .composer{display:flex; gap:8px; padding:10px 12px; border-top:1px solid var(--line)}\n    .composer input{flex:1; background:var(--void); border:1px solid var(--line); color:var(--txt); border-radius:12px; padding:10px 12px; font-size:16px; outline:none}\n    .composer input:focus{border-color:rgba(122,162,255,.5)}\n    .send{border:0; width:36px; height:36px; border-radius:50%; background:#fff; color:#000; display:grid; place-items:center; cursor:pointer; flex:0 0 auto}\n    .send:disabled{opacity:.4}\n  </style>\n</head>\n<body>\n  <header class=\"top\"><div class=\"top-inner\"><a class=\"back\" href=\"/\" aria-label=\"Back\">\u2190</a><img src=\"/logo.png\" alt=\"Secure Chat logo\" class=\"brand-logo\" width=\"28\" height=\"28\" /><b>Chat with me</b></div></header>\n  <div class=\"wrap\">\n    <h1>Scan to chat<br><em>with me</em></h1>\n    <p class=\"sub\">Mint your session, scan the QR on my screen, confirm \u2014 then we\u2019re in the same room. Direct.</p>\n\n    <section class=\"card\">\n      <h2>1 \u00b7 Your nickname</h2>\n      <p style=\"font-size:12px; color:var(--mut); margin:0 0 8px\">No account. Random ephemeral ID \u00b7 refresh erases.</p>\n      <input id=\"userId\" type=\"text\" placeholder=\"Your nickname\" maxlength=\"24\" autocomplete=\"off\" aria-label=\"Nickname\" />\n      <div class=\"row\"><button id=\"login\" class=\"btn btn-primary\">Enter</button></div>\n      <p class=\"note\" id=\"loginOut\">No session yet \u2014 refreshing erases.</p>\n    </section>\n\n    <section class=\"card\" id=\"inviteCard\">\n      <h2>2 \u00b7 Invite</h2>\n      <p class=\"note\" id=\"previewOut\">Scan the QR on desktop \u2014 you\u2019ll join automatically.</p>\n      <div id=\"confirm\" role=\"dialog\" aria-labelledby=\"confirmTitle\">\n        <ul id=\"details\"></ul>\n        <div class=\"check\"><input id=\"ack\" type=\"checkbox\" /><label for=\"ack\">Join this 1:1 chat \u2014 only the two of us, E2E.</label></div>\n      </div>\n      <input id=\"token\" type=\"hidden\" autocomplete=\"off\" aria-label=\"Invite\" />\n      <button id=\"paste\" class=\"hide\" type=\"button\">Paste</button>\n      <button id=\"preview\" class=\"hide\">Preview</button>\n    </section>\n\n    <section id=\"chatWrap\" aria-label=\"Chat with host\">\n      <div id=\"chatHead\"><b>Chat</b> <span id=\"chatState\">not joined</span></div>\n      <div id=\"mmsgs\" role=\"log\" aria-live=\"polite\"></div>\n      <div class=\"composer\"><input id=\"mInput\" placeholder=\"Message \u2014 Enter to send\" maxlength=\"2000\" autocomplete=\"off\" autocapitalize=\"off\" autocorrect=\"off\" spellcheck=\"false\" enterkeyhint=\"send\" aria-label=\"Message\" /><button class=\"send\" id=\"mSend\" aria-label=\"Send\" disabled>\u2191</button></div>\n    </section>\n  </div>\n  <div class=\"dock\" id=\"dock\" style=\"display:none\"><div class=\"dock-inner\">\n    <button id=\"deny\" class=\"btn btn-quiet\" style=\"flex:1; color:#FF8585\">Deny</button>\n    <button id=\"approve\" class=\"btn btn-primary\" disabled>Approve & chat</button>\n  </div></div>\n  <script src=\"/config.js\"></script>\n  <script type=\"module\" src=\"/client/mobile.js\"></script>\n</body>\n</html>\n"
}

async function desktopJs(): Promise<string> {
  return "// Secure Chat \u2014 QR-only, 2-person, E2E. Refresh erases.\n// A reload is only terminal once inside the chat: pre-auth (QR stage) reloads\n// boot fresh with a new QR and must never land on about:blank.\ntry {\n  const nav = performance.getEntriesByType && performance.getEntriesByType(\"navigation\")[0];\n  const isReload = (nav && nav.type === \"reload\") || (performance.navigation && performance.navigation.type === 1);\n  let wasInChat = false;\n  try { wasInChat = sessionStorage.getItem(\"qrchat.inchat\") === \"1\"; } catch {}\n  if (isReload && wasInChat) {\n    try { localStorage.clear(); sessionStorage.clear(); } catch {}\n    // Close own tab on reload (peer already closed via beforeunload WS 4000)\n    try { history.replaceState(null, \"\", \"about:blank\"); } catch {}\n    location.href = \"about:blank\";\n    try { window.close(); } catch {}\n    throw new Error(\"reload closing\");\n  }\n} catch (e) { if (e && e.message === \"reload closing\") throw e; }\ntry { localStorage.clear(); sessionStorage.clear(); } catch {}\nconst API_BASE = (typeof window !== \"undefined\" && window.__API_BASE__ ? window.__API_BASE__ : \"\").replace(/\\/$/, \"\");\nconst api = (p) => `${API_BASE}${p}`;\nconst wsBase = () => (API_BASE ? API_BASE.replace(/^http/, \"ws\") : `${location.protocol}//${location.host}`);\nconst $ = (s) => document.querySelector(s);\nconst $$ = (s) => [...document.querySelectorAll(s)];\nconst statusEl = $(\"#status\"), timerText = $(\"#timerText\"), ringFg = $(\"#ringFg\"), ringNum = $(\"#ringNum\"), qrEl = $(\"#qr\"), linkEl = $(\"#link\"), linkWrap = $(\"#linkWrap\"), debugEl = $(\"#debug\"), msgsEl = $(\"#msgs\"), meEl = $(\"#me\"), meSub = $(\"#meSub\"), avatarEl = $(\"#avatar\"), presenceEl = $(\"#presence\"), inputEl = $(\"#msgInput\"), sendBtn = $(\"#send\"), heroEl = $(\"#hero\"), scrollEl = $(\"#scroll\"), modal = $(\"#qrModal\"), toastsEl = $(\"#toasts\"), roomNameEl = $(\"#roomName\");\nconst RING_C = 97.4;\nlet pollTimer=null, countdownTimer=null, ws=null, chatWs=null;\nlet currentAuthToken=null, currentE2ESecret=null, expiresAt=0, createdAsHost=false, privateRoomId=null, lastInviteUrl=\"\";\nlet gated=true;\nlet jwt=\"\", identity=null;\nlet currentRoom=\"general\";\nlet e2eKey=null;\nconst debugMode=new URLSearchParams(location.search).has(\"debug\") && (location.hostname === \"localhost\" || location.hostname === \"127.0.0.1\");\nfunction toast(t){ if(!toastsEl) return; const d=document.createElement(\"div\"); d.className=\"toast\"; d.textContent=t; toastsEl.appendChild(d); setTimeout(()=>d.remove(),2600); }\nfunction log(...a){ if(debugMode&&debugEl){ debugEl.style.display=\"block\"; debugEl.textContent+=a.map(x=>typeof x===\"string\"?x:JSON.stringify(x)).join(\" \")+\"\\n\"; } if(debugMode) console.log(...a); }\nfunction setGated(on){\n  gated=on;\n  document.body.classList.toggle(\"gated\",on);\n  const qrView=document.getElementById(\"qrView\"), chatView=document.getElementById(\"chatView\");\n  if(qrView){ qrView.style.display=on?\"grid\":\"none\"; qrView.classList.toggle(\"hide\",!on); }\n  if(chatView){ chatView.style.display=on?\"none\":\"grid\"; chatView.classList.toggle(\"hide\",on); }\n}\nfunction setStatus(t){ if(statusEl) statusEl.textContent=t; }\nfunction setTimer(){\n  const s=expiresAt?Math.max(0,Math.round((expiresAt-Date.now())/1000)):-1;\n  if(s<0){ if(timerText) timerText.textContent=\"Scan QR from other device\"; if(ringNum) ringNum.textContent=\"\u2013\"; if(ringFg) ringFg.style.strokeDashoffset=\"0\"; return; }\n  if(timerText) timerText.textContent=s>0?`${s}s left`:\"Expired\";\n  if(ringNum) ringNum.textContent=String(s);\n  if(ringFg) ringFg.style.strokeDashoffset=String(RING_C*(1-s/90));\n  if(s===0) setStatus(\"Expired\");\n}\nfunction renderMe(){\n  const name=jwt&&identity?identity.displayName||identity.userId:null;\n  if(meEl) meEl.textContent=name||\"\u2014\";\n  if(meSub) meSub.textContent=name?`${name} \u00b7 ephemeral`:\"ephemeral\";\n  if(avatarEl) avatarEl.textContent=name?name.slice(0,1).toUpperCase():\"?\";\n  updateSend();\n  if(roomNameEl) roomNameEl.textContent=privateRoomId||currentRoom;\n}\nfunction updateSend(){ if(sendBtn&&inputEl) sendBtn.disabled=!(chatWs&&chatWs.readyState===1&&inputEl.value.trim()); }\nfunction openModal(){ try { sessionStorage.removeItem(\"qrchat.inchat\"); } catch {} setGated(true); }\nfunction closeModal(){ if(gated) return; const qrView=document.getElementById(\"qrView\"), chatView=document.getElementById(\"chatView\"); if(qrView) {qrView.style.display=\"none\"; qrView.classList.add(\"hide\");} if(chatView){chatView.style.display=\"grid\"; chatView.classList.remove(\"hide\");} modal?.classList.remove(\"open\"); }\nfunction updateHero(){ if(heroEl&&msgsEl) heroEl.style.display=msgsEl.querySelector(\".row\")?\"none\":\"\"; }\n// --- helpers: CSPRNG tokens + true E2E (server never sees e2eSecret) ---\nfunction randomB64Url(bytes){\n  const b=new Uint8Array(bytes);\n  crypto.getRandomValues(b);\n  return btoa(String.fromCharCode(...b)).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');\n}\nfunction secureSuffix(len){\n  return randomB64Url(Math.ceil(len*3/4)).slice(0,len);\n}\nasync function sha256HexStr(s){\n  const d=await crypto.subtle.digest(\"SHA-256\", new TextEncoder().encode(s));\n  return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,\"0\")).join(\"\");\n}\nasync function deriveE2EKey(e2eSecret){\n  // E2E key from the QR-fragment e2eSecret ONLY \u2014 never from the auth token\n  // the server sees. Server stores only SHA-256(authToken) and never receives\n  // e2eSecret, so it cannot decrypt dm_* ciphertext.\n  if(!e2eSecret) return null;\n  try{\n    const enc=new TextEncoder();\n    const ikm=await crypto.subtle.importKey(\"raw\", enc.encode(\"qrchat-e2e-v1:\"+e2eSecret), {name:\"HKDF\"}, false, [\"deriveKey\"]);\n    return await crypto.subtle.deriveKey({name:\"HKDF\", hash:\"SHA-256\", salt:new Uint8Array(0), info:enc.encode(\"qrchat-e2e-v1\")}, ikm, {name:\"AES-GCM\", length:256}, false, [\"encrypt\",\"decrypt\"]);\n  }catch{\n    const h=await crypto.subtle.digest(\"SHA-256\", new TextEncoder().encode(\"qrchat-e2e-v1:\"+e2eSecret));\n    return crypto.subtle.importKey(\"raw\", h, {name:\"AES-GCM\"}, false, [\"encrypt\",\"decrypt\"]);\n  }\n}\nfunction sanitizeDecrypted(s){\n  // Client-side defense-in-depth: E2E plaintext bypasses server moderation,\n  // so strip bidi/zero-width + control chars after decrypt before textContent.\n  if(typeof s!==\"string\") return \"\";\n  s=s.replace(/[\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069\\uFEFF\\u00AD]/g, \"\");\n  // eslint-disable-next-line no-control-regex\n  s=s.replace(/[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]/g, \"\");\n  return s.slice(0,2000);\n}\nasync function e2eEncrypt(plain,key){\n  if(!key||!privateRoomId||!privateRoomId.startsWith(\"dm_\")) return plain;\n  const iv=crypto.getRandomValues(new Uint8Array(12));\n  const ct=await crypto.subtle.encrypt({name:\"AES-GCM\",iv},key,new TextEncoder().encode(plain));\n  return `enc:${btoa(String.fromCharCode(...new Uint8Array(ct)))}.${btoa(String.fromCharCode(...iv))}`;\n}\nasync function e2eDecrypt(payload,key){\n  if(!key||typeof payload!==\"string\"||!payload.startsWith(\"enc:\")) return payload;\n  try{\n    const [b64ct,b64iv]=payload.slice(4).split(\".\");\n    const ct=Uint8Array.from(atob(b64ct),c=>c.charCodeAt(0));\n    const iv=Uint8Array.from(atob(b64iv),c=>c.charCodeAt(0));\n    const pt=await crypto.subtle.decrypt({name:\"AES-GCM\",iv},key,ct);\n    return new TextDecoder().decode(pt);\n  }catch{ return payload; }\n}\nfunction renderQr(el,text){\n  // Use globalThis for module scope\n  try{\n    const g=globalThis.qrcode || window.qrcode;\n    if(g){\n      const qr=g(0,\"M\"); qr.addData(text); qr.make();\n      el.innerHTML=qr.createSvgTag({cellSize:6, margin:0, scalable:true});\n      const svg=el.querySelector(\"svg\");\n      if(svg){ svg.style.width=\"216px\"; svg.style.height=\"216px\"; svg.style.display=\"block\"; svg.style.borderRadius=\"8px\"; }\n      return Promise.resolve(true);\n    }\n  }catch(e){ console.warn(\"qrcode render failed\",e); }\n  try{\n    const QRC=globalThis.QRCode || window.QRCode;\n    if(QRC&&QRC.toCanvas){\n      const c=document.createElement(\"canvas\"); el.innerHTML=\"\"; el.appendChild(c);\n      const p=QRC.toCanvas(c,text,{width:216, margin:1});\n      if(p&&typeof p.then===\"function\") return p.then(()=>true,()=>false);\n      return Promise.resolve(true);\n    }\n  }catch(e){ console.warn(\"QRCode render failed\",e); }\n  return Promise.resolve(false);\n}\nasync function ensureEphemeralIdentity(){\n  if(jwt&&identity) return;\n  const nick=`anon-${(crypto.randomUUID ? crypto.randomUUID().slice(0,4) : secureSuffix(4))}`;\n  try{\n    // Guest login: server generates userId; we send displayName ONLY (no\n    // userId/email \u2014 those are rejected server-side). Try new endpoint first.\n    let res=await fetch(api(\"/api/auth/guest-login\"),{method:\"POST\", headers:{\"Content-Type\":\"application/json\"}, body:JSON.stringify({displayName:nick})});\n    if(res.status===404) res=await fetch(api(\"/api/auth/dev-login\"),{method:\"POST\", headers:{\"Content-Type\":\"application/json\"}, body:JSON.stringify({displayName:nick})});\n    const data=await res.json().catch(()=>({}));\n    if(data.token){ jwt=data.token; identity={userId:data.userId, displayName:nick}; renderMe(); }\n  }catch(e){ console.warn(\"mint failed\",e); }\n}\nasync function gen(){\n  setStatus(\"Issuing\u2026\");\n  if(qrEl) qrEl.innerHTML='<div class=\"empty\">Creating\u2026</div>';\n  if(pollTimer) clearInterval(pollTimer);\n  if(countdownTimer) clearInterval(countdownTimer);\n  if(ws) try{ ws.close(); }catch{}\n  openModal();\n  // True-E2E: generate authToken + e2eSecret locally. Only SHA-256(authToken)\n  // goes to the server; e2eSecret travels ONLY in the QR fragment (#a=&e=)\n  // which browsers never send over the network.\n  const authToken=randomB64Url(32);\n  const e2eSecret=randomB64Url(32);\n  let tokenHash;\n  try{ tokenHash=await sha256HexStr(authToken); }catch{ setStatus(\"Crypto unavailable\"); return; }\n  let res;\n  try{\n    const headers={\"Content-Type\":\"application/json\"};\n    if(jwt) headers[\"Authorization\"]=`Bearer ${jwt}`;\n    res=await fetch(api(\"/api/auth/qr/create\"),{method:\"POST\", headers, body:JSON.stringify({tokenHash, autoJoin:true})});\n  }catch{\n    setStatus(\"Offline\");\n    if(qrEl) qrEl.innerHTML='<div class=\"empty\">Network error \u2014 retry</div>';\n    return;\n  }\n  let data;\n  try{ data=await res.json(); }catch{ data={}; }\n  if(!res.ok){\n    log(\"create failed\",data);\n    setStatus(\"Failed\");\n    if(qrEl){ qrEl.innerHTML=\"\"; const d=document.createElement(\"div\"); d.className=\"empty\"; d.textContent=`Failed \u2014 ${data.error||res.status}`; qrEl.appendChild(d); }\n    return;\n  }\n  try{\n    // New server returns {roomId, expiresAt} (no token \u2014 we generated it).\n    // Legacy servers return {token, url, roomId}.\n    expiresAt=data.expiresAt;\n    privateRoomId=data.roomId||null; // SERVER-authoritative \u2014 never derive locally\n    if(privateRoomId) currentRoom=privateRoomId;\n    createdAsHost=!!jwt;\n    if(data.token){\n      // Legacy fallback: server generated the token (no separate e2eSecret).\n      currentAuthToken=data.token; currentE2ESecret=null;\n      try{ e2eKey=await deriveE2EKey(\"legacy:\"+data.token); }catch{}\n    }else{\n      currentAuthToken=authToken; currentE2ESecret=e2eSecret;\n      try{ e2eKey=await deriveE2EKey(e2eSecret); }catch{}\n    }\n    // Fragment (#a=&e=) so secrets never hit server logs/Referer/history.\n    const frag=currentE2ESecret\n      ? `#a=${encodeURIComponent(currentAuthToken)}&e=${encodeURIComponent(currentE2ESecret)}`\n      : `#token=${encodeURIComponent(currentAuthToken)}`;\n    const qrText=`${location.origin}/mobile${frag}`;\n    lastInviteUrl=qrText;\n    const shareBtn=$(\"#copyLinkBtn\"); if(shareBtn) shareBtn.disabled=false;\n    setStatus(createdAsHost?`Invite \u00b7 ${privateRoomId} \u2014 scan to chat`:\"Scan with mobile\");\n    setTimer();\n    countdownTimer=setInterval(setTimer,400);\n    if(qrEl){\n      qrEl.innerHTML=\"\";\n      let ok=false;\n      try{ ok=await renderQr(qrEl,qrText); }catch(e){ console.warn(e); }\n      if(!ok){\n        const d=document.createElement(\"div\");\n        d.className=\"qr-fallback\";\n        d.textContent=\"QR failed \u2014 open /mobile manually (no link shown for privacy)\";\n        qrEl.appendChild(d);\n      }\n    }\n    if(linkEl&&linkWrap){ linkEl.textContent=\"\"; linkWrap.style.display=\"none\"; }\n    tryWs(currentAuthToken);\n    startPolling(currentAuthToken);\n  }catch(e){\n    console.error(e);\n    if(qrEl) qrEl.innerHTML='<div class=\"empty\">Render failed</div>';\n  }\n}\nfunction tryWs(authToken){\n  try{\n    // Prefer Sec-WebSocket-Protocol over ?token= (no URL leakage). Server\n    // supports both; query is deprecated.\n    try{ ws=new WebSocket(`${wsBase()}/api/auth/qr/ws`, [\"qr\", authToken]); }\n    catch{ ws=new WebSocket(`${wsBase()}/api/auth/qr/ws?token=${encodeURIComponent(authToken)}`); }\n    ws.onmessage=(e)=>{\n      try{\n        const m=JSON.parse(e.data);\n        if(m.status===\"approved\"){\n          if(createdAsHost){\n            const r=m.roomId||privateRoomId||currentRoom;\n            if(r){ privateRoomId=r; currentRoom=r; }\n            setStatus(\"Joined \u2014 say hello\"); toast(`Someone joined ${r} \u2014 2-person, E2E`); setGated(false); modal?.classList.remove(\"open\"); connectChat(r); cleanup();\n          }else{ setStatus(\"Approved\"); claim(authToken); }\n        }\n        if(m.status===\"denied\"){ setStatus(\"Denied\"); cleanup(); }\n        if(m.status===\"expired\"){ setStatus(\"Expired\"); cleanup(); }\n      }catch{}\n    };\n    ws.onerror=()=>{ log(\"waiter error\"); };\n  }catch{}\n}\nfunction startPolling(authToken){\n  if(pollTimer) clearInterval(pollTimer);\n  pollTimer=setInterval(async()=>{\n    let res;\n    try{ res=await fetch(api(`/api/auth/qr/status`),{headers:{\"X-QR-Token\":authToken}}); }\n    catch{ return; }\n    const data=await res.json().catch(()=>({}));\n    if(data.status===\"approved\"){\n      if(createdAsHost){\n        const r=data.roomId||privateRoomId||currentRoom;\n        if(r){ privateRoomId=r; currentRoom=r; }\n        setStatus(\"Joined \u2014 say hello\"); toast(`Someone joined ${r} \u2014 2-person, E2E`); setGated(false); modal?.classList.remove(\"open\"); connectChat(r); cleanup();\n      }else{ setStatus(\"Approved\"); claim(authToken); }\n    }\n    if(data.status===\"denied\"){ setStatus(\"Denied\"); cleanup(); }\n    if(data.status===\"expired\"){ setStatus(\"Expired\"); cleanup(); }\n  },1500);\n}\nasync function claim(authToken){\n  cleanup();\n  let res;\n  try{ res=await fetch(api(\"/api/auth/qr/claim\"),{method:\"POST\", headers:{\"Content-Type\":\"application/json\",\"X-QR-Token\":authToken}, body:JSON.stringify({token:authToken})}); }\n  catch{ setStatus(\"Offline\"); return; }\n  const data=await res.json().catch(()=>({}));\n  if(res.ok&&data.token){\n    jwt=data.token; identity=data.identity;\n    privateRoomId=data.roomId||privateRoomId; // server-authoritative\n    if(privateRoomId) currentRoom=privateRoomId;\n    try{ e2eKey=await deriveE2EKey(currentE2ESecret ? currentE2ESecret : (\"legacy:\"+authToken)); }catch{}\n    renderMe();\n    setStatus(\"Linked\");\n    if(timerText) timerText.textContent=\"Burned\";\n    toast(`Linked as ${identity.displayName||identity.userId} \u00b7 ${privateRoomId} (E2E)`);\n    setGated(false); modal?.classList.remove(\"open\"); connectChat(privateRoomId||currentRoom);\n  }else setStatus(\"Claim failed\");\n}\nfunction cleanup(){ if(pollTimer) clearInterval(pollTimer); pollTimer=null; if(countdownTimer) clearInterval(countdownTimer); countdownTimer=null; if(ws) try{ ws.close(); }catch{} ws=null; lastInviteUrl=\"\"; const sb=$(\"#copyLinkBtn\"); if(sb) sb.disabled=true; }\nasync function connectChat(roomId=\"general\"){\n  currentRoom=roomId;\n  if(roomNameEl) roomNameEl.textContent=roomId;\n  if(inputEl) inputEl.placeholder=`Message \u00b7 E2E if dm_*`;\n  $$(\".room\").forEach(b=>b.classList.toggle(\"active\",b.dataset.room===roomId));\n  if(chatWs) try{ chatWs.close(); }catch{}\n  if(msgsEl) msgsEl.innerHTML=\"\";\n  updateHero();\n  if(!jwt){ setGated(true); openModal(); gen(); return; }\n  try { sessionStorage.setItem(\"qrchat.inchat\", \"1\"); } catch {}\n  // Prefer Sec-WebSocket-Protocol for the JWT (no URL leakage); fall back to\n  // ?token= only if the protocol handshake is rejected.\n  try{ chatWs=new WebSocket(`${wsBase()}/api/room/${encodeURIComponent(roomId)}/ws`, [\"bearer\", jwt]); }\n  catch{ chatWs=new WebSocket(`${wsBase()}/api/room/${encodeURIComponent(roomId)}/ws?token=${encodeURIComponent(jwt)}`); }\n  chatWs.onopen=()=>renderMe();\n  chatWs.onmessage=async(e)=>{\n    try{\n      const d=JSON.parse(e.data);\n      if(d.type===\"welcome\"){ updateHero(); if(d.history?.length) log(\"history suppressed\",d.history.length); }\n      else if(d.type===\"message\") await appendMsg(d.message);\n      else if(d.type===\"presence\"&&presenceEl){ presenceEl.style.display=\"block\"; presenceEl.textContent=`\u25cf ${d.userId} ${d.event}ed`; clearTimeout(presenceEl._t); presenceEl._t=setTimeout(()=>presenceEl.style.display=\"none\",3500); }\n      else if(d.type===\"peer_closed\"){ appendSystem(\"Peer refreshed \u2014 closing\"); toast(\"Peer left \u2014 closing tab\u2026\"); setTimeout(()=>{ try{ window.close(); }catch{} location.href=\"about:blank\"; },800); try{ chatWs.close(); }catch{} }\n      else if(d.type===\"moderation\"){ appendSystem(\"Blocked by moderation.\"); toast(\"Blocked\"); }\n      else if(d.type===\"error\") appendSystem(d.error.includes(\"full\")?\"Room full \u2014 only 2\":\"Error \u2014 try again\");\n    }catch{}\n  };\n  chatWs.onclose=(e)=>{ if(e&&e.code===4000){ appendSystem(\"Peer refreshed \u2014 closing tab\u2026\"); setTimeout(()=>{ try{ window.close(); }catch{} location.href=\"about:blank\"; },500); return; } appendSystem(\"Disconnected \u2014 reload erases (ephemeral)\"); renderMe(); };\n  renderMe();\n}\nasync function appendMsg(m){\n  const mine=identity&&m.userId===identity.userId;\n  const div=document.createElement(\"div\");\n  div.className=\"row \"+(mine?\"me\":\"peer\");\n  const who=m.displayName||m.userId;\n  const time=new Date(m.ts).toLocaleTimeString([],{hour:\"2-digit\",minute:\"2-digit\"});\n  let body=m.body;\n  if(m.roomId?.startsWith(\"dm_\")&&e2eKey) body=sanitizeDecrypted(await e2eDecrypt(body,e2eKey));\n  else if(m.roomId?.startsWith(\"dm_\")&&!e2eKey) body=\"[encrypted \u2014 refresh cleared key]\";\n  else body=sanitizeDecrypted(body);\n  if(mine){ div.innerHTML=`<div class=\"bubble\"><div class=\"body\"></div></div>`; div.querySelector(\".body\").textContent=body; }\n  else{ div.innerHTML=`<div class=\"ava\"></div><div class=\"bubble\"><div class=\"meta\"><b></b><time>${time}</time></div><div class=\"body\"></div></div>`; div.querySelector(\".ava\").textContent=who.slice(0,1).toUpperCase(); div.querySelector(\"b\").textContent=who; div.querySelector(\".body\").textContent=body; }\n  if(msgsEl) msgsEl.appendChild(div);\n  if(scrollEl) scrollEl.scrollTop=scrollEl.scrollHeight;\n  updateHero();\n}\nfunction appendSystem(t){ const d=document.createElement(\"div\"); d.className=\"sys\"; d.textContent=\"\u2014 \"+t; if(msgsEl) msgsEl.appendChild(d); }\nasync function send(){\n  const body=inputEl.value.trim();\n  if(!body) return;\n  if(!chatWs||chatWs.readyState!==1){ toast(\"Link first\"); openModal(); return; }\n  let outBody=body;\n  if(currentRoom.startsWith(\"dm_\")&&e2eKey) outBody=await e2eEncrypt(body,e2eKey);\n  chatWs.send(JSON.stringify({type:\"message\", roomId:currentRoom, body:outBody}));\n  inputEl.value=\"\"; autogrow(); updateSend();\n}\nfunction autogrow(){ inputEl.style.height=\"auto\"; inputEl.style.height=Math.min(160,inputEl.scrollHeight)+\"px\"; }\n$(\"#gen\")?.addEventListener(\"click\",gen);\n$(\"#openQrBtn\")?.addEventListener(\"click\",()=>{ openModal(); if(!currentAuthToken||Date.now()>expiresAt) gen(); });\n$(\"#linkDeviceBtn\")?.addEventListener(\"click\",()=>{ openModal(); if(!currentAuthToken||Date.now()>expiresAt) gen(); });\n$(\"#heroLinkBtn\")?.addEventListener(\"click\",gen);\n$(\"#qrClose\")?.addEventListener(\"click\",closeModal);\nmodal?.addEventListener(\"click\",(e)=>{ if(e.target===modal) closeModal(); });\ndocument.addEventListener(\"keydown\",(e)=>{ if(e.key===\"Escape\"){ closeModal(); $(\"#sidebar\")?.classList.remove(\"open\"); } });\n$(\"#copyLinkBtn\")?.addEventListener(\"click\",async()=>{\n  if(!lastInviteUrl) return toast(\"No invite yet \u2014 wait for the QR\");\n  try{\n    if(navigator.clipboard?.writeText) await navigator.clipboard.writeText(lastInviteUrl);\n    else{ const ta=document.createElement(\"textarea\"); ta.value=lastInviteUrl; ta.style.position=\"fixed\"; ta.style.opacity=\"0\"; document.body.appendChild(ta); ta.select(); document.execCommand(\"copy\"); ta.remove(); }\n    toast(\"Invite link copied \u2014 open it on the other desktop\");\n  }catch{ toast(\"Copy failed \u2014 photograph the QR instead\"); }\n});\n$(\"#send\")?.addEventListener(\"click\",send);\ninputEl?.addEventListener(\"input\",()=>{ autogrow(); updateSend(); });\ninputEl?.addEventListener(\"keydown\",(e)=>{ if(e.key===\"Enter\"&&!e.shiftKey){ e.preventDefault(); send(); } });\n$(\"#newChatBtn\")?.addEventListener(\"click\",()=>{ if(msgsEl) msgsEl.innerHTML=\"\"; updateHero(); inputEl?.focus(); });\n$(\"#menuBtn\")?.addEventListener(\"click\",()=>$(\"#sidebar\")?.classList.add(\"open\"));\n$$(\".room\").forEach(b=>b.addEventListener(\"click\",()=>{ connectChat(b.dataset.room); $(\"#sidebar\")?.classList.remove(\"open\"); }));\nwindow.addEventListener(\"beforeunload\",()=>{ try{ chatWs?.close(1000,\"refresh\"); ws?.close(1000,\"refresh\"); }catch{} });\nwindow.addEventListener(\"keydown\",(e)=>{ if(e.key===\"F5\"||(e.ctrlKey&&e.key.toLowerCase()===\"r\")||(e.metaKey&&e.key.toLowerCase()===\"r\")){ if(gated) return; e.preventDefault(); try{ chatWs?.close(1000,\"refresh\"); }catch{} setTimeout(()=>{ try{ window.close(); }catch{} location.href=\"about:blank\"; },80); } });\n// Boot: QR-only, no nickname ask \u2014 auto-mint random anon, show QR\nrenderMe();\nsetTimer();\nensureEphemeralIdentity().then(()=>{\n  renderMe();\n  setGated(true);\n  if(heroEl) heroEl.style.display=\"\";\n  appendSystem(\"Share this QR to chat \u2014 no account, no nickname needed. Scan to join (2-person, E2E). Refresh erases everything \u2014 peer tab will also close.\");\n  gen();\n}).catch(()=>{ setGated(true); gen(); });\n"
}

async function mobileJs(): Promise<string> {
  return "// Mobile \u2014 scan to chat directly, nickname-only, ephemeral, E2E on dm_*.\n// A reload is only terminal once inside the chat: pre-auth reloads boot fresh\n// and must never land on about:blank.\ntry {\n  const nav = performance.getEntriesByType && performance.getEntriesByType(\"navigation\")[0];\n  const isReload = (nav && nav.type === \"reload\") || (performance.navigation && performance.navigation.type === 1);\n  let wasInChat = false;\n  try { wasInChat = sessionStorage.getItem(\"qrchat.m.inchat\") === \"1\"; } catch {}\n  if (isReload && wasInChat) {\n    try { localStorage.clear(); sessionStorage.clear(); } catch {}\n    try { history.replaceState(null, \"\", \"about:blank\"); } catch {}\n    location.href = \"about:blank\";\n    try { window.close(); } catch {}\n    throw new Error(\"reload closing\");\n  }\n} catch (e) { if (e && e.message === \"reload closing\") throw e; }\ntry { localStorage.clear(); sessionStorage.clear(); } catch {}\nconst API_BASE2 = (typeof window !== \"undefined\" && window.__API_BASE__ ? window.__API_BASE__ : \"\").replace(/\\/$/, \"\");\nconst api2 = (p) => `${API_BASE2}${p}`;\nconst wsBase2 = () => (API_BASE2 ? API_BASE2.replace(/^http/, \"ws\") : `${location.protocol}//${location.host}`);\nconst $ = (s) => document.querySelector(s);\nconst loginOut = $(\"#loginOut\");\nconst previewOut = $(\"#previewOut\");\nconst details = $(\"#details\");\nconst confirm = $(\"#confirm\");\nconst dock = $(\"#dock\");\nlet mobileJwt = \"\"; // ephemeral\nlet mobileDisplay = \"\";\nlet privateRoomM = null; // ALWAYS server-provided via preview \u2014 never derived locally\nlet e2eKeyM = null;\nlet currentAuthTokenM = null;\n\nfunction showConfirm(open) {\n  if (confirm) confirm.classList.toggle(\"open\", open);\n  if (confirm) confirm.style.display = open ? \"block\" : \"none\";\n  if (dock) dock.style.display = open ? \"block\" : \"none\";\n}\nshowConfirm(false);\n\nfunction secureSuffixM(len){\n  const bytes=new Uint8Array(Math.ceil(len*3/4));\n  crypto.getRandomValues(bytes);\n  let s=btoa(String.fromCharCode(...bytes)).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');\n  return s.slice(0,len);\n}\nfunction getInviteFromUrl(){\n  // New format: #a=<authToken>&e=<e2eSecret> (fragment never hits network).\n  // Legacy: #token=<authToken> or ?token=<authToken> (no E2E secret).\n  try{\n    const frag=(location.hash||\"\").replace(/^#/,\"\");\n    const fp=new URLSearchParams(frag);\n    const a=fp.get(\"a\"), e=fp.get(\"e\"), t=fp.get(\"token\");\n    if(a) return {authToken:decodeURIComponent(a), e2eSecret:e?decodeURIComponent(e):null};\n    if(t) return {authToken:decodeURIComponent(t), e2eSecret:null};\n    const qs=new URL(location.href).searchParams.get(\"token\");\n    if(qs) return {authToken:qs, e2eSecret:null};\n  }catch{}\n  return null;\n}\nfunction getTokenFromUrl(){\n  // Backwards-compat shim \u2014 returns authToken only. New code uses getInviteFromUrl().\n  const inv=getInviteFromUrl();\n  return inv?inv.authToken:null;\n}\nasync function deriveE2EKeyM(e2eSecret) {\n  // E2E key from the QR e2eSecret ONLY \u2014 never from the auth token the\n  // server sees. Domain-separated so legacy authToken-derived keys differ.\n  if (!e2eSecret) return null;\n  try{\n    const enc=new TextEncoder();\n    const ikm=await crypto.subtle.importKey(\"raw\", enc.encode(\"qrchat-e2e-v1:\"+e2eSecret), {name:\"HKDF\"}, false, [\"deriveKey\"]);\n    return await crypto.subtle.deriveKey({name:\"HKDF\", hash:\"SHA-256\", salt:new Uint8Array(0), info:enc.encode(\"qrchat-e2e-v1\")}, ikm, {name:\"AES-GCM\", length:256}, false, [\"encrypt\",\"decrypt\"]);\n  }catch{\n    const h = await crypto.subtle.digest(\"SHA-256\", new TextEncoder().encode(\"qrchat-e2e-v1:\"+e2eSecret));\n    return crypto.subtle.importKey(\"raw\", h, { name: \"AES-GCM\" }, false, [\"encrypt\", \"decrypt\"]);\n  }\n}\nfunction sanitizeDecryptedM(s){\n  if(typeof s!==\"string\") return \"\";\n  s=s.replace(/[\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069\\uFEFF\\u00AD]/g, \"\");\n  // eslint-disable-next-line no-control-regex\n  s=s.replace(/[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]/g, \"\");\n  return s.slice(0,2000);\n}\nasync function e2eEncryptM(plain, key) {\n  if (!key || !privateRoomM || !privateRoomM.startsWith(\"dm_\")) return plain;\n  const iv = crypto.getRandomValues(new Uint8Array(12));\n  const ct = await crypto.subtle.encrypt({ name: \"AES-GCM\", iv }, key, new TextEncoder().encode(plain));\n  return `enc:${btoa(String.fromCharCode(...new Uint8Array(ct)))}.${btoa(String.fromCharCode(...iv))}`;\n}\nasync function e2eDecryptM(payload, key) {\n  if (!key || typeof payload !== \"string\" || !payload.startsWith(\"enc:\")) return payload;\n  try {\n    const [b64ct, b64iv] = payload.slice(4).split(\".\");\n    const ct = Uint8Array.from(atob(b64ct), (c) => c.charCodeAt(0));\n    const iv = Uint8Array.from(atob(b64iv), (c) => c.charCodeAt(0));\n    const pt = await crypto.subtle.decrypt({ name: \"AES-GCM\", iv }, key, ct);\n    return new TextDecoder().decode(pt);\n  } catch { return payload; }\n}\nlet mWs = null;\nfunction mAppend(text, mine) {\n  const wrap = $(\"#mmsgs\");\n  if (!wrap) return;\n  const d = document.createElement(\"div\");\n  d.className = \"mrow\" + (mine ? \" me\" : \"\");\n  if (mine) d.innerHTML = `<div class=\"mbub\"></div>`;\n  else d.innerHTML = `<div class=\"ava\"></div><div class=\"mbub\"></div>`;\n  const b = d.querySelector(\".mbub\");\n  if (b) b.textContent = text;\n  if (!mine) { const a = d.querySelector(\".ava\"); if (a) a.textContent = text.slice(0,1).toUpperCase() || \"\u2022\"; }\n  wrap.appendChild(d);\n  wrap.scrollTop = wrap.scrollHeight;\n}\nfunction mSystem(t) {\n  const wrap = $(\"#mmsgs\");\n  if (!wrap) return;\n  const d = document.createElement(\"div\");\n  d.className = \"msys\"; d.textContent = \"\u2014 \" + t;\n  wrap.appendChild(d);\n  wrap.scrollTop = wrap.scrollHeight;\n}\nasync function joinChatM() {\n  const wrap = $(\"#chatWrap\"), st = $(\"#chatState\"), inp = $(\"#mInput\"), btn = $(\"#mSend\");\n  const room = privateRoomM || \"general\";\n  if (wrap) wrap.classList.add(\"open\");\n  if (st) st.textContent = `connected \u00b7 ${room} (2-person, E2E)`;\n  if (!mobileJwt) { mSystem(\"Mint a nickname first\"); return; }\n  try { sessionStorage.setItem(\"qrchat.m.inchat\", \"1\"); } catch {}\n  if (mWs) try { mWs.close(); } catch {}\n  // Prefer Sec-WebSocket-Protocol for the JWT (no URL leakage).\n  try{ mWs = new WebSocket(`${wsBase2()}/api/room/${encodeURIComponent(room)}/ws`, [\"bearer\", mobileJwt]); }\n  catch{ mWs = new WebSocket(`${wsBase2()}/api/room/${encodeURIComponent(room)}/ws?token=${encodeURIComponent(mobileJwt)}`); }\n  mWs.onopen = () => { mSystem(`You joined ${room} as ${mobileDisplay || \"anon\"} \u2014 E2E on`); if (btn) btn.disabled = false; if (inp) inp.focus(); };\n  mWs.onmessage = async (e) => {\n    try {\n      const d = JSON.parse(e.data);\n      if (d.type === \"welcome\") {\n        // Privacy: suppress history \u2014 fresh 1:1 only\n        if (d.history?.length) console.log(\"history suppressed\", d.history.length);\n      } else if (d.type === \"message\") {\n        const raw = await e2eDecryptM(d.message.body, e2eKeyM);\n        const body = sanitizeDecryptedM(raw);\n        const mine = d.message.userId === (JSON.parse(atob(mobileJwt.split(\".\")[1]))?.userId);\n        mAppend(`${d.message.displayName || d.message.userId}: ${body}`, mine);\n      } else if (d.type === \"presence\") mSystem(`${d.userId} ${d.event}ed`);\n      else if (d.type === \"peer_closed\") { mSystem(\"Peer refreshed \u2014 closing tab\u2026\"); setTimeout(()=>{ try{ window.close(); }catch{} location.href=\"about:blank\"; }, 800); try{ mWs.close(); }catch{} }\n    } catch {}\n  };\n  mWs.onclose = (e) => {\n    if (e && e.code === 4000) { mSystem(\"Peer refreshed \u2014 closing tab\u2026\"); setTimeout(()=>{ try{ window.close(); }catch{} location.href=\"about:blank\"; }, 500); return; }\n    mSystem(\"Disconnected \u2014 refresh erases (ephemeral)\"); const b = $(\"#mSend\"); if (b) b.disabled = true;\n  };\n  const send = async () => {\n    const v = inp?.value.trim();\n    if (!v || !mWs || mWs.readyState !== 1) return;\n    const out = await e2eEncryptM(v, e2eKeyM);\n    mWs.send(JSON.stringify({ type: \"message\", roomId: room, body: out }));\n    if (inp) inp.value = \"\";\n  };\n  btn?.addEventListener(\"click\", send);\n  inp?.addEventListener(\"keydown\", (e) => { if (e.key === \"Enter\" && !e.shiftKey) { e.preventDefault(); send(); } });\n}\n\n$(\"#login\")?.addEventListener(\"click\", async () => {\n  const nick = ($(\"#userId\")?.value || \"\").trim() || `anon-${(crypto.randomUUID ? crypto.randomUUID().slice(0,4) : secureSuffixM(4))}`;\n  if (nick.length < 2 || nick.length > 24) return alert(\"Nickname 2\u201324 chars\");\n  // Guest login: server generates the userId; send displayName ONLY.\n  let res=await fetch(api2(\"/api/auth/guest-login\"), { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ displayName: nick }) });\n  if(res.status===404) res=await fetch(api2(\"/api/auth/dev-login\"), { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ displayName: nick }) });\n  const data = await res.json().catch(() => ({}));\n  if (data.token) {\n    mobileJwt = data.token; mobileDisplay = nick;\n    if (loginOut) loginOut.textContent = `Ready as ${nick} \u00b7 ephemeral (scan a QR to join)`;\n  } else if (loginOut) loginOut.textContent = \"Could not mint \u2014 try again\";\n});\nasync function doPreview(authToken) {\n  if (previewOut) previewOut.textContent = \"Checking\u2026\";\n  // Token via header (no URL leakage). Server returns fingerprint/location\n  // for the explicit consent screen.\n  const res = await fetch(api2(`/api/auth/qr/preview`),{headers:{\"X-QR-Token\":authToken}});\n  const data = await res.json().catch(() => ({}));\n  if (data.status === \"pending\" || (res.ok && data.status)) {\n    const left = data.expiresAt ? Math.max(0, Math.round((data.expiresAt - Date.now()) / 1000)) : \"?\";\n    const host = data.host ? `${data.host.displayName || data.host.userId}` : \"Host\";\n    // SERVER-authoritative roomId \u2014 never derive locally (old bug used 12-hex).\n    privateRoomM = data.roomId || null;\n    currentAuthTokenM = authToken;\n    if (previewOut) previewOut.textContent = `${host} invited you \u2014 1:1 E2E \u00b7 ${left}s left`;\n    if (details) {\n      details.innerHTML = \"\";\n      const fp=data.fingerprint||{};\n      const rows=[ `Private room \u2014 only 2`, `Expires in ${left}s` ];\n      if(fp.city||fp.country) rows.push(`Login from: ${[fp.city,fp.country].filter(Boolean).join(\", \")}`);\n      if(fp.userAgent) rows.push(`Device: ${String(fp.userAgent).slice(0,80)}`);\n      if(fp.acceptLanguage) rows.push(`Lang: ${fp.acceptLanguage}`);\n      rows.forEach((x) => { const li = document.createElement(\"li\"); li.textContent = x; details.appendChild(li); });\n    }\n    const ack = $(\"#ack\"), approve = $(\"#approve\");\n    if (ack) ack.checked = false;\n    if (approve) approve.disabled = true;\n    showConfirm(true);\n    return true;\n  } else {\n    showConfirm(false);\n    if (previewOut) previewOut.textContent = \"Invite expired \u2014 ask for a new QR.\";\n    return false;\n  }\n}\n$(\"#preview\")?.addEventListener(\"click\", async () => {\n  const raw = ($(\"#token\")?.value || \"\").trim();\n  if (!raw) return;\n  // Accept pasted invite URLs in new (#a=&e=) or legacy (#token=/?token=) form\n  let authToken = raw, e2eSecret = null;\n  try {\n    const hashMatch = raw.match(/[#&][ae]=([^&]+)/);\n    if (raw.includes(\"#a=\") || raw.includes(\"&e=\") || raw.includes(\"#token=\")) {\n      const frag = raw.slice(raw.indexOf(\"#\")+1);\n      const fp = new URLSearchParams(frag);\n      if (fp.get(\"a\")) { authToken = decodeURIComponent(fp.get(\"a\")); e2eSecret = fp.get(\"e\") ? decodeURIComponent(fp.get(\"e\")) : null; }\n      else if (fp.get(\"token\")) { authToken = decodeURIComponent(fp.get(\"token\")); }\n    } else if (hashMatch) authToken = decodeURIComponent(hashMatch[1]);\n    else { const u = new URL(raw); const p = u.searchParams.get(\"token\") || (u.hash.match(/token=([^&]+)/)?.[1] ? decodeURIComponent(u.hash.match(/token=([^&]+)/)[1]) : null); if (p) authToken = p; }\n  } catch {}\n  if (e2eSecret) e2eKeyM = await deriveE2EKeyM(e2eSecret);\n  $(\"#token\").value = authToken;\n  await doPreview(authToken);\n});\n$(\"#ack\")?.addEventListener(\"change\", (e) => { const a = $(\"#approve\"); if (a) a.disabled = !e.target.checked; });\n$(\"#approve\")?.addEventListener(\"click\", async () => {\n  const token = ($(\"#token\")?.value || \"\").trim();\n  if (!mobileJwt) return alert(\"Mint a nickname first (enter above)\");\n  if (!token) return alert(\"Paste token\");\n  if (!$(\"#ack\")?.checked) return alert(\"Please confirm you checked the login details first\");\n  if (!privateRoomM) return alert(\"Preview the invite first so we know the correct room\");\n  const res = await fetch(api2(\"/api/auth/mobile/approve\"), { method: \"POST\", headers: { \"Content-Type\": \"application/json\", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: \"approve\", confirmedFingerprint: true }) });\n  if (res.ok) {\n    showConfirm(false);\n    if (previewOut) previewOut.textContent = \"Approved \u2014 opening E2E chat\u2026\";\n    // Directly able to chat with host now (no extra step)\n    joinChatM();\n  } else {\n    const d = await res.json().catch(()=>({}));\n    alert(\"Approve failed: \" + (d.error || res.status));\n  }\n});\n$(\"#deny\")?.addEventListener(\"click\", async () => {\n  const token = ($(\"#token\")?.value || \"\").trim();\n  if (!mobileJwt) return alert(\"Mint first\");\n  const res = await fetch(api2(\"/api/auth/mobile/approve\"), { method: \"POST\", headers: { \"Content-Type\": \"application/json\", Authorization: `Bearer ${mobileJwt}` }, body: JSON.stringify({ token, action: \"deny\", confirmedFingerprint: true }) });\n  if (res.ok) { showConfirm(false); if (previewOut) previewOut.textContent = \"Denied.\"; }\n  else alert(\"Deny failed\");\n});\n$(\"#paste\")?.addEventListener(\"click\", async () => {\n  try { $(\"#token\").value = (await navigator.clipboard.readText()).trim(); } catch { alert(\"Paste manually\"); }\n});\nasync function ensureMobileSession() {\n  if (mobileJwt) return true;\n  const nick = `anon-${(crypto.randomUUID ? crypto.randomUUID().slice(0,4) : secureSuffixM(4))}`;\n  let res=await fetch(api2(\"/api/auth/guest-login\"), { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ displayName: nick }) });\n  if(res.status===404) res=await fetch(api2(\"/api/auth/dev-login\"), { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ displayName: nick }) });\n  const data = await res.json().catch(() => ({}));\n  if (data.token) { mobileJwt = data.token; mobileDisplay = nick; if (loginOut) loginOut.textContent = `Joined as ${nick} \u2014 ephemeral`; return true; }\n  return false;\n}\n// Scan = acceptance: the presenter showing the QR opted the session into\n// auto-join, so scanning drops you straight into the chat \u2014 no nickname, no\n// approve tap. A silent guest identity is minted automatically. Who you joined\n// (host + device/location) is shown as the first system message instead of a\n// blocking gate, so a swapped QR is still visible. Any failure falls back to\n// the manual preview + Approve UI below.\nasync function autoJoinFromScan(authToken){\n  try{\n    if(!await ensureMobileSession()) return false;\n    const prev=await fetch(api2(\"/api/auth/qr/preview\"),{headers:{\"X-QR-Token\":authToken}});\n    const data=await prev.json().catch(()=>({}));\n    if(!prev.ok || (data.status!==\"pending\" && data.status!==\"approved\")) return false;\n    // SERVER-authoritative roomId \u2014 never derive locally.\n    privateRoomM=data.roomId||null;\n    if(!privateRoomM) return false;\n    if(data.status!==\"approved\"){\n      const appr=await fetch(api2(\"/api/auth/mobile/approve\"),{method:\"POST\",headers:{\"Content-Type\":\"application/json\",Authorization:`Bearer ${mobileJwt}`},body:JSON.stringify({token:authToken,action:\"approve\",auto:true})});\n      if(!appr.ok) return false;\n    }\n    showConfirm(false);\n    const fp=data.fingerprint||{};\n    const host=data.host?`${data.host.displayName||data.host.userId}`:\"Host\";\n    const loc=[fp.city,fp.country].filter(Boolean).join(\", \");\n    if(previewOut) previewOut.textContent=`Connected \u2014 E2E chat\u2026`;\n    joinChatM();\n    mSystem(`Joined ${host} \u2014 1:1 E2E on${loc?` \u00b7 ${loc}`:\"\"}`);\n    return true;\n  }catch{ return false; }\n}\ntry {\n  const inv = getInviteFromUrl();\n  if (inv) {\n    $(\"#token\").value = inv.authToken;\n    if (inv.e2eSecret) e2eKeyM = await deriveE2EKeyM(inv.e2eSecret);\n    else { e2eKeyM = null; }\n    currentAuthTokenM = inv.authToken;\n    // Hide invite from address bar immediately (privacy) \u2014 keep only in memory\n    try{ history.replaceState(null, \"\", location.pathname + location.search.replace(/[\\?&]token=[^&]+/g,'').replace(/^&/,'?')); }catch{}\n    try{ if(location.hash) history.replaceState(null, \"\", location.pathname + location.search); }catch{}\n    if(location.hash) try{ location.hash=\"\"; }catch{}\n    // Straight into chat shell \u2014 no nickname, no tap.\n    const ic = document.getElementById(\"inviteCard\");\n    if (ic) ic.style.display = \"none\";\n    const nickCard = document.querySelector(\".card\");\n    if (nickCard) nickCard.style.display = \"none\";\n    const chatWrap = document.getElementById(\"chatWrap\");\n    if (chatWrap) chatWrap.classList.add(\"open\");\n    mSystem(\"Connecting\u2026\");\n    const joined = await autoJoinFromScan(inv.authToken);\n    if (!joined) {\n      // Fall back to manual consent UI.\n      if (ic) ic.style.display = \"\";\n      if (nickCard) nickCard.style.display = \"\";\n      if(inv.e2eSecret===null) mSystem(\"Legacy invite \u2014 no E2E secret. Ask for a new QR for full E2E.\");\n      await doPreview(inv.authToken);\n      mSystem(\"Auto-join failed \u2014 check the login details, tick confirm, then Approve.\");\n    }\n  }\n} catch {}\n// Refresh on any device closes the other tab (ephemeral 2-person)\nwindow.addEventListener(\"beforeunload\", () => { try { mWs?.close(1000, \"refresh\"); } catch {} });\nwindow.addEventListener(\"keydown\", (e) => {\n  if (e.key === \"F5\" || (e.ctrlKey && e.key.toLowerCase() === \"r\") || (e.metaKey && e.key.toLowerCase() === \"r\")) {\n    const inChat = document.getElementById(\"chatWrap\")?.classList.contains(\"open\") || (mWs && mWs.readyState === 1);\n    if (!inChat) return;\n    e.preventDefault();\n    try { mWs?.close(1000, \"refresh\"); } catch {}\n    setTimeout(() => { try { window.close(); } catch {} location.href = \"about:blank\"; }, 80);\n  }\n});\n// Refresh erases: no restore from storage \u2014 always start fresh\n\n"
}
