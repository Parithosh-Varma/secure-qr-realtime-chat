import { CSP_VALUE } from "./constants";

export function securityHeaders(origin?: string | null): Record<string, string> {
  // Strict CORS — allow only configured origins; if none configured, echo is forbidden in prod.
  // For local dev we allow * with no credentials; browser client uses same-origin by default.
  const headers: Record<string, string> = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": CSP_VALUE,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
  };
  return headers;
}

export function corsHeaders(req: Request, env: { ALLOWED_ORIGIN?: string }): Record<string, string> {
  const origin = req.headers.get("Origin");
  const allowed = env.ALLOWED_ORIGIN?.split(",").map((s) => s.trim()).filter(Boolean) ?? [];
  // SECURITY: never allow credentialed wildcard. If * is configured, require explicit origin without credentials.
  const hasWildcard = allowed.includes("*");
  if (hasWildcard && origin) {
    // Fail closed for credentialed requests — do not echo * with credentials
    return { Vary: "Origin" };
  }
  const isAllowed =
    origin &&
    (allowed.includes(origin) ||
      allowed.some((a) => a.includes("*") && originMatches(origin, a)));
  if (isAllowed && origin) {
    return {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Credentials": "true",
      Vary: "Origin",
    };
  }
  // No CORS header = browser blocks cross-origin. Same-origin still works.
  return { Vary: "Origin" };
}

export function withSecurityHeaders(res: Response, req: Request, env: { ALLOWED_ORIGIN?: string }): Response {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(securityHeaders())) h.set(k, v);
  for (const [k, v] of Object.entries(corsHeaders(req, env))) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

export function json(data: unknown, init: ResponseInit = {}, req?: Request, env?: { ALLOWED_ORIGIN?: string }): Response {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json; charset=utf-8");
  for (const [k, v] of Object.entries(securityHeaders())) headers.set(k, v);
  if (req && env) for (const [k, v] of Object.entries(corsHeaders(req, env))) headers.set(k, v);
  return new Response(JSON.stringify(data), { ...init, headers });
}

function originMatches(origin: string, pattern: string): boolean {
  // pattern like https://*.qrchat.pages.dev
  try {
    const o = new URL(origin);
    // Enforce https for non-local origins — an http subdomain must never
    // match an https allowlist entry (credentialed CORS).
    const isLocalOrigin = o.hostname === "localhost" || o.hostname === "127.0.0.1" || o.hostname === "::1";
    if (!isLocalOrigin && o.protocol !== "https:") return false;
    const p = pattern.replace(/^https:\/\/\*\./, "https://");
    // for wildcard, allow any subdomain of base
    if (pattern.includes("*.")) {
      const base = pattern.split("*.")[1]; // e.g. qrchat.pages.dev
      return o.hostname === base || o.hostname.endsWith("." + base);
    }
    return origin === pattern;
  } catch {
    return false;
  }
}

export function requireHttps(req: Request): Response | null {
  const url = new URL(req.url);
  // In local dev (localhost, 127.0.0.1) allow http. Enforce https otherwise.
  const host = url.hostname;
  const isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1";
  if (!isLocal && url.protocol !== "https:") {
    // SECURITY FIX (was open-redirect via reflected Host):
    // Never 301 to a Host-derived URL — Host is attacker-controlled and the
    // old allowlist branch was dead code (`a ? url.host : url.host`).
    // Cloudflare edge already redirects http->https; at the Worker layer we
    // fail closed with 426 so no attacker host is ever reflected.
    return Response.json({ error: "HTTPS required" }, { status: 426 });
  }
  // Also enforce WSS for WebSocket upgrades — same check (ws:// -> wss://)
  return null;
}
