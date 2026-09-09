import { base64UrlEncode, base64UrlDecode, hmacSha256 } from "./crypto";
import type { SessionClaims, UserIdentity } from "./types";

const HEADER = { alg: "HS256", typ: "JWT" };

export const JWT_ISSUER = "secure-chat-workers";
export const JWT_AUDIENCE = "secure-chat-client";

function encode(obj: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

function decodeJson<T>(b64url: string): T {
  const bytes = base64UrlDecode(b64url);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

export async function signJwt(identity: UserIdentity, secret: string, ttlMs: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims: SessionClaims = {
    ...identity,
    iat: now,
    exp: now + Math.floor(ttlMs / 1000),
    jti: crypto.randomUUID(),
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
  };
  const h = encode(HEADER);
  const p = encode(claims);
  const sigBytes = await hmacSha256(secret, `${h}.${p}`);
  const sig = base64UrlEncode(sigBytes);
  return `${h}.${p}.${sig}`;
}

export async function verifyJwt(token: string, secret: string): Promise<SessionClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  // Strict alg check — reject none and any non-HS256 before signature verification
  try {
    const header = decodeJson<{ alg?: string; typ?: string }>(h);
    if (header.alg !== "HS256") return null;
    if (header.typ !== "JWT") return null;
  } catch {
    return null;
  }
  // Empty signature must be rejected (none alg bypass)
  if (!s) return null;
  const expected = base64UrlEncode(await hmacSha256(secret, `${h}.${p}`));
  // constant-time compare
  if (s.length !== expected.length) return null;
  let diff = 0;
  for (let i = 0; i < s.length; i++) diff |= s.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) return null;
  try {
    const claims = decodeJson<SessionClaims>(p);
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp !== undefined && now > claims.exp) return null;
    if (claims.iat !== undefined && claims.iat > now + 60) return null; // clock skew
    if (claims.exp !== undefined && claims.iat !== undefined && claims.exp <= claims.iat) return null;
    if (!claims.userId) return null;
    if (claims.jti !== undefined && typeof claims.jti !== "string") return null;
    // Fail closed on issuer/audience — tokens minted before iss/aud are rejected
    if (claims.iss !== JWT_ISSUER) return null;
    if (claims.aud !== JWT_AUDIENCE) return null;
    return claims;
  } catch {
    return null;
  }
}

export function extractBearer(req: Request): string | null {
  const h = req.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

/**
 * Extract a chat JWT for WebSocket upgrades where browsers cannot set
 * Authorization headers. Prefers Sec-WebSocket-Protocol (no URL leakage),
 * falls back to ?token= only for backwards compat (deprecated, logged).
 * QR opaque tokens must NEVER use this — they use X-QR-Token / POST body.
 */
export function extractWsJwt(req: Request, url: URL): { token: string | null; viaQuery: boolean } {
  const bearer = extractBearer(req);
  if (bearer) return { token: bearer, viaQuery: false };
  const proto = req.headers.get("Sec-WebSocket-Protocol") || "";
  // Client may offer "bearer, <jwt>" — take the last non-"bearer" token
  if (proto) {
    const parts = proto.split(",").map((s) => s.trim()).filter(Boolean);
    const candidate = parts.filter((p) => p.toLowerCase() !== "bearer").pop();
    if (candidate && candidate.length > 20) return { token: candidate, viaQuery: false };
  }
  const q = url.searchParams.get("token");
  if (q) return { token: q, viaQuery: true };
  return { token: null, viaQuery: false };
}
