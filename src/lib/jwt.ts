import { base64UrlEncode, base64UrlDecode, hmacSha256 } from "./crypto";
import type { SessionClaims, UserIdentity } from "./types";

const HEADER = { alg: "HS256", typ: "JWT" };

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
    if (!claims.userId) return null;
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
