import { describe, it, expect } from "vitest";
import { signJwt, verifyJwt, extractBearer, JWT_ISSUER, JWT_AUDIENCE } from "./jwt";
import { base64UrlEncode, hmacSha256 } from "./crypto";

const SECRET = "test-secret-at-least-32-chars-long!!";

/** Mint a token with fully caller-controlled header/claims (attack shapes). */
async function craftJwt(header: unknown, claims: unknown, secret: string): Promise<string> {
  const enc = (o: unknown) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(o)));
  const h = enc(header);
  const p = enc(claims);
  const sig = base64UrlEncode(await hmacSha256(secret, `${h}.${p}`));
  return `${h}.${p}.${sig}`;
}

function validClaims(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    userId: "guest_abc123",
    displayName: "anon",
    iat: now,
    exp: now + 3600,
    jti: "test-jti",
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
    ...overrides,
  };
}

describe("signJwt / verifyJwt roundtrip", () => {
  it("accepts a freshly minted token", async () => {
    const tok = await signJwt({ userId: "u1", displayName: "n1" }, SECRET, 3_600_000);
    const claims = await verifyJwt(tok, SECRET);
    expect(claims?.userId).toBe("u1");
    expect(claims?.iss).toBe(JWT_ISSUER);
    expect(claims?.aud).toBe(JWT_AUDIENCE);
  });

  it("rejects the wrong secret", async () => {
    const tok = await signJwt({ userId: "u1" }, SECRET, 3_600_000);
    expect(await verifyJwt(tok, "different-secret-00000000000000000")).toBeNull();
  });

  it("rejects tampered payloads", async () => {
    const tok = await signJwt({ userId: "u1" }, SECRET, 3_600_000);
    const [h, , s] = tok.split(".");
    const evil = base64UrlEncode(new TextEncoder().encode(JSON.stringify(validClaims({ userId: "admin" }))));
    expect(await verifyJwt(`${h}.${evil}.${s}`, SECRET)).toBeNull();
  });

  it("rejects alg=none and non-HS256 headers", async () => {
    const noneTok = `${base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: "none", typ: "JWT" })))}.${base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(validClaims())),
    )}.`;
    expect(await verifyJwt(noneTok, SECRET)).toBeNull();
    const hs512 = await craftJwt({ alg: "HS512", typ: "JWT" }, validClaims(), SECRET);
    expect(await verifyJwt(hs512, SECRET)).toBeNull();
  });

  it("rejects expired tokens and impossible iat/exp", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = await craftJwt(
      { alg: "HS256", typ: "JWT" },
      validClaims({ iat: now - 7200, exp: now - 3600 }),
      SECRET,
    );
    expect(await verifyJwt(expired, SECRET)).toBeNull();
    const futureIat = await craftJwt(
      { alg: "HS256", typ: "JWT" },
      validClaims({ iat: now + 3600, exp: now + 7200 }),
      SECRET,
    );
    expect(await verifyJwt(futureIat, SECRET)).toBeNull();
  });

  it("rejects wrong issuer/audience and missing userId", async () => {
    const hdr = { alg: "HS256", typ: "JWT" };
    expect(await verifyJwt(await craftJwt(hdr, validClaims({ iss: "evil" }), SECRET), SECRET)).toBeNull();
    expect(await verifyJwt(await craftJwt(hdr, validClaims({ aud: "evil" }), SECRET), SECRET)).toBeNull();
    const { userId: _drop, ...noUser } = validClaims();
    expect(await verifyJwt(await craftJwt(hdr, noUser, SECRET), SECRET)).toBeNull();
  });

  it("rejects malformed shapes", async () => {
    expect(await verifyJwt("not-a-jwt", SECRET)).toBeNull();
    expect(await verifyJwt("a.b", SECRET)).toBeNull();
    expect(await verifyJwt("", SECRET)).toBeNull();
  });
});

describe("extractBearer", () => {
  const req = (auth: string | null) =>
    new Request("https://x.test/", auth ? { headers: { Authorization: auth } } : {});

  it("parses Bearer case-insensitively, null otherwise", () => {
    expect(extractBearer(req("Bearer abc123"))).toBe("abc123");
    expect(extractBearer(req("bearer abc123"))).toBe("abc123");
    expect(extractBearer(req("Basic abc123"))).toBeNull();
    expect(extractBearer(req(null))).toBeNull();
  });
});
