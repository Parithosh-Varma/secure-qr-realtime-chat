import { describe, it, expect } from "vitest";
import {
  randomOpaqueToken,
  base64UrlEncode,
  base64UrlDecode,
  sha256Hex,
  hmacSha256,
} from "./crypto";

describe("randomOpaqueToken", () => {
  it("emits 43 url-safe chars for 32 bytes with fresh entropy", () => {
    const a = randomOpaqueToken(32);
    const b = randomOpaqueToken(32);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a).not.toBe(b);
  });
});

describe("base64Url roundtrip", () => {
  it("survives binary payloads including +/ padding edge cases", () => {
    const original = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const enc = base64UrlEncode(original);
    expect(enc).not.toMatch(/[+/=]/);
    expect(Array.from(base64UrlDecode(enc))).toEqual(Array.from(original));
  });

  it("roundtrips text bytes", () => {
    const bytes = new TextEncoder().encode("qrchat-e2e-v1:secret");
    expect(new TextDecoder().decode(base64UrlDecode(base64UrlEncode(bytes)))).toBe(
      "qrchat-e2e-v1:secret",
    );
  });
});

describe("sha256Hex", () => {
  it("matches the known SHA-256 vector", async () => {
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("is deterministic and input-sensitive", async () => {
    expect(await sha256Hex("token-a")).toBe(await sha256Hex("token-a"));
    expect(await sha256Hex("token-a")).not.toBe(await sha256Hex("token-b"));
  });
});

describe("hmacSha256", () => {
  it("yields 32 bytes, deterministic per key, distinct per key", async () => {
    const a1 = await hmacSha256("k1", "data");
    const a2 = await hmacSha256("k1", "data");
    const b = await hmacSha256("k2", "data");
    expect(a1.byteLength).toBe(32);
    expect(Array.from(a1)).toEqual(Array.from(a2));
    expect(Array.from(a1)).not.toEqual(Array.from(b));
  });
});
