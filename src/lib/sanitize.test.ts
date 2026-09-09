import { describe, it, expect } from "vitest";
import {
  sanitizeMessage,
  validateDisplayName,
  validateTokenFormat,
  validateRoomId,
  escapeHtml,
} from "./sanitize";
import { MAX_MESSAGE_LENGTH, MAX_CIPHERTEXT_LENGTH } from "./constants";

// NOTE: invisible characters below are written as \uXXXX escapes on purpose —
// never paste literal bidi/zero-width chars into source (they're invisible).

describe("sanitizeMessage", () => {
  it("passes plain text through", () => {
    expect(sanitizeMessage("hello world")).toEqual({ ok: true, value: "hello world" });
  });

  it("escapes HTML so innerHTML rendering stays safe", () => {
    const r = sanitizeMessage('<script>alert("x")</script>');
    expect(r.ok).toBe(true);
    expect(r.value).not.toContain("<script>");
    expect(r.value).toContain("&lt;script&gt;");
  });

  it("rejects null bytes and control chars but allows newline/tab", () => {
    expect(sanitizeMessage("a\u0000b").ok).toBe(false);
    expect(sanitizeMessage("a\u0008b").ok).toBe(false);
    expect(sanitizeMessage("line1\nline2\tindented").ok).toBe(true);
  });

  it("strips bidi overrides and zero-width chars (visual spoofing)", () => {
    const r = sanitizeMessage("a\u200Bb\u202Ec");
    expect(r).toEqual({ ok: true, value: "abc" });
  });

  it("rejects empty and over-long messages", () => {
    expect(sanitizeMessage("   ").ok).toBe(false);
    expect(sanitizeMessage("x".repeat(MAX_MESSAGE_LENGTH + 1)).ok).toBe(false);
    expect(sanitizeMessage("x".repeat(MAX_MESSAGE_LENGTH)).ok).toBe(true);
  });

  it("accepts E2E-sized ciphertext under the roomier cap only", () => {
    const cipher = "enc2:12345." + "A".repeat(3000);
    expect(cipher.length).toBeGreaterThan(MAX_MESSAGE_LENGTH);
    expect(sanitizeMessage(cipher).ok).toBe(false);
    const r = sanitizeMessage(cipher, MAX_CIPHERTEXT_LENGTH);
    expect(r.ok).toBe(true);
    // base64 alphabet must survive escaping untouched
    expect(r.value).toContain("A".repeat(100));
  });

  it("rejects non-strings", () => {
    expect(sanitizeMessage(null).ok).toBe(false);
    expect(sanitizeMessage({ body: "x" }).ok).toBe(false);
  });
});

describe("escapeHtml", () => {
  it("escapes all five metacharacters", () => {
    expect(escapeHtml(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&#x27;");
  });
});

describe("validateDisplayName", () => {
  it("rejects short, long, and angle-bracket names", () => {
    expect(validateDisplayName("a").ok).toBe(false);
    expect(validateDisplayName("x".repeat(25)).ok).toBe(false);
    expect(validateDisplayName("<b>bob</b>").ok).toBe(false);
  });

  it("strips invisible chars before length checks", () => {
    // "a" + zero-width space + "b" becomes "ab" after stripping
    expect(validateDisplayName("a\u200Bb").ok).toBe(true);
    // lone zero-width space becomes empty
    expect(validateDisplayName("\u200B").value).toBe(undefined);
  });

  it("accepts a normal nickname", () => {
    expect(validateDisplayName("parithosh")).toEqual({ ok: true, value: "parithosh" });
  });
});

describe("validateTokenFormat", () => {
  it("accepts 32-byte base64url tokens, rejects JWTs and short strings", () => {
    expect(validateTokenFormat("a".repeat(43)).ok).toBe(true);
    expect(validateTokenFormat("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c").ok).toBe(false); // dots
    expect(validateTokenFormat("short").ok).toBe(false);
    expect(validateTokenFormat("").ok).toBe(false);
  });
});

describe("validateRoomId", () => {
  it("enforces the room id shape", () => {
    expect(validateRoomId("general").ok).toBe(true);
    expect(validateRoomId("dm_abc123").ok).toBe(true);
    expect(validateRoomId("ab").ok).toBe(false);
    expect(validateRoomId("../escape").ok).toBe(false);
    expect(validateRoomId("has space").ok).toBe(false);
  });
});
