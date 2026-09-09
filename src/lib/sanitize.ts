import { MAX_MESSAGE_LENGTH, MAX_CIPHERTEXT_LENGTH } from "./constants";

/**
 * Server-side sanitization. Never trust client.
 * - enforce length
 * - strip/escape HTML (prevent XSS if rendered as innerHTML)
 * - normalize whitespace, reject control chars
 * - prepared-statement friendly (no SQL metachars handling needed beyond parameterization)
 */

export function sanitizeMessage(input: unknown, maxLength = MAX_MESSAGE_LENGTH): { ok: boolean; value?: string; error?: string } {
  if (typeof input !== "string") return { ok: false, error: "Message must be a string" };
  let s = input.normalize("NFC");

  // Strip bidi overrides / zero-width / invisible chars (spoofing, CVE-style visual attacks).
  // These are never legitimate in chat and survive HTML-escaping.
  // eslint-disable-next-line no-misleading-character-class
  s = s.replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00AD]/g, "");

  // reject null bytes and most control chars (allow \n \t)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(s)) {
    return { ok: false, error: "Message contains invalid control characters" };
  }

  s = s.trim();
  if (s.length === 0) return { ok: false, error: "Message cannot be empty" };
  if (s.length > maxLength) return { ok: false, error: `Message too long (max ${maxLength})` };

  // Escape HTML entities so that even if client does element.innerHTML = body, it is safe.
  // We intentionally escape rather than strip so user intent is preserved visibly.
  s = escapeHtml(s);

  // Optional: collapse excessive repeated whitespace/newlines to limit resource abuse
  s = s.replace(/\n{4,}/g, "\n\n\n");

  return { ok: true, value: s };
}

export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

export function validateRoomId(roomId: unknown): { ok: boolean; value?: string; error?: string } {
  if (typeof roomId !== "string") return { ok: false, error: "roomId must be string" };
  const v = roomId.trim();
  if (!/^[a-zA-Z0-9_-]{3,64}$/.test(v)) return { ok: false, error: "Invalid roomId format" };
  return { ok: true, value: v };
}

export function validateUserId(userId: unknown): { ok: boolean; value?: string; error?: string } {
  if (typeof userId !== "string") return { ok: false, error: "userId must be string" };
  const v = userId.trim();
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(v)) return { ok: false, error: "Invalid userId" };
  return { ok: true, value: v };
}

export function validateDisplayName(input: unknown): { ok: boolean; value?: string; error?: string } {
  if (input === undefined || input === null) return { ok: true, value: undefined };
  if (typeof input !== "string") return { ok: false, error: "displayName must be string" };
  let s = input.normalize("NFC").trim();
  // Strip invisible/bidi chars before length checks so "aaaa\u200B..." can't bypass limits
  // eslint-disable-next-line no-misleading-character-class
  s = s.replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00AD]/g, "");
  if (s.length === 0) return { ok: true, value: undefined };
  if (s.length > 24) return { ok: false, error: "displayName too long (max 24)" };
  if (s.length < 2) return { ok: false, error: "displayName too short (min 2)" };
  // Reject HTML / control chars — defense-in-depth even though client uses textContent
  if (/[<>]/.test(s)) return { ok: false, error: "displayName cannot contain < or >" };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(s)) return { ok: false, error: "displayName contains invalid chars" };
  // Escape for storage/display
  s = escapeHtml(s);
  return { ok: true, value: s };
}

export function validateTokenFormat(token: unknown): { ok: boolean; value?: string; error?: string } {
  if (typeof token !== "string") return { ok: false, error: "token must be string" };
  const v = token.trim();
  // base64url 32 bytes => ~43 chars; allow 32-128 chars
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(v)) return { ok: false, error: "Invalid token format" };
  return { ok: true, value: v };
}
