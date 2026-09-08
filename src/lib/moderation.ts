import type { ModerationResult } from "./types";
import { log } from "./logger";

// ---- Pluggable moderation hook ----
// Default: simple blocklist + length/pattern checks. Replace with external API via env.MODERATION_KEY.

const BLOCKLIST = [
  // keep tiny for demo — replace with real list / external service
  "spamword",
];

const BLOCKED_PATTERNS: RegExp[] = [
  // example: excessive caps spam is flagged not blocked
];

export type ModerationHook = (body: string, ctx: { userId: string; roomId: string; ip: string }) => Promise<ModerationResult>;

export const defaultModerationHook: ModerationHook = async (body, _ctx) => {
  const lower = body.toLowerCase();
  for (const w of BLOCKLIST) {
    if (lower.includes(w)) {
      log("warn", "moderation.blocked", { reason: "blocklist", length: body.length });
      return { allowed: false, flagged: true, reason: "Message contains blocked content" };
    }
  }
  for (const re of BLOCKED_PATTERNS) {
    if (re.test(body)) {
      return { allowed: false, flagged: true, reason: "Message matches blocked pattern" };
    }
  }
  // Flag but allow: example excessive caps / repeated chars
  if (body.length > 20 && body === body.toUpperCase() && /[A-Z]/.test(body)) {
    log("info", "moderation.flagged", { reason: "excessive_caps" });
    return { allowed: true, flagged: true, reason: "excessive_caps" };
  }
  if (/(.)\1{9,}/.test(body)) {
    return { allowed: true, flagged: true, reason: "repeated_chars" };
  }
  return { allowed: true, flagged: false };
};

// If you have an external provider, wrap it here. Never store raw bodies in logs.
export function createModerationHook(env: { MODERATION_KEY?: string }): ModerationHook {
  if (!env.MODERATION_KEY) return defaultModerationHook;
  // Example skeleton for external call (keep disabled unless key is set, with timeout + fallback)
  return async (body, ctx) => {
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 800);
      // Replace URL with your provider
      const res = await fetch("https://api.example-moderation.com/v1/check", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${env.MODERATION_KEY}` },
        body: JSON.stringify({ text: body, userId: ctx.userId, roomId: ctx.roomId }),
        signal: controller.signal,
      });
      clearTimeout(t);
      if (!res.ok) {
        log("warn", "moderation.external_error", { status: res.status });
        return defaultModerationHook(body, ctx);
      }
      const data = (await res.json()) as { blocked?: boolean; reason?: string };
      if (data.blocked) return { allowed: false, flagged: true, reason: data.reason ?? "external_block" };
      return { allowed: true, flagged: false };
    } catch (e) {
      log("warn", "moderation.external_exception", { error: String(e) });
      return defaultModerationHook(body, ctx);
    }
  };
}
