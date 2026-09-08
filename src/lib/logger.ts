/**
 * Structured logger — privacy-first: never logs message bodies, QR tokens, JWTs, or IP addresses.
 * Per checklist: "Be careful about logging IP addresses." "Don't retain unnecessary connection metadata."
 * Safe fields: event, roomId (hashed), ts, reason, counters. UserId only as ephemeral random ID.
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

export function log(level: LogLevel, event: string, fields: Record<string, unknown> = {}) {
  // Strip any accidental ip / token / body fields
  const safe: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (["ip", "token", "body", "message", "Authorization", "cookie"].includes(k)) continue;
    safe[k] = v;
  }
  const entry = {
    level,
    event,
    ts: new Date().toISOString(),
    ...safe,
  };
  const line = JSON.stringify(entry);
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

export function hashForLog(value: string): string {
  let h = 0;
  for (let i = 0; i < value.length; i++) h = (Math.imul(31, h) + value.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36).slice(0, 8);
}

export function redactIp(_ip: string): string {
  // Privacy: do not log IP at all — return placeholder
  return "***";
}
