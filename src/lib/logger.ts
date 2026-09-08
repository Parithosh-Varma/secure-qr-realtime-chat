/**
 * Structured logger — never logs message bodies, QR tokens, or JWTs.
 * Safe fields: event, ip (hashed/truncated), userId, roomId, ts, reason, counters.
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

export function log(level: LogLevel, event: string, fields: Record<string, unknown> = {}) {
  const entry = {
    level,
    event,
    ts: new Date().toISOString(),
    ...fields,
  };
  // In Workers, console.log -> Logpush / Tail
  const line = JSON.stringify(entry);
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

export function hashForLog(value: string): string {
  // truncated hash for correlation without leaking secret — not cryptographic
  let h = 0;
  for (let i = 0; i < value.length; i++) h = (Math.imul(31, h) + value.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36).slice(0, 8);
}

export function redactIp(ip: string): string {
  // keep /24 for abuse analysis, drop last octet
  if (ip.includes(".")) return ip.split(".").slice(0, 3).join(".") + ".0";
  if (ip.includes(":")) return ip.split(":").slice(0, 4).join(":") + "::";
  return "***";
}
