/**
 * Worker-side helper to talk to RateLimiter Durable Object.
 * DO implements sliding window counter with alarms for GC.
 */

export type RateLimitOpts = { limit: number; windowMs: number };

export async function checkRateLimit(
  rateLimiterNS: DurableObjectNamespace,
  key: string,
  opts: RateLimitOpts,
): Promise<{ allowed: boolean; remaining: number; resetMs: number }> {
  const id = rateLimiterNS.idFromName(`rl:${key}`);
  const stub = rateLimiterNS.get(id);
  const res = await stub.fetch("https://rl/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key, ...opts }),
  });
  if (!res.ok) {
    // Fail closed for security-sensitive paths if DO is down — deny with 503 to prevent brute-force bypass
    // For availability we could fail open, but audit flagged fail-open as brute-force bypass. Use closed.
    return { allowed: false, remaining: 0, resetMs: opts.windowMs };
  }
  return (await res.json()) as { allowed: boolean; remaining: number; resetMs: number };
}
