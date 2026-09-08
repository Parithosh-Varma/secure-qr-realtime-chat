/**
 * RateLimiter Durable Object — sliding window counter.
 *
 * One instance per key (idFromName("rl:<key>")). Keeps timestamps of hits in storage.
 * Alarm GCs old entries outside window. Strongly consistent, no race.
 *
 * Security: prevents brute-force token scanning, QR flooding, spam.
 */
import { log } from "../lib/logger";

type Stored = {
  hits: number[]; // epoch ms
};

export class RateLimiter implements DurableObject {
  private state: DurableObjectState;
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState) {
    this.state = state;
    this.storage = state.storage;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "POST" && url.pathname === "/check") {
      return this.handleCheck(req);
    }
    if (req.method === "POST" && url.pathname === "/reset") {
      await this.storage.deleteAll();
      return Response.json({ ok: true });
    }
    return new Response("Not found", { status: 404 });
  }

  private async handleCheck(req: Request): Promise<Response> {
    const body = (await req.json().catch(() => null)) as { key?: string; limit?: number; windowMs?: number } | null;
    if (!body || typeof body.key !== "string" || typeof body.limit !== "number" || typeof body.windowMs !== "number") {
      return Response.json({ error: "Invalid body" }, { status: 400 });
    }
    const { key, limit, windowMs } = body;
    if (limit <= 0 || limit > 1000 || windowMs <= 0 || windowMs > 600_000) {
      return Response.json({ error: "Invalid limit/window" }, { status: 400 });
    }

    const now = Date.now();
    const stored = (await this.storage.get<Stored>(`hits:${key}`)) ?? { hits: [] };

    // Sliding window: keep only hits within window
    const cutoff = now - windowMs;
    const recent = stored.hits.filter((t) => t > cutoff);

    const allowed = recent.length < limit;
    let remaining: number;
    let resetMs: number;

    if (allowed) {
      recent.push(now);
      await this.storage.put(`hits:${key}`, { hits: recent } satisfies Stored);
      remaining = limit - recent.length;
      resetMs = recent.length > 0 ? recent[0] + windowMs - now : windowMs;
    } else {
      remaining = 0;
      resetMs = recent[0] + windowMs - now;
      log("warn", "rate_limited", { keyHash: hashKey(key), limit, windowMs });
    }

    // Schedule alarm to GC after window elapses
    const nextAlarm = now + windowMs + 1000;
    const currentAlarm = await this.storage.getAlarm();
    if (currentAlarm === null || nextAlarm < currentAlarm) {
      await this.storage.setAlarm(nextAlarm);
    }

    return Response.json({ allowed, remaining: Math.max(0, remaining), resetMs: Math.max(0, resetMs) });
  }

  async alarm(): Promise<void> {
    // GC all keys whose hits are fully expired
    const all = await this.storage.list<Stored>({ prefix: "hits:" });
    const now = Date.now();
    // We don't know window per key after the fact, so conservatively GC entries older than 10 min
    const maxWindow = 600_000;
    for (const [k, v] of all) {
      const filtered = v.hits.filter((t) => now - t < maxWindow);
      if (filtered.length === 0) await this.storage.delete(k);
      else if (filtered.length !== v.hits.length) await this.storage.put(k, { hits: filtered });
    }
    log("debug", "rate_limiter.gc", { keys: all.size });
  }
}

function hashKey(key: string): string {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (Math.imul(31, h) + key.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36).slice(0, 6);
}
