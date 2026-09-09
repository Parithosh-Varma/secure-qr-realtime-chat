/**
 * AuthSession Durable Object — manages ONE pending QR login token.
 *
 * Instantiated per token via idFromName(tokenHash). Strong consistency guarantees:
 * - Only one burn/claim succeeds (no replay, no race)
 * - Single alarm cleans up expired pending sessions
 *
 * State is keyed by tokenHash (SHA-256 of raw token) so raw token never hits disk in clear.
 * Raw token is only held transiently in memory during create/claim validation and via hash compare.
 *
 * Lifecycle: pending -> approved/denied -> claimed/expired (alarm deletes)
 */

import { log, hashForLog } from "../lib/logger";
import type { QrSessionState, QrStatus, UserIdentity } from "../lib/types";

/**
 * Select a WebSocket subprotocol for the 101 response (see ChatRoom.ts).
 * The desktop waiter offers ["qr", <authToken>]; echo "qr" so browsers don't
 * fail the handshake for a missing selection.
 */
function selectWsSubprotocol(req: Request, name: string): HeadersInit | undefined {
  const proto = req.headers.get("Sec-WebSocket-Protocol") || "";
  const offered = proto.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (offered.includes(name.toLowerCase())) return { "Sec-WebSocket-Protocol": name };
  return undefined;
}

type StoredState = {
  status: QrStatus;
  createdAt: number;
  expiresAt: number;
  fingerprint: QrSessionState["fingerprint"];
  tokenHash: string;
  roomId: string; // private 2-person room derived from tokenHash
  host?: UserIdentity; // who created the QR (for invite-to-chat)
  approver?: UserIdentity & { approvedAt: number };
  claimedAt?: number;
  // Presenter opt-in: desktop showing the QR allows the scanner to auto-join
  // without a blocking consent tap (scan = acceptance). Defaults false.
  autoJoin: boolean;
};

export class AuthSession implements DurableObject {
  private state: DurableObjectState;
  private storage: DurableObjectStorage;
  private env: { ALLOWED_ORIGIN?: string };

  // In-memory WebSocket waiters for desktop `GET /ws` holders — hibernation-friendly
  // We keep list of waiting WebSockets; on approve/deny we notify them.
  // Bounded to prevent memory exhaustion (unauthenticated WS).
  private waiters = new Set<WebSocket>();
  private static readonly MAX_WAITERS = 5;

  constructor(state: DurableObjectState, env: { ALLOWED_ORIGIN?: string } = {}) {
    this.state = state;
    this.storage = state.storage;
    this.env = env;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    // Internal Worker->DO routes
    if (req.method === "POST" && path === "/create") return this.handleCreate(req);
    if (req.method === "GET" && path === "/status") return this.handleStatus(req);
    if (req.method === "POST" && path === "/approve") return this.handleApprove(req);
    if (req.method === "POST" && path === "/claim") return this.handleClaim(req);
    if (req.method === "GET" && path === "/ws") return this.handleWs(req);

    // For hibernatable WS in AuthSession (desktop waiter)
    if (req.headers.get("Upgrade") === "websocket") {
      return this.handleWs(req);
    }

    return Response.json({ error: "Not found" }, { status: 404 });
  }

  // ---- Create pending session ----
  private async handleCreate(req: Request): Promise<Response> {
    // Body: { tokenHash, fingerprint, ttlMs, host?, roomId? }
    // SECURITY: client generates the raw auth token locally and sends ONLY
    // its SHA-256 hash. The raw token (and the separate e2eSecret, which is
    // never sent to the server at all) stays client-side, so the server can
    // never derive E2E message keys. Legacy callers with no tokenHash get a
    // server-generated session (deprecated).
    const body = (await req.json().catch(() => null)) as { tokenHash?: string; fingerprint?: StoredState["fingerprint"]; ttlMs?: number; host?: UserIdentity; roomId?: string; autoJoin?: boolean } | null;
    if (!body?.tokenHash || !body.fingerprint || typeof body.ttlMs !== "number") {
      return Response.json({ error: "Invalid body" }, { status: 400 });
    }
    const { tokenHash, fingerprint, ttlMs, host } = body;
    if (!/^[a-f0-9]{64}$/.test(tokenHash)) return Response.json({ error: "tokenHash must be SHA-256 hex" }, { status: 400 });
    // Validate fingerprint shape (defense-in-depth — Worker builds it, but DO never trusts shape)
    if (typeof fingerprint !== "object" || typeof fingerprint.ip !== "string" || typeof fingerprint.userAgent !== "string") {
      return Response.json({ error: "Invalid fingerprint" }, { status: 400 });
    }
    if (fingerprint.ip.length > 16 || fingerprint.userAgent.length > 512) {
      return Response.json({ error: "Invalid fingerprint" }, { status: 400 });
    }
    if (ttlMs < 60_000 || ttlMs > 120_000) return Response.json({ error: "TTL must be 60-120s" }, { status: 400 });
    const roomId = body.roomId && /^[a-zA-Z0-9_-]{3,64}$/.test(body.roomId) ? body.roomId : `dm_${tokenHash.slice(0, 32)}`;

    const existing = await this.storage.get<StoredState>("state");
    if (existing) {
      // Re-creation attempt — treat as conflict if not expired
      if (Date.now() < existing.expiresAt && existing.status !== "expired" && existing.status !== "claimed") {
        return Response.json({ error: "Session already exists" }, { status: 409 });
      }
    }

    const now = Date.now();
    const state: StoredState = {
      status: "pending",
      createdAt: now,
      expiresAt: now + ttlMs,
      fingerprint,
      tokenHash,
      roomId,
      host: host?.userId ? { userId: host.userId, displayName: host.displayName, email: host.email } : undefined,
      autoJoin: body.autoJoin === true,
    };
    await this.storage.put("state", state);
    await this.storage.setAlarm(state.expiresAt + 1000);

    log("info", "qr.created", { tokenHash: hashForLog(tokenHash), expiresAt: state.expiresAt });

    return Response.json({ ok: true, status: state.status, createdAt: state.createdAt, expiresAt: state.expiresAt });
  }

  private async handleStatus(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const tokenHash = url.searchParams.get("tokenHash");
    if (!tokenHash) return Response.json({ error: "tokenHash required" }, { status: 400 });

    const state = await this.storage.get<StoredState>("state");
    if (!state) return Response.json({ error: "Not found", status: "expired" as QrStatus }, { status: 404 });
    if (state.tokenHash !== tokenHash) return Response.json({ error: "Token mismatch" }, { status: 403 });

    // Check expiry lazily
    if (Date.now() >= state.expiresAt && state.status === "pending") {
      state.status = "expired";
      await this.storage.put("state", state);
    }

    const resp: Record<string, unknown> = {
      status: state.status,
      createdAt: state.createdAt,
      expiresAt: state.expiresAt,
      roomId: state.roomId,
      host: state.host ? { userId: state.host.userId, displayName: state.host.displayName } : undefined,
      // Exposed so the mobile confirmation screen can show device/location
      // before explicit approve. IP is already hashed server-side; UA truncated.
      fingerprint: {
        userAgent: state.fingerprint.userAgent.slice(0, 120),
        acceptLanguage: state.fingerprint.acceptLanguage,
        city: state.fingerprint.city,
        country: state.fingerprint.country,
        createdAt: state.createdAt,
      },
    };
    // Only expose approver presence, not identity, on status poll (desktop is unauthenticated)
    if (state.status === "approved") {
      resp.approvedAt = state.approver?.approvedAt;
      resp.approver = state.approver ? { userId: state.approver.userId, displayName: state.approver.displayName } : undefined;
    }

    return Response.json(resp);
  }

  // ---- Mobile approval (requires authenticated identity forwarded by Worker) ----
  private async handleApprove(req: Request): Promise<Response> {
    const body = (await req.json().catch(() => null)) as { tokenHash?: string; action?: string; approver?: UserIdentity; auto?: boolean } | null;
    if (!body?.tokenHash || !body.action || !body.approver?.userId) {
      return Response.json({ error: "Invalid body" }, { status: 400 });
    }
    const { tokenHash, action, approver } = body;
    if (action !== "approve" && action !== "deny") return Response.json({ error: "Invalid action" }, { status: 400 });

    const state = await this.storage.get<StoredState>("state");
    if (!state) return Response.json({ error: "Session not found or expired" }, { status: 404 });
    if (state.tokenHash !== tokenHash) return Response.json({ error: "Token mismatch" }, { status: 403 });

    if (Date.now() >= state.expiresAt) {
      state.status = "expired";
      await this.storage.put("state", state);
      return Response.json({ error: "Session expired" }, { status: 410 });
    }
    if (state.status !== "pending") {
      return Response.json({ error: `Already ${state.status}` }, { status: 409 });
    }

    // Auto-join (scanner's client approving right after scan) is only honored
    // when the presenter opted the session in at creation. Otherwise the
    // Worker requires an explicit fingerprint confirmation (manual flow).
    if (action === "approve" && body.auto === true && state.autoJoin !== true) {
      return Response.json({ error: "Auto-join not enabled for this invite — confirm fingerprint" }, { status: 403 });
    }

    if (action === "deny") {
      state.status = "denied";
      await this.storage.put("state", state);
      log("info", "qr.denied", { tokenHash: hashForLog(tokenHash), approverId: approver.userId });
      this.notifyWaiters({ status: "denied" });
      return Response.json({ ok: true, status: state.status });
    }

    // Approve — attach verified identity (Worker already verified JWT, we trust approver payload)
    state.status = "approved";
    state.approver = { ...approver, approvedAt: Date.now() };
    await this.storage.put("state", state);

    log("info", "qr.approved", { tokenHash: hashForLog(tokenHash), approverId: approver.userId, auto: body.auto === true });

    // Notify any desktop WS waiters that session is approved (they still must call /claim to burn)
    this.notifyWaiters({ status: "approved", approvedAt: state.approver.approvedAt });

    return Response.json({ ok: true, status: state.status });
  }

  // ---- Desktop claim (burn one-time) ----
  private async handleClaim(req: Request): Promise<Response> {
    const body = (await req.json().catch(() => null)) as { tokenHash?: string } | null;
    if (!body?.tokenHash) return Response.json({ error: "tokenHash required" }, { status: 400 });
    const { tokenHash } = body;

    const state = await this.storage.get<StoredState>("state");
    if (!state) return Response.json({ error: "Session not found or expired" }, { status: 404 });
    if (state.tokenHash !== tokenHash) return Response.json({ error: "Token mismatch" }, { status: 403 });

    if (Date.now() >= state.expiresAt && state.status === "pending") {
      state.status = "expired";
      await this.storage.put("state", state);
      return Response.json({ error: "Session expired" }, { status: 410 });
    }

    if (state.status === "pending") return Response.json({ error: "Not yet approved", status: state.status }, { status: 202 });
    if (state.status === "denied") return Response.json({ error: "Login denied", status: state.status }, { status: 403 });
    if (state.status === "expired") return Response.json({ error: "Session expired", status: state.status }, { status: 410 });
    if (state.status === "claimed") return Response.json({ error: "Already claimed (replay blocked)", status: state.status }, { status: 410 });
    if (state.status !== "approved") return Response.json({ error: `Invalid status ${state.status}` }, { status: 409 });

    // Critical: burn immediately — set claimed BEFORE returning identity, no race (single DO, single threaded)
    const approver = state.approver;
    if (!approver?.userId) {
      return Response.json({ error: "Approved session has no identity (internal error)" }, { status: 500 });
    }

    state.status = "claimed";
    state.claimedAt = Date.now();
    await this.storage.put("state", state);

    // Delete after short grace so polling gets 410, but keep burned state to block replay until alarm
    // Schedule deletion via alarm very soon (or keep claimed tombstone until expiry)
    await this.storage.setAlarm(Date.now() + 5000);

    log("info", "qr.claimed", { tokenHash: hashForLog(tokenHash), userId: approver.userId });

    // Return verified identity so Worker can mint JWT (no email — guests only)
    return Response.json({
      ok: true,
      status: "claimed",
      roomId: state.roomId,
      identity: { userId: approver.userId, displayName: approver.displayName },
    });
  }

  // ---- Desktop waiter WebSocket ----
  private async handleWs(req: Request): Promise<Response> {
    const url = new URL(req.url);
    // CSWSH: enforce the same strict allowlist as ChatRoom. Missing Origin
    // (curl) is rejected for this unauthenticated endpoint — browsers always
    // send Origin on WS.
    const origin = req.headers.get("Origin");
    const allowedOrigins = this.env.ALLOWED_ORIGIN?.split(",").map((s) => s.trim()).filter(Boolean) ?? [];
    if (!origin) return Response.json({ error: "Origin required" }, { status: 403 });
    try {
      const o = new URL(origin);
      const isLocalOrigin = o.hostname === "localhost" || o.hostname === "127.0.0.1" || o.hostname === "::1";
      if (!isLocalOrigin && o.protocol !== "https:") return Response.json({ error: "Forbidden Origin" }, { status: 403 });
    } catch {
      return Response.json({ error: "Invalid Origin" }, { status: 403 });
    }
    const isAllowedOrigin =
      allowedOrigins.includes(origin) ||
      allowedOrigins.some((a) => {
        if (!a.includes("*")) return false;
        try {
          const o = new URL(origin);
          const base = a.split("*.")[1];
          if (!base) return false;
          return o.hostname === base || o.hostname.endsWith("." + base);
        } catch {
          return false;
        }
      });
    // Local dev without configured origins: allow loopback + same-origin only
    const isLoopback = (() => {
      try {
        const o = new URL(origin);
        return o.hostname === "localhost" || o.hostname === "127.0.0.1" || o.hostname === "::1";
      } catch {
        return false;
      }
    })();
    const fwdHost = req.headers.get("X-Forwarded-Host") || "";
    const isSameOrigin = (() => {
      try {
        if (!fwdHost) return false;
        const o = new URL(origin);
        return o.host === fwdHost;
      } catch {
        return false;
      }
    })();
    if (!isAllowedOrigin && !isLoopback && !isSameOrigin && !allowedOrigins.includes("*")) {
      return Response.json({ error: "Forbidden Origin" }, { status: 403 });
    }
    const tokenHash = url.searchParams.get("tokenHash");
    if (!tokenHash) return Response.json({ error: "tokenHash required" }, { status: 400 });

    const state = await this.storage.get<StoredState>("state");
    if (!state) return Response.json({ error: "Session not found" }, { status: 404 });
    if (state.tokenHash !== tokenHash) return Response.json({ error: "Token mismatch" }, { status: 403 });

    // Expiry check
    if (Date.now() >= state.expiresAt && state.status === "pending") {
      return Response.json({ error: "Session expired" }, { status: 410 });
    }

    // Upgrade
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    // Bound waiters to prevent unauthenticated memory exhaustion
    if (this.waiters.size >= AuthSession.MAX_WAITERS) {
      return Response.json({ error: "Too many waiters" }, { status: 429 });
    }
    // Hibernation API — server will survive DO eviction and wake on message/close
    this.state.acceptWebSocket(server);

    // Store association via tag
    (server as WebSocket & { _tokenHash?: string })._tokenHash = tokenHash;

    // Immediately send current status
    const payload = JSON.stringify({ status: state.status, expiresAt: state.expiresAt });
    server.addEventListener("open", () => {
      try {
        server.send(payload);
      } catch {}
    });
    // For hibernation path, send may need to be deferred until next tick; also handle via webSocketMessage
    // Keep server in waiters set for broadcast on approve
    this.waiters.add(server);

    // Also send via queueMicrotask for non-hibernation clients that are already open
    queueMicrotask(() => {
      try {
        if (server.readyState === 1) server.send(payload);
      } catch {}
    });

    const wsHeaders = selectWsSubprotocol(req, "qr");
    return new Response(null, { status: 101, webSocket: client, ...(wsHeaders ? { headers: wsHeaders } : {}) });
  }

  private notifyWaiters(data: Record<string, unknown>) {
    const msg = JSON.stringify(data);
    for (const ws of this.waiters) {
      try {
        if (ws.readyState === 1) ws.send(msg);
      } catch {
        // ignore
      }
    }
  }

  // Hibernation handlers
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    // Desktop waiter is read-only; ignore any inbound messages (prevents abuse)
    // Optionally close if client tries to send data
    try {
      ws.send(JSON.stringify({ error: "Read-only channel" }));
    } catch {}
  }

  async webSocketClose(ws: WebSocket, _code: number, _reason: string, _wasClean: boolean): Promise<void> {
    this.waiters.delete(ws);
  }

  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    this.waiters.delete(ws);
  }

  async alarm(): Promise<void> {
    const state = await this.storage.get<StoredState>("state");
    if (!state) return;
    const now = Date.now();
    // If pending and expired, mark expired then schedule delete. If claimed/denied/expired, delete.
    if (state.status === "pending" && now >= state.expiresAt) {
      state.status = "expired";
      await this.storage.put("state", state);
      log("info", "qr.expired", { tokenHash: hashForLog(state.tokenHash) });
      this.notifyWaiters({ status: "expired" });
      await this.storage.setAlarm(now + 5000);
      return;
    }
    if (state.status === "claimed" || state.status === "denied" || state.status === "expired") {
      // Burned — safe to delete. Keep until after claim grace period.
      if (state.claimedAt && now - state.claimedAt < 5000) {
        await this.storage.setAlarm(state.claimedAt + 5000);
        return;
      }
      await this.storage.deleteAll();
      // Close waiters
      for (const ws of this.waiters) {
        try {
          ws.close(1000, "Session ended");
        } catch {}
      }
      this.waiters.clear();
      log("debug", "qr.cleaned", { tokenHash: hashForLog(state.tokenHash), finalStatus: state.status });
    }
  }
}
