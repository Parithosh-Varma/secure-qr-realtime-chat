/**
 * ChatRoom Durable Object — one instance per roomId (idFromName(roomId)).
 *
 * Responsibilities:
 * - Own WebSocket connections for the room (strong consistency, no race on broadcast)
 * - Validate room membership server-side via verified JWT (never trust client room/user IDs)
 * - Rate-limit connections and messages (sliding window via RateLimiter DO + local fallback)
 * - Sanitize + validate messages, run pluggable moderation hook, block/flag before broadcast
 * - Store history in DO storage (prepared-statement-style via structured keys; D1 example in comments)
 * - Handle disconnects/reconnects without leaking state or duplicating messages
 * - Enforce payload caps, HTTPS/WSS only (enforced at Worker boundary)
 *
 * Hibernation: uses state.acceptWebSocket() so connections survive eviction.
 */

import { log, hashForLog, hashForRateLimit } from "../lib/logger";
import { sanitizeMessage, validateRoomId } from "../lib/sanitize";
import { createModerationHook } from "../lib/moderation";
import type { ChatMessage } from "../lib/types";
import { MAX_PAYLOAD_BYTES, MAX_ROOM_HISTORY } from "../lib/constants";
import { verifyJwt, extractBearer, extractWsJwt } from "../lib/jwt";

/**
 * Select a WebSocket subprotocol for the 101 response. Browsers FAIL the
 * handshake if they offered protocols and the server echoes none — so when
 * the client authenticates via Sec-WebSocket-Protocol ("bearer"), we must
 * select it back. Only ever echoes a protocol the client actually offered.
 */
function selectWsSubprotocol(req: Request, name: string): HeadersInit | undefined {
  const proto = req.headers.get("Sec-WebSocket-Protocol") || "";
  const offered = proto.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (offered.includes(name.toLowerCase())) return { "Sec-WebSocket-Protocol": name };
  return undefined;
}

// Stored keys
// messages:<roomId>:<ts>:<id> -> ChatMessage
// blocks:<userId> -> Set<blockedUserId>
// reports -> array

type SessionMeta = {
  userId: string;
  displayName?: string;
  // no ip stored — privacy: "Be careful about logging IP addresses" + "Don't retain unnecessary connection metadata"
  connectedAt: number;
  roomId: string; // bind WS to its room to prevent cross-room injection
};

type ChatEnv = {
  RATE_LIMITER: DurableObjectNamespace;
  JWT_SECRET: string;
  ROOM_MEMBERS_JSON?: string;
  MODERATION_KEY?: string;
  ALLOWED_ORIGIN?: string;
};

export class ChatRoom implements DurableObject {
  private state: DurableObjectState;
  private storage: DurableObjectStorage;
  private env: ChatEnv;

  // In-memory session map keyed by WebSocket — rebuilt on wake via serializeAttachment
  private sessions = new Map<WebSocket, SessionMeta>();
  // Last broadcast typing state per socket — used to dedupe high-frequency
  // typing frames so one keystroke storm can't spam the room.
  private typingState = new Map<WebSocket, boolean>();

  // In-memory rate counters fallback if RateLimiter DO unavailable (resets on eviction but DO alarm persists)
  private msgCounts = new Map<string, number[]>();

  // Mock membership: in prod, query D1/KV. Here allow any authenticated user; hook is pluggable.
  // Override via env.ROOM_MEMBERS_JSON or implement checkMembership below.
  private blockedUsers = new Map<string, Set<string>>(); // userId -> blocked set
  private reportedMessages: Array<{ messageId: string; reporterId: string; reason: string; ts: number }> = [];

  constructor(state: DurableObjectState, env: ChatEnv) {
    this.state = state;
    this.storage = state.storage;
    this.env = env;

    // Restore hibernated websockets' attachments after eviction
    const wsList = this.state.getWebSockets();
    for (const ws of wsList) {
      const att = ws.deserializeAttachment() as SessionMeta | null;
      if (att) this.sessions.set(ws, att);
    }
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    // Internal: get history (authenticated)
    if (req.method === "GET" && path === "/history") return this.handleHistory(req);
    if (req.method === "POST" && path === "/report") return this.handleReport(req);
    if (req.method === "POST" && path === "/block") return this.handleBlock(req);
    if (req.method === "POST" && path === "/message") return this.handleRestMessage(req);

    // WebSocket upgrade — primary path: Worker forwards authenticated request
    if (req.headers.get("Upgrade") === "websocket") {
      return this.handleWebSocket(req);
    }

    return Response.json({ error: "Not found" }, { status: 404 });
  }

  // ---- Membership check (server-side) ----
  private async checkMembership(userId: string, roomId: string): Promise<boolean> {
    // PLUG: query D1 with prepared statement:
    //   SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?
    // Example (uncomment when DB binding exists):
    //   const row = await this.env.DB.prepare("SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?").bind(roomId, userId).first();
    //   return !!row;

    // For demo: check in-memory allowlist if configured
    // If env.ROOM_MEMBERS_JSON is set like {"general":["user1","user2"]}, enforce it.
    try {
      if ((this.env as unknown as { ROOM_MEMBERS_JSON?: string }).ROOM_MEMBERS_JSON) {
        const map = JSON.parse((this.env as unknown as { ROOM_MEMBERS_JSON: string }).ROOM_MEMBERS_JSON) as Record<string, string[]>;
        if (map[roomId]) return map[roomId].includes(userId);
      }
    } catch {}
    // For general, check persistent membership — user must have joined before to read history
    // This prevents any JWT holder from scraping 100 msgs; membership is added on successful WS join
    if (roomId === "general") {
      const members = await this.storage.get<string[]>(`members:${roomId}`);
      if (members) return members.includes(userId);
      // First join always allowed — will be added after auth
      return true;
    }
    // Default: any authenticated user may join (still requires valid JWT) — dm_* capped at 2 via distinctUsers
    return true;
  }

  private async addMember(roomId: string, userId: string): Promise<void> {
    const key = `members:${roomId}`;
    const existing = (await this.storage.get<string[]>(key)) || [];
    if (!existing.includes(userId)) {
      existing.push(userId);
      // Keep bounded to 1000 members for general
      if (existing.length > 1000) existing.splice(0, existing.length - 1000);
      await this.storage.put(key, existing);
    }
  }

  private async isBlocked(senderId: string, viewerId: string): Promise<boolean> {
    // Load from storage if not in memory
    if (!this.blockedUsers.has(viewerId)) {
      const stored = await this.storage.get<Set<string>>(`blocks:${viewerId}`);
      if (stored) this.blockedUsers.set(viewerId, new Set(stored as unknown as string[]));
      else this.blockedUsers.set(viewerId, new Set());
    }
    return this.blockedUsers.get(viewerId)!.has(senderId);
  }

  // ---- WebSocket handling ----
  private async handleWebSocket(req: Request): Promise<Response> {
    const url = new URL(req.url);
    // CSWSH protection: validate Origin for WebSocket upgrade.
    // Fail closed when Origin is missing — browsers always send it on WS;
    // non-browser clients must use REST + Authorization header instead.
    const origin = req.headers.get("Origin");
    const allowedOrigins = (this.env as unknown as { ALLOWED_ORIGIN?: string }).ALLOWED_ORIGIN?.split(",").map((s) => s.trim()).filter(Boolean) ?? [];
    if (!origin) {
      return Response.json({ error: "Origin required" }, { status: 403 });
    }
    try {
      const o = new URL(origin);
      const isLocalOrigin = o.hostname === "localhost" || o.hostname === "127.0.0.1" || o.hostname === "::1";
      if (!isLocalOrigin && o.protocol !== "https:") {
        return Response.json({ error: "Forbidden Origin" }, { status: 403 });
      }
    } catch {
      return Response.json({ error: "Invalid Origin" }, { status: 403 });
    }
    {
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
      const isLoopback = (() => {
        try {
          const o = new URL(origin);
          return o.hostname === "localhost" || o.hostname === "127.0.0.1" || o.hostname === "::1";
        } catch {
          return false;
        }
      })();
      // Same-origin (Worker host forwarded by worker.ts) is always allowed —
      // otherwise same-origin dev/prod without explicit ALLOWED_ORIGIN breaks.
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
      // For wildcard *, we already reject credentialed — but for WS we still enforce explicit allow
      if (!isAllowedOrigin && !isLoopback && !isSameOrigin && !allowedOrigins.includes("*")) {
        return Response.json({ error: "Forbidden Origin" }, { status: 403 });
      }
    }

    const roomId = url.searchParams.get("roomId") || url.pathname.split("/").pop() || "";
    const vRoom = validateRoomId(roomId);
    if (!vRoom.ok) return Response.json({ error: vRoom.error }, { status: 400 });

    // Payload size cap early
    const cl = req.headers.get("Content-Length");
    if (cl && parseInt(cl, 10) > MAX_PAYLOAD_BYTES) {
      return Response.json({ error: "Payload too large" }, { status: 413 });
    }

    // Auth: prefer Authorization header / Sec-WebSocket-Protocol (no URL
    // leakage). ?token= is deprecated backwards-compat only.
    const { token, viaQuery } = extractWsJwt(req, url);
    if (!token) return Response.json({ error: "Missing Authorization" }, { status: 401 });
    if (viaQuery) log("warn", "room.ws_query_token_deprecated", { roomId: vRoom.value });
    const secret = this.env.JWT_SECRET;
    if (!secret || secret === "dev-secret-change-me" || secret.length < 32) {
      return Response.json({ error: "Server misconfigured" }, { status: 500 });
    }
    const claims = await verifyJwt(token, secret);
    if (!claims) return Response.json({ error: "Invalid or expired token" }, { status: 401 });

    // Room membership check server-side (never trust client)
    const allowed = await this.checkMembership(claims.userId, vRoom.value!);
    if (!allowed) {
      log("warn", "room.forbidden", { roomId: vRoom.value, userId: hashForLog(claims.userId) });
      return Response.json({ error: "Not a member of this room" }, { status: 403 });
    }

    // 2-person cap: only host + one visitor per private invite room (dm_*) — and 2 per any room for this app
    const distinctUsers = new Set([...this.sessions.values()].map((s) => s.userId));
    for (const w of this.state.getWebSockets()) {
      const a = w.deserializeAttachment() as SessionMeta | null;
      if (a) distinctUsers.add(a.userId);
    }
    if (distinctUsers.size >= 2 && !distinctUsers.has(claims.userId)) {
      log("warn", "room.full", { roomId: vRoom.value, present: distinctUsers.size });
      return Response.json({ error: "Room is full — only 2 people allowed", max: 2 }, { status: 403 });
    }

    // Rate-limit with strong SHA-256 bucket keys (never DJB hashForLog —
    // it collides trivially). IP key uses hash, never raw IP in DO keys/logs.
    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    if (this.env.RATE_LIMITER) {
      const ipHash = await hashForRateLimit(`conn:ip:${ip}`);
      const userHash = await hashForRateLimit(`conn:user:${claims.userId}`);
      const rl = await this.checkRateLimitWithDo(`conn:ip:${ipHash}`, { limit: 30, windowMs: 60_000 });
      if (!rl.allowed) return Response.json({ error: "Too many connections", retryAfterMs: rl.resetMs }, { status: 429 });
      const rlUser = await this.checkRateLimitWithDo(`conn:user:${userHash}`, { limit: 30, windowMs: 60_000 });
      if (!rlUser.allowed) return Response.json({ error: "Too many connections" }, { status: 429 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];

    const meta: SessionMeta = {
      userId: claims.userId,
      displayName: claims.displayName,
      connectedAt: Date.now(),
      roomId: vRoom.value!,
    };

    // Persist membership for history access (general room)
    await this.addMember(vRoom.value!, claims.userId);

    // Hibernation: attach metadata so it survives eviction
    this.state.acceptWebSocket(server);
    server.serializeAttachment(meta);
    this.sessions.set(server, meta);

    log("info", "room.join", { roomId: vRoom.value, userId: hashForLog(claims.userId) });

    // Send history + welcome — ephemeral privacy: never replay history on welcome for any room
    // Clients must fetch history explicitly via REST if needed; welcome is empty to prevent passive interception
    const welcome = {
      type: "welcome",
      roomId: vRoom.value,
      userId: claims.userId,
      history: [],
      ts: Date.now(),
    };
    // For hibernation, send after accept; queue microtask
    queueMicrotask(() => {
      try {
        server.send(JSON.stringify(welcome));
      } catch {}
    });

    // Broadcast join presence (excluding sender's blocked users handled per-recipient)
    await this.broadcast(vRoom.value!, { type: "presence", event: "join", userId: claims.userId, displayName: claims.displayName, ts: Date.now() }, claims.userId);

    const wsHeaders = selectWsSubprotocol(req, "bearer");
    return new Response(null, { status: 101, webSocket: client, ...(wsHeaders ? { headers: wsHeaders } : {}) });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const meta = ws.deserializeAttachment() as SessionMeta | null;
    if (!meta) {
      try { ws.close(1008, "Missing session"); } catch {}
      return;
    }
    // Keep session map in sync after hibernation wake
    if (!this.sessions.has(ws)) this.sessions.set(ws, meta);

    // Payload cap
    const size = typeof message === "string" ? new TextEncoder().encode(message).length : (message as ArrayBuffer).byteLength;
    if (size > MAX_PAYLOAD_BYTES) {
      this.sendError(ws, "Payload too large", 1009);
      return;
    }

    let data: unknown;
    try {
      data = JSON.parse(typeof message === "string" ? message : new TextDecoder().decode(message as ArrayBuffer));
    } catch {
      this.sendError(ws, "Invalid JSON");
      return;
    }

    const obj = data as Record<string, unknown>;
    if (obj.type === "ping") {
      ws.send(JSON.stringify({ type: "pong", ts: Date.now() }));
      return;
    }

    // Typing indicator — lightweight, never stored. Validated like messages
    // but silently dropped (no error spam) on any mismatch, deduped per
    // sender, and only delivered to OTHER sessions (never echoed).
    if (obj.type === "typing") {
      const tRoom = typeof obj.roomId === "string" ? obj.roomId : "";
      const vr = validateRoomId(tRoom);
      if (!vr.ok || vr.value !== meta.roomId) return;
      const allowed = await this.checkMembership(meta.userId, vr.value!);
      if (!allowed) return;
      const typing = obj.typing === true;
      if (this.typingState.get(ws) === typing) return;
      this.typingState.set(ws, typing);
      if (this.env.RATE_LIMITER) {
        const tKey = await hashForRateLimit(`typing:user:${meta.userId}`);
        const rl = await this.checkRateLimitWithDo(tKey, { limit: 15, windowMs: 10_000 });
        if (!rl.allowed) return;
      } else if (!this.checkLocalRateLimit(`typing:${meta.userId}`, 15, 10_000)) {
        return;
      }
      await this.broadcastExcept(vr.value!, {
        type: "typing",
        userId: meta.userId,
        displayName: meta.displayName,
        typing,
        ts: Date.now(),
      }, ws);
      return;
    }

    if (obj.type !== "message") {
      this.sendError(ws, "Unknown message type");
      return;
    }

    const roomId = typeof obj.roomId === "string" ? obj.roomId : "";
    const vRoom = validateRoomId(roomId);
    if (!vRoom.ok) {
      this.sendError(ws, vRoom.error!);
      return;
    }

    // Enforce payload roomId == connection roomId to prevent cross-room injection (IDOR)
    if (vRoom.value !== meta.roomId) {
      this.sendError(ws, "roomId mismatch");
      return;
    }

    // Double-check membership on every message (never trust client-supplied roomId alone)
    const allowed = await this.checkMembership(meta.userId, vRoom.value!);
    if (!allowed) {
      this.sendError(ws, "Not a member");
      return;
    }

    // Rate limit messages per user with strong keys (never DJB). Privacy: no IP retained.
    if (this.env.RATE_LIMITER) {
      const userHash = await hashForRateLimit(`msg:user:${meta.userId}`);
      const rlUser = await this.checkRateLimitWithDo(`msg:user:${userHash}`, { limit: 20, windowMs: 10_000 });
      if (!rlUser.allowed) {
        this.sendError(ws, "Rate limited", 1013);
        ws.send(JSON.stringify({ type: "error", code: "rate_limited", retryAfterMs: rlUser.resetMs }));
        return;
      }
    } else {
      // Fallback in-memory sliding window
      if (!this.checkLocalRateLimit(`msg:${meta.userId}`, 20, 10_000)) {
        this.sendError(ws, "Rate limited (local)");
        return;
      }
    }

    // Sanitize + validate. NOTE: dm_* rooms carry E2E ciphertext
    // (enc:...). The server cannot moderate plaintext it cannot decrypt —
    // clients MUST sanitize after decrypt (see public clients). Ciphertext
    // that fails sanitize (control chars etc.) is still rejected here.
    const s = sanitizeMessage(obj.body);
    if (!s.ok) {
      this.sendError(ws, s.error!);
      return;
    }
    const cleanBody = s.value!;
    const isE2ECipher = cleanBody.startsWith("enc:");

    // Moderation hook — flag or block before broadcast (privacy: no IP passed).
    // E2E ciphertext cannot be content-moderated server-side; enforce sender
    // rate limits + length, skip blocklist on ciphertext (would false-positive).
    const modHook = createModerationHook(this.env as unknown as { MODERATION_KEY?: string });
    const mod = isE2ECipher
      ? { allowed: true as const, flagged: false as const }
      : await modHook(cleanBody, { userId: meta.userId, roomId: vRoom.value!, ip: "***" });
    if (!mod.allowed) {
      log("warn", "moderation.blocked_broadcast", { roomId: vRoom.value, userId: hashForLog(meta.userId), reason: mod.reason });
      ws.send(JSON.stringify({ type: "moderation", allowed: false, reason: mod.reason, ts: Date.now() }));
      return;
    }

    const chatMsg: ChatMessage = {
      id: crypto.randomUUID(),
      roomId: vRoom.value!,
      userId: meta.userId,
      displayName: meta.displayName,
      body: mod.sanitizedBody ?? cleanBody,
      ts: Date.now(),
      flagged: mod.flagged || undefined,
      flagReason: mod.reason,
    };

    // Store history — Durable Object storage (strong consistency)
    // Prepared-statement style: no concatenation, structured keys
    // D1 alternative (commented):
    // await this.env.DB.prepare("INSERT INTO messages (id, room_id, user_id, body, ts, flagged) VALUES (?, ?, ?, ?, ?, ?)")
    //   .bind(chatMsg.id, chatMsg.roomId, chatMsg.userId, chatMsg.body, chatMsg.ts, chatMsg.flagged ? 1 : 0).run();

    await this.appendHistory(chatMsg);

    if (mod.flagged) {
      log("info", "moderation.flagged_broadcast", { messageId: chatMsg.id, roomId: chatMsg.roomId, userId: hashForLog(meta.userId), reason: mod.reason });
    } else {
      log("info", "room.message", { messageId: chatMsg.id.slice(0, 8), roomId: chatMsg.roomId, userId: hashForLog(meta.userId) });
    }

    // Broadcast to room (respect blocks: don't deliver to users who blocked sender, or where sender blocked viewer? we do viewer-blocks-sender)
    await this.broadcast(vRoom.value!, { type: "message", message: chatMsg }, undefined);
  }

  async webSocketClose(ws: WebSocket, code: number, _reason: string, _wasClean: boolean): Promise<void> {
    const meta = this.sessions.get(ws) || (ws.deserializeAttachment() as SessionMeta | null);
    this.sessions.delete(ws);
    // Clear stale typing so a reconnect doesn't leave a ghost indicator.
    if (this.typingState.get(ws) && meta?.roomId) {
      this.typingState.delete(ws);
      await this.broadcastExcept(meta.roomId, {
        type: "typing",
        userId: meta.userId,
        displayName: meta.displayName,
        typing: false,
        ts: Date.now(),
      }, ws);
    } else {
      this.typingState.delete(ws);
    }
    if (meta) {
      log("info", "room.leave", { userId: hashForLog(meta.userId), code });
      // Use the closing session's bound room — inferRoomId() returns null for
      // new rooms with no messages yet, which previously skipped peer-close.
      const anyRoom = meta.roomId || (await this.inferRoomId());
      if (anyRoom) {
        await this.broadcast(anyRoom, { type: "presence", event: "leave", userId: meta.userId, ts: Date.now() }, meta.userId);
        // 2-person ephemeral: if one refreshes/closes, close the peer's tab as well (refresh erases → peer closed)
        const remaining = [...this.sessions.values()];
        const hibernated = this.state.getWebSockets().map((w) => w.deserializeAttachment() as SessionMeta | null).filter(Boolean) as SessionMeta[];
        const totalRemaining = remaining.length + hibernated.length;
        // Notify remaining peers to close (refresh on any device closes the other)
        if (totalRemaining > 0) {
          await this.broadcast(anyRoom, { type: "peer_closed", reason: "peer_refreshed", ts: Date.now() });
          // also force-close remaining sockets so they trigger onclose → window.close fallback
          for (const s of this.state.getWebSockets()) {
            try { s.close(4000, "peer_refreshed"); } catch {}
          }
          this.sessions.clear();
        }
        // schedule immediate GC for ephemeral dm_* (already handled in alarm, but also clear if empty)
        if (totalRemaining === 0) await this.storage.setAlarm(Date.now() + 5000);
      }
    }
  }

  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    const meta = this.sessions.get(ws) || (ws.deserializeAttachment() as SessionMeta | null);
    this.sessions.delete(ws);
    this.typingState.delete(ws);
    log("warn", "room.ws_error", { userId: meta?.userId ?? "unknown" });
  }

  // ---- REST handlers inside DO ----
  private async handleHistory(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const roomId = url.searchParams.get("roomId") || "";
    const vRoom = validateRoomId(roomId);
    if (!vRoom.ok) return Response.json({ error: vRoom.error }, { status: 400 });

    // Auth required to read history (same JWT check as WS) — header only for REST to avoid token-in-URL leakage
    const token = extractBearer(req) || "";
    if (!token) return Response.json({ error: "Missing Authorization" }, { status: 401 });
    const secret = this.env.JWT_SECRET;
    if (!secret || secret === "dev-secret-change-me" || secret.length < 32) {
      return Response.json({ error: "Server misconfigured" }, { status: 500 });
    }
    const claims = await verifyJwt(token, secret);
    if (!claims) return Response.json({ error: "Unauthorized" }, { status: 401 });
    const allowed = await this.checkMembership(claims.userId, vRoom.value!);
    if (!allowed) return Response.json({ error: "Forbidden" }, { status: 403 });

    // dm_* are ephemeral — never replay history even via REST
    if (vRoom.value!.startsWith("dm_")) {
      return Response.json({ roomId: vRoom.value, messages: [] });
    }
    const history = await this.getHistory(vRoom.value!);
    const filtered = await this.filterHistoryForUser(history, claims.userId);
    return Response.json({ roomId: vRoom.value, messages: filtered });
  }

  private async handleReport(req: Request): Promise<Response> {
    const body = (await req.json().catch(() => null)) as { messageId?: string; reason?: string; roomId?: string } | null;
    if (!body?.messageId || !body.reason) return Response.json({ error: "messageId and reason required" }, { status: 400 });
    if (!/^[a-f0-9-]{36}$/.test(body.messageId)) return Response.json({ error: "Invalid messageId" }, { status: 400 });
    if (body.reason.length > 500) return Response.json({ error: "Reason too long" }, { status: 400 });
    if (body.reason.length < 3) return Response.json({ error: "Reason too short" }, { status: 400 });
    // Sanitize reason
    if (/[<>]/.test(body.reason)) return Response.json({ error: "Invalid characters in reason" }, { status: 400 });
    // Rate-limit reports per user (strong keys). Auth is verified below;
    // pre-check here only to shed load — final decision after auth.
    const tokenTmp = extractBearer(req);
    if (tokenTmp) {
      const secretTmp = this.env.JWT_SECRET;
      if (secretTmp) {
        const claimsTmp = await verifyJwt(tokenTmp, secretTmp);
        if (claimsTmp && this.env.RATE_LIMITER) {
          const rlKey = await hashForRateLimit(`report:user:${claimsTmp.userId}`);
          const rl = await this.checkRateLimitWithDo(rlKey, { limit: 5, windowMs: 60_000 });
          if (!rl.allowed) return Response.json({ error: "Rate limited" }, { status: 429 });
        }
      }
    }

    const token = extractBearer(req);
    if (!token) return Response.json({ error: "Unauthorized" }, { status: 401 });
    const secret = this.env.JWT_SECRET;
    if (!secret || secret === "dev-secret-change-me" || secret.length < 32) {
      return Response.json({ error: "Server misconfigured" }, { status: 500 });
    }
    const claims = await verifyJwt(token, secret);
    if (!claims) return Response.json({ error: "Invalid token" }, { status: 401 });

    // Bound in-memory + storage reports to prevent unbounded growth (DoS).
    // Keep last 100 reports per room; reports carry no message body.
    this.reportedMessages.push({ messageId: body.messageId, reporterId: claims.userId, reason: body.reason.slice(0, 500), ts: Date.now() });
    if (this.reportedMessages.length > 100) this.reportedMessages.splice(0, this.reportedMessages.length - 100);
    await this.storage.put(`reports:${Date.now()}:${crypto.randomUUID()}`, { messageId: body.messageId, reporterId: claims.userId, reason: body.reason.slice(0, 500), ts: Date.now() });
    // Trim stored reports to last 100
    {
      const all = await this.storage.list({ prefix: "reports:" });
      if (all.size > 100) {
        const keys = [...all.keys()].sort().slice(0, all.size - 100);
        for (const k of keys) await this.storage.delete(k);
      }
    }

    log("info", "room.report", { messageId: body.messageId.slice(0, 8), reporterId: claims.userId, roomId: body.roomId ?? "unknown" });
    return Response.json({ ok: true });
  }

  private async handleBlock(req: Request): Promise<Response> {
    const body = (await req.json().catch(() => null)) as { blockedUserId?: string } | null;
    if (!body?.blockedUserId || typeof body.blockedUserId !== "string") return Response.json({ error: "blockedUserId required" }, { status: 400 });
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(body.blockedUserId)) return Response.json({ error: "Invalid userId" }, { status: 400 });
    // Prevent self-block already checked after auth, but also validate length
    if (body.blockedUserId.length > 64) return Response.json({ error: "Invalid userId" }, { status: 400 });
    // Rate-limit block spam (strong keys)
    const tokenTmp2 = extractBearer(req);
    if (tokenTmp2) {
      const s2 = this.env.JWT_SECRET;
      if (s2) {
        const c2 = await verifyJwt(tokenTmp2, s2);
        if (c2 && this.env.RATE_LIMITER) {
          const rlKey2 = await hashForRateLimit(`block:user:${c2.userId}`);
          const rl = await this.checkRateLimitWithDo(rlKey2, { limit: 10, windowMs: 60_000 });
          if (!rl.allowed) return Response.json({ error: "Rate limited" }, { status: 429 });
        }
      }
    }

    const token = extractBearer(req);
    if (!token) return Response.json({ error: "Unauthorized" }, { status: 401 });
    const secret2 = this.env.JWT_SECRET;
    if (!secret2 || secret2 === "dev-secret-change-me" || secret2.length < 32) {
      return Response.json({ error: "Server misconfigured" }, { status: 500 });
    }
    const claims = await verifyJwt(token, secret2);
    if (!claims) return Response.json({ error: "Invalid token" }, { status: 401 });
    if (claims.userId === body.blockedUserId) return Response.json({ error: "Cannot block yourself" }, { status: 400 });

    let set = this.blockedUsers.get(claims.userId);
    if (!set) {
      const stored = await this.storage.get<string[]>(`blocks:${claims.userId}`);
      set = new Set(stored ?? []);
      this.blockedUsers.set(claims.userId, set);
    }
    set.add(body.blockedUserId);
    // Bound block lists (50 per user) to prevent storage exhaustion
    while (set.size > 50) {
      const first = set.values().next().value as string;
      set.delete(first);
    }
    await this.storage.put(`blocks:${claims.userId}`, [...set]);

    log("info", "room.block", { userId: claims.userId, blockedId: body.blockedUserId });
    return Response.json({ ok: true, blocked: [...set] });
  }

  private async handleRestMessage(req: Request): Promise<Response> {
    // Optional REST send (rate-limited, same sanitization).
    // SECURITY FIX: the Worker routes to this DO by URL roomId
    // (idFromName(urlRoom)). The body roomId MUST equal the URL roomId —
    // previously body.roomId was trusted, letting POST /room/A/message store
    // + broadcast as roomB (cross-room spoof / storage pollution).
    const url = new URL(req.url);
    const urlRoom = url.searchParams.get("roomId") || "";
    const body = (await req.json().catch(() => null)) as { roomId?: string; body?: string } | null;
    if (!body?.roomId || typeof body.body !== "string") return Response.json({ error: "roomId and body required" }, { status: 400 });
    const token = extractBearer(req);
    if (!token) return Response.json({ error: "Unauthorized" }, { status: 401 });
    const secret = this.env.JWT_SECRET;
    if (!secret || secret === "dev-secret-change-me" || secret.length < 32) {
      return Response.json({ error: "Server misconfigured" }, { status: 500 });
    }
    const claims = await verifyJwt(token, secret);
    if (!claims) return Response.json({ error: "Invalid token" }, { status: 401 });

    const vRoom = validateRoomId(body.roomId);
    if (!vRoom.ok) return Response.json({ error: vRoom.error }, { status: 400 });
    if (urlRoom && urlRoom !== vRoom.value) {
      return Response.json({ error: "roomId mismatch (URL vs body)" }, { status: 400 });
    }
    const allowed = await this.checkMembership(claims.userId, vRoom.value!);
    if (!allowed) return Response.json({ error: "Forbidden" }, { status: 403 });

    // REST rate-limit (was missing — WS path was limited, REST was not)
    if (this.env.RATE_LIMITER) {
      const rlKey = await hashForRateLimit(`msg:user:${claims.userId}`);
      const rl = await this.checkRateLimitWithDo(rlKey, { limit: 20, windowMs: 10_000 });
      if (!rl.allowed) return Response.json({ error: "Rate limited", retryAfterMs: rl.resetMs }, { status: 429 });
    }

    const s = sanitizeMessage(body.body);
    if (!s.ok) return Response.json({ error: s.error }, { status: 400 });

    const modHook = createModerationHook(this.env as unknown as { MODERATION_KEY?: string });
    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    const isCipher = s.value!.startsWith("enc:");
    const mod = isCipher
      ? { allowed: true as const, flagged: false as const }
      : await modHook(s.value!, { userId: claims.userId, roomId: vRoom.value!, ip });
    if (!mod.allowed) return Response.json({ error: mod.reason, flagged: true }, { status: 422 });

    const msg: ChatMessage = {
      id: crypto.randomUUID(),
      roomId: vRoom.value!,
      userId: claims.userId,
      displayName: claims.displayName,
      body: mod.sanitizedBody ?? s.value!,
      ts: Date.now(),
      flagged: mod.flagged || undefined,
      flagReason: mod.reason,
    };
    await this.appendHistory(msg);
    await this.broadcast(vRoom.value!, { type: "message", message: msg });
    return Response.json({ ok: true, message: msg });
  }

  // ---- Helpers ----
  private async getHistory(roomId: string): Promise<ChatMessage[]> {
    // List keys prefix messages:<roomId>:
    const prefix = `messages:${roomId}:`;
    const listed = await this.storage.list<ChatMessage>({ prefix, limit: MAX_ROOM_HISTORY });
    const arr = [...listed.values()].sort((a, b) => a.ts - b.ts);
    return arr.slice(-MAX_ROOM_HISTORY);
  }

  private async appendHistory(msg: ChatMessage): Promise<void> {
    const key = `messages:${msg.roomId}:${String(msg.ts).padStart(13, "0")}:${msg.id}`;
    await this.storage.put(key, msg);
    // Set auto-expiration alarm (ephemeral: 24h, or 1h for dm_*). Privacy: automatic deletion.
    const ttl = msg.roomId.startsWith("dm_") ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
    const alarmAt = Date.now() + ttl;
    const cur = await this.storage.getAlarm();
    // FIX: old code called setAlarm twice when cur===null (second call
    // overwrote the TTL alarm with now+1h). Set exactly once.
    if (cur === null || alarmAt < cur) await this.storage.setAlarm(alarmAt);
    // Trim oldest if over limit (list + delete)
    const all = await this.storage.list<ChatMessage>({ prefix: `messages:${msg.roomId}:` });
    if (all.size > MAX_ROOM_HISTORY) {
      const sorted = [...all.entries()].sort((a, b) => (a[1].ts - b[1].ts));
      const toDelete = sorted.slice(0, all.size - MAX_ROOM_HISTORY).map(([k]) => k);
      for (const k of toDelete) await this.storage.delete(k);
    }
  }

  private async filterHistoryForUser(history: ChatMessage[], viewerId: string): Promise<ChatMessage[]> {
    const out: ChatMessage[] = [];
    for (const m of history) {
      if (await this.isBlocked(m.userId, viewerId)) continue;
      out.push(m);
    }
    return out;
  }

  private async broadcast(roomId: string, data: unknown, excludeUserId?: string): Promise<void> {
    void roomId;
    const payload = JSON.stringify(data);
    const senderId = (data as { message?: ChatMessage })?.message?.userId;
    // Deliver with per-recipient block check. Previously only the in-memory
    // map was consulted, so after eviction (or for recipients never loaded)
    // blocked senders' live messages were delivered. Now storage-backed.
    for (const [ws, meta] of this.sessions) {
      if (excludeUserId && meta.userId === excludeUserId && (data as Record<string, unknown>).type === "presence") {
        // don't send join/leave to self? we do send to self for presence? skip self for join to avoid echo
        continue;
      }
      if (senderId) {
        let blockedSet = this.blockedUsers.get(meta.userId);
        if (!blockedSet) {
          const stored = await this.storage.get<string[]>(`blocks:${meta.userId}`);
          blockedSet = new Set(stored ?? []);
          this.blockedUsers.set(meta.userId, blockedSet);
        }
        if (blockedSet.has(senderId)) continue;
      }
      try {
        if (ws.readyState === 1) ws.send(payload);
      } catch {
        // remove dead
        this.sessions.delete(ws);
      }
    }
  }

  private async broadcastExcept(roomId: string, data: unknown, except: WebSocket): Promise<void> {
    void roomId;
    const payload = JSON.stringify(data);
    const senderId = (data as { userId?: string })?.userId;
    for (const [ws, meta] of this.sessions) {
      if (ws === except) continue;
      // Respect blocks: viewers who blocked the sender see nothing, not even typing.
      if (senderId) {
        let blockedSet = this.blockedUsers.get(meta.userId);
        if (!blockedSet) {
          const stored = await this.storage.get<string[]>(`blocks:${meta.userId}`);
          blockedSet = new Set(stored ?? []);
          this.blockedUsers.set(meta.userId, blockedSet);
        }
        if (blockedSet.has(senderId)) continue;
      }
      try {
        if (ws.readyState === 1) ws.send(payload);
      } catch {
        this.sessions.delete(ws);
      }
    }
  }

  private sendError(ws: WebSocket, msg: string, code = 1008): void {
    try {
      ws.send(JSON.stringify({ type: "error", error: msg, ts: Date.now() }));
    } catch {}
  }

  private async checkRateLimitWithDo(key: string, opts: { limit: number; windowMs: number }) {
    const id = this.env.RATE_LIMITER.idFromName(`rl:${key}`);
    const stub = this.env.RATE_LIMITER.get(id);
    const res = await stub.fetch("https://rl/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, ...opts }),
    });
    if (!res.ok) return { allowed: false, remaining: 0, resetMs: opts.windowMs };
    return (await res.json()) as { allowed: boolean; remaining: number; resetMs: number };
  }

  private checkLocalRateLimit(key: string, limit: number, windowMs: number): boolean {
    const now = Date.now();
    // Opportunistically GC idle keys to prevent unbounded memory growth
    if (this.msgCounts.size > 1000) {
      for (const [k, arr] of this.msgCounts) {
        if (arr.length === 0 || now - arr[arr.length - 1] > windowMs * 2) this.msgCounts.delete(k);
        if (this.msgCounts.size <= 500) break;
      }
    }
    const arr = this.msgCounts.get(key) ?? [];
    const recent = arr.filter((t) => now - t < windowMs);
    if (recent.length >= limit) {
      this.msgCounts.set(key, recent);
      return false;
    }
    recent.push(now);
    this.msgCounts.set(key, recent);
    return true;
  }

  async alarm(): Promise<void> {
    // Auto-delete expired messages (privacy: ephemeral)
    const now = Date.now();
    const all = await this.storage.list<ChatMessage>({ prefix: "messages:" });
    let deleted = 0;
    for (const [k, v] of all) {
      const age = now - v.ts;
      const ttl = v.roomId.startsWith("dm_") ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
      if (age > ttl) {
        await this.storage.delete(k);
        deleted++;
      }
    }
    // GC stale reports older than 24h (bounded storage)
    const reports = await this.storage.list({ prefix: "reports:" });
    for (const k of reports.keys()) {
      const parts = k.split(":");
      const ts = parseInt(parts[1] || "0", 10);
      if (ts && now - ts > 24 * 60 * 60 * 1000) await this.storage.delete(k);
    }
    // If no sessions and no messages, clean up fully; else reschedule
    const sessions = this.state.getWebSockets().length;
    const remaining = await this.storage.list({ prefix: "messages:" });
    if (remaining.size === 0 && sessions === 0) {
      // fully ephemeral — delete all
      await this.storage.deleteAll();
    } else if (deleted > 0 || remaining.size > 0) {
      await this.storage.setAlarm(now + 60 * 60 * 1000);
    }
    if (deleted) log("info", "room.gc", { deleted, remaining: remaining.size });
  }

  private async inferRoomId(): Promise<string | null> {
    // Try to infer from stored message keys
    const listed = await this.storage.list({ prefix: "messages:", limit: 1 });
    for (const k of listed.keys()) {
      const parts = k.split(":");
      if (parts.length >= 2) return parts[1];
    }
    return null;
  }
}
