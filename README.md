# Secure QR Realtime Chat — Cloudflare Workers + Durable Objects

> **Security-first** real-time chat where desktop login is bootstrapped by an already-authenticated mobile session via a single-use opaque QR token. One Durable Object per room (strong consistency), one per QR token (atomic burn), Workers runtime only, TypeScript, hardened headers, sliding-window rate limits, server-side sanitization + pluggable moderation.

**Repo:** `Parithosh-Varma/secure-qr-realtime-chat` • **Live after deploy:** `https://<your-worker>.workers.dev`

---

## Architecture

```
[Desktop] --POST /api/auth/qr/create--> [Worker] --SHA-256(token)--> [AuthSession DO idFromName(hash)]
   |  renders QR with https://host/mobile?token=<opaque>          |  stores pending + fingerprint, alarm 90s
   |  holds /api/auth/qr/ws?token=… ------> [AuthSession DO]  (waiters WS set)
                                                                  |
[Mobile] --POST /api/auth/mobile/approve {token, approve}+Bearer JWT--> [Worker verifies JWT] --> [AuthSession DO /approve]
       (mobile shows fingerprint/city/timestamp, explicit tap)       marks approved, notifies waiters

[Desktop] --POST /api/auth/qr/claim {token}--> [Worker] --> [AuthSession DO /claim] --burns--> returns identity --> Worker mints HS256 JWT (1h)
   |
   +--WSS /api/room/:roomId/ws?token=JWT --> [Worker] --> [ChatRoom DO idFromName(roomId)]  (acceptWebSocket, hibernation)
           validates JWT, checkMembership(), rate-limit, sanitize, moderate, broadcast, persist history
```

**Bindings (`wrangler.toml`):**

- `CHAT_ROOM` → `ChatRoom` (one DO per `roomId`)
- `AUTH_SESSION` → `AuthSession` (one DO per token hash)
- `RATE_LIMITER` → `RateLimiter` (one DO per `rl:<key>` sliding window)
- Optional `DB` (D1) for history if you outgrow DO storage

---

## Security decisions — especially QR login

### QR token is not a JWT and never contains identity

- **Opaque, random, single-use:** `crypto.getRandomValues(32)` → base64url (≈43 chars, 256-bit entropy). No `userId`, no claims, no predictable structure. Presented only as `https://host/mobile?token=<opaque>` encoded in the QR.
- **Hashed at rest:** Worker hashes with SHA-256 before `idFromName()` and before persisting. DO stores `tokenHash`, never the raw token. Logs only `hashForLog(hash).slice(0,8)`.
- **Short-lived:** default 90s (configurable `QR_TTL_SECONDS=60–120`). `storage.setAlarm(expiresAt+1s)` in DO; also lazy expiry on read.
- **Burned on claim:** `AuthSession` runs single-threaded; `POST /claim` checks `status===approved`, then flips to `claimed` + `claimedAt` and `setAlarm(now+5s)` *before* returning identity. Second `claim` gets `410 Already claimed` — no replay, no race. Alarm then deletes to prevent disk bloat but keeps tombstone until grace ends.
- **No auto-approve / no blind trust:**
  - Mobile must be **already authenticated** (valid `Bearer JWT` verified via `verifyJwt()` with `HMAC-SHA256` + constant-time compare).
  - Worker enforces explicit `action: "approve"|"deny"` body; DO rejects any other.
  - Mobile client **must** show confirmation: `fingerprint { ip, UA, acceptLanguage, city, country, timestamp }` captured at QR creation time in the DO. User taps checkbox + Approve — deny instantly flips to `denied` and notifies waiters.

### Binding to device/location & anti-flooding

- Fingerprint + approximate location (`cf.city`/`cf.country` if available) is captured server-side at `create` and surfaced on mobile preview. Helps user spot unexpected logins (attacker in different city).
- Rate limits via `RateLimiter` DO (sliding window):
  - `qrPerIp 5/min`, `qrPerUser 10/min`, `approvePerIp 20/min`, `connectPerIp 30/min`, `msgPerUser 20/10s`, `msgPerIp 40/10s`.
  - DO stores `hits: number[]` per key, GC via alarm. Worker checks before `create`, `approve`, `claim`, and `ChatRoom` checks on `connect` + `message`.
  - Token guessing is brute-force-resistant (256-bit) + per-IP/token rate caps; enumeration of `idFromName(hash)` without token is infeasible.

### Room access control — never trust the client

- `ChatRoom` validates `roomId` format `^[a-zA-Z0-9_-]{3,64}$` and verifies JWT on **every** WebSocket upgrade and every message (`extractBearer` → `verifyJwt` with `JWT_SECRET`).
- Membership check is server-side: `checkMembership(userId, roomId)` is the seam — wired to a `D1` prepared statement skeleton (`SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?` + `.bind(roomId, userId)`), never concatenated. Demo defaults to “any authenticated user” but the gate is always evaluated before `acceptWebSocket()` and on each `type: "message"` frame (re-checks membership for the `roomId` in the payload, not just the URL).
- WebSocket messages that try to spoof `userId`/`roomId` are ignored; sender identity comes only from the JWT attachment (`serializeAttachment(meta)`).

### Data protection

- **HTTPS/WSS only:** Worker `requireHttps()` redirects `http→https`; CSP `connect-src 'self' wss: https:` and `Upgrade` handling reject `ws://` in non-local envs. `Strict-Transport-Security: max-age=31536000; preload`.
- **Sanitization:** `sanitizeMessage()` runs server-side: length ≤2000, rejects control chars, normalizes NFC, escapes `&<>"'` so even `innerHTML` insertion is safe. Whitespace collapsed, empty messages rejected.
- **Persistence:** DO storage keys `messages:<roomId>:<ts>:<id>` keep last `100` per room; D1 alternative uses prepared statements only (example commented in `ChatRoom`). No string-concatenated SQL anywhere.
- **Encryption at rest:** DO storage & D1 are encrypted at rest by Cloudflare automatically; secrets (`JWT_SECRET`, `MODERATION_KEY`) are `wrangler secret put` only.

### Abuse & operational safety

- **Pluggable moderation:** `createModerationHook(env)` defaults to blocklist + caps/repetition heuristics, returns `{allowed, flagged, reason}`. If `MODERATION_KEY` is set, it calls external API with 800ms timeout and falls back to local hook on failure. Blocked messages are never broadcast; flagged ones are broadcast with `flagged:true` and logged at `info` without body. `log("moderation.blocked", {reason})` never logs raw text.
- **Reporting/blocking:** `POST /api/report {messageId, reason}` and `POST /api/block {blockedUserId}` are authenticated; reports store only `messageId+reporterId+reason` (truncated 500 chars), no body; blocks persist `blocks:<userId> -> string[]` and are enforced per-recipient in `broadcast()` and `filterHistoryForUser()`.
- **Headers:** Every response gets `HSTS, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy, Permissions-Policy, CSP, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, Cache-Control: no-store, Vary: Origin`. CORS is strict allowlist via `ALLOWED_ORIGIN` env (no wildcard in prod).
- **Payload caps:** `MAX_PAYLOAD_BYTES=8 KiB` checked via `Content-Length` and actual body size; message length 2000 chars; queue trimmed to 100 messages/room; ping/pong supported but no binary blob passthrough.
- **Disconnects:** `ChatRoom` uses hibernation (`acceptWebSocket` + `serializeAttachment` + `webSocketClose/webSocketMessage/webSocketError`). Sessions are re-hydrated from `getWebSockets()` on wake; `sessions` map is authoritative but restores from attachments so eviction never leaks or duplicates.
- **Logging:** `log(level, event, fields)` is JSON-structured. Never logs `message.body`, `token`, or `jwt`; uses `redactIp()` (`a.b.c.0`) and `hashForLog()` for correlation.

---

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/auth/qr/create` | none (IP-limited) | returns `{token, url, expiresAt, ttlMs}` — token in memory only |
| GET | `/api/auth/qr/status?token=…` | token-bound | `{status, createdAt, expiresAt}` — polling fallback |
| GET (WS) | `/api/auth/qr/ws?token=…` | token-bound | lightweight waiter WS, read-only |
| GET | `/api/auth/qr/preview?token=…` | none | for mobile confirmation screen |
| POST | `/api/auth/mobile/approve` | **Bearer JWT** (mobile) | `{token, action}` → `approved/denied` |
| POST | `/api/auth/qr/claim` | token-bound | burns token, returns `{token: jwt, identity}` — 202 pending, 410 burned |
| POST | `/api/auth/dev-login` | none (IP-limited) | **dev only** — mints mobile JWT for testing |
| GET (WS) | `/api/room/:roomId/ws` | **Bearer JWT** | chat — `?token=` also accepted for browser WS |
| GET | `/api/room/:roomId/history` | **Bearer JWT** | filtered by blocks |
| POST | `/api/report` | Bearer | `{messageId, reason, roomId}` |
| POST | `/api/block` | Bearer | `{blockedUserId, roomId}` |

---

## Local dev

```bash
npm install
# set secrets for local (or use .dev.vars)
echo 'JWT_SECRET=local-dev-secret-at-least-32-chars' > .dev.vars
echo 'ALLOWED_ORIGIN=http://localhost:8787' >> .dev.vars

npx wrangler dev
# open http://localhost:8787/desktop  (QR + chat)
# open http://localhost:8787/mobile   (approve)
```

**Deploy:**

```bash
npx wrangler secret put JWT_SECRET
# optional:
npx wrangler secret put MODERATION_KEY
npx wrangler deploy
# then set ALLOWED_ORIGIN to https://<your-domain>
```

Create D1 if you want it (optional — history works without it):

```bash
npx wrangler d1 create chat-history
# put the id in wrangler.toml [[d1_databases]] and uncomment DB usage in ChatRoom
```

---

## Client examples

- **`public/desktop.html` + `public/client/desktop.js`** — generate QR via `QRCode.toCanvas()`, hold WS waiter + 1.5s poll fallback, `claim` → store JWT in `localStorage`, auto-connect `WSS /api/room/general/ws`, send `{"type":"message","roomId":"general","body":"…"}` with local sanitization preview but server is authoritative.
- **`public/mobile.html` + `public/client/mobile.js`** — dev-login mint, paste token (or open QR link with `?token=`), preview shows expiry + location, explicit `ack` checkbox gates Approve, calls `POST /api/auth/mobile/approve` with `Authorization: Bearer <mobileJwt>`.

Both also have **Worker-embedded fallbacks** (`worker.ts` `desktopFallbackHtml`/`mobileFallbackHtml`/`desktopJs`/`mobileJs`) so `npx wrangler dev` works even without a static assets binding.

---

## Threat model (condensed)

- **Token replay / theft:** mitigated by short TTL, hash-at-rest, one-time burn, alarms, and no JWT-in-QR. Even if QR photo is stolen within 90s, attacker still needs to win the race to `claim`; mobile approval is still gated and desktops that claimed first invalidate attacker. In a higher-assurance variant, bind token to desktop `code_verifier` (PKCE-like) or require desktop to prove possession of a `claimKey` generated alongside token.
- **Brute force:** 256-bit opaque space + IP/user/token rate limits + 410 on burned tokens.
- **XSS:** server escapes HTML; CSP blocks inline scripts except the demo’s `unsafe-inline` (replace with nonce/hash in prod).
- **CSWSH / CSRF on WS:** `Origin` checked via strict CORS allowlist; `Authorization: Bearer` not cookie, so CSRF is moot. Consider `Sec-WebSocket-Protocol` + token binding for cookie-based auth variants.
- **SQLi:** no concatenation; `DB.prepare(...).bind(...)` only.
- **DoS:** 8 KiB payload cap, 2000-char message cap, 20 msg/10s, 100-msg history, alarms GC.
- **Privacy:** no message body in logs, IP redacted, tokens never logged.

---

## File map

```
wrangler.toml                — bindings, migrations, limits
src/worker.ts                — all HTTP routes + WS forwards + embedded demo fallbacks
src/durable/AuthSession.ts   — QR lifecycle, hash, burn, alarm, waiter WS
src/durable/ChatRoom.ts      — room WS, membership, sanitize, moderate, history, block/report
src/durable/RateLimiter.ts   — sliding-window counters
src/lib/jwt.ts               — HS256 sign/verify (WebCrypto)
src/lib/crypto.ts            — randomOpaqueToken, sha256Hex
src/lib/sanitize.ts          — escapeHtml, validateRoomId/token
src/lib/headers.ts           — HSTS/CSP/CORS
src/lib/moderation.ts        — pluggable hook
src/lib/types.ts / logger.ts / constants.ts
public/desktop.html, public/mobile.html, public/client/*.js
```

---

## License

MIT — do not use `dev-login` in production; wire real IdP JWTs to `mobile/approve`.
