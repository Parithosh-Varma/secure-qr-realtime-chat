export const QR_TTL_MS = 90_000; // 60-120s required — pick 90s midpoint, configurable via env
export const QR_TTL_MIN = 60_000;
export const QR_TTL_MAX = 120_000;
export const JWT_TTL_MS = 3_600_000; // 1h short-lived session
export const MAX_MESSAGE_LENGTH = 2000;
export const MAX_PAYLOAD_BYTES = 8 * 1024; // 8 KiB
export const MAX_ROOM_HISTORY = 100;
export const RATE_LIMIT = {
  // qr generation: 5 / minute per IP, 10 / minute per user
  qrPerIp: { limit: 5, windowMs: 60_000 },
  qrPerUser: { limit: 10, windowMs: 60_000 },
  // approve attempts: 10 / minute per token, 20 / minute per IP
  approvePerIp: { limit: 20, windowMs: 60_000 },
  // chat connections: 30 / minute per IP
  connectPerIp: { limit: 30, windowMs: 60_000 },
  // messages: 20 per 10s sliding window per user, 40 per 10s per IP fallback
  msgPerUser: { limit: 20, windowMs: 10_000 },
  msgPerIp: { limit: 40, windowMs: 10_000 },
} as const;

export const ALLOWED_ORIGINS = [
  // tighten in production — set via ALLOWED_ORIGIN env var and replace this list
  // e.g. "https://chat.example.com"
];

export const CSP_VALUE = [
  "default-src 'self'",
  // No inline scripts: mobile/desktop have no <script> blocks (consent flow
  // needs no head inline JS). Keep script-src locked to 'self' only.
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "img-src 'self' data: blob:",
  "connect-src 'self' https: wss:",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");
