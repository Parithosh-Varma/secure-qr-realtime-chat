export type UserIdentity = {
  userId: string;
  displayName?: string;
  email?: string;
};

export type SessionClaims = UserIdentity & {
  iat: number;
  exp: number;
  jti: string;
};

export type QrStatus = "pending" | "approved" | "claimed" | "expired" | "denied";

export type QrSessionState = {
  tokenHash: string; // store hash, not raw token, inside DO where possible
  status: QrStatus;
  createdAt: number;
  expiresAt: number;
  fingerprint: {
    ip: string;
    userAgent: string;
    acceptLanguage?: string;
    city?: string; // from cf.ipCity if available (approx location)
    country?: string;
  };
  // set only after mobile approval
  approver?: UserIdentity & { approvedAt: number };
  // burn flag
  claimedAt?: number;
};

export type ChatMessage = {
  id: string;
  roomId: string;
  userId: string;
  displayName?: string;
  body: string; // already sanitized
  rawBody?: never; // never store raw
  ts: number;
  flagged?: boolean;
  flagReason?: string;
};

export type ModerationResult = {
  allowed: boolean;
  flagged: boolean;
  reason?: string;
  sanitizedBody?: string;
};

export type RateLimitResult = {
  allowed: boolean;
  remaining: number;
  resetMs: number;
};
