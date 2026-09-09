import { validateTokenFormat } from "./sanitize";

export type ApproveAction = "approve" | "deny";

export type ApproveInput = {
  token?: unknown;
  action?: unknown;
  confirmedFingerprint?: unknown;
  auto?: unknown;
};

export type ApproveValidation =
  | { ok: true; token: string; action: ApproveAction; auto: boolean }
  | { ok: false; error: string };

/**
 * Pure validation for POST /api/auth/mobile/approve bodies.
 * Transport concerns (X-QR-Token vs ?token= query) stay in the Worker —
 * this only judges the decoded fields, so it is unit-testable in plain Node.
 *
 * Rules:
 * - token must be a well-formed opaque token (never a JWT, never identity)
 * - action must be exactly "approve" or "deny"
 * - "approve" additionally requires the mobile client to attest EITHER an
 *   explicit fingerprint confirmation (manual flow) OR a scan auto-join
 *   (presenter-opted-in sessions; the DO re-checks the session flag).
 *   "deny" needs no attestation — refusing must always be frictionless.
 */
export function validateApproveInput(body: unknown): ApproveValidation {
  if (!body || typeof body !== "object") return { ok: false, error: "Invalid body" };
  const b = body as ApproveInput;
  if (typeof b.token !== "string" || typeof b.action !== "string") {
    return { ok: false, error: "token and action required" };
  }
  const v = validateTokenFormat(b.token);
  if (!v.ok) return { ok: false, error: v.error! };
  if (b.action !== "approve" && b.action !== "deny") {
    return { ok: false, error: "action must be approve or deny" };
  }
  const auto = b.auto === true;
  if (b.action === "approve" && b.confirmedFingerprint !== true && !auto) {
    return { ok: false, error: "Explicit fingerprint confirmation required (confirmedFingerprint:true) or auto-join" };
  }
  return { ok: true, token: v.value!, action: b.action, auto };
}
