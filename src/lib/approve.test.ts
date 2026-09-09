import { describe, it, expect } from "vitest";
import { validateApproveInput } from "./approve";

const TOKEN = "a".repeat(43); // well-formed opaque token

describe("validateApproveInput", () => {
  it("rejects missing/invalid bodies", () => {
    expect(validateApproveInput(null).ok).toBe(false);
    expect(validateApproveInput(undefined).ok).toBe(false);
    expect(validateApproveInput("token").ok).toBe(false);
    expect(validateApproveInput({}).ok).toBe(false);
    expect(validateApproveInput({ token: TOKEN }).ok).toBe(false);
    expect(validateApproveInput({ action: "approve" }).ok).toBe(false);
  });

  it("rejects malformed tokens and actions", () => {
    expect(validateApproveInput({ token: "short", action: "approve", confirmedFingerprint: true }).ok).toBe(
      false,
    );
    expect(validateApproveInput({ token: TOKEN, action: "maybe", confirmedFingerprint: true }).ok).toBe(
      false,
    );
    // JWT-shaped tokens (dots) are never valid QR tokens
    expect(
      validateApproveInput({
        token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        action: "deny",
      }).ok,
    ).toBe(false);
  });

  it("requires confirmation OR auto attestation for approve", () => {
    expect(validateApproveInput({ token: TOKEN, action: "approve" })).toEqual({
      ok: false,
      error: "Explicit fingerprint confirmation required (confirmedFingerprint:true) or auto-join",
    });
    expect(
      validateApproveInput({ token: TOKEN, action: "approve", confirmedFingerprint: false }),
    ).toEqual({
      ok: false,
      error: "Explicit fingerprint confirmation required (confirmedFingerprint:true) or auto-join",
    });
  });

  it("accepts explicit confirmation", () => {
    expect(
      validateApproveInput({ token: TOKEN, action: "approve", confirmedFingerprint: true }),
    ).toEqual({ ok: true, token: TOKEN, action: "approve", auto: false });
  });

  it("accepts scan auto-join attestation (DO re-checks the session flag)", () => {
    expect(validateApproveInput({ token: TOKEN, action: "approve", auto: true })).toEqual({
      ok: true,
      token: TOKEN,
      action: "approve",
      auto: true,
    });
  });

  it("lets deny through with no attestation — refusing stays frictionless", () => {
    expect(validateApproveInput({ token: TOKEN, action: "deny" })).toEqual({
      ok: true,
      token: TOKEN,
      action: "deny",
      auto: false,
    });
  });
});
