/**
 * Staff sessions.
 *
 * Per the OWASP Session Management guidance in `asb-secure-development`:
 * ≥64 bits of CSPRNG entropy in the session id, `Secure` + `HttpOnly` +
 * `SameSite` on the cookie, a generic cookie name that does not fingerprint the
 * stack, a fresh id minted on login (session fixation), and both idle and
 * absolute timeouts enforced server-side rather than by a client-side timer.
 *
 * The session payload is HMAC-signed so it cannot be forged client-side. It
 * carries only what authorisation needs — a session id, the staff email as the
 * audit subject, the local role, and the two timestamps. No tokens, no assertion
 * XML, nothing from the SAML response beyond the email claim.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Generic on purpose: `next-auth.session-token` advertises the stack. */
export const SESSION_COOKIE = "__Host-asbtw";

/** OWASP: idle 2–30 min by risk; absolute 4–8 hours. Public-news portal → upper end. */
export const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
export const ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;

export type Role = "reader" | "owner";

export interface Session {
  readonly sid: string;
  readonly email: string;
  readonly displayName: string;
  readonly role: Role;
  /** Epoch ms when the session was created — drives the absolute timeout. */
  readonly createdAt: number;
  /** Epoch ms of last activity — drives the idle timeout. */
  readonly lastSeenAt: number;
}

export class SessionSecretMissingError extends Error {
  constructor() {
    super(
      "SESSION_SECRET is not set. It must be injected from SSM SecureString at deploy time; " +
        "there is deliberately no default, because a default would be a hardcoded secret.",
    );
    this.name = "SessionSecretMissingError";
  }
}

function secret(): Buffer {
  const value = process.env.SESSION_SECRET;
  // Fails closed at synth/first-use rather than falling back to a constant —
  // a signing key with a default value is worse than no signing at all,
  // because it looks like a control while providing none.
  if (!value || value.length < 32) throw new SessionSecretMissingError();
  return Buffer.from(value, "utf8");
}

/** 256 bits, well above the OWASP ≥64-bit floor. */
export function newSessionId(): string {
  return randomBytes(32).toString("base64url");
}

function sign(payload: string): string {
  return createHmac("sha256", secret()).update(payload).digest("base64url");
}

export function serialiseSession(session: Session): string {
  const payload = Buffer.from(JSON.stringify(session), "utf8").toString("base64url");
  return `${payload}.${sign(payload)}`;
}

/**
 * Verify and decode. Returns undefined for anything that is not a currently
 * valid session — bad signature, malformed payload, or either timeout expired.
 * Callers cannot distinguish the cases, and neither can an attacker.
 */
export function parseSession(cookieValue: string | undefined, now = Date.now()): Session | undefined {
  if (!cookieValue) return undefined;

  const dot = cookieValue.lastIndexOf(".");
  if (dot <= 0) return undefined;

  const payload = cookieValue.slice(0, dot);
  const provided = cookieValue.slice(dot + 1);

  let expected: string;
  try {
    expected = sign(payload);
  } catch {
    return undefined; // secret missing — fail closed, never accept unsigned
  }

  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  // Constant-time compare: a fast-exit comparison leaks the signature prefix.
  if (a.length !== b.length || !timingSafeEqual(a, b)) return undefined;

  let session: Session;
  try {
    session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Session;
  } catch {
    return undefined;
  }

  if (
    typeof session.sid !== "string" ||
    typeof session.email !== "string" ||
    (session.role !== "reader" && session.role !== "owner") ||
    typeof session.createdAt !== "number" ||
    typeof session.lastSeenAt !== "number"
  ) {
    return undefined;
  }

  if (now - session.createdAt > ABSOLUTE_TIMEOUT_MS) return undefined;
  if (now - session.lastSeenAt > IDLE_TIMEOUT_MS) return undefined;

  return session;
}

/** Mint a session for a verified identity. New sid every time — fixation. */
export function createSession(
  identity: { email: string; displayName: string; role: Role },
  now = Date.now(),
): Session {
  return {
    sid: newSessionId(),
    email: identity.email.toLowerCase(),
    displayName: identity.displayName,
    role: identity.role,
    createdAt: now,
    lastSeenAt: now,
  };
}

export function touchSession(session: Session, now = Date.now()): Session {
  return { ...session, lastSeenAt: now };
}

export interface CookieOptions {
  readonly httpOnly: true;
  readonly secure: true;
  readonly sameSite: "lax";
  readonly path: "/";
  readonly maxAge: number;
}

/**
 * `SameSite=Lax` rather than `Strict` because the SAML ACS callback is a
 * cross-site POST — under Strict the browser would withhold the cookie on the
 * very request that completes login. CSRF tokens (not SameSite) are the actual
 * CSRF control on state-changing routes; see api/report.
 */
export function cookieOptions(): CookieOptions {
  return {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: Math.floor(ABSOLUTE_TIMEOUT_MS / 1000),
  };
}
