/**
 * CSRF protection for state-changing requests.
 *
 * Synchroniser-token pattern, per the OWASP CSRF Prevention guidance in
 * `asb-secure-development`. `SameSite=Lax` on the session cookie is defence in
 * depth, explicitly NOT a substitute — and it cannot be Strict here because the
 * SAML ACS callback is a cross-site POST.
 *
 * The token is derived from the session id via HMAC rather than stored: it is
 * therefore bound to the session, needs no server-side state, and is invalidated
 * automatically when the session rotates.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { SessionSecretMissingError } from "./session";

export const CSRF_FIELD = "csrf_token";
/** A custom header a plain HTML form cannot set — the API-side check. */
export const CSRF_HEADER = "x-asbtw-csrf";

function secret(): Buffer {
  const value = process.env.SESSION_SECRET;
  if (!value || value.length < 32) throw new SessionSecretMissingError();
  return Buffer.from(value, "utf8");
}

export function csrfTokenFor(sid: string): string {
  return createHmac("sha256", secret()).update(`csrf:${sid}`).digest("base64url");
}

export function csrfTokenValid(sid: string, provided: string | null | undefined): boolean {
  if (!provided) return false;
  let expected: string;
  try {
    expected = csrfTokenFor(sid);
  } catch {
    return false; // no secret => fail closed
  }
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Verify the `Origin` header against the app's own public base URL.
 *
 * Belt and braces alongside the token: `Origin` is set by the browser on
 * cross-origin POSTs and cannot be forged by page script. A missing Origin is
 * treated as acceptable only when a valid token is present — some legitimate
 * clients omit it, and the token is the primary control.
 */
export function originAcceptable(origin: string | null, publicBaseUrl: string): boolean {
  if (!origin) return true;
  try {
    return new URL(origin).origin === new URL(publicBaseUrl).origin;
  } catch {
    return false;
  }
}
