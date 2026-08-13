/**
 * The ACS handler. Serves BOTH SP-initiated and IdP-initiated logins, per
 * `asb-entra-sso` — one handler, no duplication.
 *
 * Two things here are easy to get wrong and are called out deliberately:
 *
 *   1. **This route is exempt from CSRF/same-origin gating.** That is correct,
 *      not an oversight: the request is authenticated by the IdP's *signed
 *      assertion*, not by a session cookie, and it arrives as a cross-site POST
 *      by design. There is no session yet to protect.
 *
 *   2. **The redirect must be 303 See Other.** A 307 preserves the method and
 *      body, so the browser would re-POST the IdP's form to the redirect target
 *      and trip CSRF protection on whatever it lands on.
 */

import { NextResponse, type NextRequest } from "next/server";
import { handleAcs, samlEnv } from "../../../../../lib/auth/saml";
import { lookupStaffUser } from "../../../../../lib/auth/users";
import {
  cookieOptions,
  createSession,
  serialiseSession,
  SESSION_COOKIE,
} from "../../../../../lib/auth/session";
import { log, errorSummary } from "../../../../../lib/log";

export const dynamic = "force-dynamic";

function failure(baseUrl: string) {
  return NextResponse.redirect(new URL("/login?error=1", baseUrl), 303);
}

export async function POST(request: NextRequest) {
  let baseUrl = "http://localhost";
  try {
    baseUrl = samlEnv().publicBaseUrl;
  } catch (err) {
    log.error("saml.acs_env_missing", { error: errorSummary(err) });
    return failure(baseUrl);
  }

  let samlResponse: string | null = null;
  try {
    const form = await request.formData();
    const value = form.get("SAMLResponse");
    samlResponse = typeof value === "string" ? value : null;
  } catch (err) {
    log.warn("saml.acs_unreadable_body", { error: errorSummary(err) });
  }

  if (!samlResponse) {
    log.warn("saml.acs_missing_response");
    return failure(baseUrl);
  }

  const outcome = await handleAcs(samlResponse);

  if (!outcome.ok) {
    // Real reason server-side only; the user sees the generic login error.
    log.warn("auth.login_failed", { reason: outcome.reason });
    return failure(baseUrl);
  }

  // Two-sided access, per asb-entra-sso: assigned in Entra AND provisioned
  // locally. A valid assertion for an unprovisioned email is denied here.
  const user = await lookupStaffUser(outcome.identity.email);

  if (!user || user.status !== "active") {
    log.warn("auth.login_denied_not_provisioned", {
      email: outcome.identity.email,
      provisioned: Boolean(user),
      status: user?.status ?? "absent",
    });
    return failure(baseUrl);
  }

  // Fresh session id on every login — session fixation.
  const session = createSession({
    email: user.email,
    displayName: user.displayName || outcome.identity.displayName,
    role: user.role,
  });

  log.info("auth.login_succeeded", {
    email: session.email,
    role: session.role,
    sid: session.sid.slice(0, 8), // prefix only, for correlation not reconstruction
  });

  // 303, not 307 — see the file header.
  const response = NextResponse.redirect(new URL("/feed", baseUrl), 303);
  response.cookies.set(SESSION_COOKIE, serialiseSession(session), cookieOptions());
  return response;
}

/**
 * Entra will occasionally probe the ACS with a GET. Answer it without leaking
 * whether the endpoint is wired up correctly.
 */
export async function GET() {
  return new NextResponse("Method Not Allowed", { status: 405 });
}
