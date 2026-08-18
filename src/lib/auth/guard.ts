/**
 * Server-side access control.
 *
 * Per the OWASP Authorization guidance in `asb-secure-development`: deny by
 * default, enforce server-side only, and check on every request. There is no
 * client-side gate anywhere in this app — a page either resolves a session on
 * the server or redirects.
 */

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { parseSession, SESSION_COOKIE, type Role, type Session } from "./session";
import { previewEnabled, PREVIEW_SESSION } from "../dev/preview";
import { log } from "../log";

/** Returns the session or undefined. Never throws for an absent session. */
export async function currentSession(): Promise<Session | undefined> {
  // Local preview only. Requires NODE_ENV === "development", which `next build`
  // makes statically false — this cannot be switched on in a deployed build.
  if (previewEnabled()) return PREVIEW_SESSION;

  const store = await cookies();
  return parseSession(store.get(SESSION_COOKIE)?.value);
}

/**
 * Require any authenticated staff member. Redirects to login when absent.
 * Every page under the portal calls this — deny by default means the check is
 * opt-out-impossible rather than opt-in.
 */
export async function requireSession(): Promise<Session> {
  const session = await currentSession();
  if (!session) redirect("/login");
  return session;
}

/**
 * Require the owner role. Note this is an authorisation decision made from the
 * *local* role, not from anything in the SAML assertion — per `asb-entra-sso`,
 * SAML authenticates identity and this app owns permissions.
 */
export async function requireOwner(): Promise<Session> {
  const session = await requireSession();
  if (session.role !== "owner") {
    // Log the denial (OWASP: log authorisation decisions), then 404 rather than
    // 403 so the existence of the admin surface is not confirmed to a reader.
    log.warn("authz.denied", { email: session.email, required: "owner", actual: session.role });
    redirect("/feed");
  }
  return session;
}

export function hasRole(session: Session | undefined, role: Role): boolean {
  return session?.role === role;
}
