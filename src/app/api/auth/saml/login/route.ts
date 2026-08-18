/**
 * SP-initiated login: build an AuthnRequest and redirect to Entra.
 *
 * The matching IdP-initiated flow (the Microsoft MyApps tile) posts straight to
 * the ACS route — per `asb-entra-sso`, both flows are served by ONE ACS handler,
 * so there is nothing to duplicate here.
 */

import { NextResponse } from "next/server";
import { samlClient, samlEnv } from "../../../../../lib/auth/saml";
import { loadRuntimeConfig } from "../../../../../lib/runtime-config";
import { log, errorSummary } from "../../../../../lib/log";

export const dynamic = "force-dynamic";

export async function GET() {
  const config = await loadRuntimeConfig();

  // Env kill-switch for SSO, per asb-entra-sso. When SSO is off, the break-glass
  // local admin form is the only way in — which is the point of having one.
  if (!config.ssoEnabled) {
    log.warn("saml.login_blocked_sso_disabled");
    return NextResponse.redirect(new URL("/login?error=1", samlEnv().publicBaseUrl), 303);
  }

  try {
    const env = samlEnv();
    const url = await samlClient(env).getAuthorizeUrlAsync("", undefined, {});
    // 303 See Other, not 302/307 — see the ACS route for why this matters.
    return NextResponse.redirect(url, 303);
  } catch (err) {
    log.error("saml.login_failed", { error: errorSummary(err) });
    // Cannot use samlEnv() here — it may be what threw. Relative redirect.
    return NextResponse.redirect(new URL("/login?error=1", "http://localhost"), 303);
  }
}
