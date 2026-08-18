/**
 * Entra ID SAML 2.0 — staff SSO.
 *
 * Configuration follows `asb-entra-sso` exactly. That skill encodes a working
 * production integration, so the values below are not re-derived; the comments
 * record *why* each one is what it is, because these are the settings whose
 * defaults are wrong and which cost real debugging time when changed.
 *
 * Tenant constants (tenant id, IdP entityID, SSO URL, metadata URL, email claim)
 * deliberately do NOT live in this repo — they are read from the environment at
 * deploy time. Keeping them out of source keeps a public repo from advertising
 * the bank's tenant topology.
 */

import { SAML } from "@node-saml/node-saml";
import { log, errorSummary } from "../log";

export interface SamlEnv {
  readonly idpEntryPoint: string;
  readonly idpIssuer: string;
  readonly idpCertPem: string;
  readonly spEntityId: string;
  readonly acsUrl: string;
  readonly publicBaseUrl: string;
}

/** Standard Entra email claim URI. */
export const EMAIL_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";

export class SamlConfigError extends Error {}

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new SamlConfigError(`${name} is not set`);
  return v;
}

export function samlEnv(): SamlEnv {
  return {
    idpEntryPoint: required("SAML_IDP_ENTRY_POINT"),
    idpIssuer: required("SAML_IDP_ISSUER"),
    idpCertPem: normalisePem(required("SAML_IDP_CERT")),
    spEntityId: required("SAML_SP_ENTITY_ID"),
    acsUrl: required("SAML_ACS_URL"),
    // Gotcha 4: build redirects from a public-base-URL env var, never from the
    // request URL — behind a proxy the request URL is 127.0.0.1 and users land
    // on localhost.
    publicBaseUrl: required("PUBLIC_BASE_URL"),
  };
}

/**
 * Gotcha 6: a pasted certificate arrives with collapsed whitespace or no
 * BEGIN/END armour, and the library then reports "Invalid document signature" —
 * which reads like a cert problem but is a formatting problem. Normalise before
 * the library ever sees it.
 */
export function normalisePem(raw: string): string {
  const body = raw
    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const wrapped = body.match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
}

/**
 * Gotcha 7: replay protection needs a PROCESS-WIDE request-id cache. A
 * per-request instance means `InResponseTo` validation fails on every
 * SP-initiated login, because the id was stored on an object that no longer
 * exists by the time the assertion comes back.
 *
 * Entries are the request id only — never assertion XML, never PII.
 */
class RequestIdCache {
  private readonly entries = new Map<string, number>();
  constructor(private readonly ttlMs = 10 * 60 * 1000) {}

  private prune(now: number): void {
    for (const [key, at] of this.entries) {
      if (now - at > this.ttlMs) this.entries.delete(key);
    }
  }

  saveAsync(key: string, _value: string, callback: (err: Error | null, cached: unknown) => void): void {
    const now = Date.now();
    this.prune(now);
    this.entries.set(key, now);
    callback(null, { createdAt: new Date(now).toISOString(), value: key });
  }

  getAsync(key: string, callback: (err: Error | null, value: string | null) => void): void {
    callback(null, this.entries.has(key) ? key : null);
  }

  removeAsync(key: string, callback: (err: Error | null, key: string | null) => void): void {
    const existed = this.entries.delete(key);
    callback(null, existed ? key : null);
  }
}

const requestIdCache = new RequestIdCache();

/**
 * IdP-initiated logins carry no `InResponseTo`, so replay protection for that
 * flow needs its own one-time-use check. Keyed on a hash of the assertion —
 * never the raw XML, which is PII-bearing.
 */
const seenAssertions = new Map<string, number>();

export async function assertionIsReplay(assertionXml: string): Promise<boolean> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(assertionXml),
  );
  const key = Array.from(new Uint8Array(digest).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const now = Date.now();
  for (const [k, at] of seenAssertions) {
    if (now - at > 10 * 60 * 1000) seenAssertions.delete(k);
  }

  if (seenAssertions.has(key)) return true;
  seenAssertions.set(key, now);
  return false;
}

let cachedSaml: SAML | undefined;

export function samlClient(env: SamlEnv = samlEnv()): SAML {
  if (cachedSaml) return cachedSaml;

  cachedSaml = new SAML({
    callbackUrl: env.acsUrl,
    entryPoint: env.idpEntryPoint,
    // Must equal the Entra app "Identifier" exactly.
    issuer: env.spEntityId,
    idpCert: env.idpCertPem,
    // Not a few seconds: clock drift causes flaky rejects in production.
    acceptedClockSkewMs: 60_000,
    wantAssertionsSigned: true,
    // CRITICAL (gotcha, and the library default is wrong for Entra): Entra signs
    // the ASSERTION, not the Response wrapper. Leaving this at its `true`
    // default fails every single login with "Invalid document signature".
    wantAuthnResponseSigned: false,
    // Otherwise Entra rejects MFA/passwordless users with AADSTS75011.
    disableRequestedAuthnContext: true,
    validateInResponseTo: "ifPresent" as never,
    cacheProvider: requestIdCache as never,
    audience: env.spEntityId,
  });

  return cachedSaml;
}

export interface SamlIdentity {
  readonly email: string;
  readonly displayName: string;
}

export type AcsOutcome =
  | { readonly ok: true; readonly identity: SamlIdentity }
  | { readonly ok: false; readonly reason: string };

/**
 * Validate an ACS POST body and extract the identity.
 *
 * The failure `reason` is for the server log only. Callers must show the user a
 * generic message — a specific reason (unknown email vs bad signature vs clock
 * skew) is a user-enumeration and configuration-probing oracle.
 */
export async function handleAcs(samlResponseB64: string): Promise<AcsOutcome> {
  const client = samlClient();

  try {
    const { profile } = await client.validatePostResponseAsync({
      SAMLResponse: samlResponseB64,
    });

    if (!profile) return { ok: false, reason: "no_profile" };

    const xml = Buffer.from(samlResponseB64, "base64").toString("utf8");
    if (await assertionIsReplay(xml)) {
      return { ok: false, reason: "assertion_replay" };
    }

    const claims = profile as unknown as Record<string, unknown>;
    const email =
      (typeof claims[EMAIL_CLAIM] === "string" ? (claims[EMAIL_CLAIM] as string) : undefined) ??
      (typeof profile.email === "string" ? profile.email : undefined) ??
      (typeof profile.nameID === "string" && profile.nameID.includes("@")
        ? profile.nameID
        : undefined);

    if (!email) return { ok: false, reason: "missing_email_claim" };

    const displayName =
      (typeof claims["displayName"] === "string" ? (claims["displayName"] as string) : undefined) ??
      email.split("@")[0] ??
      email;

    return { ok: true, identity: { email: email.toLowerCase(), displayName } };
  } catch (err) {
    // PII-safe: structural facts only, never the assertion body.
    log.warn("saml.acs_validation_failed", { error: errorSummary(err) });
    return { ok: false, reason: "validation_failed" };
  }
}
