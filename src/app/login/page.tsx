/**
 * Login (S1 in docs/design/screens.md).
 *
 * One SSO button. The error message is deliberately generic and identical for
 * every failure mode — bad signature, clock skew, unknown email, disabled
 * account. The real reason is logged server-side only, because a specific
 * message here is a user-enumeration and configuration-probing oracle.
 */

export const dynamic = "force-dynamic";

const GENERIC_ERROR =
  "Sign-in did not complete. If this keeps happening, contact the Innovation Department — " +
  "the reason has been logged.";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const params = await searchParams;
  // Note we read only whether an error occurred, never echo its content.
  const failed = Boolean(params.error);

  return (
    <div className="login">
      <h1>Al Salam Bank · Threat Watch</h1>
      <p className="excerpt">Staff access only.</p>

      {failed ? <div className="banner">{GENERIC_ERROR}</div> : null}

      {/* GET is correct here: this initiates a redirect to the IdP and changes
          no state on our side. The state-changing half is the ACS callback. */}
      <a className="btn" href="/api/auth/saml/login">
        Sign in with Microsoft
      </a>
    </div>
  );
}
