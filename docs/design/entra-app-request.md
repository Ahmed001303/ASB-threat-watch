# Request to Bank IT — Entra Enterprise Application

**Status: draft, not yet sent.** Hostnames below are placeholders until the
`dev` stage is deployed and its URL is known. Send this once the InfoSec
pre-design gate has cleared and the hostname exists.

Per `asb-entra-sso`, this is a blocking dependency on IT — but it does not block
building, so it should be queued early rather than discovered late.

---

## Draft message

> **Subject:** Entra Enterprise App registration — asb-threat-watch (Innovation Department)
>
> Hello,
>
> We're standing up an internal, staff-only news and awareness portal for the
> Innovation Department (`asb-threat-watch`). It aggregates **public** security and
> technology news — no customer, account, or core-banking data is involved at any
> point.
>
> Could you please register a SAML 2.0 Enterprise Application for it with the
> following service-provider details:
>
> | Item | Value |
> |---|---|
> | Identifier (entityID) | `https://<stage-host>/saml/metadata` |
> | Reply URL (ACS) | `https://<stage-host>/api/auth/saml/callback` |
> | Sign-on URL | `https://<stage-host>/login` |
> | Logout URL | `https://<stage-host>/logout` |
>
> And could you also:
>
> 1. Set **Assignment required = Yes**, and assign the Innovation Department
>    users/group.
> 2. Release the email claim
>    (`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`).
> 3. Confirm assertions are **signed, not encrypted**.
> 4. Send us the app ID so we can fetch the signing certificate from the
>    federation metadata endpoint.
>
> Thanks,
> Innovation Department

---

## Notes for whoever implements the callback

Do not re-derive any of this — `asb-entra-sso` has the working configuration and
the full write-up of seven gotchas in its `references/gotchas.md`. The ones that
have already cost real debugging time:

- `wantAuthnResponseSigned: false` — Entra signs the **assertion**, not the
  Response wrapper. Leaving it at its `true` default fails every login with
  "Invalid document signature."
- `disableRequestedAuthnContext: true` — otherwise Entra rejects MFA/passwordless
  users with `AADSTS75011`.
- `acceptedClockSkewMs: 60000` — not a few seconds; clock drift causes flaky
  rejects.
- ACS redirect must be **303 See Other**. A 307 re-POSTs the IdP's body to the
  redirect target and trips CSRF.
- Replay protection needs a **process-wide** request-id cache, not per-instance.
  IdP-initiated logins carry no `InResponseTo`, so add a one-time-use assertion
  dedupe — hash the assertion, never store raw assertion XML.
- Build redirects from a public-base-URL env var, not the request URL, or users
  behind the proxy land on localhost.
- `AADSTS50105` means the user is not assigned to the app in Entra — an IT action,
  not a code bug. Access is two-sided: assigned in Entra **and** provisioned
  locally.

The tenant constants (tenant ID, IdP entityID, SSO URL, metadata URL pattern,
email claim) are in `asb-entra-sso` — read them from there rather than copying
them into this repo.

## Related open decision

The provisioning model — pre-provision-only versus Entra-group-as-gate — is still
open and needs an InfoSec ruling. See `process-flow.md`. It changes what happens
on first login, not what we ask IT for, so this request can go either way.
