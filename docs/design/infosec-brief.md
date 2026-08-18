# InfoSec review brief — asb-threat-watch

**To:** Information Security Unit
**From:** Innovation Department
**Date:** 2026-08-13
**Classification of this document:** Internal
**Status of the project:** Built, not deployed. No AWS resource exists.

---

## 1. What we are asking for

Two things, in one session if possible:

1. **The design-phase review** required by the Application Project Development
   Security Guidelines. The four artifacts are in `docs/design/` — data flow,
   process flow, screens, data dictionary.
2. **Three rulings** we have deliberately not made ourselves (section 8).

We are also disclosing, up front, that implementation has run ahead of the
pre-implementation gate. See section 9. Nothing is deployed and nothing is
merged; we are not asking you to ratify that after the fact, we are telling you
before you find it.

---

## 2. What the system is

An internal, staff-only web portal for the Innovation Department. It pulls public
security and technology news from a fixed list of RSS feeds, has a language model
write a short summary and a one-line awareness note for each item, and publishes
the result to staff.

The purpose is awareness: helping colleagues use AI tooling carefully and learn
from incidents at other organisations.

| | |
|---|---|
| Users | Innovation Department staff, via Entra SSO |
| Data classification | **Public only** |
| Hosting | ASB AWS account, `eu-west-1`, SST-managed |
| Model | Amazon Bedrock, in-account |
| Expected PCI scope | **Out of scope** — to be confirmed by you, not assumed by us |

---

## 3. What data is involved — and what is not

**In scope:** publicly published news articles (headline, excerpt, link), the
generated summaries, staff email and display name from the SAML assertion, and
the free text of any item a staff member reports.

**Explicitly not in scope, with no code path to it:**

- No customer, account, transaction, card, or T24 data.
- No data-lake or Athena access. The application holds no credentials for either.
- No cardholder or payment data anywhere in the flow.
- No user-supplied input reaches the model. Staff read only; the report reason
  goes to a mailbox, never into a prompt.

If any of that changes, the classification changes and we come back to you.

---

## 4. The security argument, in one paragraph

This application deliberately pipes **untrusted internet content into a language
model** and publishes the output to staff **with no human in the loop**. That
combination is the whole risk, and it is not a risk a normal CRUD application
has. Our position is that the untrusted content can be contained but not made
trustworthy: the controls below stop injected content from *doing* anything, and
accept that it may still produce *misleading text*. The controls for misleading
text are disclosure and fast reversal, not prevention.

**Start your review at `docs/design/data-flow.md`.** It draws the trust boundary
on one page.

---

## 5. Where untrusted content enters, and what it can touch

| Boundary | Control |
|---|---|
| Public feed → fetcher | Host allowlist committed in source; no user- or content-supplied URL is ever resolved; redirects **not** followed; response size capped; request timeout; no credentials sent |
| Article link → published link | The item's link host is validated against the feed that produced it. An allowlisted feed cannot inject arbitrary link targets |
| Article text → model | Passed as clearly delimited untrusted data, with the delimiter neutralised in the content so it cannot close its own block |
| Model → storage | The model has **no tools, no network egress, and no write access**. The database write is performed by the calling code, not the model |
| Storage → browser | All feed-derived text escaped on render; markup stripped at ingest; no `dangerouslySetInnerHTML` anywhere; strict CSP |
| Browser → app | Entra SSO; deny-by-default authorisation checked server-side on every request |

The "no write access" claim is enforced in three independent places, so no single
mistake removes it: the request sends no tools; the IAM role permits
`bedrock:InvokeModel` on one model ARN and nothing else; and the write is in the
caller.

---

## 6. The seven project-specific controls

These are recorded in the repository's `CLAUDE.md` and each is implemented in a
named file and covered by an automated test.

| # | Control | Enforced in | Test |
|---|---|---|---|
| 1 | Ingested content is data, never instruction | `src/lib/summarise/prompt.ts` | ✅ |
| 2 | Feed allowlist only; no SSRF path | `config/feeds.ts`, `src/lib/feeds/fetch.ts` | ✅ |
| 3 | Every item labelled AI-generated, with source link | `src/components/ItemCard.tsx` | visual |
| 4 | Awareness note is awareness, never instruction | `src/lib/summarise/validate.ts` | ✅ |
| 5 | Report button on every item | `src/components/ItemCard.tsx`, `src/app/api/report/route.ts` | — |
| 6 | Kill switch, no redeploy required | `src/lib/runtime-config.ts` | ✅ |
| 7 | Sanitise on render | `src/lib/feeds/parse.ts`, `src/lib/render/escape.ts` | ✅ |

Two of these deserve a specific note:

**Control 4 is enforced on model output, not requested in the prompt.** The
prompt asks for "Worth checking whether we…" framing; the validator *guarantees*
it. Output that reads as a directive ("we must…", "immediately disable…") or that
asserts what the bank does or lacks is rejected, and the item degrades to
headline-and-link. We did not want an unreviewed model authoring security
guidance inside a regulated bank.

**Control 6 fails safe.** If the runtime config store is unreachable, the portal
behaves as though the kill switch is *on*. A configuration outage must not be the
reason unreviewed model text keeps publishing.

---

## 7. Baseline controls

Applied per the Guidelines and the OWASP references:

- **Authentication** — Entra SAML 2.0, no bespoke login. Assertion signature,
  audience, and clock skew validated; replay protection for both SP- and
  IdP-initiated flows.
- **Authorisation** — roles owned by this application, not by the assertion.
  Deny by default, server-side only, checked per request.
- **Sessions** — 256-bit CSPRNG id, HMAC-signed cookie, `Secure` + `HttpOnly` +
  `SameSite`, `__Host-` prefix, fresh id per login, 30-minute idle and 8-hour
  absolute timeouts enforced server-side.
- **CSRF** — synchroniser token bound to the session, plus `Origin` check, on
  every state-changing request.
- **Headers** — CSP, HSTS, `nosniff`, `frame-ancestors none`, Referrer-Policy,
  Permissions-Policy, COOP/CORP.
- **Secrets** — none in source or history. SSM SecureString injected at deploy;
  the session key throws rather than falling back to a default.
- **IAM** — least privilege, one execution role per function, no wildcard
  actions or resources.
- **Logging** — auth events, authorisation denials, privileged actions and ingest
  outcomes are logged; session tokens, assertion XML, report text and article
  bodies are not. Log values are stripped of control characters so feed content
  cannot forge a log line.
- **Supply chain** — CI runs typecheck, tests, build, `npm audit` and produces a
  CycloneDX SBOM per build. Currently **0 advisories**.
- **Reports you can pull** — users and their roles, and the privileges of each
  role, are on the admin screen. Privileged actions are logged.

---

## 8. Three rulings we need from you

**8.1 — SSO provisioning model.** The standard is pre-provision-only: an admin
creates the local user before first login, and an unknown email is denied. That
is what we have implemented. On a portal whose value depends on the whole
department reading it casually, it is also real adoption friction. The
alternative is to make Entra group membership the gate and create the local
record on first successful assertion. We have **not** implemented that, and the
flag that would enable it is hard-coded rather than configurable, specifically so
it cannot be switched on without this ruling. Options are set out in
`docs/design/process-flow.md`.

**8.2 — PCI DSS scope.** We expect this project to be out of scope: no
cardholder or payment data touches it. We are asking you to confirm rather than
assuming it.

**8.3 — SST major version.** The deploy standard specifies SST Ion/v3. We have
pinned v4. Reason: the v3 dependency chain carried seven high-severity advisories
in the SST CLI's own dependencies, and v4 is clean. The blast radius of those
advisories is developer and CI machines rather than deployed code, so this was a
choice between two real risks and not an obvious one. We would rather you signed
off whichever way than have us decide it quietly.

---

## 9. Disclosure: implementation ran ahead of the gate

The Guidelines make the IS review a gate twice — before design and before
implementation. Application code for this project now exists, which means the
second gate has been passed without being cleared.

The facts, plainly:

- The code was written on explicit instruction from the department.
- Nothing is deployed. No AWS resource has been created. The infrastructure
  definition has never been executed, and could not be — the authoring
  environment had no AWS credentials, so it has not even been validated against
  a plan.
- Nothing is merged. It sits in an open pull request.
- Both gates still govern merge and deploy, and we are not treating the existing
  code as a reason to shorten either.

We are raising this rather than letting you discover it. If your view is that the
implementation should be re-done after review rather than reviewed as-is, we will
accept that.

---

## 10. Known gaps and residual risks

We would rather list these than have you find them.

| Risk | Mitigation | What remains |
|---|---|---|
| Prompt injection produces a misleading summary | Content-as-data framing; model has no tools, network, or writes | Misleading *text* can still reach staff. Contained by the AI label, source link, report button and kill switch — not prevented |
| Staff read the awareness note as an instruction | Enforced phrasing constraint on output | Needs a human read of real generated output during UAT, not just a passing test |
| An allowlisted source is compromised | Allowlist limits who, not what | Per-source disable and kill switch, both without redeploy |
| Model cost abuse | Scheduled ingest, per-source item cap | Budget alarm is detective, not preventive |
| Break-glass lockout | — | **Not yet built.** A SAML misconfiguration could currently lock out the whole department. Scheduled for the first post-review change |
| Admin write access | Toggles are read-only; the screen prints the exact CLI command | Deliberate. Granting the portal write access to its own runtime config is a privileged mutation we want reviewed first |
| Infrastructure unvalidated | — | No `sts get-caller-identity`, no `sst diff`. Both are prerequisites to any deploy |

---

## 11. Outside your review, but you should know

The repository currently sits on a personal GitHub account rather than the
`alsalambank` organisation, contrary to the team standard. It is being moved. No
secrets, tenant identifiers or account IDs are present in the history — every
commit was scanned before push — but the location itself is a deviation and we
are not waiting to be told.

---

## 12. Where to look

| Question | File |
|---|---|
| Trust boundary, what crosses it | `docs/design/data-flow.md` |
| Ingest cycle, login flow, report flow | `docs/design/process-flow.md` |
| Screens, and which rule each element implements | `docs/design/screens.md` |
| Fields, classification, retention, what is never logged | `docs/design/data-dictionary.md` |
| The 15 approved sources | `config/feeds.ts`, `docs/design/feed-allowlist.md` |
| Operating rules and open items | `CLAUDE.md` |
| The security tests | `tests/security.test.ts` |

**Contact:** Innovation Department.
