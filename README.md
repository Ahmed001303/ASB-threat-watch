# asb-threat-watch

Internal security & technology news portal for the Al Salam Bank Innovation
Department. Aggregates public news on breaches, AI security incidents,
vulnerabilities and banking technology; summarises each item and adds a short
awareness note. Goal is staff awareness — using AI tooling carefully and
learning from other organisations' incidents.

- **Owner:** Innovation-Department
- **Type:** web app (staff-only, Entra SSO)
- **Data classification:** public news only — no customer, account, or T24 data

## Operating rules

See [`CLAUDE.md`](CLAUDE.md) at the repo root. It is the source of truth for
branching, deploy, tagging, and the project-specific security rules around the
ingest and summariser. Read it before making any change.

## Running locally

Requires Node 22+.

```bash
npm ci

# Tests and typecheck need no AWS access at all — the pipeline's security
# controls are pure functions and are tested as such.
SESSION_SECRET=local-dev-secret-at-least-32-chars npm test
npm run typecheck

# The portal reads DynamoDB and SSM, so `npm run dev` needs AWS credentials for
# the target stage. Without them the pages render their fail-safe state:
# summaries suppressed, with a banner saying so.
SESSION_SECRET=local-dev-secret-at-least-32-chars npm run dev
```

Environment variables the app reads (all injected at deploy time — none have
insecure defaults, and `SESSION_SECRET` throws rather than falling back):

| Variable | Purpose |
|---|---|
| `SESSION_SECRET` | HMAC key for session and CSRF tokens. SSM SecureString. |
| `STAGE` | `dev` / `staging` / `prod`. Selects the SSM parameter prefix. |
| `PUBLIC_BASE_URL` | Public origin. All redirects are built from this, never from the request URL. |
| `BEDROCK_MODEL_ID` | Defaults to `anthropic.claude-opus-5`. |
| `SAML_IDP_*`, `SAML_SP_*`, `SAML_ACS_URL` | Entra config; values come from `asb-entra-sso`, not this repo. |
| `ASB_BUDGET_ALERT_EMAIL` | Required at `sst diff`/`deploy` — synth fails without it. |

## Status

Application code exists and is **not deployed**. `npm test`, `npm run typecheck`
and `npx next build` all pass; no AWS resource has been created, and
`sst.config.ts` has never been run. See `CLAUDE.md` → Open items for what blocks
first deploy — including both InfoSec review gates.

## Design

The design-phase artifacts required before implementation live in
[`docs/design/`](docs/design/) — data flow, process flow, screens, and data
dictionary, plus the proposed feed allowlist and the Entra app request. These
are the package the InfoSec pre-design review reads.

## Infrastructure

Every deployed resource is logged in
[`docs/INFRASTRUCTURE.md`](docs/INFRASTRUCTURE.md), in the same PR that creates
it. Nothing is deployed yet.
