# Design phase — asb-threat-watch

`asb-secure-development` requires four artifacts before implementation, and an
InfoSec review of them **before the design phase** and again **before
implementation**. This directory is that package.

Everything here is **proposed, not built.** No code, no AWS resources, and no
deploy exist for this project yet.

| Artifact | File | Required by |
|---|---|---|
| Data flow diagram | [`data-flow.md`](data-flow.md) | `asb-secure-development` — design phase |
| Process flow | [`process-flow.md`](process-flow.md) | `asb-secure-development` — design phase |
| Necessary screens | [`screens.md`](screens.md) | `asb-secure-development` — design phase |
| Data dictionary | [`data-dictionary.md`](data-dictionary.md) | `asb-secure-development` — design phase |
| Feed allowlist proposal | [`feed-allowlist.md`](feed-allowlist.md) | `CLAUDE.md` rule 2 (committed config) |
| Entra app request | [`entra-app-request.md`](entra-app-request.md) | `asb-entra-sso` — blocking IT dependency |

## The one thing a reviewer should look at first

[`data-flow.md`](data-flow.md). This application deliberately pipes untrusted
internet content into an LLM and publishes the result to staff with no human in
the loop. That diagram shows where untrusted content enters and what it is
allowed to touch afterwards — which is the whole security argument for the
project.

## Decisions still open (see `CLAUDE.md` → Open items)

1. Summariser hosting — in-account Bedrock vs external API. Recommendation:
   Bedrock, because it keeps everything inside ASB's AWS accounts and avoids the
   third-party risk assessment and DPA path entirely.
2. SSO provisioning model — pre-provision-only vs Entra-group-as-gate. Needs an
   InfoSec ruling, not a code decision. See `process-flow.md`.
3. Feed allowlist sign-off by Innovation-Department.
4. GitHub remote move to `github.com/alsalambank`.
5. Both IS review gates booked.
