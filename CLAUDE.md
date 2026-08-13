# asb-threat-watch — CLAUDE.md

Al Salam Bank Innovation project. Read this file before doing anything else in
this repo.

## Project identity

| Field | Value |
|---|---|
| Project ID | `asb-threat-watch` |
| Type | web app |
| Owner | Innovation-Department |
| Stages | `dev`, `staging`, `prod` |

## What this is

An internal, staff-only portal that aggregates public security and technology
news (breaches, AI incidents, vulnerabilities, banking-tech developments),
summarises each item, and adds a short awareness note. Purpose is staff
awareness — helping colleagues use AI tooling carefully and spot the mistakes
other organisations have already made.

**Data classification: public only.** This project ingests nothing but publicly
published news. No customer data, no account data, no T24 data, no data-lake
access. If that ever changes, this file and the InfoSec scope change with it.

## Standards this project follows (by reference — do not duplicate, read the skill)

This project is governed by the ASB Innovation team's shared Claude Code skills.
Load the relevant skill rather than re-deriving these rules from memory or
improvising:

- **`asb-secure-development`** — InfoSec application security gates (OWASP, PCI
  DSS scope, SSO/least-privilege, IS review checkpoints). Applies to every change
  that touches auth, data handling, or externally-reachable endpoints.
- **`asb-deploy`** — AWS/SST deploy conventions: resource naming, mandatory tags,
  IAM, prod sign-off. Read before writing or changing any `sst.config.ts` / infra
  code, and before any deploy.
- **`asb-team-coordination`** — branch naming/hygiene, one-task-one-branch,
  worktrees for parallel work, PR size, commit conventions, org-only repos
  (`github.com/alsalambank`), and logging spun-up resources in
  `docs/INFRASTRUCTURE.md`. Read before creating a branch, opening a PR, or
  spinning up any resource.
- **`asb-entra-sso`** — staff SAML SSO via Microsoft Entra ID. Read before
  implementing or touching any login/auth flow.

## Naming & tagging (from `asb-deploy` — reference, don't reinvent)

- Resource names: `asb-threat-watch-<stage>-<resource>`, lowercase + hyphens,
  stage ∈ `dev`/`staging`/`prod`.
- Every resource carries these tags: `org=asb`, `project=threat-watch`,
  `stage=<stage>`, `managed-by=sst`, `owner=Innovation-Department`.
- Infra is SST (Ion/v3). Never hand-roll CloudFormation/Terraform in parallel to
  it.

## Secrets

- Never hardcode secrets, API keys, connection strings, or tokens in code,
  config, or commit history.
- Use SSM Parameter Store / Secrets Manager for all of them, per `asb-deploy`.
- Run `aws sts get-caller-identity` to confirm you're on the right identity
  before any deploy.
- `prod` deploys require explicit human sign-off — never automate past that gate.

## Branching & git hygiene (from `asb-team-coordination` — reference, don't reinvent)

- One task = one branch: `feature/<slug>`, `fix/<slug>`, `chore/<slug>`.
- `git fetch` + `git branch -a` (+ check open PRs) before creating a new branch —
  reuse/continue existing work, don't duplicate it.
- Never commit or push directly to `main`. Branch → PR → review → merge, always.
- Small, focused, reviewable PRs. Conventional commit messages
  (`type(scope): summary`).
- Use `git worktree` for parallel sessions; never share one working tree across
  two concurrent tasks.
- Delete branches once merged; keep the repo free of stale/abandoned branches.
- This repo lives under `github.com/alsalambank`, never a personal account —
  confirm `git remote -v` before pushing. **See "Open items" — this is currently
  not the case.**
- Log every resource that outlives the session (AWS resource, DB, queue,
  deployed URL, secret name, third-party integration) in
  `docs/INFRASTRUCTURE.md`, in the same PR that creates it — including its
  teardown command.

## Security baseline (from `asb-secure-development` — reference, don't reinvent)

- OWASP Top 10 and PCI DSS scope apply if this project touches cardholder or
  payment data — confirm scope with InfoSec early, not at launch. (Expected out
  of PCI scope here; confirm, don't assume.)
- Least-privilege IAM everywhere; no wildcard resource/action policies.
- Staff-facing auth goes through Entra SSO (`asb-entra-sso`), not a bespoke login
  flow.
- **The IS (InfoSec) review is a gate twice, not once:** once **before the design
  phase** and again **before implementation** — see `asb-secure-development`.
  Production go-live is not the first checkpoint. Book both early; neither is a
  rubber stamp. The pre-design gate reviews the artifacts in `docs/design/`
  (data flow, process flow, screens, data dictionary).

## Project-specific security rules (read before touching the ingest or summariser)

This project deliberately pipes untrusted internet content into an LLM and
publishes the output to staff with no human in the loop. That combination creates
risks a normal CRUD app doesn't have. These are not optional.

1. **Ingested content is data, never instruction.** Feed article text to the
   model as clearly delimited untrusted input. The summariser gets no tools, no
   network access, no write access to anything.
2. **Feed allowlist only.** Sources live in a committed config file. The fetcher
   must never resolve a URL supplied by a user or by article content — that is an
   SSRF path into the VPC. Redirect-following stays disabled in the fetch client
   (per the OWASP SSRF guidance in `asb-secure-development`), or an allowlisted
   host can redirect the fetcher anywhere.
3. **Every published item is labelled AI-generated and shows its source link.**
   Staff must always be one click from the original.
4. **The "what this means for ASB" line is awareness, not instruction.** Phrase
   as "worth checking whether we…", never as a directive to change a control or
   system.
5. **Report button on every item**, routing to the owner.
6. **Kill switch:** a config flag that drops the portal to headline-and-link
   only, with no model-generated text, deployable without a code change. Because
   it must work without a redeploy, it lives in runtime config (SSM parameter or
   a DB row) — never in the bundle.
7. **Sanitise on render.** Third-party HTML/RSS content is an XSS vector — escape
   it, never `dangerouslySetInnerHTML` on feed content.

## Open items (must be resolved before first deploy)

- ~~`owner` tag~~ — resolved: `Innovation-Department`.
- **GitHub remote is a personal account.** `origin` currently points at
  `github.com/Ahmed001303/ASB-threat-watch`. `asb-team-coordination` requires
  `github.com/alsalambank/asb-threat-watch`. Needs org repo creation, then
  `git remote set-url`.
- **IS review not yet booked** — both gates (pre-design, pre-implementation).
- **Summariser model/hosting decision not yet made** (in-account Bedrock vs
  external API) — this determines whether an InfoSec third-party review and a
  Data Processing Agreement are needed.
- **Feed allowlist not yet approved.** Proposal in
  `docs/design/feed-allowlist.md`; it becomes the committed config file for
  rule 2 once the owner signs off.
- **SSO provisioning model needs an InfoSec decision.** `asb-entra-sso` mandates
  pre-provision-only (no JIT). On a portal meant for casual department-wide
  reading, that is adoption friction — see `docs/design/process-flow.md`. Raise
  it; do not deviate unilaterally.

## What's NOT covered here

This file is the index, not the encyclopedia. For the actual rules, load the
named skill — this file should stay short enough that every session actually
reads it.
