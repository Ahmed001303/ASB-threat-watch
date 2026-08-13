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

Not yet implemented — scaffold only. This section gets filled in with the first
`feature/` branch that adds the app.

## Design

The design-phase artifacts required before implementation live in
[`docs/design/`](docs/design/) — data flow, process flow, screens, and data
dictionary, plus the proposed feed allowlist and the Entra app request. These
are the package the InfoSec pre-design review reads.

## Infrastructure

Every deployed resource is logged in
[`docs/INFRASTRUCTURE.md`](docs/INFRASTRUCTURE.md), in the same PR that creates
it. Nothing is deployed yet.
