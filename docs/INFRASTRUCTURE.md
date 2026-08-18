# Infrastructure log — asb-threat-watch

Every resource that outlives a working session gets logged here, in the same PR
that creates it. That includes AWS resources, deployed URLs, secret names,
queues, and third-party integrations. Include the teardown command so nothing
becomes an orphan.

**Naming:** `asb-threat-watch-<stage>-<resource>`

**Tags on every resource:** `org=asb`, `project=threat-watch`, `stage=<stage>`,
`managed-by=sst`, `owner=Innovation-Department`

Owner is assigned (`Innovation-Department`), so the owner-tag blocker is cleared.
Deployment remains blocked on the other open items in `CLAUDE.md` — the InfoSec
pre-design and pre-implementation gates, the summariser hosting decision, and the
org GitHub remote. Do not deploy until those are resolved.

| Date | Stage | Resource name | Type | Created by | Purpose | Teardown |
|---|---|---|---|---|---|---|
| — | — | (none yet) | — | — | — | — |
