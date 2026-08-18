# Screens — asb-threat-watch

Design-phase artifact required by `asb-secure-development` ("necessary screens").
Status: **proposed, not built.** Five screens plus two states. Deliberately small —
this is a read-only awareness portal, not a workflow tool.

## S1 — Login

```
┌────────────────────────────────────────────┐
│                                            │
│        Al Salam Bank · Threat Watch        │
│                                            │
│     ┌────────────────────────────────┐     │
│     │  Sign in with Microsoft        │     │
│     └────────────────────────────────┘     │
│                                            │
│     Staff access only.                     │
└────────────────────────────────────────────┘
```

- Single SSO button (SP-initiated). Also reachable via the Entra MyApps tile
  (IdP-initiated) — one ACS handler serves both.
- Generic error text on failure. Real reason (signature / audience / clock /
  unknown email) logged **server-side only**.
- Break-glass local admin form at `/login?staff=1`, reachable even when SSO is on.

## S2 — Feed (the main screen)

```
┌──────────────────────────────────────────────────────────────┐
│ Threat Watch          [All][AI][Breaches][Vulns][Banking] 🔍 │
├──────────────────────────────────────────────────────────────┤
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ ● AI INCIDENT            BleepingComputer · 2 hours ago  │ │
│ │ Staff at <company> pasted source code into a public      │ │
│ │ chatbot; the vendor retained it for training             │ │
│ │                                                          │ │
│ │ ┌──────────────────────────────────────────────────────┐ │ │
│ │ │ 🤖 AI-GENERATED SUMMARY                              │ │ │
│ │ │ Three engineers pasted proprietary code into a        │ │ │
│ │ │ consumer AI assistant. Retained under the free        │ │ │
│ │ │ tier's training terms; the company has since          │ │ │
│ │ │ blocked the tool at the network layer.                │ │ │
│ │ │                                                      │ │ │
│ │ │ Worth checking whether we — have guidance on which   │ │ │
│ │ │ AI tools may receive internal code, and whether      │ │ │
│ │ │ staff know where that guidance lives.                │ │ │
│ │ └──────────────────────────────────────────────────────┘ │ │
│ │                                                          │ │
│ │ [🔗 Read the original ↗]                    [⚑ Report]   │ │
│ └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

Every element below is a rule, not a style preference:

| Element | Rule |
|---|---|
| `🤖 AI-GENERATED SUMMARY` band | Rule 3 — label is on the card itself, not in a footer or tooltip |
| `Read the original ↗` | Rule 3 — one click to source, always present, `rel="noopener noreferrer"` |
| `Worth checking whether we —` | Rule 4 — awareness framing, never a directive. This prefix is fixed in the prompt and asserted in tests |
| `⚑ Report` | Rule 5 — on every item |
| Title, excerpt, source name | Rule 7 — all feed-derived, all escaped. No raw HTML from RSS is ever rendered |
| Category tabs | Derived from the feed's own category in the committed allowlist config, never from article content |

## S3 — Item detail

Same card, expanded: full excerpt, published timestamp, source, summary, awareness
note, model id and generation time (so a staff member can see *what* wrote it and
*when*), source link, report button. No comments, no sharing, no free-text input.

## S4 — Report confirmation

Modal: item title (escaped), optional reason (max ~500 chars, server-validated),
submit. Needs a CSRF token and per-user rate limiting. Reporter identity comes
from the session, never from the form body.

## S5 — Admin (owner only)

Minimal, and only what the security rules require an operator to be able to do
without a deploy:

- **Kill switch** toggle → headline-and-link only, no model text (rule 6).
- **Per-feed enable/disable** — for when a source is compromised or noisy.
- **Reported items** queue → hide an item, or disable its source.
- **Users and roles** list — required so InfoSec can pull the "users and their
  roles" and "detailed privileges of each role" reports named in
  `asb-secure-development`.

Both toggles write to SSM runtime config, so they take effect on the next ingest
cycle with no redeploy.

## States

**Kill switch ON** — cards render as headline, source, timestamp and link only.
The AI-generated band and awareness note are absent, and a banner reads
*"AI summaries are temporarily disabled."* This must be visibly different from
"summary failed for this one item", or an operator cannot tell a killed portal
from a broken one.

**Access denied** — for an authenticated Entra user with no local account (or a
disabled one). Generic message plus who to contact. Real reason server-side only.

## Accessibility & scope notes

- The AI-generated label must not rely on colour alone — icon plus text.
- Read-only for all non-admin roles. No screen accepts free text that reaches the
  model; the only user input in the whole app is the report reason, which goes to
  a mailbox, never to a prompt.
