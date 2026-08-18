# Data dictionary — asb-threat-watch

Design-phase artifact required by `asb-secure-development`. Status: **proposed,
not built.** Storage engine not yet chosen (DynamoDB per `asb-deploy` §6 is the
default for this stack); field semantics below hold either way.

**Classification for every entity in this document: Public**, except `staff_user`
and `report`, which hold staff identity (internal personal data, not customer
PII). No entity in this application holds customer, account, transaction, card,
or T24 data.

## `feed_source` — committed config, not user data

Lives in a **committed config file** (rule 2), not in the database, so a source
cannot be added at runtime by anyone without a reviewed PR.

| Field | Type | Notes |
|---|---|---|
| `source_id` | string (slug) | Stable key, e.g. `krebs`, `ncsc-news` |
| `display_name` | string | Shown on the card |
| `feed_url` | string (https) | The **only** URL the fetcher may resolve for this source |
| `allowed_host` | string | Hostname items must match. Item links off this host are dropped |
| `category` | enum | `ai` \| `breach` \| `vuln` \| `banking-tech` — set here, never inferred from article content |
| `enabled_default` | bool | Runtime override lives in SSM, see `runtime_config` |

## `news_item` — raw ingested item

Untrusted content. Every string field here is escaped at render (rule 7).

| Field | Type | Notes |
|---|---|---|
| `item_id` | string (uuid) | Internal id. Not derived from feed content |
| `source_id` | string | FK → `feed_source` |
| `guid` | string | Feed-supplied guid, used with `source_id` for dedupe. Treated as an opaque string, never as a URL |
| `title` | string | **Untrusted.** Escaped on render |
| `link` | string (https) | **Untrusted.** Host validated against `allowed_host`; rendered with `rel="noopener noreferrer"`; never fetched again |
| `excerpt` | string (truncated) | **Untrusted.** Plain text only — markup stripped at ingest, escaped again at render |
| `published_at` | timestamp (UTC) | From the feed; null if absent or unparseable — never defaulted to "now" |
| `fetched_at` | timestamp (UTC) | Set by the fetcher |
| `hidden` | bool | Set by owner from the admin screen |

## `item_summary` — model output

| Field | Type | Notes |
|---|---|---|
| `item_id` | string | FK → `news_item`, 1:1 |
| `summary` | string | Model-generated. Display text only — never used as a URL, command, or fetch target |
| `awareness_note` | string | Rule 4 framing. Fixed `Worth checking whether we —` prefix |
| `model_id` | string | e.g. the Bedrock model id. Recorded so a bad batch is traceable to a model version |
| `generated_at` | timestamp (UTC) | |
| `status` | enum | `ok` \| `failed` \| `rejected` — `rejected` means output validation caught markup or a URL. A non-`ok` item renders as headline-and-link |

## `staff_user` — internal personal data

| Field | Type | Notes |
|---|---|---|
| `user_id` | string (uuid) | |
| `email` | string | Matched against the SAML email claim. The join key per `asb-entra-sso` |
| `display_name` | string | From the assertion |
| `role` | enum | `reader` \| `owner` — roles are owned by this app, not by SAML |
| `status` | enum | `active` \| `disabled` — disabled denies login |
| `last_login_at` | timestamp (UTC) | |

Never stored: passwords for SSO users, raw assertion XML, session tokens, Entra
object IDs beyond what is needed to match. Break-glass admin credentials, if any,
are hashed with Argon2id/bcrypt and held for **one** account only.

## `report` — rule 5 submissions

| Field | Type | Notes |
|---|---|---|
| `report_id` | string (uuid) | |
| `item_id` | string | FK → `news_item` |
| `reported_by` | string | FK → `staff_user`. Taken from the session, **never** from the request body |
| `reason` | string (≤500) | Staff-supplied free text. Escaped on render; never sent to the model |
| `created_at` | timestamp (UTC) | |
| `resolution` | enum | `open` \| `item_hidden` \| `source_disabled` \| `no_action` |

## `runtime_config` — SSM Parameter Store

Not a table. Lives in SSM so it changes without a redeploy (rule 6).

| Parameter | Type | Purpose |
|---|---|---|
| `/asb-threat-watch/<stage>/kill-switch` | String `on`\|`off` | `on` → headline-and-link only, no model text |
| `/asb-threat-watch/<stage>/feeds/<source_id>/enabled` | String `true`\|`false` | Per-source disable without a PR |
| `/asb-threat-watch/<stage>/sso/enabled` | String `true`\|`false` | Env kill-switch for SSO per `asb-entra-sso` |

No secrets in the above. Any genuine secret (e.g. an SP private key, only if
encrypted assertions are ever mandated) is a **SecureString** and is referenced,
never logged.

## Logging

Per `asb-secure-development`: log auth successes and failures, authorisation
denials, privileged actions (kill switch, feed toggles, hide item, user/role
changes), and ingest outcomes.

Never logged: session tokens, assertion XML, the report `reason` body, or full
article text. Staff email appears in auth logs as the audit subject — that is
intentional and is the minimum needed for the "privileged activities" report
InfoSec must be able to pull. Log retention is bounded at the log group.

## Retention

| Data | Retention | Rationale |
|---|---|---|
| `news_item`, `item_summary` | 12 months, then delete | It is an awareness feed; old items have no operational value |
| `report` | 12 months | Long enough to show a pattern for a noisy source |
| `staff_user` | While employed / until access revoked | Access control record |
| Application logs | 1 month `dev`, per InfoSec guidance `prod` | Bounded so the log group is not an open-ended store |
