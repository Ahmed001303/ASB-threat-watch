# Proposed feed allowlist — asb-threat-watch

**Status: proposal awaiting owner approval.** This is not yet the committed config
file rule 2 requires. Once Innovation-Department signs off on the rows below, they
become that config file (`config/feeds.*`) and land with the fetcher.

Every URL in the "verified" table was actually requested on **2026-08-13** from
this session — status codes and content types below are observed, not assumed.
Rows that did not verify are listed separately rather than being quietly included.

## Verified — resolve and return a real feed

| # | Source | Category | Feed URL | Observed |
|---|---|---|---|---|
| 1 | KrebsOnSecurity | `breach` | `https://krebsonsecurity.com/feed/` | 200, XML |
| 2 | BleepingComputer | `breach` | `https://www.bleepingcomputer.com/feed/` | 200, XML |
| 3 | The Record | `breach` | `https://therecord.media/feed` | 200, XML |
| 4 | NCSC UK — news | `vuln` | `https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml` | 200, XML |
| 5 | NCSC UK — reports/advisories | `vuln` | `https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml` | 200, XML |
| 6 | Microsoft MSRC — Security Update Guide | `vuln` | `https://api.msrc.microsoft.com/update-guide/rss` | 200, `application/rss+xml` |
| 7 | AWS Security Bulletins | `vuln` | `https://aws.amazon.com/security/security-bulletins/rss/feed/` | 200, XML |
| 8 | Schneier on Security | `ai` | `https://www.schneier.com/feed/atom/` | 200, XML |
| 9 | Dark Reading | `ai` | `https://www.darkreading.com/rss.xml` | 200, XML |
| 10 | Help Net Security | `breach` | `https://www.helpnetsecurity.com/feed/` | 200, XML |
| 11 | Google — Safety & Security blog | `ai` | `https://blog.google/technology/safety-security/rss/` | 200, XML |
| 12 | OpenAI blog | `ai` | `https://openai.com/blog/rss.xml` | 200, XML |
| 13 | Ars Technica — Technology Lab | `banking-tech` | `https://feeds.arstechnica.com/arstechnica/technology-lab` | 200, XML |
| 14 | Finextra headlines | `banking-tech` | `https://www.finextra.com/rss/headlines.aspx` | 200, RSS |
| 15 | Central Bank of Bahrain | `banking-tech` | `https://www.cbb.gov.bh/rss/` | 200, `application/rss+xml` |

## Did not verify — decide before including

| Source | Tried | Result | What to do |
|---|---|---|---|
| **CISA advisories** | `https://www.cisa.gov/cybersecurity-advisories/all.xml` and `https://www.cisa.gov/news.xml` | **403 Access Denied** (Akamai edge) | This is very likely this environment's egress IP being blocked, **not** a wrong URL — CISA does publish advisory RSS. Re-test from the deployed VPC's egress before dropping it. CISA is the single most valuable source here; worth the retest |
| **Anthropic** | `https://www.anthropic.com/rss.xml` | 404 | No feed URL confirmed. Either find the correct one at implementation or drop the row — do not guess a URL into an allowlist |
| **OWASP blog** | `https://owasp.org/blog/feed.xml` | 404 | Same. OWASP guidance is already embedded in `asb-secure-development`, so this is low loss |

## Coverage against the stated purpose

Your goal was AI misuse/leakage awareness plus general cyber news. Mapping:

- **AI leakage & AI incidents** — rows 8, 9, 11, 12, plus AI-tagged items from 1,
  2, 3. This is the thinnest category, and it is the one the project exists for.
  If Anthropic and CISA come back, both help. Worth asking whether the department
  wants a dedicated AI-incident source added later.
- **Breaches** — rows 1, 2, 3, 10. Well covered.
- **Vulnerabilities** — rows 4, 5, 6, 7. Good, and 6/7 are directly actionable
  for the bank's own stack.
- **Banking technology & local regulatory** — rows 13, 14, 15. Row 15 (CBB) is
  the one a Bahrain-based bank should not be without.

## Rules that apply to this list once it is config

1. Adding or changing a source is a **reviewed PR**, never a runtime action. The
   only runtime control is enable/disable per source (see `data-dictionary.md`).
2. `allowed_host` is derived from `feed_url`'s host. An item whose `link` points
   elsewhere is **dropped**, not followed.
3. The fetcher **does not follow redirects.** If a source starts 301-ing, that is
   a PR to update the URL, not something the client resolves silently.
4. `category` comes from this table only — never inferred from article content.
5. No credentials are sent to any of these hosts. All are public, unauthenticated
   feeds.

## What I need from you

- Strike any source the department does not want.
- Confirm the four categories are the right tabs (`ai`, `breach`, `vuln`,
  `banking-tech`).
- Tell me whether to attempt the CISA retest at implementation time, or drop it.
