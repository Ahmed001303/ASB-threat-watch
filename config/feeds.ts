/**
 * THE COMMITTED FEED ALLOWLIST — CLAUDE.md rule 2.
 *
 * This file is the only place a URL may enter the fetcher. The fetcher never
 * resolves a URL supplied by a user or taken from article content; doing so
 * would turn an RSS feed into an SSRF primitive against the VPC and the
 * instance metadata endpoint.
 *
 * Adding or changing a source is a reviewed PR. The only runtime control is
 * enable/disable per source (see lib/runtime-config.ts) — that exists so an
 * operator can drop a compromised or noisy source without waiting for a deploy.
 *
 * Every `feedUrl` below was requested on 2026-08-13 and returned 200 with a
 * feed content type. Sources that did not verify are listed in
 * docs/design/feed-allowlist.md rather than being included on faith. Awaiting
 * owner sign-off on the list itself; see CLAUDE.md open items.
 */

export const CATEGORIES = ["ai", "breach", "vuln", "banking-tech"] as const;
export type Category = (typeof CATEGORIES)[number];

export interface FeedSource {
  /** Stable slug. Used as the storage key — never change it for an existing source. */
  readonly sourceId: string;
  readonly displayName: string;
  /** The ONLY URL the fetcher may resolve for this source. */
  readonly feedUrl: string;
  /**
   * Hostname that item links must match. An item whose link points elsewhere is
   * dropped, not followed — rule 2 one level deeper than the feed URL itself.
   */
  readonly allowedHost: string;
  /** Set here, never inferred from article content. */
  readonly category: Category;
}

export const FEED_SOURCES: readonly FeedSource[] = [
  {
    sourceId: "krebs",
    displayName: "KrebsOnSecurity",
    feedUrl: "https://krebsonsecurity.com/feed/",
    allowedHost: "krebsonsecurity.com",
    category: "breach",
  },
  {
    sourceId: "bleepingcomputer",
    displayName: "BleepingComputer",
    feedUrl: "https://www.bleepingcomputer.com/feed/",
    allowedHost: "www.bleepingcomputer.com",
    category: "breach",
  },
  {
    sourceId: "therecord",
    displayName: "The Record",
    feedUrl: "https://therecord.media/feed",
    allowedHost: "therecord.media",
    category: "breach",
  },
  {
    sourceId: "helpnetsecurity",
    displayName: "Help Net Security",
    feedUrl: "https://www.helpnetsecurity.com/feed/",
    allowedHost: "www.helpnetsecurity.com",
    category: "breach",
  },
  {
    sourceId: "ncsc-news",
    displayName: "NCSC UK — News",
    feedUrl: "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",
    allowedHost: "www.ncsc.gov.uk",
    category: "vuln",
  },
  {
    sourceId: "ncsc-reports",
    displayName: "NCSC UK — Reports & Advisories",
    feedUrl: "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    allowedHost: "www.ncsc.gov.uk",
    category: "vuln",
  },
  {
    sourceId: "msrc",
    displayName: "Microsoft Security Update Guide",
    feedUrl: "https://api.msrc.microsoft.com/update-guide/rss",
    allowedHost: "api.msrc.microsoft.com",
    category: "vuln",
  },
  {
    sourceId: "aws-security",
    displayName: "AWS Security Bulletins",
    feedUrl: "https://aws.amazon.com/security/security-bulletins/rss/feed/",
    allowedHost: "aws.amazon.com",
    category: "vuln",
  },
  {
    sourceId: "schneier",
    displayName: "Schneier on Security",
    feedUrl: "https://www.schneier.com/feed/atom/",
    allowedHost: "www.schneier.com",
    category: "ai",
  },
  {
    sourceId: "darkreading",
    displayName: "Dark Reading",
    feedUrl: "https://www.darkreading.com/rss.xml",
    allowedHost: "www.darkreading.com",
    category: "ai",
  },
  {
    sourceId: "google-security",
    displayName: "Google — Safety & Security",
    feedUrl: "https://blog.google/technology/safety-security/rss/",
    allowedHost: "blog.google",
    category: "ai",
  },
  {
    sourceId: "openai",
    displayName: "OpenAI Blog",
    feedUrl: "https://openai.com/blog/rss.xml",
    allowedHost: "openai.com",
    category: "ai",
  },
  {
    sourceId: "arstechnica-tech",
    displayName: "Ars Technica — Technology Lab",
    feedUrl: "https://feeds.arstechnica.com/arstechnica/technology-lab",
    allowedHost: "arstechnica.com",
    category: "banking-tech",
  },
  {
    sourceId: "finextra",
    displayName: "Finextra",
    feedUrl: "https://www.finextra.com/rss/headlines.aspx",
    allowedHost: "www.finextra.com",
    category: "banking-tech",
  },
  {
    sourceId: "cbb",
    displayName: "Central Bank of Bahrain",
    feedUrl: "https://www.cbb.gov.bh/rss/",
    allowedHost: "www.cbb.gov.bh",
    category: "banking-tech",
  },
];

/** Fail fast at import time rather than producing a silently broken allowlist. */
function validateAllowlist(sources: readonly FeedSource[]): void {
  const seen = new Set<string>();
  for (const s of sources) {
    if (seen.has(s.sourceId)) {
      throw new Error(`Duplicate sourceId in feed allowlist: ${s.sourceId}`);
    }
    seen.add(s.sourceId);

    let url: URL;
    try {
      url = new URL(s.feedUrl);
    } catch {
      throw new Error(`Invalid feedUrl for ${s.sourceId}: ${s.feedUrl}`);
    }
    if (url.protocol !== "https:") {
      throw new Error(`feedUrl for ${s.sourceId} must be https, got ${url.protocol}`);
    }
    if (!CATEGORIES.includes(s.category)) {
      throw new Error(`Unknown category for ${s.sourceId}: ${s.category}`);
    }
    if (!s.allowedHost) {
      throw new Error(`allowedHost is required for ${s.sourceId}`);
    }
  }
}

validateAllowlist(FEED_SOURCES);

export function findSource(sourceId: string): FeedSource | undefined {
  return FEED_SOURCES.find((s) => s.sourceId === sourceId);
}
