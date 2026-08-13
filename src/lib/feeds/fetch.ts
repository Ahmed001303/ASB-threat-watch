/**
 * The fetch client — CLAUDE.md rule 2 and the OWASP SSRF guidance in
 * `asb-secure-development` (references/web-security.md).
 *
 * This is the only module in the application that performs an outbound HTTP
 * request. Every control here exists because this project pipes untrusted
 * internet content into a system that sits inside a bank's AWS account:
 *
 *   1. The URL must be one of the committed allowlist's `feedUrl` values —
 *      matched by identity against config/feeds.ts, not parsed from input.
 *   2. Redirects are NOT followed. An allowlisted host that starts 301-ing
 *      could otherwise walk the fetcher to the instance metadata endpoint or
 *      any internal service. A moved feed is a PR, not a runtime resolution.
 *   3. The response is size-capped while streaming, so a hostile or broken
 *      source cannot exhaust Lambda memory with an endless body.
 *   4. There is a wall-clock timeout, so a stalled connection fails as a
 *      timeout rather than hanging the ingest cycle.
 *   5. No credentials, cookies, or auth headers are ever sent. Every
 *      allowlisted source is a public, unauthenticated feed.
 */

import { FEED_SOURCES } from "../../../config/feeds";
import { log, errorSummary } from "../log";

/** 5 MiB. Comfortably above any real RSS feed; far below Lambda memory. */
export const MAX_FEED_BYTES = 5 * 1024 * 1024;

/** Wall-clock ceiling for one feed fetch. */
export const FETCH_TIMEOUT_MS = 15_000;

const USER_AGENT = "asb-threat-watch/0.1 (+internal staff awareness portal)";

export class FeedFetchError extends Error {
  constructor(
    message: string,
    readonly code:
      | "not_allowlisted"
      | "redirect_refused"
      | "http_error"
      | "too_large"
      | "timeout"
      | "network",
  ) {
    super(message);
    this.name = "FeedFetchError";
  }
}

/**
 * A URL is fetchable only if it is *identical* to a `feedUrl` in the committed
 * allowlist. Note this is an identity check against a fixed set, not a
 * pattern match on a caller-supplied string — there is deliberately no way to
 * express "any URL on this host". Per the OWASP SSRF guidance, we never accept
 * a full user-supplied URL for a server-side fetch.
 */
export function isAllowlistedFeedUrl(url: string): boolean {
  return FEED_SOURCES.some((s) => s.feedUrl === url);
}

/**
 * Does an item's link belong to the source that produced it?
 *
 * Without this, an allowlisted feed could inject arbitrary `<link>` targets and
 * we would publish them to staff as trustworthy "source" links. The host must
 * match exactly or be a subdomain of the source's `allowedHost`, and the scheme
 * must be https. Note the fetcher never requests these URLs — they are only
 * ever rendered as links — but a link we publish is a link staff will click,
 * so it gets the same allowlist discipline.
 */
export function isAllowedItemLink(link: string, allowedHost: string): boolean {
  let url: URL;
  try {
    url = new URL(link);
  } catch {
    return false;
  }
  if (url.protocol !== "https:") return false;
  const host = url.hostname.toLowerCase();
  const allowed = allowedHost.toLowerCase();
  return host === allowed || host.endsWith(`.${allowed}`);
}

/**
 * Read a response body with a hard byte ceiling, aborting the stream as soon as
 * the cap is passed rather than buffering the whole thing and checking after.
 */
async function readCapped(response: Response, maxBytes: number): Promise<string> {
  const body = response.body;
  if (!body) return "";

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new FeedFetchError(
          `response exceeded ${maxBytes} bytes`,
          "too_large",
        );
      }
      chunks.push(value);
    }
  } finally {
    // Release the connection whether we finished or bailed out early.
    await reader.cancel().catch(() => {});
  }

  const joined = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    joined.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(joined);
}

/**
 * Fetch one allowlisted feed. Returns the raw body as text; parsing is a
 * separate concern (see parse.ts) so that this module has exactly one job.
 */
export async function fetchFeed(
  feedUrl: string,
  opts: { maxBytes?: number; timeoutMs?: number; fetchImpl?: typeof fetch } = {},
): Promise<string> {
  if (!isAllowlistedFeedUrl(feedUrl)) {
    // Deliberately does not echo the URL into the exception message — this
    // branch is reachable only from a bug, and a caller-supplied URL in an
    // error string is how SSRF attempts end up in logs and dashboards.
    throw new FeedFetchError("URL is not in the committed allowlist", "not_allowlisted");
  }

  const maxBytes = opts.maxBytes ?? MAX_FEED_BYTES;
  const timeoutMs = opts.timeoutMs ?? FETCH_TIMEOUT_MS;
  const doFetch = opts.fetchImpl ?? fetch;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await doFetch(feedUrl, {
      // The control that matters most in this call. `manual` makes a 3xx an
      // opaque response we refuse below, instead of a hop we follow blindly.
      redirect: "manual",
      signal: controller.signal,
      headers: { accept: "application/rss+xml, application/atom+xml, application/xml, text/xml", "user-agent": USER_AGENT },
      // No credentials on a public feed, ever.
      credentials: "omit",
      cache: "no-store",
    });

    // With redirect: "manual", fetch surfaces a redirect as either a 3xx status
    // or an opaqueredirect type depending on the runtime. Refuse both.
    if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
      log.warn("feed.redirect_refused", { feedUrl, status: response.status });
      throw new FeedFetchError(
        "source responded with a redirect; update the allowlist in a PR instead of following it",
        "redirect_refused",
      );
    }

    if (!response.ok) {
      throw new FeedFetchError(`source returned HTTP ${response.status}`, "http_error");
    }

    return await readCapped(response, maxBytes);
  } catch (err) {
    if (err instanceof FeedFetchError) throw err;
    if (err instanceof Error && err.name === "AbortError") {
      throw new FeedFetchError(`fetch exceeded ${timeoutMs}ms`, "timeout");
    }
    log.warn("feed.network_error", { feedUrl, error: errorSummary(err) });
    throw new FeedFetchError(errorSummary(err), "network");
  } finally {
    clearTimeout(timer);
  }
}
