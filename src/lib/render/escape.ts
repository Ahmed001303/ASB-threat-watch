/**
 * Render-time escaping — CLAUDE.md rule 7.
 *
 * React escapes text children automatically, and every component in this app
 * renders feed content as a text child rather than via `dangerouslySetInnerHTML`
 * — that is the primary control. This module exists for the two cases React's
 * default does not cover:
 *
 *   - any place we build a string that will reach an HTML sink directly;
 *   - attribute values, where the escaping rules differ from text content.
 *
 * Per the OWASP XSS Prevention guidance, escaping is context-specific. Keeping
 * the two functions separate makes the caller state which context they are in.
 */

const HTML_ENTITIES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** Escape for HTML *text* context. `&` first, so escapes are not double-encoded. */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => HTML_ENTITIES[c] ?? c);
}

/**
 * Escape for an HTML *attribute* context, which additionally needs whitespace
 * handled: an unquoted attribute can otherwise be broken out of with a space.
 */
export function escapeAttribute(value: string): string {
  return escapeHtml(value).replace(/[\r\n\t]/g, " ");
}

/**
 * Decide whether a URL is safe to place in an href.
 *
 * Item links are already host-checked at ingest (see feeds/fetch.ts), so this is
 * the second layer: it refuses any scheme other than https, which rules out
 * `javascript:` and `data:` hrefs regardless of how a value reached here.
 */
export function safeHref(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" ? parsed.toString() : undefined;
  } catch {
    return undefined;
  }
}
