/**
 * Feed parsing: RSS 2.0 / Atom XML to plain-text items.
 *
 * Everything this module returns is UNTRUSTED. Two defences are applied here,
 * and a third is applied again at render time (CLAUDE.md rule 7 — defence in
 * depth, because a single escape is one bug away from an XSS):
 *
 *   1. Markup is stripped, so no HTML from a feed is ever carried forward. We
 *      keep plain text only — this portal has no need to render source HTML,
 *      so the safest thing is to not have any.
 *   2. Fields are length-capped, so a hostile source cannot push a megabyte of
 *      text into a card, a prompt, or a DynamoDB item.
 *
 * `fast-xml-parser` is used rather than a hand-rolled parser, and is configured
 * to not process entities beyond the standard set — XML external entity
 * expansion is a documented parser-level attack (OWASP A05 Injection), and a
 * feed is exactly the untrusted XML that would carry it.
 */

import { XMLParser } from "fast-xml-parser";
import type { FeedSource } from "../../../config/feeds";
import { isAllowedItemLink } from "./fetch";
import { log } from "../log";

export const MAX_TITLE_CHARS = 300;
export const MAX_EXCERPT_CHARS = 1200;

export interface ParsedItem {
  /** Feed-supplied guid, treated as an opaque dedupe key — never as a URL. */
  readonly guid: string;
  readonly title: string;
  readonly link: string;
  readonly excerpt: string;
  /** null when the feed omits it or it cannot be parsed — never defaulted to now. */
  readonly publishedAt: string | null;
}

/**
 * Strip tags and decode the small set of entities a feed realistically uses,
 * then collapse whitespace. Order matters: tags are removed *before* entities
 * are decoded, so an encoded `&lt;script&gt;` cannot become a live tag by
 * being decoded first.
 */
export function toPlainText(input: string, maxChars: number): string {
  let text = input;

  // Drop entire script/style elements including their contents, then all tags.
  text = text.replace(/<(script|style)\b[\s\S]*?<\/\1\s*>/gi, " ");
  text = text.replace(/<[^>]*>/g, " ");

  // CDATA wrappers appear constantly in RSS descriptions.
  text = text.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");

  // Decode after stripping. Numeric forms included because feeds use them.
  text = text
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;|&apos;/gi, "'")
    .replace(/&nbsp;/gi, " ")
    .replace(/&#x?([0-9a-f]+);/gi, (_m, code: string) => {
      const n = /^x/i.test(_m.slice(1, 2)) ? parseInt(code, 16) : parseInt(code, 10);
      // Only decode printable BMP characters; anything else becomes a space.
      if (!Number.isFinite(n) || n < 0x20 || n > 0xfffd) return " ";
      return String.fromCodePoint(n);
    })
    // Ampersand last, so decoding it cannot re-form another entity.
    .replace(/&amp;/gi, "&");

  // Any tag-looking residue after decoding is stripped again.
  text = text.replace(/<[^>]*>/g, " ");

  // Remove control characters and collapse whitespace.
  text = text.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();

  return text.length > maxChars ? `${text.slice(0, maxChars - 1).trimEnd()}…` : text;
}

function firstString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    for (const v of value) {
      const s = firstString(v);
      if (s) return s;
    }
    return "";
  }
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    // Atom <content>/<title> often carry text in #text; links carry @_href.
    if (typeof obj["#text"] === "string") return obj["#text"];
  }
  return "";
}

/**
 * Atom links are `<link href="..." rel="alternate"/>`; RSS links are text
 * content. Prefer rel="alternate" (or no rel) over rel="self"/"edit".
 */
function extractLink(raw: unknown): string {
  if (typeof raw === "string") return raw.trim();
  const candidates = Array.isArray(raw) ? raw : [raw];
  let fallback = "";
  for (const c of candidates) {
    if (typeof c === "string" && c.trim()) return c.trim();
    if (c && typeof c === "object") {
      const obj = c as Record<string, unknown>;
      const href = typeof obj["@_href"] === "string" ? obj["@_href"].trim() : "";
      if (!href) continue;
      const rel = typeof obj["@_rel"] === "string" ? obj["@_rel"] : "alternate";
      if (rel === "alternate") return href;
      if (!fallback) fallback = href;
    }
  }
  return fallback;
}

function parseDate(raw: unknown): string | null {
  const s = firstString(raw).trim();
  if (!s) return null;
  const ms = Date.parse(s);
  if (!Number.isFinite(ms)) return null;
  // Reject absurd dates rather than storing them; a feed with a year-9999
  // pubDate would otherwise pin itself to the top of the list forever.
  const year = new Date(ms).getUTCFullYear();
  if (year < 1990 || year > 2100) return null;
  return new Date(ms).toISOString();
}

/**
 * Parse a feed body into items belonging to `source`.
 *
 * Items are dropped (not repaired) when they lack a usable title or link, or
 * when the link fails the host check. Dropping is deliberate: a card with no
 * working source link would violate rule 3, which requires staff always be one
 * click from the original.
 */
export function parseFeed(xml: string, source: FeedSource): ParsedItem[] {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
    // Do not expand anything beyond the predefined XML entities. This is the
    // parser-level XXE / entity-expansion control.
    processEntities: false,
    htmlEntities: false,
    trimValues: true,
  });

  let doc: Record<string, unknown>;
  try {
    doc = parser.parse(xml) as Record<string, unknown>;
  } catch {
    log.warn("feed.parse_failed", { sourceId: source.sourceId });
    return [];
  }

  const rss = doc["rss"] as Record<string, unknown> | undefined;
  const channel = rss?.["channel"] as Record<string, unknown> | undefined;
  const feed = doc["feed"] as Record<string, unknown> | undefined;

  const rawEntries = channel?.["item"] ?? feed?.["entry"] ?? [];
  const entries = Array.isArray(rawEntries) ? rawEntries : [rawEntries];

  const items: ParsedItem[] = [];
  let droppedLink = 0;

  for (const raw of entries) {
    if (!raw || typeof raw !== "object") continue;
    const e = raw as Record<string, unknown>;

    const title = toPlainText(firstString(e["title"]), MAX_TITLE_CHARS);
    const link = extractLink(e["link"] ?? e["guid"]);
    if (!title || !link) continue;

    if (!isAllowedItemLink(link, source.allowedHost)) {
      droppedLink += 1;
      continue;
    }

    const excerptRaw =
      firstString(e["description"]) ||
      firstString(e["summary"]) ||
      firstString(e["content"]) ||
      firstString(e["content:encoded"]);

    // guid is opaque: used only with sourceId as a dedupe key.
    const guidRaw = firstString(e["guid"]) || firstString(e["id"]) || link;

    items.push({
      guid: toPlainText(guidRaw, 400) || link,
      title,
      link,
      excerpt: toPlainText(excerptRaw, MAX_EXCERPT_CHARS),
      publishedAt: parseDate(e["pubDate"] ?? e["published"] ?? e["updated"]),
    });
  }

  if (droppedLink > 0) {
    // Worth an explicit log line: a source suddenly emitting off-host links is
    // either a CDN change (a PR) or something worse (an incident).
    log.warn("feed.items_dropped_offhost", {
      sourceId: source.sourceId,
      dropped: droppedLink,
      allowedHost: source.allowedHost,
    });
  }

  return items;
}
