/**
 * Pipeline behaviour tests: parsing real-world feed shapes, session handling,
 * and CSRF. These complement tests/security.test.ts, which covers the numbered
 * rules in CLAUDE.md.
 */

import { beforeAll, describe, expect, it } from "vitest";

import { FEED_SOURCES } from "../config/feeds";
import { parseFeed } from "../src/lib/feeds/parse";
import { deriveItemId, retentionExpiry } from "../src/lib/store";
import {
  ABSOLUTE_TIMEOUT_MS,
  createSession,
  IDLE_TIMEOUT_MS,
  parseSession,
  serialiseSession,
  SESSION_COOKIE,
  touchSession,
} from "../src/lib/auth/session";
import { csrfTokenFor, csrfTokenValid, originAcceptable } from "../src/lib/auth/csrf";
import { normalisePem } from "../src/lib/auth/saml";

const krebs = FEED_SOURCES.find((s) => s.sourceId === "krebs")!;
const schneier = FEED_SOURCES.find((s) => s.sourceId === "schneier")!;

beforeAll(() => {
  // 32+ chars, as the session module requires. Test-only value.
  process.env.SESSION_SECRET = "test-secret-value-at-least-32-chars-long";
});

describe("parsing real feed shapes", () => {
  it("parses RSS 2.0", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <rss version="2.0"><channel>
        <title>KrebsOnSecurity</title>
        <item>
          <title>Data broker leaks 1.2m records</title>
          <link>https://krebsonsecurity.com/2026/08/broker-leak/</link>
          <guid isPermaLink="false">https://krebsonsecurity.com/?p=1234</guid>
          <pubDate>Tue, 12 Aug 2026 14:05:00 +0000</pubDate>
          <description><![CDATA[<p>A broker exposed <b>1.2m</b> records.</p>]]></description>
        </item>
      </channel></rss>`;

    const [item] = parseFeed(xml, krebs);
    expect(item?.title).toBe("Data broker leaks 1.2m records");
    expect(item?.link).toBe("https://krebsonsecurity.com/2026/08/broker-leak/");
    expect(item?.excerpt).toBe("A broker exposed 1.2m records.");
    expect(item?.publishedAt).toBe("2026-08-12T14:05:00.000Z");
  });

  it("parses Atom, preferring rel=alternate over rel=self", () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
      <feed xmlns="http://www.w3.org/2005/Atom">
        <entry>
          <title>On AI agents and trust</title>
          <link rel="self" href="https://www.schneier.com/feed/atom/"/>
          <link rel="alternate" href="https://www.schneier.com/blog/archives/2026/08/agents.html"/>
          <id>tag:schneier.com,2026:agents</id>
          <updated>2026-08-11T09:00:00Z</updated>
          <summary>Short note on agent trust boundaries.</summary>
        </entry>
      </feed>`;

    const [item] = parseFeed(xml, schneier);
    expect(item?.link).toBe("https://www.schneier.com/blog/archives/2026/08/agents.html");
    expect(item?.publishedAt).toBe("2026-08-11T09:00:00.000Z");
  });

  it("handles a single item that is not wrapped in an array", () => {
    const xml = `<rss version="2.0"><channel><item>
      <title>Only one</title><link>https://krebsonsecurity.com/a</link><guid>1</guid>
    </channel></rss>`;
    expect(parseFeed(xml, krebs)).toHaveLength(1);
  });

  it("returns an empty list rather than throwing on malformed XML", () => {
    expect(parseFeed("this is not xml at all <<<", krebs)).toEqual([]);
    expect(parseFeed("", krebs)).toEqual([]);
  });

  it("leaves publishedAt null when the date is absent or unparseable", () => {
    const xml = `<rss version="2.0"><channel>
      <item><title>No date</title><link>https://krebsonsecurity.com/a</link><guid>1</guid></item>
      <item><title>Bad date</title><link>https://krebsonsecurity.com/b</link><guid>2</guid><pubDate>not a date</pubDate></item>
      <item><title>Absurd date</title><link>https://krebsonsecurity.com/c</link><guid>3</guid><pubDate>Tue, 01 Jan 9999 00:00:00 +0000</pubDate></item>
    </channel></rss>`;

    // Never defaulted to "now" — an invented timestamp would misrepresent the source.
    for (const item of parseFeed(xml, krebs)) {
      expect(item.publishedAt).toBeNull();
    }
  });

  it("drops items with no title", () => {
    const xml = `<rss version="2.0"><channel><item>
      <link>https://krebsonsecurity.com/a</link><guid>1</guid>
    </item></channel></rss>`;
    expect(parseFeed(xml, krebs)).toEqual([]);
  });
});

describe("item ids are deterministic and collision-resistant", () => {
  it("is stable for the same (source, guid) pair — re-ingest is idempotent", async () => {
    const a = await deriveItemId("krebs", "guid-1");
    const b = await deriveItemId("krebs", "guid-1");
    expect(a).toBe(b);
  });

  it("differs across sources sharing a guid", async () => {
    expect(await deriveItemId("krebs", "g")).not.toBe(await deriveItemId("therecord", "g"));
  });

  it("cannot be confused by a separator in the inputs", async () => {
    // Without a delimiter that cannot occur in either value, ("ab","c") and
    // ("a","bc") would hash identically.
    expect(await deriveItemId("ab", "c")).not.toBe(await deriveItemId("a", "bc"));
  });
});

describe("retention", () => {
  it("expires items twelve months out", () => {
    const from = new Date("2026-08-13T00:00:00Z");
    const expiry = new Date(retentionExpiry(from) * 1000);
    expect(expiry.getUTCFullYear()).toBe(2027);
    expect(expiry.getUTCMonth()).toBe(from.getUTCMonth());
  });
});

describe("sessions", () => {
  it("round-trips a signed session", () => {
    const s = createSession({ email: "A.Person@alsalambank.com", displayName: "A Person", role: "reader" });
    const parsed = parseSession(serialiseSession(s));
    expect(parsed?.email).toBe("a.person@alsalambank.com"); // normalised
    expect(parsed?.role).toBe("reader");
  });

  it("rejects a tampered payload", () => {
    const s = createSession({ email: "a@b.com", displayName: "A", role: "reader" });
    const cookie = serialiseSession(s);
    const [payload, sig] = cookie.split(".");

    // Escalate reader -> owner and re-attach the original signature.
    const forged = Buffer.from(
      JSON.stringify({ ...s, role: "owner" }),
      "utf8",
    ).toString("base64url");

    expect(parseSession(`${forged}.${sig}`)).toBeUndefined();
    expect(payload).toBeTruthy();
  });

  it("rejects an unsigned cookie", () => {
    const payload = Buffer.from(
      JSON.stringify(createSession({ email: "a@b.com", displayName: "A", role: "owner" })),
      "utf8",
    ).toString("base64url");
    expect(parseSession(payload)).toBeUndefined();
    expect(parseSession(`${payload}.`)).toBeUndefined();
  });

  it("enforces the idle timeout server-side", () => {
    const now = Date.now();
    const s = createSession({ email: "a@b.com", displayName: "A", role: "reader" }, now);
    const cookie = serialiseSession(s);
    expect(parseSession(cookie, now + IDLE_TIMEOUT_MS - 1000)).toBeDefined();
    expect(parseSession(cookie, now + IDLE_TIMEOUT_MS + 1000)).toBeUndefined();
  });

  it("enforces the absolute timeout even when activity is recent", () => {
    const start = Date.now();
    const s = createSession({ email: "a@b.com", displayName: "A", role: "reader" }, start);
    // Kept alive right up to the absolute ceiling...
    const active = touchSession(s, start + ABSOLUTE_TIMEOUT_MS + 1000);
    // ...but createdAt still governs: the session is over.
    expect(parseSession(serialiseSession(active), start + ABSOLUTE_TIMEOUT_MS + 2000)).toBeUndefined();
  });

  it("mints a fresh session id per login (fixation)", () => {
    const a = createSession({ email: "a@b.com", displayName: "A", role: "reader" });
    const b = createSession({ email: "a@b.com", displayName: "A", role: "reader" });
    expect(a.sid).not.toBe(b.sid);
    // 32 bytes base64url ≈ 43 chars, far above the 64-bit OWASP floor.
    expect(a.sid.length).toBeGreaterThanOrEqual(40);
  });

  it("uses a cookie name that does not fingerprint the framework", () => {
    expect(SESSION_COOKIE).not.toMatch(/next|auth\.session/i);
    expect(SESSION_COOKIE.startsWith("__Host-")).toBe(true);
  });
});

describe("CSRF", () => {
  it("accepts the token bound to the session", () => {
    const sid = "session-abc";
    expect(csrfTokenValid(sid, csrfTokenFor(sid))).toBe(true);
  });

  it("rejects a token minted for a different session", () => {
    expect(csrfTokenValid("session-abc", csrfTokenFor("session-xyz"))).toBe(false);
  });

  it("rejects an absent or empty token", () => {
    expect(csrfTokenValid("s", undefined)).toBe(false);
    expect(csrfTokenValid("s", "")).toBe(false);
  });

  it("accepts a same-origin Origin and rejects a foreign one", () => {
    const base = "https://tw.alsalambank.com";
    expect(originAcceptable("https://tw.alsalambank.com", base)).toBe(true);
    expect(originAcceptable("https://evil.test", base)).toBe(false);
    // Absent Origin is allowed: the token is the primary control.
    expect(originAcceptable(null, base)).toBe(true);
  });
});

describe("SAML certificate normalisation", () => {
  it("re-armours a certificate pasted without headers or line breaks", () => {
    const body = "A".repeat(200);
    const pem = normalisePem(body);
    expect(pem.startsWith("-----BEGIN CERTIFICATE-----\n")).toBe(true);
    expect(pem.trimEnd().endsWith("-----END CERTIFICATE-----")).toBe(true);
    // 64-char lines, as the library expects.
    const lines = pem.split("\n").slice(1, -1);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(64);
  });

  it("is idempotent on an already-correct certificate", () => {
    const once = normalisePem("B".repeat(128));
    expect(normalisePem(once)).toBe(once);
  });
});
