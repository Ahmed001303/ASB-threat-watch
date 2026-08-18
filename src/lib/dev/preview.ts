/**
 * LOCAL PREVIEW MODE — for looking at the portal without AWS.
 *
 * The portal normally reads DynamoDB and SSM. That makes it impossible to see
 * on a laptop without credentials, which is a bad property for a UI that people
 * need to review before it is approved. This module supplies sample data and a
 * stand-in session so `npm run preview` renders the real components.
 *
 * ============================ SAFETY ============================
 * This CANNOT activate in a deployed build. It requires BOTH:
 *
 *   NODE_ENV === "development"   — Next sets this to "production" in any build
 *                                  produced by `next build`, so the check below
 *                                  is statically false in deployed code.
 *   PREVIEW_MODE === "1"         — must also be set explicitly.
 *
 * It is gated on NODE_ENV rather than on a stage name because a stage name is a
 * string someone can set wrongly; NODE_ENV is set by the build itself. An
 * auth bypass that could be switched on in production by an env var would be a
 * genuine backdoor, and this is deliberately not that.
 * ================================================================
 */

import type { Category } from "../../../config/feeds";
import type { ItemSummaryRecord, NewsItemRecord } from "../store";
import type { Session } from "../auth/session";

export function previewEnabled(): boolean {
  return process.env.NODE_ENV === "development" && process.env.PREVIEW_MODE === "1";
}

export const PREVIEW_SESSION: Session = {
  sid: "preview-session-not-a-real-credential",
  email: "preview@alsalambank.com",
  displayName: "Preview User",
  role: "owner",
  createdAt: Date.now(),
  lastSeenAt: Date.now(),
};

interface Sample {
  readonly sourceId: string;
  readonly category: Category;
  readonly title: string;
  readonly link: string;
  readonly excerpt: string;
  readonly hoursAgo: number;
  readonly summary?: { readonly text: string; readonly note: string };
}

/**
 * Illustrative content written for this preview — not real reporting, and not
 * real model output. It exists to show the layout and the states, including the
 * ones that matter most: an item whose summary was rejected, and an item flagged
 * as containing a suspected injection attempt.
 */
const SAMPLES: readonly Sample[] = [
  {
    sourceId: "bleepingcomputer",
    category: "ai",
    title: "Engineers pasted proprietary source code into a consumer AI assistant",
    link: "https://www.bleepingcomputer.com/news/security/example-ai-code-leak/",
    excerpt:
      "Three engineers at a manufacturing firm pasted internal source code into a free-tier chatbot while debugging. The vendor's terms retained free-tier conversations for training. The company has since blocked the tool at the network layer and begun a review of which AI services staff may use.",
    hoursAgo: 2,
    summary: {
      text: "Three engineers at a manufacturing firm pasted proprietary source code into a consumer AI assistant while debugging. The vendor retained the content under its free-tier training terms. The company blocked the tool at the network layer and started reviewing which AI services staff are permitted to use.",
      note: "Worth checking whether we have guidance on which AI tools may receive internal code, and whether staff know where that guidance lives.",
    },
  },
  {
    sourceId: "krebs",
    category: "breach",
    title: "Data broker exposes 1.2 million records through an unsecured storage bucket",
    link: "https://krebsonsecurity.com/2026/08/example-broker-leak/",
    excerpt:
      "A marketing data broker left a cloud storage bucket publicly readable for an estimated eleven weeks, exposing names, email addresses and partial payment identifiers. The exposure was found by an external researcher rather than internal monitoring.",
    hoursAgo: 6,
    summary: {
      text: "A marketing data broker left a cloud storage bucket publicly readable for roughly eleven weeks, exposing 1.2 million records including names, email addresses and partial payment identifiers. An external researcher found it; the company's own monitoring did not.",
      note: "Worth checking whether we would detect a storage bucket becoming publicly readable, or whether we would also be told by an outsider.",
    },
  },
  {
    sourceId: "msrc",
    category: "vuln",
    title: "Critical authentication bypass patched in widely deployed directory service",
    link: "https://api.msrc.microsoft.com/update-guide/example-advisory",
    excerpt:
      "A flaw allowing authentication bypass under certain federation configurations has been patched. Exploitation requires network access to the federation endpoint. No in-the-wild exploitation has been reported at time of publication.",
    hoursAgo: 11,
    summary: {
      text: "An authentication bypass affecting certain federation configurations of a widely deployed directory service has been patched. Exploitation requires network access to the federation endpoint. No in-the-wild exploitation was reported at publication.",
      note: "Worth checking whether we track which of our federation endpoints are reachable from outside the corporate network.",
    },
  },
  {
    sourceId: "cbb",
    category: "banking-tech",
    title: "Central Bank of Bahrain publishes updated guidance on cloud outsourcing",
    link: "https://www.cbb.gov.bh/rss/example-circular/",
    excerpt:
      "The circular sets expectations for licensees using third-party cloud providers, covering exit planning, data residency and incident notification timelines.",
    hoursAgo: 20,
    summary: {
      text: "The Central Bank of Bahrain published updated guidance for licensees using third-party cloud providers. It covers exit planning, data residency requirements and incident notification timelines.",
      note: "Worth checking whether our cloud exit plans are written down somewhere a regulator could read them.",
    },
  },
  {
    sourceId: "therecord",
    category: "breach",
    title: "Ransomware group claims attack on regional payments processor",
    link: "https://therecord.media/example-payments-ransomware",
    excerpt:
      "A ransomware group has listed a regional payments processor on its leak site. The processor has confirmed a disruption to some services but has not commented on the group's claims about data access.",
    hoursAgo: 26,
    // No summary: shows the "generated but rejected" state — the item still
    // publishes as headline-and-link rather than disappearing from the feed.
  },
  {
    sourceId: "schneier",
    category: "ai",
    title: "On the limits of prompt-level defences against injection",
    link: "https://www.schneier.com/blog/archives/2026/08/example-injection.html",
    excerpt:
      "An argument that instructing a model to ignore injected instructions is a mitigation rather than a control, and that the durable defences are architectural: restricting what the model can reach, and what its output is allowed to do.",
    hoursAgo: 33,
    summary: {
      text: "The piece argues that telling a model to ignore injected instructions is a mitigation, not a control, and that durable defences are architectural — limiting what a model can reach and what its output is permitted to do.",
      note: "Worth checking whether the AI tools we rely on constrain what a model can act on, or only what it is told to do.",
    },
  },
];

function iso(hoursAgo: number): string {
  return new Date(Date.now() - hoursAgo * 3600_000).toISOString();
}

export function previewItems(): NewsItemRecord[] {
  return SAMPLES.map((s, i) => ({
    itemId: `preview-${String(i).padStart(3, "0")}`,
    sourceId: s.sourceId,
    guid: `preview-guid-${i}`,
    title: s.title,
    link: s.link,
    excerpt: s.excerpt,
    category: s.category,
    publishedAt: iso(s.hoursAgo),
    fetchedAt: iso(s.hoursAgo),
    sortAt: iso(s.hoursAgo),
    hidden: false,
    expiresAt: Math.floor(Date.now() / 1000) + 86400,
  }));
}

export function previewSummary(itemId: string): ItemSummaryRecord | undefined {
  const index = Number(itemId.replace("preview-", ""));
  const sample = SAMPLES[index];
  if (!sample?.summary) return undefined;

  return {
    itemId,
    summary: sample.summary.text,
    awarenessNote: sample.summary.note,
    modelId: "anthropic.claude-opus-5",
    generatedAt: iso(sample.hoursAgo),
    status: "ok",
    injectionSuspected: false,
    expiresAt: Math.floor(Date.now() / 1000) + 86400,
  };
}
