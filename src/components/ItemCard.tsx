/**
 * One news item. This component is where CLAUDE.md rules 3, 4, 5 and 7 are
 * visible to staff, so each is annotated where it is implemented.
 *
 * Rule 7 note: every field below is rendered as a JSX text child, which React
 * escapes. There is no `dangerouslySetInnerHTML` anywhere in this file — and
 * there must never be, because every string here originates in a third-party
 * feed or a model that read one.
 */

import type { Category } from "../../config/feeds";
import { safeHref } from "../lib/render/escape";

export interface ItemCardProps {
  readonly itemId: string;
  readonly title: string;
  readonly link: string;
  readonly excerpt: string;
  readonly sourceName: string;
  readonly category: Category;
  readonly publishedAt: string | null;
  readonly fetchedAt: string;
  /** Absent when the summary failed, was rejected, or the kill switch is on. */
  readonly summary?: {
    readonly text: string;
    readonly awarenessNote: string;
    readonly modelId: string;
    readonly generatedAt: string;
  };
  /** True when the kill switch is on, as opposed to this one item failing. */
  readonly killSwitchActive: boolean;
}

const CATEGORY_LABEL: Record<Category, string> = {
  ai: "AI incident",
  breach: "Breach",
  vuln: "Vulnerability",
  "banking-tech": "Banking tech",
};

function formatWhen(iso: string | null): string {
  if (!iso) return "date unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "date unknown";
  return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

export function ItemCard(props: ItemCardProps) {
  // Rule 3 + defence in depth: the link was host-checked at ingest, and is
  // checked again here. If it somehow isn't https, we render no link at all
  // rather than an unsafe one.
  const href = safeHref(props.link);

  return (
    <article className="card">
      <div className="meta">
        <span>{CATEGORY_LABEL[props.category]}</span>
        <span aria-hidden="true">·</span>
        <span>{props.sourceName}</span>
        <span aria-hidden="true">·</span>
        <span>{formatWhen(props.publishedAt ?? props.fetchedAt)}</span>
      </div>

      <h2>
        {href ? (
          <a href={href} target="_blank" rel="noopener noreferrer">
            {props.title}
          </a>
        ) : (
          props.title
        )}
      </h2>

      {props.excerpt ? <p className="excerpt">{props.excerpt}</p> : null}

      {props.summary ? (
        <div className="ai-block">
          {/* Rule 3: label on the card itself. Icon + text so it does not rely
              on colour, and inside the block it describes rather than beside it. */}
          <div className="ai-label">🤖 AI-generated summary</div>
          <p>{props.summary.text}</p>
          {/* Rule 4: awareness framing. The required prefix is enforced in
              validate.ts — by the time it renders it has already been checked. */}
          <p className="awareness">{props.summary.awarenessNote}</p>
          <div className="provenance">
            Generated {formatWhen(props.summary.generatedAt)} by {props.summary.modelId}
          </div>
        </div>
      ) : (
        // Two distinct states, deliberately worded differently. An operator must
        // be able to tell a killed portal from a broken item at a glance —
        // otherwise "the summaries are gone" is ambiguous during an incident.
        <div className="no-summary">
          {props.killSwitchActive
            ? "AI summaries are disabled portal-wide. Headline and source link only."
            : "No AI summary for this item — it was not generated, or it failed validation. Read the original."}
        </div>
      )}

      <div className="actions">
        {href ? (
          <a className="primary" href={href} target="_blank" rel="noopener noreferrer">
            Read the original ↗
          </a>
        ) : null}
        <a href={`/items/${encodeURIComponent(props.itemId)}`}>Details</a>
        {/* Rule 5: a report route on every item, no exceptions. */}
        <a href={`/items/${encodeURIComponent(props.itemId)}#report`}>⚑ Report</a>
      </div>
    </article>
  );
}
