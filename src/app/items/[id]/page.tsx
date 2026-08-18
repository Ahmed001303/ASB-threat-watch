/**
 * Item detail + report form (S3 and S4 in docs/design/screens.md).
 *
 * The report form is a plain HTML form with a CSRF token — no client JavaScript.
 * That is a deliberate choice: it means the CSP can stay strict, and the only
 * user input in the entire application is this one textarea.
 */

import { notFound } from "next/navigation";
import { FEED_SOURCES } from "../../../../config/feeds";
import { ItemCard } from "../../../components/ItemCard";
import { requireSession } from "../../../lib/auth/guard";
import { csrfTokenFor, CSRF_FIELD } from "../../../lib/auth/csrf";
import { loadRuntimeConfig } from "../../../lib/runtime-config";
import { getItem, getSummary } from "../../../lib/store";
import { MAX_REASON_CHARS } from "../../api/report/route";

export const dynamic = "force-dynamic";

export default async function ItemPage({ params }: { params: Promise<{ id: string }> }) {
  const session = await requireSession();
  const { id } = await params;

  const item = await getItem(id);
  if (!item) notFound();

  const config = await loadRuntimeConfig();
  const summary = config.killSwitch ? undefined : await getSummary(item.itemId);
  const source = FEED_SOURCES.find((s) => s.sourceId === item.sourceId);

  return (
    <>
      <header className="site">
        <h1>
          <a href="/feed" style={{ textDecoration: "none", color: "inherit" }}>
            ← Threat Watch
          </a>
        </h1>
        <span className="who">{session.displayName}</span>
      </header>

      <ItemCard
        itemId={item.itemId}
        title={item.title}
        link={item.link}
        excerpt={item.excerpt}
        sourceName={source?.displayName ?? item.sourceId}
        category={item.category}
        publishedAt={item.publishedAt}
        fetchedAt={item.fetchedAt}
        killSwitchActive={config.killSwitch}
        summary={
          summary && summary.status === "ok"
            ? {
                text: summary.summary,
                awarenessNote: summary.awarenessNote,
                modelId: summary.modelId,
                generatedAt: summary.generatedAt,
              }
            : undefined
        }
      />

      <article className="card" id="report">
        <h2>Report this item</h2>
        <p className="excerpt">
          Wrong, misleading, or inappropriate? This goes to the Innovation Department,
          who can hide the item or disable the source without a deploy.
        </p>

        <form method="post" action="/api/report">
          <input type="hidden" name="itemId" value={item.itemId} />
          {/* Synchroniser token, bound to this session. */}
          <input type="hidden" name={CSRF_FIELD} value={csrfTokenFor(session.sid)} />
          <label htmlFor="reason" style={{ display: "block", fontSize: "0.85rem" }}>
            What is wrong with it? (optional, up to {MAX_REASON_CHARS} characters)
          </label>
          <textarea
            id="reason"
            name="reason"
            rows={4}
            maxLength={MAX_REASON_CHARS}
            style={{
              width: "100%",
              marginTop: "0.35rem",
              marginBottom: "0.6rem",
              font: "inherit",
              padding: "0.5rem",
            }}
          />
          <div className="actions">
            <button type="submit">Send report</button>
          </div>
        </form>
      </article>
    </>
  );
}
