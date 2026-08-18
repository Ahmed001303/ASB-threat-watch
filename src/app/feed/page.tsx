/**
 * The main screen (S2 in docs/design/screens.md).
 *
 * Server component: the session check, the runtime-config read, and the data
 * fetch all happen server-side, so nothing about authorisation depends on the
 * client. The page ships no JavaScript of its own.
 */

import { CATEGORIES, FEED_SOURCES, type Category } from "../../../config/feeds";
import { ItemCard } from "../../components/ItemCard";
import { requireSession } from "../../lib/auth/guard";
import { loadRuntimeConfig } from "../../lib/runtime-config";
import { getSummary, listRecentItems } from "../../lib/store";
import { log } from "../../lib/log";

export const dynamic = "force-dynamic"; // never cache a per-session page

const CATEGORY_LABEL: Record<Category, string> = {
  ai: "AI",
  breach: "Breaches",
  vuln: "Vulnerabilities",
  "banking-tech": "Banking tech",
};

function sourceName(sourceId: string): string {
  return FEED_SOURCES.find((s) => s.sourceId === sourceId)?.displayName ?? sourceId;
}

export default async function FeedPage({
  searchParams,
}: {
  searchParams: Promise<{ category?: string }>;
}) {
  const session = await requireSession();
  const params = await searchParams;

  // Validate the category against the known set rather than trusting the query
  // string — allowlist, not sanitisation.
  const requested = params.category;
  const category = CATEGORIES.find((c) => c === requested);

  const config = await loadRuntimeConfig();
  const items = await listRecentItems({ category, limit: 50 });

  // Read summaries only when the kill switch is off. When it is on we do not
  // even load model text, so there is nothing to accidentally render.
  const summaries = config.killSwitch
    ? new Map<string, Awaited<ReturnType<typeof getSummary>>>()
    : new Map(
        await Promise.all(
          items.map(
            async (i) => [i.itemId, await getSummary(i.itemId)] as const,
          ),
        ),
      );

  log.info("feed.viewed", {
    email: session.email,
    category: category ?? "all",
    items: items.length,
    killSwitch: config.killSwitch,
  });

  return (
    <>
      <header className="site">
        <h1>Threat Watch</h1>
        <span className="who">
          {session.displayName} · {session.role}
          {session.role === "owner" ? " · " : ""}
          {session.role === "owner" ? <a href="/admin">Admin</a> : null}
        </span>
      </header>

      {config.degraded ? (
        <div className="banner">
          Runtime configuration could not be read, so the portal is running in its
          fail-safe state: AI summaries are suppressed. This is an operational
          issue — tell the Innovation Department.
        </div>
      ) : config.killSwitch ? (
        <div className="banner">
          AI summaries are temporarily disabled. Items below show the headline and a
          link to the original only.
        </div>
      ) : null}

      <nav className="tabs">
        <a href="/feed" aria-current={category ? undefined : "page"}>
          All
        </a>
        {CATEGORIES.map((c) => (
          <a
            key={c}
            href={`/feed?category=${c}`}
            aria-current={category === c ? "page" : undefined}
          >
            {CATEGORY_LABEL[c]}
          </a>
        ))}
      </nav>

      {items.length === 0 ? (
        <p className="excerpt">
          Nothing here yet. The ingest job publishes items on a schedule; if this stays
          empty, check the job rather than the portal.
        </p>
      ) : (
        items.map((item) => {
          const s = summaries.get(item.itemId);
          return (
            <ItemCard
              key={item.itemId}
              itemId={item.itemId}
              title={item.title}
              link={item.link}
              excerpt={item.excerpt}
              sourceName={sourceName(item.sourceId)}
              category={item.category}
              publishedAt={item.publishedAt}
              fetchedAt={item.fetchedAt}
              killSwitchActive={config.killSwitch}
              summary={
                s && s.status === "ok"
                  ? {
                      text: s.summary,
                      awarenessNote: s.awarenessNote,
                      modelId: s.modelId,
                      generatedAt: s.generatedAt,
                    }
                  : undefined
              }
            />
          );
        })
      )}
    </>
  );
}
