/**
 * The ingest cycle — orchestration only.
 *
 * Shape of the pipeline, and why:
 *   read runtime config -> per enabled source: fetch -> parse -> dedupe
 *   -> per new item: store raw -> summarise -> validate -> store summary
 *
 * Two properties this module is responsible for:
 *
 *   1. **The model never writes.** `summariseItem` returns text; the write is
 *      performed here, by the caller. That is what makes "no write access" in
 *      CLAUDE.md rule 1 a structural fact rather than a promise.
 *
 *   2. **Failures are per-item, never per-cycle.** One dead feed or one rejected
 *      summary must not stop the others. An item whose summary fails publishes
 *      as headline-and-link, which is the same safe state the kill switch
 *      produces.
 */

import { FEED_SOURCES, type FeedSource } from "../../config/feeds";
import { fetchFeed } from "./feeds/fetch";
import { parseFeed, type ParsedItem } from "./feeds/parse";
import { summariseItem, summariserConfigFromEnv, type SummariserConfig } from "./summarise/bedrock";
import { isFeedEnabled, loadRuntimeConfig, type RuntimeConfig } from "./runtime-config";
import {
  deriveItemId,
  itemExists,
  putItem,
  putSummary,
  retentionExpiry,
  type NewsItemRecord,
} from "./store";
import { log, errorSummary } from "./log";

export interface IngestSummary {
  readonly sourcesConsidered: number;
  readonly sourcesSkipped: number;
  readonly sourcesFailed: number;
  readonly itemsSeen: number;
  readonly itemsNew: number;
  readonly summariesOk: number;
  readonly summariesRejected: number;
  readonly summariesFailed: number;
  readonly killSwitchActive: boolean;
}

/** Cap per source per cycle, so one busy feed cannot dominate a run. */
const MAX_NEW_ITEMS_PER_SOURCE = 20;

interface Deps {
  readonly now: () => Date;
  readonly config?: RuntimeConfig;
  readonly summariserConfig?: SummariserConfig;
}

async function ingestSource(
  source: FeedSource,
  runtime: RuntimeConfig,
  deps: Deps,
  counters: {
    itemsSeen: number;
    itemsNew: number;
    summariesOk: number;
    summariesRejected: number;
    summariesFailed: number;
  },
): Promise<void> {
  const body = await fetchFeed(source.feedUrl);
  const parsed = parseFeed(body, source);
  counters.itemsSeen += parsed.length;

  let newForThisSource = 0;

  for (const item of parsed) {
    if (newForThisSource >= MAX_NEW_ITEMS_PER_SOURCE) {
      log.info("ingest.source_item_cap_reached", {
        sourceId: source.sourceId,
        cap: MAX_NEW_ITEMS_PER_SOURCE,
      });
      break;
    }

    const itemId = await deriveItemId(source.sourceId, item.guid);
    if (await itemExists(itemId)) continue;

    const now = deps.now();
    const record: NewsItemRecord = {
      itemId,
      sourceId: source.sourceId,
      guid: item.guid,
      title: item.title,
      link: item.link,
      excerpt: item.excerpt,
      category: source.category,
      publishedAt: item.publishedAt,
      fetchedAt: now.toISOString(),
      // GSI range key. Falls back to fetchedAt when the feed gave no date, so
      // an undated item still sorts sensibly instead of dropping out of the index.
      sortAt: item.publishedAt ?? now.toISOString(),
      hidden: false,
      expiresAt: retentionExpiry(now),
    };

    // Store the raw item BEFORE summarising. If summarisation fails or the
    // process dies, the item still publishes as headline-and-link rather than
    // being lost — the feed degrades, it does not gap.
    await putItem(record);
    counters.itemsNew += 1;
    newForThisSource += 1;

    if (runtime.killSwitch) continue; // rule 6: no model-generated text at all

    await summariseOne(record, item, deps, counters);
  }
}

async function summariseOne(
  record: NewsItemRecord,
  item: ParsedItem,
  deps: Deps,
  counters: {
    summariesOk: number;
    summariesRejected: number;
    summariesFailed: number;
  },
): Promise<void> {
  const source = FEED_SOURCES.find((s) => s.sourceId === record.sourceId);
  const generatedAt = deps.now().toISOString();

  try {
    const result = await summariseItem(
      {
        title: item.title,
        excerpt: item.excerpt,
        sourceName: source?.displayName ?? record.sourceId,
        category: record.category,
      },
      deps.summariserConfig ?? summariserConfigFromEnv(),
    );

    if (result.validated.status === "ok") {
      await putSummary({
        itemId: record.itemId,
        summary: result.validated.summary,
        awarenessNote: result.validated.awarenessNote,
        modelId: result.modelId,
        generatedAt,
        status: "ok",
        injectionSuspected: result.validated.injectionSuspected,
        expiresAt: record.expiresAt,
      });
      counters.summariesOk += 1;
      return;
    }

    // Record the rejection rather than silently having no row: the admin screen
    // needs to distinguish "not summarised yet" from "summary was refused".
    await putSummary({
      itemId: record.itemId,
      summary: "",
      awarenessNote: "",
      modelId: result.modelId,
      generatedAt,
      status: "rejected",
      injectionSuspected: result.validated.injectionSuspected,
      expiresAt: record.expiresAt,
    });
    counters.summariesRejected += 1;
  } catch (err) {
    counters.summariesFailed += 1;
    log.error("ingest.summarise_failed", {
      itemId: record.itemId,
      sourceId: record.sourceId,
      error: errorSummary(err),
    });
    // No summary row written on infrastructure failure — the next cycle can
    // retry it, whereas a "rejected" row would suppress that retry.
  }
}

export async function runIngest(deps: Partial<Deps> = {}): Promise<IngestSummary> {
  const resolved: Deps = { now: deps.now ?? (() => new Date()), ...deps };

  // Read at the top of every cycle, never cached — rule 6 requires that
  // flipping the switch takes effect on the next run with no redeploy.
  const runtime = resolved.config ?? (await loadRuntimeConfig());

  if (runtime.degraded) {
    log.warn("ingest.runtime_config_degraded_assuming_kill_switch");
  }

  const counters = {
    itemsSeen: 0,
    itemsNew: 0,
    summariesOk: 0,
    summariesRejected: 0,
    summariesFailed: 0,
  };
  let sourcesSkipped = 0;
  let sourcesFailed = 0;

  for (const source of FEED_SOURCES) {
    if (!isFeedEnabled(runtime, source.sourceId)) {
      sourcesSkipped += 1;
      continue;
    }
    try {
      await ingestSource(source, runtime, resolved, counters);
    } catch (err) {
      // Per-source isolation: this is the boundary that keeps one broken feed
      // from ending the cycle for the other fourteen.
      sourcesFailed += 1;
      log.warn("ingest.source_failed", {
        sourceId: source.sourceId,
        error: errorSummary(err),
      });
    }
  }

  const summary: IngestSummary = {
    sourcesConsidered: FEED_SOURCES.length,
    sourcesSkipped,
    sourcesFailed,
    killSwitchActive: runtime.killSwitch,
    ...counters,
  };

  log.info("ingest.cycle_complete", { ...summary });
  return summary;
}
