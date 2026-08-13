/**
 * DynamoDB storage. Names and tags follow `asb-deploy`; the schema follows
 * docs/design/data-dictionary.md.
 *
 * Single-table-per-entity rather than one overloaded table: the access patterns
 * here are few and simple (list recent items by category, fetch one item, list
 * open reports), and three small tables with explicit keys are easier for a
 * reviewer to reason about than one table with a synthetic partition key.
 *
 * Every query is bounded and index-backed — `asb-deploy` §6 says never rely on
 * scans, and a feed that grows unbounded would make a scan progressively worse.
 */

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import type { Category } from "../../config/feeds";

export interface NewsItemRecord {
  readonly itemId: string;
  readonly sourceId: string;
  readonly guid: string;
  readonly title: string;
  readonly link: string;
  readonly excerpt: string;
  readonly category: Category;
  readonly publishedAt: string | null;
  readonly fetchedAt: string;
  /**
   * Range key of the `byCategory` GSI: publishedAt when the feed supplied one,
   * else fetchedAt. Stored explicitly rather than computed at query time so the
   * index always has a sortable value and the query never degrades to a scan.
   */
  readonly sortAt: string;
  readonly hidden: boolean;
  /** Unix seconds. DynamoDB TTL enforces the 12-month retention policy. */
  readonly expiresAt: number;
}

export type SummaryStatus = "ok" | "failed" | "rejected";

export interface ItemSummaryRecord {
  readonly itemId: string;
  readonly summary: string;
  readonly awarenessNote: string;
  readonly modelId: string;
  readonly generatedAt: string;
  readonly status: SummaryStatus;
  readonly injectionSuspected: boolean;
  readonly expiresAt: number;
}

export interface ReportRecord {
  readonly reportId: string;
  readonly itemId: string;
  /** Taken from the session, never from the request body. */
  readonly reportedBy: string;
  readonly reason: string;
  readonly createdAt: string;
  readonly resolution: "open" | "item_hidden" | "source_disabled" | "no_action";
  readonly expiresAt: number;
}

export interface TableNames {
  readonly items: string;
  readonly summaries: string;
  readonly reports: string;
}

export function tableNamesFromEnv(): TableNames {
  const stage = process.env.STAGE ?? "dev";
  return {
    items: process.env.ITEMS_TABLE ?? `asb-threat-watch-${stage}-items`,
    summaries: process.env.SUMMARIES_TABLE ?? `asb-threat-watch-${stage}-summaries`,
    reports: process.env.REPORTS_TABLE ?? `asb-threat-watch-${stage}-reports`,
  };
}

let cachedDoc: DynamoDBDocumentClient | undefined;

export function docClient(region = process.env.AWS_REGION ?? "eu-west-1"): DynamoDBDocumentClient {
  if (!cachedDoc) {
    cachedDoc = DynamoDBDocumentClient.from(new DynamoDBClient({ region }), {
      marshallOptions: { removeUndefinedValues: true },
    });
  }
  return cachedDoc;
}

/** 12 months, per the retention table in the data dictionary. */
export function retentionExpiry(from: Date): number {
  const d = new Date(from);
  d.setUTCFullYear(d.getUTCFullYear() + 1);
  return Math.floor(d.getTime() / 1000);
}

/**
 * Deterministic item id from (sourceId, guid) — the dedupe key. Using a hash of
 * the natural key rather than a random uuid means re-ingesting the same feed
 * item is idempotent, so a retried cycle cannot duplicate cards.
 *
 * Not a security boundary: it is a dedupe key, not a secret, so a fast
 * non-cryptographic digest would do — sha256 is used only because it is
 * available without a dependency and removes any collision worry.
 */
export async function deriveItemId(sourceId: string, guid: string): Promise<string> {
  // "\u0000" as the separator so a sourceId or guid containing the delimiter
  // cannot collide with a different pair — a NUL cannot appear in either value,
  // since both are run through toPlainText, which strips control characters.
  const data = new TextEncoder().encode(`${sourceId}\u0000${guid}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function itemExists(
  itemId: string,
  tables: TableNames = tableNamesFromEnv(),
): Promise<boolean> {
  const out = await docClient().send(
    new GetCommand({
      TableName: tables.items,
      Key: { itemId },
      ProjectionExpression: "itemId",
    }),
  );
  return Boolean(out.Item);
}

export async function putItem(
  item: NewsItemRecord,
  tables: TableNames = tableNamesFromEnv(),
): Promise<void> {
  await docClient().send(new PutCommand({ TableName: tables.items, Item: item }));
}

export async function putSummary(
  summary: ItemSummaryRecord,
  tables: TableNames = tableNamesFromEnv(),
): Promise<void> {
  await docClient().send(new PutCommand({ TableName: tables.summaries, Item: summary }));
}

export async function getSummary(
  itemId: string,
  tables: TableNames = tableNamesFromEnv(),
): Promise<ItemSummaryRecord | undefined> {
  const out = await docClient().send(
    new GetCommand({ TableName: tables.summaries, Key: { itemId } }),
  );
  return out.Item as ItemSummaryRecord | undefined;
}

export async function getItem(
  itemId: string,
  tables: TableNames = tableNamesFromEnv(),
): Promise<NewsItemRecord | undefined> {
  const out = await docClient().send(
    new GetCommand({ TableName: tables.items, Key: { itemId } }),
  );
  return out.Item as NewsItemRecord | undefined;
}

/**
 * Recent items, newest first, via a GSI on (category, sortKey). `sortKey` is
 * publishedAt when the feed supplied one and fetchedAt otherwise — the item
 * record stores it explicitly so the index never has to fall back to a scan.
 */
export async function listRecentItems(
  opts: { category?: Category; limit?: number } = {},
  tables: TableNames = tableNamesFromEnv(),
): Promise<NewsItemRecord[]> {
  const limit = Math.min(opts.limit ?? 50, 100);

  // `feedPartition` is a constant per category so the GSI has a small, known
  // set of partitions and the query is always bounded.
  const partitions: Category[] = opts.category
    ? [opts.category]
    : ["ai", "breach", "vuln", "banking-tech"];

  const results = await Promise.all(
    partitions.map(async (category) => {
      const out = await docClient().send(
        new QueryCommand({
          TableName: tables.items,
          IndexName: "byCategory",
          // `category` is a DynamoDB reserved word in some contexts, so it is
          // bound through an expression-attribute name rather than inlined.
          KeyConditionExpression: "#c = :c",
          ExpressionAttributeNames: { "#c": "category" },
          ExpressionAttributeValues: { ":c": category },
          // Newest first, using the GSI's own range key — the sort below is only
          // a merge across the per-category queries, not the primary ordering.
          ScanIndexForward: false,
          Limit: limit,
        }),
      );
      return (out.Items ?? []) as NewsItemRecord[];
    }),
  );

  return results
    .flat()
    .filter((i) => !i.hidden)
    .sort((a, b) => (a.sortAt < b.sortAt ? 1 : a.sortAt > b.sortAt ? -1 : 0))
    .slice(0, limit);
}

export async function putReport(
  report: ReportRecord,
  tables: TableNames = tableNamesFromEnv(),
): Promise<void> {
  await docClient().send(new PutCommand({ TableName: tables.reports, Item: report }));
}

export async function setItemHidden(
  itemId: string,
  hidden: boolean,
  tables: TableNames = tableNamesFromEnv(),
): Promise<void> {
  await docClient().send(
    new UpdateCommand({
      TableName: tables.items,
      Key: { itemId },
      UpdateExpression: "SET hidden = :h",
      ExpressionAttributeValues: { ":h": hidden },
    }),
  );
}
