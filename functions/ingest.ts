/**
 * Lambda entry point for the scheduled ingest cycle.
 *
 * Thin on purpose: all logic is in src/lib/ingest.ts so it is unit-testable
 * without a Lambda runtime. This file exists only to adapt the handler signature
 * and to make sure a thrown error is logged in the PII-safe format rather than
 * as a raw stack trace in CloudWatch.
 */

import { runIngest } from "../src/lib/ingest";
import { log, errorSummary } from "../src/lib/log";

export async function handler(): Promise<{ statusCode: number; body: string }> {
  const startedAt = Date.now();

  try {
    const summary = await runIngest();
    return {
      statusCode: 200,
      body: JSON.stringify({ ...summary, durationMs: Date.now() - startedAt }),
    };
  } catch (err) {
    // Only reachable if config loading itself fails — per-source failures are
    // handled inside runIngest and never reach here.
    log.error("ingest.cycle_failed", {
      error: errorSummary(err),
      durationMs: Date.now() - startedAt,
    });
    // Rethrow so the invocation is recorded as a failure and the alarm fires.
    throw err;
  }
}
