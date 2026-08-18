/**
 * Rule 5 — the report endpoint.
 *
 * State-changing, so it carries the full set: session required, CSRF token
 * verified, Origin checked, per-user rate limit, and server-side validation of
 * the body. Two details matter most:
 *
 *   - **The reporter identity comes from the session, never the request body.**
 *     Accepting a `reportedBy` field would let any authenticated reader file a
 *     report as a colleague.
 *   - **The reason text is never logged and never sent to the model.** It is
 *     staff free text, so it is treated as untrusted input for rendering and as
 *     private content for logging.
 */

import { NextResponse, type NextRequest } from "next/server";
import { currentSession } from "../../../lib/auth/guard";
import { csrfTokenValid, CSRF_HEADER, CSRF_FIELD, originAcceptable } from "../../../lib/auth/csrf";
import { getItem, putReport, retentionExpiry } from "../../../lib/store";
import { log } from "../../../lib/log";

export const dynamic = "force-dynamic";

export const MAX_REASON_CHARS = 500;

/**
 * In-process rate limit. Adequate for a low-traffic internal portal and honest
 * about its limitation: it is per-instance, so it throttles rather than
 * guarantees. A shared limiter belongs on the API gateway; noted here rather
 * than pretended away.
 */
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 5;
const recent = new Map<string, number[]>();

function rateLimited(email: string, now = Date.now()): boolean {
  const hits = (recent.get(email) ?? []).filter((t) => now - t < RATE_WINDOW_MS);
  if (hits.length >= RATE_MAX) {
    recent.set(email, hits);
    return true;
  }
  hits.push(now);
  recent.set(email, hits);
  return false;
}

export async function POST(request: NextRequest) {
  const session = await currentSession();
  if (!session) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  const publicBaseUrl = process.env.PUBLIC_BASE_URL ?? "";
  if (publicBaseUrl && !originAcceptable(request.headers.get("origin"), publicBaseUrl)) {
    log.warn("report.origin_rejected", { email: session.email });
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  let itemId = "";
  let reason = "";
  let token: string | null = request.headers.get(CSRF_HEADER);

  const contentType = request.headers.get("content-type") ?? "";
  try {
    if (contentType.includes("application/json")) {
      const body = (await request.json()) as Record<string, unknown>;
      itemId = typeof body["itemId"] === "string" ? body["itemId"] : "";
      reason = typeof body["reason"] === "string" ? body["reason"] : "";
      if (!token && typeof body[CSRF_FIELD] === "string") token = body[CSRF_FIELD] as string;
    } else {
      const form = await request.formData();
      itemId = String(form.get("itemId") ?? "");
      reason = String(form.get("reason") ?? "");
      if (!token) token = String(form.get(CSRF_FIELD) ?? "") || null;
    }
  } catch {
    return NextResponse.json({ error: "bad_request" }, { status: 400 });
  }

  if (!csrfTokenValid(session.sid, token)) {
    log.warn("report.csrf_rejected", { email: session.email });
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  if (rateLimited(session.email)) {
    log.warn("report.rate_limited", { email: session.email });
    return NextResponse.json({ error: "too_many_requests" }, { status: 429 });
  }

  // Semantic validation: the item must actually exist. This also prevents the
  // reports table being used as arbitrary storage keyed on a made-up id.
  const item = itemId ? await getItem(itemId) : undefined;
  if (!item) {
    return NextResponse.json({ error: "unknown_item" }, { status: 404 });
  }

  const trimmed = reason.trim().slice(0, MAX_REASON_CHARS);
  const now = new Date();

  await putReport({
    reportId: crypto.randomUUID(),
    itemId: item.itemId,
    // From the session. Never from the body.
    reportedBy: session.email,
    reason: trimmed,
    createdAt: now.toISOString(),
    resolution: "open",
    expiresAt: retentionExpiry(now),
  });

  // Note what was reported and by whom — never the reason body.
  log.info("report.filed", {
    email: session.email,
    itemId: item.itemId,
    sourceId: item.sourceId,
    reasonLength: trimmed.length,
  });

  return NextResponse.json({ ok: true });
}
