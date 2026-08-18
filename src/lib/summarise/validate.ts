/**
 * Output validation — the control that actually enforces CLAUDE.md rules 1 and 4.
 *
 * The prompt asks the model for the right shape; this module refuses anything
 * that isn't. A prompt is a request; validation is a guarantee. Everything here
 * is a pure function, so every rule below is directly testable.
 *
 * A rejected summary is not a failure of the portal — the item still publishes,
 * as headline-and-link only, exactly as it would under the kill switch. Failing
 * closed to "no model text" is always safe; publishing unvalidated model text to
 * staff is not.
 */

import { AWARENESS_PREFIX } from "./prompt";

export type RejectionReason =
  | "empty"
  | "too_long"
  | "contains_markup"
  | "contains_url"
  | "awareness_prefix_missing"
  | "awareness_directive"
  | "awareness_multi_sentence";

export interface ValidationResult {
  readonly ok: boolean;
  readonly reasons: readonly RejectionReason[];
}

export const MAX_SUMMARY_CHARS = 900;
export const MAX_AWARENESS_CHARS = 320;

/**
 * Model output is display text and nothing else. It is never used as a URL, a
 * command, or a fetch target — so a URL appearing in it is not a feature we need
 * and is a signal something has gone wrong (a hallucinated link, or injected
 * content echoed back). Reject rather than strip: a rejected item degrades to
 * headline-and-link, which is a safe state.
 */
const URL_PATTERN = /\b(?:https?:\/\/|www\.|[a-z0-9-]+\.(?:com|net|org|io|gov|edu|co)\b)/i;

const MARKUP_PATTERN = /<[a-z/!?]|&(?:lt|gt|amp|quot|#\d|#x[0-9a-f])/i;

/**
 * Rule 4's real teeth. These are the phrasings that turn an awareness note into
 * an instruction — a directive to change a control, or an assertion about what
 * the bank currently does. Either would make an unreviewed model the author of
 * security guidance inside a regulated bank.
 */
const DIRECTIVE_PATTERNS: readonly RegExp[] = [
  /\bwe (?:must|should|need to|have to|ought to)\b/i,
  /\byou (?:must|should|need to|have to)\b/i,
  /\b(?:asb|the bank|we) (?:lacks?|is missing|does not have|doesn't have|fails? to)\b/i,
  /\b(?:immediately|urgently|as soon as possible)\b/i,
  /\b(?:disable|enable|deploy|patch|revoke|rotate|block|configure|implement|migrate) (?:the|our|all|your)\b/i,
  /\brecommend(?:ed|ation)?\b/i,
  /\bit is (?:critical|essential|imperative|vital)\b/i,
];

function countSentences(text: string): number {
  const matches = text.match(/[.!?](?:\s|$)/g);
  return matches ? matches.length : text.trim() ? 1 : 0;
}

export function validateSummary(summary: string): ValidationResult {
  const reasons: RejectionReason[] = [];
  const text = summary.trim();

  if (!text) reasons.push("empty");
  if (text.length > MAX_SUMMARY_CHARS) reasons.push("too_long");
  if (MARKUP_PATTERN.test(text)) reasons.push("contains_markup");
  if (URL_PATTERN.test(text)) reasons.push("contains_url");

  return { ok: reasons.length === 0, reasons };
}

export function validateAwarenessNote(note: string): ValidationResult {
  const reasons: RejectionReason[] = [];
  const text = note.trim();

  if (!text) {
    reasons.push("empty");
    return { ok: false, reasons };
  }
  if (text.length > MAX_AWARENESS_CHARS) reasons.push("too_long");
  if (MARKUP_PATTERN.test(text)) reasons.push("contains_markup");
  if (URL_PATTERN.test(text)) reasons.push("contains_url");

  // Case-sensitive on the first word, case-insensitive after: the model is told
  // the exact prefix, and a drifting prefix is a signal worth catching.
  if (!text.toLowerCase().startsWith(AWARENESS_PREFIX.toLowerCase())) {
    reasons.push("awareness_prefix_missing");
  }

  if (countSentences(text) > 1) reasons.push("awareness_multi_sentence");

  for (const pattern of DIRECTIVE_PATTERNS) {
    if (pattern.test(text)) {
      reasons.push("awareness_directive");
      break;
    }
  }

  return { ok: reasons.length === 0, reasons };
}

export interface RawModelOutput {
  readonly summary?: unknown;
  readonly awareness_note?: unknown;
  readonly injection_suspected?: unknown;
}

export type ValidatedSummary =
  | {
      readonly status: "ok";
      readonly summary: string;
      readonly awarenessNote: string;
      readonly injectionSuspected: boolean;
    }
  | {
      readonly status: "rejected";
      readonly reasons: readonly RejectionReason[];
      readonly injectionSuspected: boolean;
    };

/**
 * Validate a parsed model response end to end. Returns a discriminated union so
 * a caller cannot accidentally read `summary` off a rejected result.
 */
export function validateModelOutput(raw: RawModelOutput): ValidatedSummary {
  const injectionSuspected = raw.injection_suspected === true;

  const summary = typeof raw.summary === "string" ? raw.summary.trim() : "";
  const note = typeof raw.awareness_note === "string" ? raw.awareness_note.trim() : "";

  const summaryResult = validateSummary(summary);
  const noteResult = validateAwarenessNote(note);

  if (!summaryResult.ok || !noteResult.ok) {
    return {
      status: "rejected",
      reasons: [...new Set([...summaryResult.reasons, ...noteResult.reasons])],
      injectionSuspected,
    };
  }

  return { status: "ok", summary, awarenessNote: note, injectionSuspected };
}
