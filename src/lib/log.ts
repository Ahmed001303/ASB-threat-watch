/**
 * PII-safe structured logging.
 *
 * `asb-secure-development` requires that activity affecting confidentiality,
 * integrity and availability is logged, and that logs are scrubbed of personal
 * and sensitive data. Those two pull against each other, so the rule this module
 * enforces is: log the *shape* and *outcome* of an event, never its body.
 *
 * Never passed to this module: session tokens, SAML assertion XML, report
 * reason text, or full article text. Staff email is permitted only as the
 * audit subject of an auth or privileged event — that is the minimum needed for
 * the "privileged activities" report InfoSec must be able to pull.
 */

type Level = "info" | "warn" | "error";

/** Values safe to serialise into a log line. No free-form objects. */
type Scalar = string | number | boolean | null | undefined;

export interface LogFields {
  readonly [key: string]: Scalar;
}

/**
 * Strip CR/LF and control characters so a value taken from feed content cannot
 * forge a second log line (OWASP Logging Cheat Sheet — log injection).
 */
export function sanitiseLogValue(value: Scalar): Scalar {
  if (typeof value !== "string") return value;
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 512);
}

function emit(level: Level, event: string, fields: LogFields): void {
  const safe: Record<string, Scalar> = {};
  for (const [k, v] of Object.entries(fields)) {
    safe[k] = sanitiseLogValue(v);
  }
  const line = JSON.stringify({ level, event, ...safe });
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

export const log = {
  info: (event: string, fields: LogFields = {}) => emit("info", event, fields),
  warn: (event: string, fields: LogFields = {}) => emit("warn", event, fields),
  error: (event: string, fields: LogFields = {}) => emit("error", event, fields),
};

/**
 * Reduce an unknown thrown value to a loggable summary. Deliberately drops the
 * stack and any nested cause: an error raised while parsing feed content can
 * carry attacker-influenced text, and a stack trace in a log body is exactly
 * the sort of detail the OWASP error-handling guidance says to keep out.
 */
export function errorSummary(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message.slice(0, 200)}`;
  return String(err).slice(0, 200);
}
