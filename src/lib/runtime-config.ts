/**
 * Runtime configuration — CLAUDE.md rule 6 (the kill switch).
 *
 * The rule says the kill switch must be deployable "without a code change".
 * That single requirement decides where this lives: SSM Parameter Store, read at
 * the start of every ingest cycle and on page render, never bundled. A flag
 * compiled into the bundle would need a redeploy to flip, which is exactly the
 * situation the rule exists to prevent — an operator needing to disable
 * model-generated text at speed cannot be waiting on a pipeline.
 *
 * Fail-safe direction matters and is deliberate: if SSM is unreachable, we
 * behave as if the kill switch is ON (headline-and-link only). An outage in the
 * config store must not be the reason unreviewed model text keeps publishing.
 */

import { GetParametersByPathCommand, SSMClient } from "@aws-sdk/client-ssm";
import { log, errorSummary } from "./log";

export interface RuntimeConfig {
  /** true => portal shows headline + source link only, no model-generated text. */
  readonly killSwitch: boolean;
  /** sourceId -> enabled. A source absent from the map defaults to enabled. */
  readonly feedEnabled: Readonly<Record<string, boolean>>;
  /** false => SSO is bypassed/disabled (env kill-switch per asb-entra-sso). */
  readonly ssoEnabled: boolean;
  /** true when these values are defaults because SSM could not be read. */
  readonly degraded: boolean;
}

/** Used when SSM cannot be read. Note killSwitch: true — fail safe. */
export const FAIL_SAFE_CONFIG: RuntimeConfig = {
  killSwitch: true,
  feedEnabled: {},
  ssoEnabled: true,
  degraded: true,
};

export function parameterPrefix(stage: string): string {
  return `/asb-threat-watch/${stage}`;
}

let cachedClient: SSMClient | undefined;
function client(region: string): SSMClient {
  if (!cachedClient) cachedClient = new SSMClient({ region });
  return cachedClient;
}

function parseBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const v = value.trim().toLowerCase();
  if (["true", "on", "1", "yes"].includes(v)) return true;
  if (["false", "off", "0", "no"].includes(v)) return false;
  return fallback;
}

/**
 * Turn a flat list of SSM parameters into a RuntimeConfig. Exported separately
 * from the fetch so the mapping is unit-testable without touching AWS.
 */
export function mapParameters(
  params: ReadonlyArray<{ Name?: string; Value?: string }>,
  prefix: string,
): RuntimeConfig {
  let killSwitch = false; // default OFF once we have actually read config
  let ssoEnabled = true;
  const feedEnabled: Record<string, boolean> = {};

  for (const p of params) {
    if (!p.Name) continue;
    const key = p.Name.startsWith(prefix) ? p.Name.slice(prefix.length) : p.Name;

    if (key === "/kill-switch") {
      killSwitch = parseBool(p.Value, false);
      continue;
    }
    if (key === "/sso/enabled") {
      ssoEnabled = parseBool(p.Value, true);
      continue;
    }
    const feedMatch = key.match(/^\/feeds\/([a-z0-9-]+)\/enabled$/);
    if (feedMatch?.[1]) {
      feedEnabled[feedMatch[1]] = parseBool(p.Value, true);
    }
  }

  return { killSwitch, feedEnabled, ssoEnabled, degraded: false };
}

/**
 * Read runtime config from SSM. Deliberately un-cached across invocations: a
 * kill switch that takes effect on the next cycle is the requirement, and a
 * warm-Lambda cache would silently defer it.
 */
export async function loadRuntimeConfig(
  opts: { stage?: string; region?: string } = {},
): Promise<RuntimeConfig> {
  const stage = opts.stage ?? process.env.STAGE ?? "dev";
  const region = opts.region ?? process.env.AWS_REGION ?? "eu-west-1";
  const prefix = parameterPrefix(stage);

  try {
    const collected: Array<{ Name?: string; Value?: string }> = [];
    let nextToken: string | undefined;

    do {
      const out = await client(region).send(
        new GetParametersByPathCommand({
          Path: prefix,
          Recursive: true,
          WithDecryption: false, // nothing under this prefix is a secret
          NextToken: nextToken,
        }),
      );
      collected.push(...(out.Parameters ?? []));
      nextToken = out.NextToken;
    } while (nextToken);

    return mapParameters(collected, prefix);
  } catch (err) {
    // Fail safe, and say so loudly — a degraded config is an operational event.
    log.error("runtime_config.unreadable_failing_safe", {
      stage,
      error: errorSummary(err),
    });
    return FAIL_SAFE_CONFIG;
  }
}

export function isFeedEnabled(config: RuntimeConfig, sourceId: string): boolean {
  return config.feedEnabled[sourceId] ?? true;
}
