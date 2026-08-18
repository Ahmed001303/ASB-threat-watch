/**
 * The summariser — in-account Amazon Bedrock.
 *
 * Bedrock rather than an external API, per the decision recorded in CLAUDE.md:
 * article text and model output never leave ASB's AWS accounts, which keeps this
 * project out of the third-party risk assessment and Data Processing Agreement
 * path in `asb-secure-development` entirely.
 *
 * CLAUDE.md rule 1 — the summariser gets no tools, no network access, and no
 * write access. That is enforced in three places, and it is worth being explicit
 * about which is which:
 *   - here, by sending no `tools` in the request at all;
 *   - in sst.config.ts, by an execution role scoped to `bedrock:InvokeModel` on
 *     one model ARN and nothing else;
 *   - in ingest.ts, where the *caller* performs the database write — the model
 *     returns text and never touches storage.
 *
 * Bedrock model IDs carry an `anthropic.` provider prefix; a first-party
 * `claude-opus-5` would 400 here.
 */

import {
  BedrockRuntimeClient,
  InvokeModelCommand,
} from "@aws-sdk/client-bedrock-runtime";
import { buildUserMessage, OUTPUT_SCHEMA, SYSTEM_PROMPT, type SummariseInput } from "./prompt";
import { validateModelOutput, type ValidatedSummary } from "./validate";
import { log, errorSummary } from "../log";

/**
 * Default model. Bedrock's `anthropic.` prefix is required.
 *
 * NOT YET VERIFIED against `aws bedrock list-foundation-models` — no AWS
 * credentials were available in the session that wrote this, so the exact
 * availability of this id in the target region is unconfirmed. Check before the
 * first deploy; it is an environment variable precisely so that confirming it
 * does not require a code change.
 */
export const DEFAULT_MODEL_ID = "anthropic.claude-opus-5";

export interface SummariserConfig {
  readonly region: string;
  readonly modelId: string;
  readonly maxTokens: number;
  readonly timeoutMs: number;
}

export function summariserConfigFromEnv(): SummariserConfig {
  return {
    region: process.env.BEDROCK_REGION ?? process.env.AWS_REGION ?? "eu-west-1",
    modelId: process.env.BEDROCK_MODEL_ID ?? DEFAULT_MODEL_ID,
    maxTokens: Number(process.env.BEDROCK_MAX_TOKENS ?? 2000),
    timeoutMs: Number(process.env.BEDROCK_TIMEOUT_MS ?? 60_000),
  };
}

let cachedClient: BedrockRuntimeClient | undefined;

function client(region: string): BedrockRuntimeClient {
  if (!cachedClient) cachedClient = new BedrockRuntimeClient({ region });
  return cachedClient;
}

/** Shape of the Bedrock Messages-API response we depend on. */
interface BedrockMessagesResponse {
  readonly content?: ReadonlyArray<{ type?: string; text?: string }>;
  readonly stop_reason?: string;
  readonly usage?: { input_tokens?: number; output_tokens?: number };
}

export interface SummariseResult {
  readonly validated: ValidatedSummary;
  readonly modelId: string;
  readonly stopReason: string | undefined;
}

/**
 * Summarise one item. Never throws for content reasons — a refusal, a truncated
 * response, or output that fails validation all come back as
 * `validated.status === "rejected"` so the caller can publish the item as
 * headline-and-link. Only genuine infrastructure failures throw.
 */
export async function summariseItem(
  input: SummariseInput,
  config: SummariserConfig = summariserConfigFromEnv(),
): Promise<SummariseResult> {
  const body = {
    anthropic_version: "bedrock-2023-05-31",
    max_tokens: config.maxTokens,
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: buildUserMessage(input) }],
    // Structured outputs: the response is constrained to OUTPUT_SCHEMA, so
    // validation can focus on content rules rather than JSON repair.
    output_config: { format: { type: "json_schema", schema: OUTPUT_SCHEMA } },
    // No `tools` key at all — rule 1. The model cannot call anything.
    // No temperature/top_p/top_k: those are rejected on current models.
  };

  const command = new InvokeModelCommand({
    modelId: config.modelId,
    contentType: "application/json",
    accept: "application/json",
    body: JSON.stringify(body),
  });

  const response = await client(config.region).send(command, {
    abortSignal: AbortSignal.timeout(config.timeoutMs),
  });

  const decoded = new TextDecoder().decode(response.body);
  let parsed: BedrockMessagesResponse;
  try {
    parsed = JSON.parse(decoded) as BedrockMessagesResponse;
  } catch (err) {
    log.error("summarise.unparseable_response", { error: errorSummary(err) });
    return {
      validated: { status: "rejected", reasons: ["empty"], injectionSuspected: false },
      modelId: config.modelId,
      stopReason: undefined,
    };
  }

  // A safety refusal is a normal outcome, not an error. Handle it before
  // reading content — on a refusal there may be no content block at all.
  if (parsed.stop_reason === "refusal") {
    log.warn("summarise.refused", { modelId: config.modelId });
    return {
      validated: { status: "rejected", reasons: ["empty"], injectionSuspected: false },
      modelId: config.modelId,
      stopReason: parsed.stop_reason,
    };
  }

  const text = (parsed.content ?? [])
    .filter((b) => b.type === "text" && typeof b.text === "string")
    .map((b) => b.text as string)
    .join("");

  if (!text.trim()) {
    return {
      validated: { status: "rejected", reasons: ["empty"], injectionSuspected: false },
      modelId: config.modelId,
      stopReason: parsed.stop_reason,
    };
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    // Structured outputs should make this unreachable; treat it as a rejection
    // rather than attempting to salvage text of unknown shape.
    log.warn("summarise.non_json_output", { modelId: config.modelId });
    return {
      validated: { status: "rejected", reasons: ["empty"], injectionSuspected: false },
      modelId: config.modelId,
      stopReason: parsed.stop_reason,
    };
  }

  const validated = validateModelOutput(
    (raw ?? {}) as Parameters<typeof validateModelOutput>[0],
  );

  if (validated.status === "rejected") {
    // Log the reasons but never the rejected text: it is model output derived
    // from untrusted content, and a log body is not the place for it.
    log.warn("summarise.output_rejected", {
      modelId: config.modelId,
      reasons: validated.reasons.join(","),
      injectionSuspected: validated.injectionSuspected,
    });
  } else if (validated.injectionSuspected) {
    log.warn("summarise.injection_suspected", { modelId: config.modelId });
  }

  return { validated, modelId: config.modelId, stopReason: parsed.stop_reason };
}
