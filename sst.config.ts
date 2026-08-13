/// <reference path="./.sst/platform/config.d.ts" />

/**
 * Infrastructure for asb-threat-watch.
 *
 * ============================ NOT YET APPLIED ============================
 * Written but never run. The session that authored this had no `aws` CLI and no
 * AWS credentials, so `aws sts get-caller-identity` (step 1 of the ASB deploy
 * standard) could not confirm the target account, and `sst diff` could not
 * validate a single line below. Treat this as a reviewed proposal, not as
 * verified infrastructure.
 *
 * Before applying: run `aws sts get-caller-identity`, confirm the account,
 * then `sst diff --stage <stage>` and READ THE PLAN.
 *
 * Also unresolved and blocking, per CLAUDE.md:
 *   - Both InfoSec review gates (pre-design, pre-implementation).
 *   - AWS account id for this project — deliberately NOT copied from the
 *     sibling project. Guessing an account id is how infrastructure lands in
 *     the wrong one.
 *   - The Bedrock model id below is unverified against
 *     `aws bedrock list-foundation-models` in this region.
 *   - SST major version: package.json pins v4, while CLAUDE.md and asb-deploy
 *     both say Ion/v3. v4 was taken because the v3 dependency chain carried
 *     seven high-severity advisories. That is a deviation and needs sign-off.
 * =========================================================================
 */

const PROJECT = "threat-watch";
const OWNER = "Innovation-Department";

/** Matches the department's existing footprint. Confirm per-project. */
const REGION = "eu-west-1";

/**
 * Bedrock, not an external API — the decision recorded in CLAUDE.md. Keeping
 * inference in-account is what avoids the third-party risk assessment and Data
 * Processing Agreement path entirely.
 *
 * Bedrock model ids carry an `anthropic.` provider prefix; a first-party
 * `claude-opus-5` would 400 here.
 */
const MODEL_ID = "anthropic.claude-opus-5";

/**
 * Read from the environment and throw at synth rather than defaulting. A budget
 * alarm with no subscriber deploys perfectly happily and then tells nobody
 * anything — which is worse than no alarm, because it looks like coverage.
 */
function budgetAlertEmail(): string {
  const email = process.env.ASB_BUDGET_ALERT_EMAIL;
  if (!email) {
    throw new Error(
      "ASB_BUDGET_ALERT_EMAIL is not set. Set it to the address that should receive " +
        "the cost alert before deploying, e.g.\n" +
        "  ASB_BUDGET_ALERT_EMAIL=you@alsalambank.com npx sst diff --stage dev",
    );
  }
  return email;
}

export default $config({
  app(input) {
    return {
      name: `asb-${PROJECT}`,
      // prod retains its resources on `sst remove`; dev/staging are disposable.
      removal: input?.stage === "prod" ? "retain" : "remove",
      protect: input?.stage === "prod",
      home: "aws",
      providers: {
        aws: {
          region: REGION,
          defaultTags: {
            tags: {
              // The five mandatory tags from asb-deploy §4.
              org: "asb",
              project: PROJECT,
              stage: input?.stage ?? "unknown",
              "managed-by": "sst",
              owner: OWNER,
              // This project ingests nothing but published news. No customer,
              // account, transaction or T24 data of any kind.
              DataClassification: "Public",
            },
          },
        },
      },
    };
  },

  async run() {
    const stage = $app.stage;
    const name = (resource: string) => `asb-${PROJECT}-${stage}-${resource}`;

    // ---------------------------------------------------------------- storage

    /**
     * PAY_PER_REQUEST per asb-deploy §6 (the default there), PITR on prod.
     * The `byCategory` GSI exists so the feed page is always an index-backed
     * Query — §6 says never rely on scans, and an unbounded feed makes a scan
     * progressively worse rather than merely slow.
     */
    const items = new sst.aws.Dynamo(`${PROJECT}-items`, {
      fields: { itemId: "string", category: "string", sortAt: "string" },
      primaryIndex: { hashKey: "itemId" },
      globalIndexes: { byCategory: { hashKey: "category", rangeKey: "sortAt" } },
      ttl: "expiresAt",
      transform: {
        table: (args) => {
          args.name = name("items");
          args.pointInTimeRecovery = { enabled: stage === "prod" };
        },
      },
    });

    const summaries = new sst.aws.Dynamo(`${PROJECT}-summaries`, {
      fields: { itemId: "string" },
      primaryIndex: { hashKey: "itemId" },
      ttl: "expiresAt",
      transform: {
        table: (args) => {
          args.name = name("summaries");
          args.pointInTimeRecovery = { enabled: stage === "prod" };
        },
      },
    });

    const reports = new sst.aws.Dynamo(`${PROJECT}-reports`, {
      fields: { reportId: "string", itemId: "string" },
      primaryIndex: { hashKey: "reportId" },
      globalIndexes: { byItem: { hashKey: "itemId" } },
      ttl: "expiresAt",
      transform: {
        table: (args) => {
          args.name = name("reports");
          args.pointInTimeRecovery = { enabled: stage === "prod" };
        },
      },
    });

    /** Staff users: email -> role. Roles are owned by this app, not by SAML. */
    const users = new sst.aws.Dynamo(`${PROJECT}-users`, {
      fields: { email: "string" },
      primaryIndex: { hashKey: "email" },
      transform: {
        table: (args) => {
          args.name = name("users");
          // No TTL: an access-control record must not silently expire.
          args.pointInTimeRecovery = { enabled: true };
        },
      },
    });

    // ---------------------------------------------------------------- secrets

    /**
     * SSM SecureString / Secrets Manager only, per asb-deploy §5 — never in code
     * or config. These are referenced, never echoed.
     */
    const sessionSecret = new sst.Secret("SessionSecret");
    const samlIdpCert = new sst.Secret("SamlIdpCert");
    const samlIdpEntryPoint = new sst.Secret("SamlIdpEntryPoint");
    const samlIdpIssuer = new sst.Secret("SamlIdpIssuer");

    // ------------------------------------------------------------- ingest fn

    /**
     * The summariser's execution role. Scoped to `bedrock:InvokeModel` on ONE
     * model ARN — not `bedrock:*`, not a wildcard resource. This is the third of
     * the three places rule 1's "no tools, no network, no writes" is enforced:
     * if this function is ever abused, the blast radius is "invoke one model".
     *
     * One execution role for this one function, never shared (asb-deploy §5).
     */
    const ingest = new sst.aws.Function(`${PROJECT}-ingest`, {
      name: name("ingest"),
      handler: "functions/ingest.handler",
      runtime: "nodejs22.x",
      timeout: "5 minutes",
      memory: "1024 MB",
      link: [items, summaries, sessionSecret],
      environment: {
        STAGE: stage,
        BEDROCK_REGION: REGION,
        BEDROCK_MODEL_ID: MODEL_ID,
        ITEMS_TABLE: items.name,
        SUMMARIES_TABLE: summaries.name,
      },
      permissions: [
        {
          actions: ["bedrock:InvokeModel"],
          resources: [
            $interpolate`arn:aws:bedrock:${REGION}::foundation-model/${MODEL_ID}`,
            $interpolate`arn:aws:bedrock:${REGION}:${aws.getCallerIdentityOutput({}).accountId}:inference-profile/${MODEL_ID}`,
          ],
        },
        {
          // Read-only on this project's own parameter prefix, nothing wider.
          actions: ["ssm:GetParametersByPath", "ssm:GetParameter"],
          resources: [
            $interpolate`arn:aws:ssm:${REGION}:${aws.getCallerIdentityOutput({}).accountId}:parameter/asb-threat-watch/${stage}/*`,
          ],
        },
      ],
      // Article text is untrusted third-party content. The handler never logs
      // article bodies (see src/lib/log.ts); a bounded retention keeps the log
      // group from becoming an open-ended store regardless.
      logging: { retention: stage === "prod" ? "3 months" : "1 month" },
    });

    /**
     * Hourly. Deliberately not more frequent: this is an awareness feed, not a
     * monitoring system, and every cycle is metered model spend.
     */
    new sst.aws.Cron(`${PROJECT}-ingest-schedule`, {
      schedule: "rate(1 hour)",
      function: ingest.arn,
    });

    // ----------------------------------------------------------------- portal

    /**
     * The staff portal. Behind Entra SSO — there is no unauthenticated route
     * except the login page and the SAML ACS callback.
     */
    const portal = new sst.aws.Nextjs(`${PROJECT}-portal`, {
      link: [items, summaries, reports, users, sessionSecret, samlIdpCert],
      environment: {
        STAGE: stage,
        ITEMS_TABLE: items.name,
        SUMMARIES_TABLE: summaries.name,
        REPORTS_TABLE: reports.name,
        USERS_TABLE: users.name,
        SAML_IDP_ENTRY_POINT: samlIdpEntryPoint.value,
        SAML_IDP_ISSUER: samlIdpIssuer.value,
        SAML_IDP_CERT: samlIdpCert.value,
        SESSION_SECRET: sessionSecret.value,
        // Must be the public URL, not the request URL — behind the proxy the
        // request URL is localhost and every redirect would land there.
        PUBLIC_BASE_URL: process.env.PUBLIC_BASE_URL ?? "",
        SAML_SP_ENTITY_ID: `${process.env.PUBLIC_BASE_URL ?? ""}/saml/metadata`,
        SAML_ACS_URL: `${process.env.PUBLIC_BASE_URL ?? ""}/api/auth/saml/callback`,
      },
      permissions: [
        {
          actions: ["ssm:GetParametersByPath", "ssm:GetParameter"],
          resources: [
            $interpolate`arn:aws:ssm:${REGION}:${aws.getCallerIdentityOutput({}).accountId}:parameter/asb-threat-watch/${stage}/*`,
          ],
        },
      ],
    });

    // ---------------------------------------------------------- runtime config

    /**
     * Rule 6: the kill switch must be flippable WITHOUT a redeploy, which is why
     * it is an SSM parameter read at runtime rather than a bundled constant.
     *
     * `ignoreChanges` on the value is the load-bearing part: SST creates the
     * parameter with a default, and thereafter an operator's manual change is
     * NOT reverted by the next deploy. Without this, a deploy would silently
     * re-enable summaries an operator had just disabled.
     */
    new aws.ssm.Parameter(`${PROJECT}-kill-switch`, {
      name: `/asb-threat-watch/${stage}/kill-switch`,
      type: "String",
      value: "off",
      description: "on => portal shows headline+link only, no model-generated text",
    }, { ignoreChanges: ["value"] });

    new aws.ssm.Parameter(`${PROJECT}-sso-enabled`, {
      name: `/asb-threat-watch/${stage}/sso/enabled`,
      type: "String",
      value: "true",
      description: "false => SSO disabled; break-glass local admin only",
    }, { ignoreChanges: ["value"] });

    // ------------------------------------------------------ detective controls

    /**
     * Notifies; it cannot stop spend. The real preventive limits are the hourly
     * schedule and the per-source item cap in the ingest code — this alarm is
     * here to catch the case where those assumptions turn out to be wrong.
     */
    new aws.budgets.Budget(`${PROJECT}-budget`, {
      name: name("monthly"),
      budgetType: "COST",
      limitAmount: "75",
      limitUnit: "USD",
      timeUnit: "MONTHLY",
      costFilters: [{ name: "TagKeyValue", values: [`user:project$${PROJECT}`] }],
      notifications: [
        {
          comparisonOperator: "GREATER_THAN",
          threshold: 80,
          thresholdType: "PERCENTAGE",
          notificationType: "FORECASTED",
          subscriberEmailAddresses: [budgetAlertEmail()],
        },
      ],
    });

    return {
      portalUrl: portal.url,
      ingestFunction: ingest.name,
      killSwitchParameter: `/asb-threat-watch/${stage}/kill-switch`,
      itemsTable: items.name,
    };
  },
});
