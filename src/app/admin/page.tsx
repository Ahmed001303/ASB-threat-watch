/**
 * Owner-only operations screen (S5 in docs/design/screens.md).
 *
 * Scope is deliberately narrow: exactly the things an operator must be able to
 * do without a deploy (rule 6), plus the two reports `asb-secure-development`
 * requires InfoSec be able to pull — users with their roles, and the privileges
 * each role carries.
 *
 * The toggles are read-only in this build. Writing to SSM from a web request is
 * a privileged, un-gated mutation and belongs behind the pre-implementation
 * InfoSec review, not ahead of it — so this screen shows current state and the
 * exact CLI command, which is auditable and needs no new IAM grant on the portal.
 */

import { FEED_SOURCES } from "../../../config/feeds";
import { requireOwner } from "../../lib/auth/guard";
import { isFeedEnabled, loadRuntimeConfig, parameterPrefix } from "../../lib/runtime-config";
import { JIT_PROVISIONING_ENABLED } from "../../lib/auth/users";
import { log } from "../../lib/log";

export const dynamic = "force-dynamic";

const ROLE_PRIVILEGES: ReadonlyArray<{ role: string; privileges: string }> = [
  { role: "reader", privileges: "Read the feed and item detail. File a report. Nothing else." },
  {
    role: "owner",
    privileges:
      "Everything a reader can do, plus: view this screen, view reported items, " +
      "hide an item, and provision or disable staff users.",
  },
];

export default async function AdminPage() {
  const session = await requireOwner();
  const config = await loadRuntimeConfig();
  const stage = process.env.STAGE ?? "dev";
  const prefix = parameterPrefix(stage);

  // Viewing the admin surface is itself a privileged action — logged as one.
  log.info("privileged.admin_viewed", { email: session.email, stage });

  return (
    <>
      <header className="site">
        <h1>
          <a href="/feed" style={{ textDecoration: "none", color: "inherit" }}>
            ← Threat Watch
          </a>{" "}
          · Admin
        </h1>
        <span className="who">{session.email}</span>
      </header>

      {config.degraded ? (
        <div className="banner">
          Runtime configuration is unreadable, so the values below are the fail-safe
          defaults, not live state. Fix SSM access before trusting this screen.
        </div>
      ) : null}

      <article className="card">
        <h2>Kill switch (rule 6)</h2>
        <p className="excerpt">
          Currently <strong>{config.killSwitch ? "ON" : "OFF"}</strong>.{" "}
          {config.killSwitch
            ? "The portal is showing headline and link only — no model-generated text."
            : "AI summaries are publishing normally."}
        </p>
        <p className="excerpt">
          Takes effect on the next ingest cycle and the next page render. No deploy
          required — that is the requirement this parameter exists to satisfy.
        </p>
        <pre style={{ fontSize: "0.78rem", overflowX: "auto", background: "var(--bg)", padding: "0.6rem", borderRadius: "8px" }}>
          {`aws ssm put-parameter --overwrite \\\n  --name ${prefix}/kill-switch \\\n  --type String --value ${config.killSwitch ? "off" : "on"}`}
        </pre>
      </article>

      <article className="card">
        <h2>Sources</h2>
        <p className="excerpt">
          Disable a source when it is compromised or noisy. Adding or changing a source
          is a reviewed PR against <code>config/feeds.ts</code> — never a runtime action.
        </p>
        <table className="admin">
          <thead>
            <tr>
              <th>Source</th>
              <th>Category</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {FEED_SOURCES.map((s) => (
              <tr key={s.sourceId}>
                <td>{s.displayName}</td>
                <td>{s.category}</td>
                <td>{isFeedEnabled(config, s.sourceId) ? "enabled" : "disabled"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </article>

      <article className="card">
        <h2>Roles and privileges</h2>
        <p className="excerpt">
          One of the reports InfoSec must be able to pull. Roles are owned by this
          application — the SAML assertion authenticates identity only and grants
          nothing.
        </p>
        <table className="admin">
          <thead>
            <tr>
              <th>Role</th>
              <th>Privileges</th>
            </tr>
          </thead>
          <tbody>
            {ROLE_PRIVILEGES.map((r) => (
              <tr key={r.role}>
                <td>
                  <code>{r.role}</code>
                </td>
                <td>{r.privileges}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="excerpt" style={{ marginTop: "0.75rem" }}>
          Provisioning model:{" "}
          <strong>{JIT_PROVISIONING_ENABLED ? "just-in-time" : "pre-provision only"}</strong>.
          A staff member must have a local record before their first SAML login. This is
          the InfoSec open item in CLAUDE.md — the friction is known and deliberate
          until that ruling lands.
        </p>
      </article>
    </>
  );
}
