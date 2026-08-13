/**
 * Local staff user records.
 *
 * Per `asb-entra-sso`: roles and permissions are owned by THIS app, not by the
 * SAML assertion. SAML answers "who is this?"; this table answers "what may they
 * see?". Matching is on the email claim.
 *
 * Provisioning model: **pre-provision only, no JIT** — the skill's mandated
 * default. An assertion for an email with no local row is denied at login.
 *
 * This is the open item flagged in CLAUDE.md and docs/design/process-flow.md: on
 * a portal meant for casual department-wide reading, pre-provisioning every
 * colleague is adoption friction, and the alternative (Entra group membership as
 * the gate, local row created on first successful assertion) needs an InfoSec
 * ruling. The compliant behaviour is implemented here; the deviation is NOT,
 * deliberately — see `JIT_PROVISIONING_ENABLED` below.
 */

import { GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import { docClient } from "../store";
import type { Role } from "./session";
import { log } from "../log";

export interface StaffUser {
  readonly email: string;
  readonly displayName: string;
  readonly role: Role;
  readonly status: "active" | "disabled";
  readonly lastLoginAt?: string;
}

/**
 * Hard-coded false, and intentionally not an environment variable.
 *
 * Making this runtime-configurable would let the pre-provisioning requirement be
 * switched off without the InfoSec decision the skill requires — which is the
 * exact "deviate unilaterally" failure CLAUDE.md warns against. If InfoSec
 * approves the Entra-group model, this becomes a real implementation in a PR
 * that cites the approval.
 */
export const JIT_PROVISIONING_ENABLED = false;

export function usersTable(): string {
  const stage = process.env.STAGE ?? "dev";
  return process.env.USERS_TABLE ?? `asb-threat-watch-${stage}-users`;
}

export async function lookupStaffUser(email: string): Promise<StaffUser | undefined> {
  const key = email.trim().toLowerCase();
  if (!key) return undefined;

  const out = await docClient().send(
    new GetCommand({ TableName: usersTable(), Key: { email: key } }),
  );
  return out.Item as StaffUser | undefined;
}

/**
 * Admin-side provisioning. This is a privileged action, so it is logged as one
 * — `asb-secure-development` requires InfoSec be able to pull a report of
 * privileged activities and of users and their roles.
 */
export async function provisionStaffUser(
  user: Pick<StaffUser, "email" | "displayName" | "role">,
  actorEmail: string,
): Promise<void> {
  const record: StaffUser = {
    email: user.email.trim().toLowerCase(),
    displayName: user.displayName,
    role: user.role,
    status: "active",
  };

  await docClient().send(new PutCommand({ TableName: usersTable(), Item: record }));

  log.info("privileged.user_provisioned", {
    actor: actorEmail,
    subject: record.email,
    role: record.role,
  });
}
