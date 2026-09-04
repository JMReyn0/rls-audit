import type { Check } from "../types.js";
import { rlsDisabled } from "./rls-disabled.js";
import { rlsNoPolicies } from "./rls-no-policies.js";
import { rlsNotForced } from "./rls-not-forced.js";
import { permissivePolicy } from "./permissive-policy.js";
import { policyMissingWithCheck } from "./policy-missing-with-check.js";
import { anonWriteGrant } from "./anon-write-grant.js";
import { sensitiveColumnExposed } from "./sensitive-column-exposed.js";
import { securityDefinerBypass } from "./security-definer-bypass.js";

export const CHECKS: Check[] = [
  rlsDisabled,
  rlsNoPolicies,
  rlsNotForced,
  permissivePolicy,
  policyMissingWithCheck,
  anonWriteGrant,
  sensitiveColumnExposed,
  securityDefinerBypass,
];

export function selectChecks(only?: string[], skip?: string[]): Check[] {
  let list = CHECKS;
  if (only?.length) list = list.filter((c) => only.includes(c.id));
  if (skip?.length) list = list.filter((c) => !skip.includes(c.id));
  return list;
}
