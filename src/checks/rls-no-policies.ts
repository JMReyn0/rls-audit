import type { Check } from "../types.js";

/**
 * RLS is enabled but the table has no policies. Postgres then denies all access
 * to non-owner roles. Usually a half-finished migration: someone enabled RLS and
 * forgot the policies, so the feature silently 404s / returns empty for the API.
 */
export const rlsNoPolicies: Check = {
  id: "rls-no-policies",
  description: "RLS enabled but no policies defined (deny-all)",
  run(ctx) {
    return ctx.tables
      .filter((t) => t.rlsEnabled && t.policies.length === 0)
      .map((t) => ({
        check: this.id,
        severity: t.apiGrants.length ? "medium" : "low",
        object: `${t.schema}.${t.name}`,
        title: "RLS enabled with zero policies",
        detail:
          "No policy exists, so every non-owner request returns no rows. Safe, but almost always an unfinished migration rather than an intentional lockdown.",
        remediation: `Add the intended policies, or if the table should be private drop the anon/authenticated grants and document it.`,
      }));
  },
};
