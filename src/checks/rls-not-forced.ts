import type { Check } from "../types.js";

/**
 * RLS is enabled but not FORCED. The table owner (and any BYPASSRLS role) skips
 * policies entirely. This is fine only if you are certain PostgREST / your
 * server code never connects as the owner. Forcing it removes the footgun.
 */
export const rlsNotForced: Check = {
  id: "rls-not-forced",
  description: "RLS enabled but not FORCED (table owner bypasses policies)",
  run(ctx) {
    return ctx.tables
      .filter((t) => t.rlsEnabled && !t.rlsForced && t.policies.length > 0)
      .map((t) => ({
        check: this.id,
        severity: "low",
        object: `${t.schema}.${t.name}`,
        title: "RLS not forced",
        detail: `Policies exist but are skipped for the table owner (${t.owner}) and any BYPASSRLS role. A connection pool or job that authenticates as the owner would see everything.`,
        remediation: `ALTER TABLE ${t.schema}.${t.name} FORCE ROW LEVEL SECURITY; (only if no trusted process legitimately needs the bypass).`,
      }));
  },
};
