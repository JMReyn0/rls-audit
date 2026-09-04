import type { Check } from "../types.js";

/**
 * A table that PostgREST/Supabase will serve (it lives in an exposed schema and
 * `anon`/`authenticated` hold privileges on it) but has RLS switched off. Every
 * row is readable/writable by anyone with the anon key.
 */
export const rlsDisabled: Check = {
  id: "rls-disabled",
  description: "API-reachable table with Row-Level Security disabled",
  run(ctx) {
    return ctx.tables
      .filter((t) => !t.rlsEnabled && t.apiGrants.length > 0)
      .map((t) => {
        const privs = [...new Set(t.apiGrants.map((g) => g.privilege))]
          .sort()
          .join(", ");
        const grantees = [...new Set(t.apiGrants.map((g) => g.grantee))].join(
          ", ",
        );
        const write = t.apiGrants.some((g) =>
          ["INSERT", "UPDATE", "DELETE"].includes(g.privilege),
        );
        return {
          check: this.id,
          severity: write ? "critical" : "high",
          object: `${t.schema}.${t.name}`,
          title: "RLS disabled on an API-reachable table",
          detail: `${grantees} can ${privs} every row — RLS is off, so no policy limits access.`,
          remediation: `ALTER TABLE ${t.schema}.${t.name} ENABLE ROW LEVEL SECURITY; then add policies scoping rows to the caller (e.g. USING (auth.uid() = user_id)).`,
          reference: "https://supabase.com/docs/guides/database/postgres/row-level-security",
        };
      });
  },
};
