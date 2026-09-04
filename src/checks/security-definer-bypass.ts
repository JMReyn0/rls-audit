import type { Check } from "../types.js";

/**
 * A SECURITY DEFINER function in an API-exposed schema, owned by a role that
 * bypasses RLS. Callable as `anon`/`authenticated` via PostgREST RPC, it runs
 * with the owner's rights and RLS does not apply to queries inside it. That's a
 * valid pattern for controlled writes — but each one is a hole that needs its
 * own authorization checks, so the audit lists them for review.
 */
export const securityDefinerBypass: Check = {
  id: "security-definer-bypass",
  description: "SECURITY DEFINER function in an exposed schema (RLS does not apply inside)",
  run(ctx) {
    return ctx.functions
      .filter((f) => f.securityDefiner && f.ownerBypassesRls)
      .map((f) => ({
        check: this.id,
        severity: "medium" as const,
        object: `${f.schema}.${f.name}(${f.args})`,
        title: "SECURITY DEFINER function callable from the API",
        detail: `Owned by ${f.owner} (bypasses RLS). If it's granted to anon/authenticated it runs privileged for any caller; RLS won't protect the tables it touches.`,
        remediation:
          "Confirm the function does its own authorization (auth.uid() checks, input validation), SET search_path is pinned, and EXECUTE is granted only to the roles that need it. Add a test.",
        reference: "https://www.postgresql.org/docs/current/sql-createfunction.html",
      }));
  },
};
