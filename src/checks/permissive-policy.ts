import type { Check, PolicyInfo } from "../types.js";

const API_ROLES = new Set(["anon", "authenticated", "public", "web_anon"]);

/** Was the expression written as a literal `true` (not merely absent)? */
function isExplicitlyTrue(expr: string | null): boolean {
  if (expr === null) return false;
  const e = expr.replace(/\s+/g, "").toLowerCase();
  return e === "true" || e === "(true)";
}

function appliesToApi(p: PolicyInfo): boolean {
  // pg_policies lists roles as {public} when the policy targets PUBLIC
  return p.roles.some((r) => API_ROLES.has(r.toLowerCase()));
}

/**
 * A PERMISSIVE policy that targets anon/authenticated and was written with an
 * explicit `USING (true)` / `WITH CHECK (true)`. The table has RLS on, but this
 * policy hands back (or accepts) every row anyway. INSERT policies with an
 * absent WITH CHECK are the `policy-missing-with-check` check's job, not this one.
 */
export const permissivePolicy: Check = {
  id: "permissive-policy",
  description: "Permissive RLS policy explicitly written as USING (true) for API roles",
  run(ctx) {
    const findings = [];
    for (const t of ctx.tables) {
      for (const p of t.policies) {
        if (!p.permissive || !appliesToApi(p)) continue;
        const readOpen =
          ["SELECT", "UPDATE", "DELETE", "ALL"].includes(p.command) &&
          isExplicitlyTrue(p.using);
        const writeOpen =
          ["UPDATE", "ALL"].includes(p.command) && isExplicitlyTrue(p.withCheck);
        if (!readOpen && !writeOpen) continue;
        findings.push({
          check: this.id,
          severity: writeOpen && readOpen ? ("critical" as const) : ("high" as const),
          object: `${t.schema}.${t.name}`,
          title: `Policy "${p.name}" imposes no restriction`,
          detail: `${p.command} policy for ${p.roles.join("/")}: USING (${p.using ?? "—"})${p.withCheck ? ` WITH CHECK (${p.withCheck})` : ""}. RLS is on but this makes the table effectively open.`,
          remediation: `Scope it to the caller, e.g. USING (auth.uid() = user_id). If the data really is public, keep it but add a test and a comment so the next audit knows it's intentional.`,
        });
      }
    }
    return findings;
  },
};
