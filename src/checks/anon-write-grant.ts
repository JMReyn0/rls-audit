import type { Check } from "../types.js";

const WRITE = ["INSERT", "UPDATE", "DELETE"];

/**
 * `anon` holds a write privilege on a table. Even with a correct RLS policy this
 * is rarely intended — anonymous visitors writing to your database is a spam /
 * abuse vector. `authenticated` write grants are normal; `anon` ones deserve a
 * second look.
 */
export const anonWriteGrant: Check = {
  id: "anon-write-grant",
  description: "anon role has INSERT/UPDATE/DELETE on a table",
  run(ctx) {
    const findings = [];
    for (const t of ctx.tables) {
      const anonWrites = t.apiGrants.filter(
        (g) => g.grantee.toLowerCase() === "anon" && WRITE.includes(g.privilege),
      );
      if (!anonWrites.length) continue;
      const privs = anonWrites.map((g) => g.privilege).join(", ");
      const guarded =
        t.rlsEnabled &&
        t.policies.some((p) =>
          ["INSERT", "UPDATE", "DELETE", "ALL"].includes(p.command),
        );
      findings.push({
        check: this.id,
        severity: guarded ? ("medium" as const) : ("critical" as const),
        object: `${t.schema}.${t.name}`,
        title: `anon can ${privs}`,
        detail: guarded
          ? "A write policy exists, but anonymous writes are still an abuse surface (spam rows, resource exhaustion)."
          : "No RLS write policy — any anon-key holder can write arbitrary rows.",
        remediation: `REVOKE ${privs} ON ${t.schema}.${t.name} FROM anon; move the operation behind an Edge Function or RPC with SECURITY DEFINER + explicit checks, or a rate-limited endpoint.`,
      });
    }
    return findings;
  },
};
