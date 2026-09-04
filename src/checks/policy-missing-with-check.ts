import type { Check } from "../types.js";

/**
 * Write policies that don't constrain the rows being written.
 *
 * - INSERT policy with no WITH CHECK  → any matching role can insert arbitrary
 *   rows, including a forged user_id / owner column. (Postgres permits this.)
 * - UPDATE / ALL policy with a USING clause but no WITH CHECK → Postgres reuses
 *   USING as the write check. Usually fine for symmetric ownership, but it's
 *   implicit; an asymmetric intent (read own, but don't let them write it into
 *   someone else's) is silently lost.
 */
export const policyMissingWithCheck: Check = {
  id: "policy-missing-with-check",
  description: "Write policy that does not validate the rows being written",
  run(ctx) {
    const findings = [];
    for (const t of ctx.tables) {
      for (const p of t.policies) {
        if (p.withCheck !== null) continue;

        if (p.command === "INSERT") {
          findings.push({
            check: this.id,
            severity: "high" as const,
            object: `${t.schema}.${t.name}`,
            title: `INSERT policy "${p.name}" has no WITH CHECK`,
            detail: `${p.roles.join("/")} can insert rows with any column values — nothing stops a forged user_id, role, or price.`,
            remediation: `Add WITH CHECK mirroring ownership, e.g. WITH CHECK (auth.uid() = user_id).`,
          });
        } else if (
          ["UPDATE", "ALL"].includes(p.command) &&
          p.using !== null &&
          p.using.replace(/\s+/g, "").toLowerCase() !== "true"
        ) {
          findings.push({
            check: this.id,
            severity: "low" as const,
            object: `${t.schema}.${t.name}`,
            title: `${p.command} policy "${p.name}" reuses USING as its write check`,
            detail: `No explicit WITH CHECK, so Postgres applies USING (${p.using}) to writes too. Fine if that's intended; state it explicitly so an asymmetric rule isn't lost later.`,
            remediation: `Add an explicit WITH CHECK (even if identical to USING).`,
          });
        }
      }
    }
    return findings;
  },
};
