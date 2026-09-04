import type { Check, TableInfo } from "../types.js";

/** Column-name patterns that usually mean "do not serve this to the public". */
const SENSITIVE = [
  /pass(word|wd)?$/i,
  /secret/i,
  /(^|_)token(_|$)/i,
  /api[_-]?key/i,
  /private[_-]?key/i,
  /ssn|social_security/i,
  /(date_of_birth|dob)$/i,
  /(^|_)dob$/i,
  /credit_card|card_number|cvv/i,
  /bank_account|routing_number|iban/i,
  /(^|_)email(_|$)/i,
  /phone(_number)?$/i,
  /address$/i,
  /stripe_(customer|account)_id/i,
  /refresh_token|access_token/i,
];

/** Is this table reachable, unfiltered, by an anon-key holder? */
function anonCanRead(t: TableInfo): boolean {
  const anonSelect = t.apiGrants.some(
    (g) => g.grantee.toLowerCase() === "anon" && ["SELECT"].includes(g.privilege),
  );
  const publicSelect = t.apiGrants.some(
    (g) => g.grantee.toLowerCase() === "public" && g.privilege === "SELECT",
  );
  if (!anonSelect && !publicSelect) return false;
  if (!t.rlsEnabled) return true; // no RLS → full read
  // RLS on: reachable if a permissive SELECT/ALL policy for anon has no filter
  return t.policies.some((p) => {
    if (!p.permissive) return false;
    if (!["SELECT", "ALL"].includes(p.command)) return false;
    if (!p.roles.some((r) => ["anon", "public"].includes(r.toLowerCase())))
      return false;
    const q = (p.using ?? "true").replace(/\s+/g, "").toLowerCase();
    return q === "true" || q === "(true)";
  });
}

export const sensitiveColumnExposed: Check = {
  id: "sensitive-column-exposed",
  description: "Sensitive-looking column on a table an anon key can read",
  run(ctx) {
    const findings = [];
    for (const t of ctx.tables) {
      if (!anonCanRead(t)) continue;
      const hits = t.columns.filter((c) =>
        SENSITIVE.some((re) => re.test(c.name)),
      );
      if (!hits.length) continue;
      findings.push({
        check: this.id,
        severity: "critical" as const,
        object: `${t.schema}.${t.name}`,
        title: `Anon-readable table exposes ${hits.map((h) => h.name).join(", ")}`,
        detail: `An anon-key holder can SELECT this table with no row filter, and it contains column(s) that look like PII / secrets: ${hits.map((h) => `${h.name} (${h.type})`).join(", ")}.`,
        remediation:
          "Enable + scope RLS, or expose a view with only the safe columns and revoke access to the base table. Never rely on the client to omit columns.",
      });
    }
    return findings;
  },
};
