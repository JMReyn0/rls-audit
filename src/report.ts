import pc from "picocolors";
import { SEVERITY_RANK, type AuditContext, type Finding, type Severity } from "./types.js";

export type Format = "table" | "json" | "markdown" | "sarif";

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgRed(pc.white(s)),
  high: pc.red,
  medium: pc.yellow,
  low: pc.blue,
  info: pc.dim,
};

export function sortFindings(f: Finding[]): Finding[] {
  return [...f].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.object.localeCompare(b.object) ||
      a.check.localeCompare(b.check),
  );
}

export function render(
  findings: Finding[],
  ctx: AuditContext,
  fmt: Format,
): string {
  const sorted = sortFindings(findings);
  switch (fmt) {
    case "json":
      return JSON.stringify(
        { summary: summarize(sorted, ctx), findings: sorted },
        null,
        2,
      );
    case "markdown":
      return markdown(sorted, ctx);
    case "sarif":
      return JSON.stringify(sarif(sorted), null, 2);
    default:
      return table(sorted, ctx);
  }
}

export function summarize(findings: Finding[], ctx: AuditContext) {
  const bySeverity = {} as Record<Severity, number>;
  for (const s of ["critical", "high", "medium", "low", "info"] as Severity[])
    bySeverity[s] = findings.filter((f) => f.severity === s).length;
  return {
    scannedSchemas: ctx.exposedSchemas,
    tables: ctx.tables.length,
    functions: ctx.functions.length,
    findings: findings.length,
    bySeverity,
  };
}

function table(findings: Finding[], ctx: AuditContext): string {
  const s = summarize(findings, ctx);
  const lines: string[] = [];
  lines.push(
    pc.dim(
      `scanned ${s.tables} tables / ${s.functions} functions in ${ctx.exposedSchemas.join(", ")}`,
    ),
  );
  lines.push("");
  if (!findings.length) {
    lines.push(pc.green("✓ no findings"));
    return lines.join("\n");
  }
  for (const f of findings) {
    lines.push(
      `${SEV_COLOR[f.severity](f.severity.toUpperCase().padEnd(8))} ${pc.bold(f.object)}  ${pc.dim(`[${f.check}]`)}`,
    );
    lines.push(`  ${f.title}`);
    lines.push(pc.dim(`  ${f.detail}`));
    lines.push(pc.dim(`  → ${f.remediation}`));
    lines.push("");
  }
  const tally = (["critical", "high", "medium", "low"] as Severity[])
    .filter((k) => s.bySeverity[k])
    .map((k) => SEV_COLOR[k](`${s.bySeverity[k]} ${k}`))
    .join("  ");
  lines.push(`${findings.length} findings: ${tally}`);
  return lines.join("\n");
}

function markdown(findings: Finding[], ctx: AuditContext): string {
  const s = summarize(findings, ctx);
  const out: string[] = [
    "# RLS audit",
    "",
    `Scanned **${s.tables} tables** / **${s.functions} functions** in \`${ctx.exposedSchemas.join("`, `")}\`.`,
    "",
    `| critical | high | medium | low |`,
    `|---|---|---|---|`,
    `| ${s.bySeverity.critical} | ${s.bySeverity.high} | ${s.bySeverity.medium} | ${s.bySeverity.low} |`,
    "",
  ];
  if (!findings.length) {
    out.push("✓ No findings.");
    return out.join("\n");
  }
  out.push("| severity | object | check | finding |", "|---|---|---|---|");
  for (const f of findings)
    out.push(
      `| ${f.severity} | \`${f.object}\` | ${f.check} | ${f.title} |`,
    );
  out.push("");
  for (const f of findings) {
    out.push(`### ${f.object} — ${f.title}`, "");
    out.push(`- **severity:** ${f.severity}`);
    out.push(`- **detail:** ${f.detail}`);
    out.push(`- **remediation:** ${f.remediation}`);
    if (f.reference) out.push(`- **reference:** ${f.reference}`);
    out.push("");
  }
  return out.join("\n");
}

function sarif(findings: Finding[]) {
  const rules = [...new Map(findings.map((f) => [f.check, f])).values()].map(
    (f) => ({
      id: f.check,
      shortDescription: { text: f.title },
      helpUri: f.reference,
    }),
  );
  const sarifLevel: Record<Severity, string> = {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "note",
    info: "note",
  };
  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "rls-audit",
            informationUri: "https://github.com/justinmreynolds93-afk/rls-audit",
            rules,
          },
        },
        results: findings.map((f) => ({
          ruleId: f.check,
          level: sarifLevel[f.severity],
          message: { text: `${f.object}: ${f.detail} — ${f.remediation}` },
          locations: [
            { logicalLocations: [{ fullyQualifiedName: f.object }] },
          ],
        })),
      },
    ],
  };
}
