#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { audit } from "./db.js";
import { selectChecks, CHECKS } from "./checks/index.js";
import { render, summarize, type Format } from "./report.js";
import { SEVERITY_RANK, type Finding, type Severity } from "./types.js";

const HELP = `rls-audit — audit Postgres / Supabase Row-Level Security posture

USAGE
  rls-audit --db-url <postgres url> [options]
  DATABASE_URL=<url> rls-audit

OPTIONS
  --db-url <url>        Postgres connection string (or env DATABASE_URL)
  --schema <name>       extra schema to treat as API-exposed (repeatable)
  --format <fmt>        table | json | markdown | sarif        (default: table)
  --fail-on <severity>  exit 1 if a finding >= this severity   (default: high)
  --only <ids>          run only these checks (comma-separated)
  --skip <ids>          skip these checks (comma-separated)
  --list-checks         print the available checks and exit
  -h, --help            this text

CHECKS
${CHECKS.map((c) => `  ${c.id.padEnd(26)} ${c.description}`).join("\n")}

The connection should use a role that can read pg_catalog / information_schema
(the Supabase "postgres" / service role, or any superuser). rls-audit only reads.
`;

async function main() {
  const { values } = parseArgs({
    options: {
      "db-url": { type: "string" },
      schema: { type: "string", multiple: true },
      format: { type: "string", default: "table" },
      "fail-on": { type: "string", default: "high" },
      only: { type: "string" },
      skip: { type: "string" },
      "list-checks": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (values.help) return void console.log(HELP);
  if (values["list-checks"])
    return void console.log(
      CHECKS.map((c) => `${c.id}\t${c.description}`).join("\n"),
    );

  const url =
    values["db-url"] ?? process.env.DATABASE_URL ?? process.env.SUPABASE_DB_URL;
  if (!url) {
    console.error("error: no connection string (pass --db-url or set DATABASE_URL)\n");
    console.error(HELP);
    process.exit(2);
  }

  const format = values.format as Format;
  if (!["table", "json", "markdown", "sarif"].includes(format)) {
    console.error(`error: unknown --format "${format}"`);
    process.exit(2);
  }

  const failOn = values["fail-on"] as Severity;
  if (!(failOn in SEVERITY_RANK)) {
    console.error(`error: unknown --fail-on "${failOn}"`);
    process.exit(2);
  }

  const checks = selectChecks(
    values.only?.split(",").map((s) => s.trim()),
    values.skip?.split(",").map((s) => s.trim()),
  );

  let ctx;
  try {
    ctx = await audit({ url, schemas: values.schema });
  } catch (err) {
    console.error(`error: could not audit the database: ${(err as Error).message}`);
    process.exit(2);
  }

  const findings: Finding[] = checks.flatMap((c) => c.run(ctx));
  process.stdout.write(render(findings, ctx, format) + "\n");

  const worst = Math.max(0, ...findings.map((f) => SEVERITY_RANK[f.severity]));
  if (worst >= SEVERITY_RANK[failOn]) {
    if (format === "table")
      process.stderr.write(
        `\nfailing: a finding meets or exceeds --fail-on ${failOn}\n`,
      );
    process.exit(1);
  }
  void summarize; // exported for library use / tests
}

main();
