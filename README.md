# rls-audit

Audit Postgres / Supabase **Row-Level Security** posture from the command line.
Finds the tables anyone with your anon key can read, the policies that don't
actually restrict anything, and the sensitive columns sitting behind them.

![ci](https://github.com/justinmreynolds93-afk/rls-audit/actions/workflows/ci.yml/badge.svg)
![license](https://img.shields.io/badge/license-MIT-blue)
![node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen)

```
npx rls-audit --db-url "postgres://postgres:...@db.<ref>.supabase.co:5432/postgres"
```

## Why

Supabase and PostgREST expose every table in the `public` schema over HTTP. The
*only* thing standing between an anon key and your data is Row-Level Security —
and RLS has sharp edges:

- a table with RLS **off** is world-readable (and often world-writable)
- RLS **on** with no policies silently returns nothing — usually a half-finished migration
- a policy of `USING (true)` passes review but restricts nothing
- an `INSERT` policy with no `WITH CHECK` lets callers forge `user_id`
- `SECURITY DEFINER` functions run privileged and RLS doesn't apply inside them

`rls-audit` connects with a read-only introspection query, checks all of the
above, and exits non-zero so you can gate deploys on it.

## Checks

| id | severity | what it catches |
|---|---|---|
| `rls-disabled` | critical / high | API-reachable table with RLS off |
| `permissive-policy` | critical / high | `USING (true)` policy for `anon`/`authenticated` |
| `sensitive-column-exposed` | critical | anon-readable table with an `email` / `token` / `ssn` / … column |
| `anon-write-grant` | critical / medium | `anon` holds `INSERT`/`UPDATE`/`DELETE` |
| `policy-missing-with-check` | high / medium | write policy with no `WITH CHECK` |
| `rls-no-policies` | medium / low | RLS enabled, zero policies (deny-all) |
| `security-definer-bypass` | medium | `SECURITY DEFINER` function in an exposed schema |
| `rls-not-forced` | low | RLS on but not `FORCE`d (table owner bypasses it) |

`rls-audit --list-checks` for the current set.

## Usage

```bash
# human-readable
rls-audit --db-url "$SUPABASE_DB_URL"

# CI: markdown report, fail the build on anything >= high
rls-audit --db-url "$SUPABASE_DB_URL" --format markdown --fail-on high

# SARIF for GitHub code scanning
rls-audit --db-url "$SUPABASE_DB_URL" --format sarif > rls.sarif

# scope, or narrow the checks
rls-audit --db-url "$DB" --schema public --schema api --skip rls-not-forced
```

`DATABASE_URL` / `SUPABASE_DB_URL` are read from the environment if `--db-url`
is omitted. Use the `postgres` / service role — the tool only issues `SELECT`s
against `pg_catalog` and `information_schema`.

### In GitHub Actions

```yaml
- run: npx rls-audit --db-url "${{ secrets.SUPABASE_DB_URL }}" --format sarif > rls.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: rls.sarif }
```

## Output

```
CRITICAL public.profiles  [rls-disabled]
  RLS disabled on an API-reachable table
  anon, authenticated can SELECT every row — RLS is off, so no policy limits access.
  → ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY; then add policies …

CRITICAL public.profiles  [sensitive-column-exposed]
  Anon-readable table exposes email, phone_number, stripe_customer_id
  …

4 findings: 2 critical  1 high  1 medium
```

## What it does not do (yet)

- **Live policy testing** — impersonating a JWT and diffing visible rows. Planned;
  the static checks catch the common mistakes first.
- Storage bucket / Realtime / Edge Function policy review.
- It reasons about `USING (true)` textually, not by evaluating arbitrary
  expressions — a policy of `USING ((SELECT true))` won't be flagged.

## Development

```bash
npm install
npm run test:db:up      # postgres:16 on :55432 with the flawed fixture schema
npm test                # node --test against it
npm run build
npm run test:db:down
```

`test/fixtures/schema.sql` is a schema built to trip every check; the test suite
asserts each one fires (and that a correctly-scoped table produces nothing).

## License

[MIT](LICENSE)
