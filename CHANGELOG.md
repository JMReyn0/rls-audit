# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] — 2026-09-04

Initial release.

### Added
- Eight static checks over Postgres / Supabase RLS posture: `rls-disabled`,
  `permissive-policy`, `sensitive-column-exposed`, `anon-write-grant`,
  `policy-missing-with-check`, `rls-no-policies`, `security-definer-bypass`,
  `rls-not-forced`
- `table` / `json` / `markdown` / `sarif` output; `--fail-on <severity>` for CI
- Auto-detects PostgREST-exposed schemas (`pgrst.db_schemas`), `--schema` to add more
- Test suite: a deliberately-flawed fixture schema, every check asserted, run
  against `postgres:16` in CI
