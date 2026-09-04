# RLS audit

Scanned **6 tables** / **2 functions** in `public`.

| critical | high | medium | low |
|---|---|---|---|
| 3 | 3 | 2 | 1 |

| severity | object | check | finding |
|---|---|---|---|
| critical | `public.contact_messages` | anon-write-grant | anon can INSERT |
| critical | `public.contact_messages` | rls-disabled | RLS disabled on an API-reachable table |
| critical | `public.profiles` | sensitive-column-exposed | Anon-readable table exposes email, phone_number, stripe_customer_id |
| high | `public.comments` | policy-missing-with-check | INSERT policy "insert comments" has no WITH CHECK |
| high | `public.posts` | permissive-policy | Policy "anyone can read posts" imposes no restriction |
| high | `public.profiles` | rls-disabled | RLS disabled on an API-reachable table |
| medium | `public.orders` | rls-no-policies | RLS enabled with zero policies |
| medium | `public.promote_user(target uuid)` | security-definer-bypass | SECURITY DEFINER function callable from the API |
| low | `public.posts` | rls-not-forced | RLS not forced |

### public.contact_messages — anon can INSERT

- **severity:** critical
- **detail:** No RLS write policy — any anon-key holder can write arbitrary rows.
- **remediation:** REVOKE INSERT ON public.contact_messages FROM anon; move the operation behind an Edge Function or RPC with SECURITY DEFINER + explicit checks, or a rate-limited endpoint.

### public.contact_messages — RLS disabled on an API-reachable table

- **severity:** critical
- **detail:** anon can INSERT, SELECT every row — RLS is off, so no policy limits access.
- **remediation:** ALTER TABLE public.contact_messages ENABLE ROW LEVEL SECURITY; then add policies scoping rows to the caller (e.g. USING (auth.uid() = user_id)).
- **reference:** https://supabase.com/docs/guides/database/postgres/row-level-security

### public.profiles — Anon-readable table exposes email, phone_number, stripe_customer_id

- **severity:** critical
- **detail:** An anon-key holder can SELECT this table with no row filter, and it contains column(s) that look like PII / secrets: email (text), phone_number (text), stripe_customer_id (text).
- **remediation:** Enable + scope RLS, or expose a view with only the safe columns and revoke access to the base table. Never rely on the client to omit columns.

### public.comments — INSERT policy "insert comments" has no WITH CHECK

- **severity:** high
- **detail:** authenticated can insert rows with any column values — nothing stops a forged user_id, role, or price.
- **remediation:** Add WITH CHECK mirroring ownership, e.g. WITH CHECK (auth.uid() = user_id).

### public.posts — Policy "anyone can read posts" imposes no restriction

- **severity:** high
- **detail:** SELECT policy for anon/authenticated: USING (true). RLS is on but this makes the table effectively open.
- **remediation:** Scope it to the caller, e.g. USING (auth.uid() = user_id). If the data really is public, keep it but add a test and a comment so the next audit knows it's intentional.

### public.profiles — RLS disabled on an API-reachable table

- **severity:** high
- **detail:** anon, authenticated can SELECT every row — RLS is off, so no policy limits access.
- **remediation:** ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY; then add policies scoping rows to the caller (e.g. USING (auth.uid() = user_id)).
- **reference:** https://supabase.com/docs/guides/database/postgres/row-level-security

### public.orders — RLS enabled with zero policies

- **severity:** medium
- **detail:** No policy exists, so every non-owner request returns no rows. Safe, but almost always an unfinished migration rather than an intentional lockdown.
- **remediation:** Add the intended policies, or if the table should be private drop the anon/authenticated grants and document it.

### public.promote_user(target uuid) — SECURITY DEFINER function callable from the API

- **severity:** medium
- **detail:** Owned by postgres (bypasses RLS). If it's granted to anon/authenticated it runs privileged for any caller; RLS won't protect the tables it touches.
- **remediation:** Confirm the function does its own authorization (auth.uid() checks, input validation), SET search_path is pinned, and EXECUTE is granted only to the roles that need it. Add a test.
- **reference:** https://www.postgresql.org/docs/current/sql-createfunction.html

### public.posts — RLS not forced

- **severity:** low
- **detail:** Policies exist but are skipped for the table owner (postgres) and any BYPASSRLS role. A connection pool or job that authenticates as the owner would see everything.
- **remediation:** ALTER TABLE public.posts FORCE ROW LEVEL SECURITY; (only if no trusted process legitimately needs the bypass).

