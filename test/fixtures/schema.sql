-- A deliberately-flawed schema that trips every check in rls-audit.
-- Mirrors the roles PostgREST / Supabase create.
create role anon nologin;
create role authenticated nologin;
grant usage on schema public to anon, authenticated;

-- stand-in for Supabase's auth.uid(); defined first so tables below can use it
create function public.auth_uid() returns uuid language sql stable as $$
  select '00000000-0000-0000-0000-000000000000'::uuid
$$;

-- 1. rls-disabled + sensitive-column-exposed: no RLS, anon can read PII
create table public.profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  display_name text,
  email text,                 -- sensitive
  phone_number text,          -- sensitive
  stripe_customer_id text     -- sensitive
);
grant select on public.profiles to anon, authenticated;

-- 2. anon-write-grant (unguarded): anon can INSERT, no policy
create table public.contact_messages (
  id bigint generated always as identity primary key,
  body text
);
grant select, insert on public.contact_messages to anon;

-- 3. rls-no-policies: RLS on, zero policies, still granted to authenticated
create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  total_cents integer
);
alter table public.orders enable row level security;
grant select, insert, update on public.orders to authenticated;

-- 4. permissive-policy (read) + rls-not-forced: RLS on but USING (true)
create table public.posts (
  id bigint generated always as identity primary key,
  author_id uuid not null,
  title text,
  draft_body text
);
alter table public.posts enable row level security;
grant select on public.posts to anon, authenticated;
create policy "anyone can read posts" on public.posts
  for select to anon, authenticated using (true);

-- 5. policy-missing-with-check: INSERT policy with no WITH CHECK at all
--    (Postgres allows this; it then permits inserting arbitrary rows)
create table public.comments (
  id bigint generated always as identity primary key,
  post_id bigint,
  user_id uuid not null,
  body text
);
alter table public.comments enable row level security;
alter table public.comments force row level security;
grant select, insert on public.comments to authenticated;
create policy "read own comments" on public.comments
  for select to authenticated using (user_id = auth_uid());
create policy "insert comments" on public.comments
  for insert to authenticated;

-- a correctly-scoped table: should produce NO findings
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth_uid(),
  body text
);
alter table public.notes enable row level security;
alter table public.notes force row level security;
grant select, insert, update, delete on public.notes to authenticated;
create policy "own notes select" on public.notes
  for select to authenticated using (user_id = auth_uid());
create policy "own notes write" on public.notes
  for all to authenticated using (user_id = auth_uid()) with check (user_id = auth_uid());

-- 6. security-definer-bypass: SECURITY DEFINER fn owned by superuser, in public
create function public.promote_user(target uuid) returns void
  language sql security definer as $$ update public.profiles set display_name = 'admin' where user_id = target $$;
grant execute on function public.promote_user(uuid) to authenticated;
