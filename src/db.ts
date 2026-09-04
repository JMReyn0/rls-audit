import postgres from "postgres";
import type {
  AuditContext,
  FunctionInfo,
  PolicyInfo,
  TableInfo,
} from "./types.js";

/** Roles that define the anonymous / logged-in API surface in Supabase & PostgREST. */
const API_ROLES = ["anon", "authenticated", "PUBLIC", "web_anon"];

export interface ConnectOptions {
  url: string;
  /** extra schemas to treat as API-exposed on top of what's auto-detected */
  schemas?: string[];
}

export async function audit(opts: ConnectOptions): Promise<AuditContext> {
  const sql = postgres(opts.url, { max: 1, idle_timeout: 5, onnotice: () => {} });
  try {
    const exposedSchemas = await detectExposedSchemas(sql, opts.schemas ?? []);
    const tables = await loadTables(sql, exposedSchemas);
    const functions = await loadFunctions(sql, exposedSchemas);
    return { tables, functions, exposedSchemas };
  } finally {
    await sql.end({ timeout: 5 });
  }
}

/**
 * PostgREST exposes `db-schema` (default `public`). Supabase stores it in
 * `pgrst.db_schemas` GUC when configured; fall back to `public`.
 */
async function detectExposedSchemas(
  sql: postgres.Sql,
  extra: string[],
): Promise<string[]> {
  const rows = await sql<{ setting: string | null }[]>`
    select current_setting('pgrst.db_schemas', true) as setting
  `;
  const fromGuc = (rows[0]?.setting ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const set = new Set<string>([
    ...(fromGuc.length ? fromGuc : ["public"]),
    ...extra,
  ]);
  return [...set];
}

async function loadTables(
  sql: postgres.Sql,
  schemas: string[],
): Promise<TableInfo[]> {
  const rows = await sql<
    {
      schema: string;
      name: string;
      rls_enabled: boolean;
      rls_forced: boolean;
      owner: string;
    }[]
  >`
    select n.nspname               as schema,
           c.relname               as name,
           c.relrowsecurity        as rls_enabled,
           c.relforcerowsecurity   as rls_forced,
           pg_get_userbyid(c.relowner) as owner
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where c.relkind in ('r', 'p')
      and n.nspname = any(${schemas})
    order by 1, 2
  `;

  const grants = await sql<
    { schema: string; name: string; grantee: string; privilege: string }[]
  >`
    select table_schema as schema, table_name as name,
           grantee, privilege_type as privilege
    from information_schema.role_table_grants
    where table_schema = any(${schemas})
      and grantee = any(${API_ROLES})
  `;

  const policies = await sql<
    {
      schema: string;
      name: string;
      policyname: string;
      permissive: string;
      roles: string[];
      cmd: string;
      qual: string | null;
      with_check: string | null;
    }[]
  >`
    select schemaname as schema, tablename as name, policyname,
           permissive, roles, cmd, qual, with_check
    from pg_policies
    where schemaname = any(${schemas})
  `;

  const columns = await sql<
    { schema: string; name: string; column: string; type: string }[]
  >`
    select table_schema as schema, table_name as name,
           column_name as column, data_type as type
    from information_schema.columns
    where table_schema = any(${schemas})
    order by ordinal_position
  `;

  return rows.map((t) => {
    const key = `${t.schema}.${t.name}`;
    return {
      schema: t.schema,
      name: t.name,
      rlsEnabled: t.rls_enabled,
      rlsForced: t.rls_forced,
      owner: t.owner,
      apiGrants: grants
        .filter((g) => `${g.schema}.${g.name}` === key)
        .map((g) => ({ grantee: g.grantee, privilege: g.privilege })),
      policies: policies
        .filter((p) => `${p.schema}.${p.name}` === key)
        .map<PolicyInfo>((p) => ({
          name: p.policyname,
          permissive: p.permissive === "PERMISSIVE",
          roles: p.roles,
          command: p.cmd,
          using: p.qual,
          withCheck: p.with_check,
        })),
      columns: columns
        .filter((c) => `${c.schema}.${c.name}` === key)
        .map((c) => ({ name: c.column, type: c.type })),
    };
  });
}

async function loadFunctions(
  sql: postgres.Sql,
  schemas: string[],
): Promise<FunctionInfo[]> {
  const rows = await sql<
    {
      schema: string;
      name: string;
      args: string;
      owner: string;
      security_definer: boolean;
      owner_bypasses_rls: boolean;
    }[]
  >`
    select n.nspname as schema,
           p.proname as name,
           pg_get_function_identity_arguments(p.oid) as args,
           pg_get_userbyid(p.proowner) as owner,
           p.prosecdef as security_definer,
           (r.rolsuper or r.rolbypassrls) as owner_bypasses_rls
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    join pg_roles r on r.oid = p.proowner
    where n.nspname = any(${schemas})
    order by 1, 2
  `;
  return rows.map((r) => ({
    schema: r.schema,
    name: r.name,
    args: r.args,
    owner: r.owner,
    securityDefiner: r.security_definer,
    ownerBypassesRls: r.owner_bypasses_rls,
  }));
}
