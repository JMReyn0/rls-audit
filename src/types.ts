export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export interface Finding {
  /** stable machine id, e.g. "rls-disabled" */
  check: string;
  severity: Severity;
  /** the object the finding is about, e.g. "public.profiles" */
  object: string;
  title: string;
  detail: string;
  /** what an operator should do */
  remediation: string;
  /** optional ATT&CK-style / CWE reference */
  reference?: string;
}

export interface TableInfo {
  schema: string;
  name: string;
  /** relrowsecurity — RLS toggled on */
  rlsEnabled: boolean;
  /** relforcerowsecurity — enforced even for the table owner */
  rlsForced: boolean;
  owner: string;
  /** privileges granted to anon / authenticated / PUBLIC (the PostgREST surface) */
  apiGrants: { grantee: string; privilege: string }[];
  policies: PolicyInfo[];
  columns: { name: string; type: string }[];
}

export interface PolicyInfo {
  name: string;
  /** PERMISSIVE | RESTRICTIVE */
  permissive: boolean;
  /** roles the policy applies to */
  roles: string[];
  command: string; // ALL | SELECT | INSERT | UPDATE | DELETE
  using: string | null; // USING expression
  withCheck: string | null; // WITH CHECK expression
}

export interface FunctionInfo {
  schema: string;
  name: string;
  args: string;
  owner: string;
  securityDefiner: boolean;
  /** true if the owner can bypass RLS (superuser / BYPASSRLS) */
  ownerBypassesRls: boolean;
}

export interface AuditContext {
  tables: TableInfo[];
  functions: FunctionInfo[];
  /** schemas exposed through the PostgREST/Supabase API */
  exposedSchemas: string[];
}

export interface Check {
  id: string;
  description: string;
  run(ctx: AuditContext): Finding[];
}
