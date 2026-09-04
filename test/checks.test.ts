import { test } from "node:test";
import assert from "node:assert/strict";
import { audit } from "../src/db.ts";
import { CHECKS } from "../src/checks/index.ts";
import type { Finding } from "../src/types.ts";

const URL =
  process.env.TEST_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:55432/rlsaudit";

let findings: Finding[];

test("audit the fixture schema", async (t) => {
  const ctx = await audit({ url: URL });
  findings = CHECKS.flatMap((c) => c.run(ctx));

  const has = (check: string, object: string) =>
    findings.some((f) => f.check === check && f.object === object);

  await t.test("rls-disabled on public.profiles (critical/high)", () => {
    assert.ok(has("rls-disabled", "public.profiles"));
  });

  await t.test("sensitive columns flagged on public.profiles", () => {
    const f = findings.find(
      (x) => x.check === "sensitive-column-exposed" && x.object === "public.profiles",
    );
    assert.ok(f, "expected a sensitive-column finding");
    assert.match(f!.title, /email/);
  });

  await t.test("anon INSERT on public.contact_messages is critical", () => {
    const f = findings.find(
      (x) => x.check === "anon-write-grant" && x.object === "public.contact_messages",
    );
    assert.equal(f?.severity, "critical");
  });

  await t.test("rls-no-policies on public.orders", () => {
    assert.ok(has("rls-no-policies", "public.orders"));
  });

  await t.test("permissive USING (true) policy on public.posts", () => {
    assert.ok(has("permissive-policy", "public.posts"));
  });

  await t.test("posts RLS not forced", () => {
    assert.ok(has("rls-not-forced", "public.posts"));
  });

  await t.test("comments INSERT policy missing WITH CHECK", () => {
    assert.ok(has("policy-missing-with-check", "public.comments"));
  });

  await t.test("SECURITY DEFINER promote_user flagged", () => {
    assert.ok(
      findings.some(
        (f) =>
          f.check === "security-definer-bypass" &&
          f.object.startsWith("public.promote_user"),
      ),
    );
  });

  await t.test("the correctly-scoped public.notes produces no findings", () => {
    assert.equal(
      findings.filter((f) => f.object === "public.notes").length,
      0,
    );
  });
});
