// WP3.11b: the access page and display gating against the real server (IAM-01, IAM-06, IAM-10;
// docs/access.md).
//
// - Grants: the administrator gives a person the operator role over 203.0.113.0/24 and what lies
//   inside it through the scope picker, sees it in the list, and revokes a second one.
// - The sign-in requirement per role: a policy stored for the viewer role, then the profile again.
// - Service accounts and scoped tokens: an account created in the page, a token with a viewer
//   grant over one prefix shown once, and that token used as a bearer reads that prefix and not
//   the one beside it, and cannot write.
// - Display gating, the acceptance of WP3.11b: the scoped operator signs in and sees the write
//   actions on the prefix of the grant and none on the prefix beside it.
// - Swedish: the access page.
//
// Arrangement: prefixes and the person come through the API; the person has a PIN, as the Lab
// profile of the test server allows, and changes it at the first sign-in as every account
// created with a password must.

import type { Locator } from "@playwright/test";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { withKey } from "./support/ui";

type Prefix = Schemas["Prefix"];
type GrantView = Schemas["GrantView"];

/** The scoped person of the scenarios; an invented PIN, digits only as Lab's preset wants. */
const CASEY = { name: "casey", displayName: "Casey Example", password: "482917", changed: "915372" } as const;

interface Arranged {
  inScope: Prefix;
  beside: Prefix;
  casey: Schemas["UserInfo"];
}

async function arrange(api: Api): Promise<Arranged> {
  const inScope = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "203.0.113.0/24", description: "Lab" })).item!;
  const beside = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "198.51.100.0/24", description: "IoT" })).item!;
  const casey = await api.post<Schemas["UserInfo"]>("/users", {
    name: CASEY.name,
    display_name: CASEY.displayName,
    password: CASEY.password,
    roles: [],
  });
  return { inScope, beside, casey };
}

/** Picks a prefix in an open scope picker. */
async function pickPrefix(scope: Locator, prefix: Prefix): Promise<void> {
  await scope.getByTestId("field-scope-kind-prefix").check();
  await expect(scope.getByTestId("field-scope-object").locator(`option[value="${prefix.id}"]`)).toHaveCount(1);
  await scope.getByTestId("field-scope-object").selectOption(prefix.id);
}

test("grants a scoped role through the scope picker and revokes one", async ({ page, api, signedIn }) => {
  void signedIn;
  const { inScope, beside, casey } = await arrange(api);
  await api.post("/access/grants", { subject: casey.id, role: "viewer", scope: { kind: "prefix", value: { id: beside.id, subtree: false } } });

  await page.goto("/settings/access");
  await expect(page.getByTestId("page-access")).toBeVisible();
  await expect(page.getByTestId("access-grant")).toHaveCount(1);
  await page.getByTestId("access-grant-add").click();
  const dialog = page.getByTestId("dialog-grant");
  await expect(dialog.getByTestId("field-subject").locator(`option[value="${casey.id}"]`)).toHaveCount(1);
  await dialog.getByTestId("field-subject").selectOption(casey.id);
  await dialog.getByTestId("field-role-operator").check();
  await pickPrefix(dialog.getByTestId("scope-picker"), inScope);
  await expect(dialog.getByTestId("field-scope-subtree")).toBeChecked();
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeHidden();
  await expect(page.getByTestId("access-grant")).toHaveCount(2);

  const grants = await api.get<Schemas["Page_GrantView"]>("/access/grants", { subject: casey.id });
  const operator = grants.items.find((g: GrantView) => g.role === "operator");
  expect(operator?.scope).toEqual({ kind: "prefix", value: { id: inScope.id, subtree: true } });
  await expect(withKey(page, "access-grant", operator!.id).getByTestId("access-grant-scope")).toHaveText(
    "prefix 203.0.113.0/24 and everything inside it",
  );

  const viewer = grants.items.find((g: GrantView) => g.role === "viewer")!;
  await withKey(page, "access-grant", viewer.id).getByTestId("access-grant-revoke").click();
  await page.getByTestId("dialog-confirm").getByTestId("confirm-ok").click();
  await expect(page.getByTestId("access-grant")).toHaveCount(1);
  expect((await api.get<Schemas["Page_GrantView"]>("/access/grants", { subject: casey.id })).items).toHaveLength(1);
});

test("stores a sign-in requirement for a role and follows the profile again", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/access");
  const viewer = withKey(page, "access-role", "viewer");
  await viewer.getByTestId("access-role-policy-edit").click();
  const dialog = page.getByTestId("dialog-role-policy");
  await dialog.getByTestId("field-mfa-totp_or_stronger").check();
  await dialog.getByTestId("form-submit").click();
  await expect(viewer.getByTestId("access-role-mfa")).toHaveAttribute("data-mfa", "totp_or_stronger");
  let policies = await api.get<Schemas["Page_RolePolicyView"]>("/access/role-policies");
  expect(policies.items.find((p) => p.role === "viewer")?.stored).toBe("totp_or_stronger");

  await viewer.getByTestId("access-role-policy-edit").click();
  await dialog.getByTestId("field-mfa-profile").check();
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeHidden();
  await expect.poll(async () => {
    policies = await api.get<Schemas["Page_RolePolicyView"]>("/access/role-policies");
    return policies.items.find((p) => p.role === "viewer")?.stored ?? null;
  }).toBeNull();
});

test("creates a service account with a scoped token that reads only its prefix", async ({ page, api, server, playwright, signedIn }) => {
  void signedIn;
  const { inScope, beside } = await arrange(api);
  await page.goto("/settings/access");
  await page.getByTestId("access-service-account-add").click();
  const create = page.getByTestId("dialog-service-account");
  await create.getByTestId("field-name").fill("ipam-reader");
  await create.getByTestId("field-display_name").fill("IPAM reader");
  await create.getByTestId("form-submit").click();
  const account = withKey(page, "access-service-account", "ipam-reader");
  await expect(account).toBeVisible();

  await account.getByTestId("access-service-account-tokens").click();
  await account.getByTestId("access-sa-token-create").click();
  const dialog = page.getByTestId("dialog-token");
  await dialog.getByTestId("field-name").fill("reader");
  const grant = dialog.getByTestId("token-grant");
  // A service account holds nothing yet: the token grant needs a scope the account holds, so
  // the grant goes to the account first (a token never exceeds its owner).
  await api.post("/access/grants", {
    subject: (await api.get<Schemas["Page_UserInfo"]>("/access/service-accounts")).items[0]!.id,
    role: "viewer",
    scope: { kind: "prefix", value: { id: inScope.id, subtree: true } },
  });
  await pickPrefix(grant.getByTestId("scope-picker"), inScope);
  await dialog.getByTestId("form-submit").click();
  const shown = page.getByTestId("dialog-token-created");
  const secret = (await shown.getByTestId("token-secret").textContent()) ?? "";
  expect(secret).toMatch(/^tnk_/);
  await shown.getByTestId("token-stored").check();
  await shown.getByTestId("token-done").click();
  await expect(withKey(account, "access-sa-token", "reader")).toContainText("Viewer over prefix 203.0.113.0/24 and everything inside it");

  // The token as a bearer, outside the browser's session.
  const bearer = await playwright.request.newContext({ baseURL: server.url, extraHTTPHeaders: { Authorization: `Bearer ${secret}` } });
  try {
    const list = (await (await bearer.get("/api/v1/prefixes")).json()) as Schemas["Page_Prefix"];
    const cidrs = list.items.map((p) => p.cidr);
    expect(cidrs).toContain("203.0.113.0/24");
    expect(cidrs).not.toContain("198.51.100.0/24");
    expect((await bearer.get(`/api/v1/prefixes/${beside.id}`)).status()).toBe(403);
    const write = await bearer.post("/api/v1/prefixes", {
      data: { cidr: "203.0.113.128/25" },
      headers: { Origin: server.url, "Idempotency-Key": crypto.randomUUID() },
    });
    expect(write.status()).toBe(403);
  } finally {
    await bearer.dispose();
  }
});

test("shows a scoped operator the write actions inside the scope only", async ({ page, api, signedIn }) => {
  void signedIn;
  const { inScope, beside, casey } = await arrange(api);
  await api.post("/access/grants", { subject: casey.id, role: "operator", scope: { kind: "prefix", value: { id: inScope.id, subtree: true } } });
  // A viewer grant makes the prefix beside it readable, so the page shows it without actions.
  await api.post("/access/grants", { subject: casey.id, role: "viewer", scope: { kind: "prefix", value: { id: beside.id, subtree: false } } });

  // The browser takes casey's session (the API shares its cookies).
  // An account created with a password changes it at the first sign-in.
  await api.logout();
  await api.loginPassword(CASEY.name, CASEY.password);
  await api.post("/auth/password", { current_password: CASEY.password, new_password: CASEY.changed }, { idempotencyKey: null });
  await api.logout().catch(() => undefined);
  const login = await api.loginPassword(CASEY.name, CASEY.changed);
  expect(login.status).toBe("authenticated");
  const session = await api.session();
  expect(session.roles).toEqual([]);
  expect(session.grants?.map((g) => g.role).sort()).toEqual(["operator", "viewer"]);

  await page.goto("/ipam/prefixes/203.0.113.0/24");
  const own = withKey(page, "prefix-pane", "203.0.113.0/24");
  await expect(own).toBeVisible();
  for (const action of ["prefix-edit", "prefix-delete"]) await expect(own.getByTestId(action)).toBeVisible();

  await page.goto("/ipam/prefixes/198.51.100.0/24");
  const other = withKey(page, "prefix-pane", "198.51.100.0/24");
  await expect(other).toBeVisible();
  await expect(other.getByTestId("prefix-summary")).toBeVisible();
  for (const action of ["prefix-edit", "prefix-delete", "prefix-next-free-address"]) await expect(other.getByTestId(action)).toHaveCount(0);

  // The settings stay closed: they are global-only.
  await page.goto("/settings/access");
  await expect(page.getByTestId("page-access")).toHaveCount(0);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the access page in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/settings/access");
    await expect(page.getByTestId("access-role")).toHaveCount(4);
    await expectRendered(page, page.getByTestId("page-access"), "sv", testInfo, "access");
  });
});
