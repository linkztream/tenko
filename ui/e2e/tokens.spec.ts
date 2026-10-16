// WP3.8a: the service-account and token pages (IAM-10; docs/access.md, sections 6 and 7) against
// the real server. access.spec.ts shows a scoped token being created and used as a bearer; this
// file covers the rest of the life of a token and of an account.
//
// - Service accounts: a name the rule refuses (a space) is refused inline and nothing is created;
//   a token of an account cannot exceed what the account holds (the server's refusal stays in the
//   dialog and no token is listed).
// - A token's life: shown once (the confirm button waits for the "stored" box), listed afterwards
//   by its prefix only, never in the page again, valid as a bearer until it is revoked, and
//   refused (401) after the revocation; the expiry follows the lifetime that was chosen.
// - Personal tokens (/account/tokens): a personal token and a scoped token of the signed-in
//   administrator, with the same rules, listed with what each may do; revoking ends them.
// - Swedish: the token list and the dialog that shows a token.
//
// Arrangement: prefixes and grants come through the API; documentation values only
// (203.0.113.0/24, 198.51.100.0/24). A token's text is looked for in the page after it was
// closed, and never found.

import type { APIRequestContext, Locator, Page } from "@playwright/test";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { withKey } from "./support/ui";

type Prefix = Schemas["Prefix"];
type TokenInfo = Schemas["TokenInfo"];

interface Arranged {
  inScope: Prefix;
  beside: Prefix;
}

async function arrange(api: Api): Promise<Arranged> {
  const inScope = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "203.0.113.0/24", description: "Lab" })).item!;
  const beside = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "198.51.100.0/24", description: "IoT" })).item!;
  return { inScope, beside };
}

/** Picks a prefix in an open scope picker. */
async function pickPrefix(scope: Locator, prefix: Prefix): Promise<void> {
  await scope.getByTestId("field-scope-kind-prefix").check();
  await expect(scope.getByTestId("field-scope-object").locator(`option[value="${prefix.id}"]`)).toHaveCount(1);
  await scope.getByTestId("field-scope-object").selectOption(prefix.id);
}

/** A request context that carries `secret` as a bearer token, outside the browser's session. */
async function bearer(playwright: { request: { newContext: (options: { baseURL: string; extraHTTPHeaders: Record<string, string> }) => Promise<APIRequestContext> } }, origin: string, secret: string) {
  return playwright.request.newContext({ baseURL: origin, extraHTTPHeaders: { Authorization: `Bearer ${secret}` } });
}

/** The cidrs the token lists at `/prefixes`, or the status that refused it. */
async function listedBy(context: APIRequestContext): Promise<string[] | number> {
  const response = await context.get("/api/v1/prefixes");
  if (!response.ok()) return response.status();
  return ((await response.json()) as Schemas["Page_Prefix"]).items.map((p) => p.cidr);
}

/** Creates the service account `name` in the access page and opens its tokens. */
async function createAccount(page: Page, name: string): Promise<Locator> {
  await page.goto("/settings/access");
  await page.getByTestId("access-service-account-add").click();
  const dialog = page.getByTestId("dialog-service-account");
  await dialog.getByTestId("field-name").fill(name);
  await dialog.getByTestId("form-submit").click();
  const account = withKey(page, "access-service-account", name);
  await expect(account).toBeVisible();
  await account.getByTestId("access-service-account-tokens").click();
  return account;
}

/** The id of the service account `name`, from the API. */
async function accountId(api: Api, name: string): Promise<string> {
  const accounts = await api.get<Schemas["Page_UserInfo"]>("/access/service-accounts");
  const found = accounts.items.find((a) => a.name === name);
  expect(found, `service account ${name}`).toBeTruthy();
  return found!.id;
}

test("IAM-10: a service account name with a space is refused inline and nothing is created", async ({ page, api, signedIn }) => {
  void signedIn;
  await page.goto("/settings/access");
  await page.getByTestId("access-service-account-add").click();
  const dialog = page.getByTestId("dialog-service-account");
  await dialog.getByTestId("field-name").fill("ipam reader");
  await dialog.getByTestId("form-submit").click();
  await expect(dialog.getByTestId("field-name")).toHaveAttribute("aria-invalid", "true");
  await expect(dialog).toBeVisible();
  expect((await api.get<Schemas["Page_UserInfo"]>("/access/service-accounts")).items).toHaveLength(0);

  await dialog.getByTestId("field-name").fill("ipam-reader");
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeHidden();
  await expect(withKey(page, "access-service-account", "ipam-reader")).toBeVisible();
  expect((await api.get<Schemas["Page_UserInfo"]>("/access/service-accounts")).items.map((a) => a.name)).toEqual(["ipam-reader"]);
});

test("IAM-10: a token cannot exceed what its service account holds, and the refusal stays in the dialog", async ({ page, api, signedIn }) => {
  void signedIn;
  const { inScope } = await arrange(api);
  const account = await createAccount(page, "ipam-reader");
  await account.getByTestId("access-sa-token-create").click();
  const dialog = page.getByTestId("dialog-token");
  await dialog.getByTestId("field-name").fill("too-much");
  // The account holds no grant, so a token with a viewer grant over a prefix exceeds its owner.
  await pickPrefix(dialog.getByTestId("token-grant"), inScope);
  await dialog.getByTestId("form-submit").click();
  await expect(dialog.getByTestId("error-notice")).toBeVisible();
  await expect(dialog.getByTestId("error-notice")).toHaveAttribute("data-code", /^auth\./);
  await expect(page.getByTestId("dialog-token-created")).toHaveCount(0);
  const id = await accountId(api, "ipam-reader");
  expect((await api.get<Schemas["Page_TokenInfo"]>(`/access/service-accounts/${id}/tokens`)).items).toHaveLength(0);
  await dialog.getByTestId("form-cancel").click();
  await expect(account.getByTestId("access-sa-token")).toHaveCount(0);
});

test("IAM-10: a service account's token is shown once, listed by its prefix, works as a bearer and ends at its revocation", async ({
  page,
  api,
  server,
  playwright,
  signedIn,
}) => {
  void signedIn;
  const { inScope } = await arrange(api);
  const account = await createAccount(page, "ipam-reader");
  const id = await accountId(api, "ipam-reader");
  await api.post("/access/grants", { subject: id, role: "viewer", scope: { kind: "prefix", value: { id: inScope.id, subtree: true } } });

  await account.getByTestId("access-sa-token-create").click();
  const dialog = page.getByTestId("dialog-token");
  await dialog.getByTestId("field-name").fill("reader");
  // The first lifetime on offer; the expiry in the list follows it.
  const days = Number(await dialog.getByTestId("field-lifetime").inputValue());
  expect(days).toBeGreaterThan(0);
  await pickPrefix(dialog.getByTestId("token-grant"), inScope);
  await dialog.getByTestId("form-submit").click();

  const shown = page.getByTestId("dialog-token-created");
  const secret = ((await shown.getByTestId("token-secret").textContent()) ?? "").trim();
  expect(secret).toMatch(/^tnk_/);
  // The person must say that the token is stored before the dialog closes.
  await expect(shown.getByTestId("token-done")).toBeDisabled();
  await shown.getByTestId("token-stored").check();
  await shown.getByTestId("token-done").click();
  await expect(shown).toHaveCount(0);

  const row = withKey(account, "access-sa-token", "reader");
  const listed = (await api.get<Schemas["Page_TokenInfo"]>(`/access/service-accounts/${id}/tokens`)).items;
  expect(listed).toHaveLength(1);
  const info: TokenInfo = listed[0]!;
  expect(secret.startsWith(info.prefix)).toBe(true);
  expect(secret.length).toBeGreaterThan(info.prefix.length + 20);
  await expect(row).toContainText(info.prefix);
  await expect(row).toContainText("Viewer over prefix 203.0.113.0/24 and everything inside it");
  const expires = Date.parse(info.expires_at ?? "");
  expect(Math.abs(expires - (Date.now() + days * 86_400_000))).toBeLessThan(2 * 86_400_000);
  // Neither the API list nor the page holds the text of the token any more, also after a reload.
  expect(JSON.stringify(listed)).not.toContain(secret);
  expect(await page.content()).not.toContain(secret);
  await page.reload();
  await withKey(page, "access-service-account", "ipam-reader").getByTestId("access-service-account-tokens").click();
  await expect(withKey(page, "access-sa-token", "reader")).toBeVisible();
  expect(await page.content()).not.toContain(secret);

  const context = await bearer(playwright, server.url, secret);
  try {
    expect(await listedBy(context)).toEqual(["203.0.113.0/24"]);

    // Revoking asks first; keeping the token leaves it working.
    const token = withKey(page, "access-sa-token", "reader");
    await token.getByTestId("access-sa-token-revoke").click();
    await page.getByTestId("dialog-confirm").getByTestId("confirm-cancel").click();
    await expect(token).toBeVisible();
    expect(await listedBy(context)).toEqual(["203.0.113.0/24"]);

    await token.getByTestId("access-sa-token-revoke").click();
    await page.getByTestId("dialog-confirm").getByTestId("confirm-ok").click();
    await expect(token).toHaveCount(0);
    expect((await api.get<Schemas["Page_TokenInfo"]>(`/access/service-accounts/${id}/tokens`)).items).toHaveLength(0);
    // The bearer is refused from the next request on.
    expect(await listedBy(context)).toBe(401);
  } finally {
    await context.dispose();
  }
});

test("IAM-10: a personal token of the administrator is shown once, works as a bearer and ends at its revocation", async ({
  page,
  server,
  playwright,
  signedIn,
}) => {
  void signedIn;
  await page.goto("/account/tokens");
  await expect(page.getByTestId("page-account")).toBeVisible();
  await expect(page.getByTestId("account-token")).toHaveCount(0);

  await page.getByTestId("account-token-create").click();
  const dialog = page.getByTestId("dialog-token");
  await dialog.getByTestId("field-name").fill("automation");
  await expect(dialog.getByTestId("field-kind-personal")).toBeChecked();
  await dialog.getByTestId("form-submit").click();
  const shown = page.getByTestId("dialog-token-created");
  const secret = ((await shown.getByTestId("token-secret").textContent()) ?? "").trim();
  expect(secret).toMatch(/^tnk_/);
  await expect(shown.getByTestId("token-done")).toBeDisabled();
  await shown.getByTestId("token-stored").check();
  await shown.getByTestId("token-done").click();
  await expect(shown).toHaveCount(0);

  const row = withKey(page, "account-token", "automation");
  await expect(row).toBeVisible();
  await expect(row.getByTestId("token-reach")).toHaveAttribute("data-scoped", "false");
  expect(await page.content()).not.toContain(secret);

  const context = await bearer(playwright, server.url, secret);
  try {
    // A personal token acts as its owner: the administrator reads the whole inventory.
    expect(Array.isArray(await listedBy(context))).toBe(true);
    await row.getByTestId("account-token-revoke").click();
    await page.getByTestId("dialog-confirm").getByTestId("confirm-ok").click();
    await expect(row).toHaveCount(0);
    expect(await listedBy(context)).toBe(401);
  } finally {
    await context.dispose();
  }
});

test("IAM-10: a scoped personal token reads only the prefix it was given", async ({ page, api, server, playwright, signedIn }) => {
  void signedIn;
  const { inScope } = await arrange(api);
  await page.goto("/account/tokens");
  await page.getByTestId("account-token-create").click();
  const dialog = page.getByTestId("dialog-token");
  await dialog.getByTestId("field-name").fill("prefix-reader");
  await dialog.getByTestId("field-kind-scoped").check();
  await pickPrefix(dialog.getByTestId("token-grant"), inScope);
  // The form is submitted with the Enter key from the name field; the next scenario clicks.
  await dialog.getByTestId("field-name").press("Enter");
  const shown = page.getByTestId("dialog-token-created");
  const secret = ((await shown.getByTestId("token-secret").textContent()) ?? "").trim();
  await shown.getByTestId("token-stored").check();
  await shown.getByTestId("token-done").click();

  const row = withKey(page, "account-token", "prefix-reader");
  await expect(row.getByTestId("token-reach")).toHaveAttribute("data-scoped", "true");
  await expect(row.getByTestId("token-reach")).toContainText("203.0.113.0/24");
  const context = await bearer(playwright, server.url, secret);
  try {
    expect(await listedBy(context)).toEqual(["203.0.113.0/24"]);
  } finally {
    await context.dispose();
  }
});

// The dialog of a scoped personal token is taller than a 1280x720 window: it stays inside the
// window and scrolls, so its Create button can be clicked (deviation 66 of the exit document).
test("IAM-10: the Create button of the scoped personal-token dialog can be clicked in a 1280x720 window", async ({
  page,
  api,
  signedIn,
}) => {
  void signedIn;
  await page.setViewportSize({ width: 1280, height: 720 });
  const { inScope } = await arrange(api);
  await page.goto("/account/tokens");
  await page.getByTestId("account-token-create").click();
  const dialog = page.getByTestId("dialog-token");
  await dialog.getByTestId("field-name").fill("prefix-clicker");
  await dialog.getByTestId("field-kind-scoped").check();
  await pickPrefix(dialog.getByTestId("token-grant"), inScope);
  const box = await dialog.boundingBox();
  expect(box, "the dialog is laid out").not.toBeNull();
  expect((box?.y ?? 0) + (box?.height ?? 0), "the dialog ends inside the window").toBeLessThanOrEqual(720);
  await dialog.getByTestId("form-submit").click({ timeout: 5_000 });
  await expect(page.getByTestId("dialog-token-created")).toBeVisible();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("IAM-10: renders the token list and the dialog that shows a token in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/account/tokens");
    await page.getByTestId("account-token-create").click();
    const dialog = page.getByTestId("dialog-token");
    await expectRendered(page, dialog, "sv", testInfo, "token-create");
    await dialog.getByTestId("field-name").fill("automation");
    await dialog.getByTestId("form-submit").click();
    const shown = page.getByTestId("dialog-token-created");
    await expect(shown.getByTestId("token-secret")).toBeVisible();
    await expectRendered(page, shown, "sv", testInfo, "token-created");
    await shown.getByTestId("token-stored").check();
    await shown.getByTestId("token-done").click();
    await expect(withKey(page, "account-token", "automation")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-account"), "sv", testInfo, "tokens");
  });
});
