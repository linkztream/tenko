// WP3.8a: what disappears for a scoped operator (IAM-01, IAM-06; docs/access.md, sections 2 and 3.5)
// against the real server. A scoped operator holds no global role, only an operator grant over
// the prefix 203.0.113.0/24 and what lies inside it. Display gating is a convenience: the server
// decides every request, and the pages say so when it refuses (`auth.forbidden`). The scenarios
// compare the scoped operator with the administrator (and with a global operator) on the same
// server, so that every absence is one the role causes and not a page that is empty.
//
// - Pages: every settings page and the updates page show "Administrators only" instead of the
//   page, with no settings tabs; the secrets page says that the role shows none.
// - Navigation: the rail still lists every area (the server refuses what is not allowed); the
//   command palette offers no "Updates" and no "Secrets" to a scoped operator, which a global
//   operator gets for Secrets and an administrator for both.
// - Actions: no metrics tiles on the start page, no "Create connector", no enrolment of a node
//   and no token list, no "Add a controller"; the cluster and scans pages show the refusal; the
//   write actions of IPAM stay on the prefix of the grant.
// - A viewer's pane in the same server is covered by access.spec.ts (display gating on a prefix
//   the operator may only read); Swedish: the refusal of a settings page.
//
// Arrangement: prefixes and accounts come through the API; the PINs are invented, digits only as
// the Lab profile of the test server allows, and are changed at the first sign-in as the server
// demands for an initial password.

import type { Page } from "@playwright/test";
import { signInCreatedAccount } from "./support/accounts";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { withKey } from "./support/ui";

/** The scoped operator; an invented PIN. */
const CASEY = { name: "casey", pin: "482917", changed: "915372" } as const;
/** A global operator, for the contrast. */
const OLIVE = { name: "olive", pin: "603518", changed: "271846" } as const;

/** The settings pages and the page root they show to an administrator. */
const ADMIN_PAGES: ReadonlyArray<{ path: string; root: string }> = [
  { path: "/settings/security", root: "settings-nav" },
  { path: "/settings/users", root: "settings-nav" },
  { path: "/updates", root: "page-updates" },
  { path: "/settings/access", root: "page-access" },
  { path: "/settings/audit-export", root: "page-audit-export" },
  { path: "/settings/vault", root: "page-vault" },
  { path: "/settings/backup", root: "page-backup" },
  { path: "/settings/reconciler", root: "page-reconciler" },
  { path: "/settings/guardrails", root: "page-guardrails" },
  { path: "/settings/languages", root: "page-languages" },
];

interface Arranged {
  inScope: Schemas["Prefix"];
}

/** A prefix inside the scope, a scoped operator over it and a global operator. */
async function arrange(api: Api): Promise<Arranged> {
  const inScope = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "203.0.113.0/24", description: "Lab" })).item!;
  await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "198.51.100.0/24", description: "IoT" });
  const casey = await api.post<Schemas["UserInfo"]>("/users", { name: CASEY.name, display_name: "Casey Example", password: CASEY.pin, roles: [] });
  await api.post("/access/grants", { subject: casey.id, role: "operator", scope: { kind: "prefix", value: { id: inScope.id, subtree: true } } });
  await api.post("/users", { name: OLIVE.name, display_name: "Olive Example", password: OLIVE.pin, roles: ["operator"] });
  return { inScope };
}

/** The ids of the commands the palette lists with the empty query. */
async function paletteCommands(page: Page): Promise<string[]> {
  await page.keyboard.press("Control+k");
  const palette = page.getByTestId("dialog-palette");
  await expect(palette).toBeVisible();
  await expect(palette.getByTestId("palette-item").first()).toBeVisible();
  const keys = await palette.getByTestId("palette-item").evaluateAll((items) => items.map((item) => item.getAttribute("data-key") ?? ""));
  await page.keyboard.press("Escape");
  await expect(palette).toHaveCount(0);
  return keys;
}

test("IAM-01: the settings pages and the updates page are closed to a scoped operator", async ({ page, api, signedIn }) => {
  void signedIn;
  await arrange(api);

  // The administrator sees each page, so an absence below is the role's doing.
  for (const { path, root } of ADMIN_PAGES) {
    await page.goto(path);
    await expect(page.getByTestId(root), path).toBeVisible();
    await expect(page.getByTestId("page-forbidden"), path).toHaveCount(0);
  }

  await signInCreatedAccount(api, CASEY.name, CASEY.pin, CASEY.changed);
  const session = await api.session();
  expect(session.roles).toEqual([]);
  expect(session.grants?.map((g) => g.role)).toEqual(["operator"]);
  for (const { path, root } of ADMIN_PAGES) {
    await page.goto(path);
    await expect(page.getByTestId("page-forbidden"), path).toBeVisible();
    await expect(page.getByTestId(root), path).toHaveCount(0);
    // No tab of the settings leads anywhere from a page one may not open.
    await expect(page.getByTestId("settings-nav"), path).toHaveCount(0);
  }
});

test("IAM-01: the secrets page tells a scoped operator that the role shows none, and a global operator sees the page", async ({ page, api, signedIn }) => {
  void signedIn;
  await arrange(api);
  await signInCreatedAccount(api, CASEY.name, CASEY.pin, CASEY.changed);
  await page.goto("/settings/secrets");
  await expect(page.getByTestId("page-secrets")).toBeVisible();
  await expect(page.getByTestId("secrets-no-access")).toBeVisible();
  await expect(page.getByTestId("secrets-create")).toHaveCount(0);
  await expect(page.getByTestId("settings-nav")).toHaveCount(0);

  await signInCreatedAccount(api, OLIVE.name, OLIVE.pin, OLIVE.changed);
  await page.goto("/settings/secrets");
  await expect(page.getByTestId("page-secrets")).toBeVisible();
  await expect(page.getByTestId("secrets-no-access")).toHaveCount(0);
  // An operator reads the secrets (and reveals them) but does not create one: that is the administrator's.
  await expect(page.getByTestId("secrets-create")).toHaveCount(0);
});

test("IAM-01: the rail keeps every area and the command palette drops Updates and Secrets for a scoped operator", async ({ page, api, signedIn }) => {
  void signedIn;
  await arrange(api);
  await page.goto("/");
  const rail = page.getByRole("navigation", { name: "Main" }).getByRole("link");
  await expect(rail.first()).toBeVisible();
  const railLinks = await rail.evaluateAll((links) => links.map((link) => link.getAttribute("href")));
  expect(await paletteCommands(page)).toEqual(expect.arrayContaining(["shell.goto.updates", "shell.goto.secrets", "shell.goto.cluster"]));

  await signInCreatedAccount(api, OLIVE.name, OLIVE.pin, OLIVE.changed);
  await page.goto("/");
  await expect(rail.first()).toBeVisible();
  const olive = await paletteCommands(page);
  expect(olive).toContain("shell.goto.secrets");
  expect(olive).not.toContain("shell.goto.updates");

  await signInCreatedAccount(api, CASEY.name, CASEY.pin, CASEY.changed);
  await page.goto("/");
  await expect(rail.first()).toBeVisible();
  // The rail is the same for everyone: a page one may not use says so when it is opened.
  expect(await rail.evaluateAll((links) => links.map((link) => link.getAttribute("href")))).toEqual(railLinks);
  const casey = await paletteCommands(page);
  expect(casey).toContain("shell.goto.cluster");
  expect(casey).toContain("shell.goto.ipam");
  expect(casey).not.toContain("shell.goto.updates");
  expect(casey).not.toContain("shell.goto.secrets");
});

test("IAM-01: a scoped operator gets no metrics, no connector, node or controller actions, and the refusals of the cluster and scans pages", async ({
  page,
  api,
  signedIn,
}) => {
  void signedIn;
  await arrange(api);

  // The administrator's pages carry the actions the scoped operator loses.
  await page.goto("/");
  await expect(page.getByTestId("metrics-tiles")).toBeVisible();
  await page.goto("/connectors");
  await expect(page.getByTestId("connectors-create")).toBeVisible();
  await page.goto("/nodes");
  await expect(page.getByTestId("nodes-enrol")).toBeVisible();
  await expect(page.getByTestId("nodes-tokens")).toBeVisible();
  await page.goto("/cluster");
  await expect(page.getByTestId("cluster-add-controller")).toBeVisible();
  await page.goto("/scans");
  await expect(page.getByTestId("scans-stop-all")).toBeVisible();

  await signInCreatedAccount(api, CASEY.name, CASEY.pin, CASEY.changed);

  await page.goto("/");
  await expect(page.getByTestId("page-dashboard")).toBeVisible();
  await expect(page.getByTestId("dashboard-waiting")).toBeVisible();
  await expect(page.getByTestId("metrics-tiles")).toHaveCount(0);

  await page.goto("/connectors");
  await expect(page.getByTestId("page-connectors")).toBeVisible();
  await expect(page.getByTestId("connectors-create")).toHaveCount(0);

  await page.goto("/nodes");
  await expect(page.getByTestId("page-nodes")).toBeVisible();
  await expect(page.getByTestId("nodes-enrol")).toHaveCount(0);
  await expect(page.getByTestId("nodes-tokens")).toHaveCount(0);

  // The cluster and scans pages are global-only: the server refuses the reads and the page says so.
  await page.goto("/cluster");
  await expect(page.getByTestId("page-cluster")).toBeVisible();
  await expect(page.getByTestId("error-notice").first()).toHaveAttribute("data-code", "auth.forbidden");
  await expect(page.getByTestId("cluster-add-controller")).toHaveCount(0);
  await expect(page.getByTestId("cluster-members")).toHaveCount(0);

  await page.goto("/scans");
  await expect(page.getByTestId("page-scans")).toBeVisible();
  await expect(page.getByTestId("error-notice").first()).toBeVisible();
  await expect(page.getByTestId("scans-stop-all")).toHaveCount(0);
});

test("IAM-01: the write actions of IPAM stay on the prefix of the grant for a scoped operator", async ({ page, api, signedIn }) => {
  void signedIn;
  await arrange(api);
  await signInCreatedAccount(api, CASEY.name, CASEY.pin, CASEY.changed);
  await page.goto("/ipam");
  await expect(page.getByTestId("page-ipam")).toBeVisible();
  await expect(page.getByTestId("ipam-add-prefix")).toBeVisible();
  // The prefix beside the scope is not even listed: a grant over one prefix reads only that prefix.
  await expect(withKey(page.getByTestId("ipam-tree"), "tree-node", "203.0.113.0/24")).toBeVisible();
  await expect(withKey(page.getByTestId("ipam-tree"), "tree-node", "198.51.100.0/24")).toHaveCount(0);
  await page.goto("/ipam/prefixes/203.0.113.0/24");
  const own = withKey(page, "prefix-pane", "203.0.113.0/24");
  await expect(own.getByTestId("prefix-edit")).toBeVisible();
  await expect(own.getByTestId("prefix-delete")).toBeVisible();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("IAM-01: renders the refusal of a settings page for a scoped operator in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    await arrange(api);
    await signInCreatedAccount(api, CASEY.name, CASEY.pin, CASEY.changed);
    await page.goto("/settings/backup");
    await expect(page.getByTestId("page-forbidden")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-forbidden"), "sv", testInfo, "forbidden");
    await page.goto("/settings/secrets");
    await expect(page.getByTestId("secrets-no-access")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-secrets"), "sv", testInfo, "secrets-no-access");
  });
});
