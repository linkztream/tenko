// WP9.4: a DHCPv6 scope against the real configuration routes. An IPv6 network, a range of the role
// DHCP pool and a scope are made through the API; then, in the UI, the scope list tags the scope
// DHCPv6, the scope page has a DHCPv6 tab (and no network boot tab), the default of the preferred
// lifetime is explained with its value, a preferred lifetime above the valid lifetime is refused,
// the preferred lifetime, Rapid Commit and the relay Interface-Id are saved and kept across a
// reload, and the DHCPv6 options of the scope are edited with the DHCPv6 catalog. Swedish
// rendering of the tab.
//
// NO FAKES: the DHCP and IPAM routes are the real server's. Documentation values only:
// 2001:db8:10::/64.

import type { Page } from "@playwright/test";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { cell, gridRow, withKey } from "./support/ui";

/** The valid lifetime of the scope: its own default lease time, 2 hours. */
const VALID_SECS = 7200;

/** The network 2001:db8:10::/64, its pool 2001:db8:10::100 to 2001:db8:10::1ff and a scope with lease times of its own. */
async function arrange(api: Api): Promise<{ prefix: Schemas["Prefix"] }> {
  const prefix = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "2001:db8:10::/64", description: "Office, IPv6" })).item!;
  await api.post(`/prefixes/${prefix.id}/ranges`, { first: "2001:db8:10::100", last: "2001:db8:10::1ff", role: "dhcp_pool" });
  await api.post("/dhcp/scopes", {
    prefix: prefix.id,
    description: "Office LAN, IPv6",
    lease: { default_secs: VALID_SECS, min_secs: 600, max_secs: 86_400 },
  });
  return { prefix };
}

const isScopePatch = (id: string) => (response: { url(): string; request(): { method(): string } }) =>
  response.request().method() === "PATCH" && response.url().endsWith(`/api/v1/dhcp/scopes/${id}`);

async function openV6Tab(page: Page, id: string): Promise<void> {
  await page.goto(`/dhcp/scopes/${id}`);
  await expect(page.getByTestId("scope-name")).toHaveText("2001:db8:10::/64");
  await page.getByTestId("scope-tab-v6").click();
  await expect(page.getByTestId("scope-v6")).toBeVisible();
}

test("shows the family, explains the defaults and saves the DHCPv6 settings of a scope", async ({ page, api, signedIn }) => {
  void signedIn;
  const { prefix } = await arrange(api);

  // The scope list tags the scope.
  await page.goto("/dhcp");
  const listed = gridRow(page, "dhcp-scopes", "2001:db8:10::/64");
  await expect(listed).toBeVisible();
  await expect(cell(listed, "family").getByTestId("scope-family")).toHaveAttribute("data-key", "v6");
  await expect(cell(listed, "pools")).toHaveText("1");

  // The scope page: the family, the DHCPv6 tab, no network boot tab.
  await listed.getByTestId("scope-link").click();
  await expect(page.getByTestId("page-dhcp-scope")).toBeVisible();
  await expect(page.getByTestId("scope-family")).toHaveAttribute("data-key", "v6");
  await expect(page.getByTestId("scope-tab-v6")).toBeVisible();
  await expect(page.getByTestId("scope-tab-boot")).toHaveCount(0);
  await expect(page.getByTestId("field-server_id")).toHaveCount(0);
  await expect(page.getByTestId("scope-classes")).toHaveCount(0);

  // The defaults: five eighths of the valid lifetime, here 7 200 s.
  await page.getByTestId("scope-tab-v6").click();
  await expect(page.getByTestId("scope-v6")).toBeVisible();
  await expect(page.getByTestId("v6-preferred-default")).toHaveAttribute("data-value", String(Math.floor((VALID_SECS * 5) / 8)));
  await expect(page.getByTestId("field-rapid_commit")).toBeChecked();
  await expect(page.getByTestId("field-preferred")).toHaveValue("");

  // A preferred lifetime above the valid lifetime is refused before anything is sent.
  await page.getByTestId("field-preferred").fill(String(VALID_SECS + 1));
  await page.getByTestId("v6-save").click();
  await expect(page.getByTestId("field-error")).toHaveAttribute("data-field", "preferred");

  // The preferred lifetime and the relay Interface-Id are saved with the whole v6 object.
  await page.getByTestId("field-preferred").fill("3600");
  await page.getByTestId("field-interface_id").fill("Gi0/1");
  const [saved] = await Promise.all([page.waitForResponse(isScopePatch(prefix.id)), page.getByTestId("v6-save").click()]);
  expect(saved.ok()).toBe(true);
  expect(saved.request().postDataJSON()).toEqual({ v6: { rapid_commit: true, preferred_secs: 3600, interface_id: "Gi0/1" } });
  const stored = await api.get<Schemas["DhcpScopeItem"]>(`/dhcp/scopes/${prefix.id}`);
  expect(stored.family).toBe("v6");
  expect(stored.v6).toMatchObject({ preferred_secs: 3600, interface_id: "Gi0/1" });

  // The values are kept across a reload.
  await page.reload();
  await expect(page.getByTestId("scope-v6")).toBeVisible();
  await expect(page.getByTestId("field-preferred")).toHaveValue("3600");
  await expect(page.getByTestId("field-interface_id")).toHaveValue("Gi0/1");
  await expect(page.getByTestId("field-rapid_commit")).toBeChecked();

  // Rapid Commit off.
  await page.getByTestId("field-rapid_commit").uncheck();
  const [off] = await Promise.all([page.waitForResponse(isScopePatch(prefix.id)), page.getByTestId("v6-save").click()]);
  expect(off.ok()).toBe(true);
  await expect.poll(async () => (await api.get<Schemas["DhcpScopeItem"]>(`/dhcp/scopes/${prefix.id}`)).v6?.rapid_commit).toBe(false);

  // The defaults again.
  const [cleared] = await Promise.all([page.waitForResponse(isScopePatch(prefix.id)), page.getByTestId("v6-defaults").click()]);
  expect(cleared.request().postDataJSON()).toEqual({ clear_v6: true });
  await expect(page.getByTestId("field-preferred")).toHaveValue("");
  await expect(page.getByTestId("field-rapid_commit")).toBeChecked();
  await expect.poll(async () => (await api.get<Schemas["DhcpScopeItem"]>(`/dhcp/scopes/${prefix.id}`)).v6 ?? null).toBeNull();
});

test("says on the network boot tab of a DHCPv6 scope that it is DHCPv4 only", async ({ page, api, signedIn }) => {
  void signedIn;
  const { prefix } = await arrange(api);
  // The old link to the tab does not lead to a dead tab.
  await page.goto(`/dhcp/scopes/${prefix.id}/boot`);
  await expect(page.getByTestId("scope-name")).toHaveText("2001:db8:10::/64");
  await expect(page.getByTestId("scope-boot-v6").getByTestId("v4-only")).toBeVisible();
  await expect(page.getByTestId("scope-boot")).toHaveCount(0);
});

test("edits the DHCPv6 options of the scope with the DHCPv6 catalog", async ({ page, api, signedIn }) => {
  void signedIn;
  const { prefix } = await arrange(api);
  await page.goto(`/dhcp/scopes/${prefix.id}`);
  await page.getByTestId("scope-tab-options").click();
  const editor = page.getByTestId("scope-optset");
  await expect(editor.getByTestId("optset-empty")).toBeVisible();
  // Only DHCPv6 codes are offered: 23 (the DNS servers) is, 3 (the IA_NA the server writes) is not.
  const add = editor.getByTestId("optset-add");
  await expect(add.locator('option[value="dhcp6|23"]')).toHaveCount(1);
  await expect(add.locator('option[value="dhcp6|3"]')).toHaveCount(0);
  await expect(add.locator('option[value="dhcp4|6"]')).toHaveCount(0);
  await add.selectOption("dhcp6|23");
  await withKey(editor, "optset-row", "dhcp6:23").getByTestId("optset-value").fill("2001:db8:10::53");
  await editor.getByTestId("optset-save").click();
  await expect
    .poll(async () => (await api.get<Schemas["OptionSetItem"]>(`/dhcp/option-sets/scope:${prefix.id}`)).values.map((v) => [v.space, v.code, v.name]))
    .toEqual([["dhcp6", 23, "dns-servers"]]);
  const set = await api.get<Schemas["OptionSetItem"]>(`/dhcp/option-sets/scope:${prefix.id}`);
  expect(set.values[0]?.typed).toEqual({ ipv6: { values: ["2001:db8:10::53"] } });
  // The effective options of a client are a DHCPv4 view.
  await expect(page.getByTestId("effective-show")).toHaveCount(0);
  await expect(page.getByTestId("v4-only")).toBeVisible();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the DHCPv6 tab in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    const { prefix } = await arrange(api);
    await openV6Tab(page, prefix.id);
    await expectRendered(page, page.getByTestId("page-dhcp-scope"), "sv", testInfo, "dhcp6-scope");
  });
});
