// WP7.4: the DHCP scopes against the real configuration routes. An IPAM network and a range of the
// role DHCP pool are made through the API; then, in the UI, a scope is created for the network, its
// pool shows with its size, an exclusion is added (the pool shrinks by the addresses it holds), the
// scope's option 6 is set and shows in the effective options of a MAC address with the level
// "scope", and the server settings are saved. Swedish rendering of the scope list, the scope page
// and the settings.
//
// NO FAKES: the DHCP, IPAM and settings routes are the real server's (the e2e server runs every
// module). Documentation values only: 192.0.2.0/24, MAC 00:00:5e:00:53:xx.

import type { Page } from "@playwright/test";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { cell, gridRow, withKey } from "./support/ui";

/** The network 192.0.2.0/24 and the pool 192.0.2.100 to 192.0.2.199 (100 addresses). */
async function arrange(api: Api): Promise<{ prefix: Schemas["Prefix"]; pool: Schemas["Range"] }> {
  const prefix = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "192.0.2.0/24", description: "Office" })).item!;
  const pool = (
    await api.post<Schemas["WriteResponse_Range"]>(`/prefixes/${prefix.id}/ranges`, {
      first: "192.0.2.100",
      last: "192.0.2.199",
      role: "dhcp_pool",
    })
  ).item!;
  return { prefix, pool };
}

const POOL_KEY = "192.0.2.100-192.0.2.199";

async function openTab(page: Page, tab: string): Promise<void> {
  await page.getByTestId(`scope-tab-${tab}`).click();
}

test("creates a scope for an IPAM network and sets its pool, an exclusion and an option", async ({ page, api, signedIn }) => {
  void signedIn;
  const { prefix, pool } = await arrange(api);

  await page.goto("/dhcp");
  await expect(page.getByTestId("page-dhcp-scopes")).toBeVisible();
  await expect(page.getByTestId("dhcp-nav").locator('[data-key="scopes"]')).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("dhcp-scopes-empty")).toBeVisible();

  // The network is offered, and the scope is made with the lease times of its own.
  await page.getByTestId("dhcp-scope-create").click();
  const form = page.getByTestId("dialog-scope-form");
  await form.getByTestId("field-prefix").selectOption(prefix.id);
  await form.getByTestId("field-lease-inherit").uncheck();
  await form.getByTestId("field-lease-default").fill("12");
  await form.getByTestId("field-lease-default-unit").selectOption("hours");
  await form.getByTestId("field-description").fill("Office LAN");
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);
  const row = gridRow(page, "dhcp-scopes", "192.0.2.0/24");
  await expect(row).toBeVisible();
  await expect(row.getByTestId("scope-enabled")).toHaveAttribute("data-key", "on");
  await expect(cell(row, "pools")).toHaveText("1");
  await expect(cell(row, "description")).toHaveText("Office LAN");
  await expect(row.getByTestId("scope-util")).toBeVisible();

  const stored = await api.get<Schemas["DhcpScopeItem"]>(`/dhcp/scopes/${prefix.id}`);
  expect(stored.lease).toMatchObject({ default_secs: 43_200 });

  // The scope page: settings, then the pool with its size.
  await row.getByTestId("scope-link").click();
  await expect(page.getByTestId("page-dhcp-scope")).toBeVisible();
  await expect(page.getByTestId("scope-name")).toHaveText("192.0.2.0/24");
  await expect(page.getByTestId("util-pool_size")).toHaveAttribute("data-value", "100");
  await openTab(page, "pools");
  const poolRow = gridRow(page, "dhcp-pools", POOL_KEY);
  await expect(poolRow).toBeVisible();
  await expect(poolRow.getByTestId("pool-size")).toHaveAttribute("data-value", "100");
  await expect(page.getByTestId("pools-ipam-link")).toHaveAttribute("href", "/ipam/prefixes/192.0.2.0/24");

  // An exclusion takes ten addresses out of the pool.
  await openTab(page, "exclusions");
  await page.getByTestId("exclusion-add").click();
  const exclusion = page.getByTestId("dialog-exclusion-form");
  await exclusion.getByTestId("field-first").fill("192.0.2.150");
  await exclusion.getByTestId("field-last").fill("198.51.100.159");
  await exclusion.getByTestId("form-submit").click();
  await expect(exclusion.getByTestId("field-error")).toHaveAttribute("data-field", "last");
  await exclusion.getByTestId("field-last").fill("192.0.2.159");
  await exclusion.getByTestId("form-submit").click();
  await expect(exclusion).toHaveCount(0);
  await expect(gridRow(page, "dhcp-exclusions", "192.0.2.150-192.0.2.159")).toBeVisible();
  await openTab(page, "pools");
  await expect(gridRow(page, "dhcp-pools", POOL_KEY).getByTestId("pool-size")).toHaveAttribute("data-value", "90");

  // The pool gets lease times of its own.
  await gridRow(page, "dhcp-pools", POOL_KEY).getByRole("button", { name: /Actions for/ }).click();
  await page.getByTestId("row-menu").locator('[data-key="edit"]').click();
  const poolForm = page.getByTestId("dialog-pool-form");
  await poolForm.getByTestId("field-lease-inherit").uncheck();
  await poolForm.getByTestId("field-lease-default").fill("2");
  await poolForm.getByTestId("field-lease-default-unit").selectOption("hours");
  await poolForm.getByTestId("field-lease-min").fill("30");
  await poolForm.getByTestId("field-lease-min-unit").selectOption("minutes");
  await poolForm.getByTestId("field-lease-max").fill("4");
  await poolForm.getByTestId("field-lease-max-unit").selectOption("hours");
  await poolForm.getByTestId("form-submit").click();
  await expect(poolForm).toHaveCount(0);
  const settings = await api.get<Schemas["DhcpPoolItem"]>(`/dhcp/pools/${pool.id}`);
  expect(settings.settings?.lease).toMatchObject({ default_secs: 7200, min_secs: 1800, max_secs: 14_400 });

  // Option 6 of the scope, and what a client gets.
  await openTab(page, "options");
  const editor = page.getByTestId("scope-optset");
  await expect(editor.getByTestId("optset-empty")).toBeVisible();
  await editor.getByTestId("optset-add").selectOption("dhcp4|6");
  const dns = withKey(editor, "optset-row", "dhcp4:6");
  await dns.getByTestId("optset-value").fill("192.0.2.53, 192.0.2.54");
  await editor.getByTestId("optset-save").click();
  await expect.poll(async () => (await api.get<Schemas["OptionSetItem"]>(`/dhcp/option-sets/scope:${prefix.id}`)).values.length).toBe(1);
  const set = await api.get<Schemas["OptionSetItem"]>(`/dhcp/option-sets/scope:${prefix.id}`);
  expect(set.values.map((v) => [v.code, v.name])).toEqual([[6, "domain-name-servers"]]);
  expect(set.values[0]?.typed).toEqual({ ipv4: { values: ["192.0.2.53", "192.0.2.54"] } });

  await page.getByTestId("field-mac").fill("00:00:5e:00:53:01");
  await page.getByTestId("effective-show").click();
  const effective = withKey(page.getByTestId("effective-options"), "effective-option", "dhcp4:6");
  await expect(effective).toHaveAttribute("data-level", "scope");
  await expect(effective).toContainText("192.0.2.53");
  await expect(effective.getByTestId("effective-level")).toHaveAttribute("data-key", "scope");

  // The server settings.
  await page.goto("/settings/dhcp");
  await expect(page.getByTestId("page-dhcp-settings")).toBeVisible();
  await expect(page.getByTestId("settings-nav").locator('[data-key="dhcp"]')).toBeVisible();
  await page.getByTestId("field-lease-default").fill("2");
  await page.getByTestId("field-lease-default-unit").selectOption("days");
  await page.getByTestId("dhcp-settings-save").click();
  await expect.poll(async () => (await api.get<Schemas["DhcpSettingsItem"]>("/dhcp/settings")).lease?.default_secs).toBe(172_800);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the scope pages and the settings in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    const { prefix } = await arrange(api);
    await api.post("/dhcp/scopes", { prefix: prefix.id, description: "Kontoret" });
    await page.goto("/dhcp");
    await expect(gridRow(page, "dhcp-scopes", "192.0.2.0/24")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dhcp-scopes"), "sv", testInfo, "dhcp-scopes");
    await page.getByTestId("dhcp-scope-create").click();
    await expectRendered(page, page.getByTestId("dialog-scope-form"), "sv", testInfo, "dhcp-scope-form");
    await page.getByTestId("form-cancel").click();

    await gridRow(page, "dhcp-scopes", "192.0.2.0/24").getByTestId("scope-link").click();
    await expectRendered(page, page.getByTestId("page-dhcp-scope"), "sv", testInfo, "dhcp-scope");
    await openTab(page, "options");
    await expect(page.getByTestId("scope-optset")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dhcp-scope"), "sv", testInfo, "dhcp-scope-options");

    await page.goto("/settings/dhcp");
    await expect(page.getByTestId("dhcp-settings-form")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dhcp-settings"), "sv", testInfo, "dhcp-settings");
  });
});
