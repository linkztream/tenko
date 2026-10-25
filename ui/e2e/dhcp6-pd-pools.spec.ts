// WP9.2: the delegation pools of a DHCPv6 scope against the real configuration routes. An IPv6
// network and a scope on it are made through the API; then, in the UI, the pools tab of the scope has
// a section of delegation pools (empty at first), a delegated length that is not longer than the
// network's is refused at its field, a pool is added through the dialog and listed with its
// delegated length (/60) and its 16 prefixes, the IPAM range it made has the role Delegation pool, and
// the scope's utilization counts the delegated prefixes. Swedish rendering of the tab.
//
// NO FAKES: the DHCP and IPAM routes are the real server's. Documentation values only:
// 2001:db8:180::/48.

import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { cell, gridRow } from "./support/ui";

const FIRST = "2001:db8:180:100::";
const LAST = "2001:db8:180:1ff:ffff:ffff:ffff:ffff";

/** The network 2001:db8:180::/48 and a scope on it, which has no pool yet. */
async function arrange(api: Api): Promise<{ prefix: Schemas["Prefix"] }> {
  const prefix = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "2001:db8:180::/48", description: "Delegation, IPv6" })).item!;
  await api.post("/dhcp/scopes", { prefix: prefix.id, description: "Delegation scope, IPv6" });
  return { prefix };
}

const isRangePost = (id: string) => (response: { url(): string; request(): { method(): string } }) =>
  response.request().method() === "POST" && response.url().endsWith(`/api/v1/prefixes/${id}/ranges`);

test("adds a delegation pool to a DHCPv6 scope and lists it with its prefixes", async ({ page, api, signedIn }) => {
  void signedIn;
  const { prefix } = await arrange(api);

  await page.goto(`/dhcp/scopes/${prefix.id}/pools`);
  await expect(page.getByTestId("scope-name")).toHaveText("2001:db8:180::/48");
  // The delegation pools are a section of their own below the address pools, empty at first.
  await expect(page.getByTestId("pd-pools")).toBeVisible();
  await expect(page.getByTestId("pd-pools-empty")).toBeVisible();

  // A delegated length that is not longer than the length of the network is refused at its field.
  await page.getByTestId("pd-pool-add").click();
  const dialog = page.getByTestId("dialog-pd-pool-form");
  await expect(dialog).toBeVisible();
  await dialog.getByTestId("field-first").fill(FIRST);
  await dialog.getByTestId("field-last").fill(LAST);
  await dialog.getByTestId("field-delegated_len").fill("40");
  await dialog.getByTestId("form-submit").click();
  await expect(dialog.getByTestId("field-error")).toHaveAttribute("data-field", "delegated_len");
  expect((await api.get<{ items: Schemas["Range"][] }>(`/prefixes/${prefix.id}/ranges`)).items).toHaveLength(0);

  // A length of 60 is accepted: the pool is an IPAM range of the role Delegation pool.
  await dialog.getByTestId("field-delegated_len").fill("60");
  const [made] = await Promise.all([page.waitForResponse(isRangePost(prefix.id)), dialog.getByTestId("form-submit").click()]);
  expect(made.ok()).toBe(true);
  expect(made.request().postDataJSON()).toEqual({ first: FIRST, last: LAST, delegated_len: 60, role: "dhcp_pd_pool" });
  await expect(dialog).toHaveCount(0);

  // The row: the delegated length and the 16 prefixes of a /60 between the two addresses, none bound.
  const listed = gridRow(page, "dhcp-pd-pools", `${FIRST}-${LAST}`);
  await expect(listed).toBeVisible();
  await expect(cell(listed, "len")).toHaveText("/60");
  await expect(cell(listed, "size")).toHaveText("16");
  await expect(listed.getByTestId("pd-pool-size")).toHaveAttribute("data-value", "16");
  await expect(listed.getByTestId("pd-pool-leased")).toHaveAttribute("data-value", "0");
  await expect(page.getByTestId("pd-pools-empty")).toHaveCount(0);

  // The server's view: the range, the pool of the scope and the utilization in prefixes.
  const ranges = (await api.get<{ items: Schemas["Range"][] }>(`/prefixes/${prefix.id}/ranges`)).items;
  expect(ranges).toHaveLength(1);
  expect(ranges[0]).toMatchObject({ role: "dhcp_pd_pool", delegated_len: 60, first: FIRST, last: LAST });
  const pools = (await api.get<{ items: Schemas["DhcpPoolItem"][] }>("/dhcp/pools", { scope: prefix.id })).items;
  expect(pools).toHaveLength(1);
  expect(pools[0]).toMatchObject({ role: "dhcp_pd_pool", delegated_len: 60, size: 16, leased: 0 });
  const util = await api.get<Schemas["DhcpScopeUtilization"]>(`/dhcp/scopes/${prefix.id}/utilization`);
  expect(util.pd).toMatchObject({ pools: 1, pool_size: 16, leased: 0, free: 16 });

  // The settings tab says the same in words.
  await page.getByTestId("scope-tab-settings").click();
  await expect(page.getByTestId("util-pd")).toHaveAttribute("data-size", "16");
  await expect(page.getByTestId("util-pd")).toHaveAttribute("data-leased", "0");
});

test("refuses a delegation pool off the boundaries of its length before anything is sent", async ({ page, api, signedIn }) => {
  void signedIn;
  const { prefix } = await arrange(api);
  await page.goto(`/dhcp/scopes/${prefix.id}/pools`);
  await page.getByTestId("pd-pool-add").click();
  const dialog = page.getByTestId("dialog-pd-pool-form");
  // 2001:db8:180:108:: is not the first address of a /60 prefix.
  await dialog.getByTestId("field-first").fill("2001:db8:180:108::");
  await dialog.getByTestId("field-last").fill(LAST);
  await dialog.getByTestId("field-delegated_len").fill("60");
  await dialog.getByTestId("form-submit").click();
  await expect(dialog.getByTestId("field-error")).toHaveAttribute("data-field", "first");
  expect((await api.get<{ items: Schemas["Range"][] }>(`/prefixes/${prefix.id}/ranges`)).items).toHaveLength(0);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the delegation pools in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    const { prefix } = await arrange(api);
    await api.post(`/prefixes/${prefix.id}/ranges`, { first: FIRST, last: LAST, role: "dhcp_pd_pool", delegated_len: 60 });
    await page.goto(`/dhcp/scopes/${prefix.id}/pools`);
    await expect(gridRow(page, "dhcp-pd-pools", `${FIRST}-${LAST}`)).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dhcp-scope"), "sv", testInfo, "dhcp6-pd-pools");
    // The dialog is words too.
    await page.getByTestId("pd-pool-add").click();
    await expectRendered(page, page.getByTestId("dialog-pd-pool-form"), "sv");
  });
});
