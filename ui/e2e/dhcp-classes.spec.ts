// WP7.4: classes, policies and MAC filters against the real configuration routes. A class with a
// vendor class prefix match is created in the UI, a policy of a scope on it, and a MAC filter; a
// deletion of the class is refused while the policy names it, with the server's message, and goes
// through once the policy is deleted; the filter is deleted too.
//
// NO FAKES: the DHCP and IPAM routes are the real server's (the e2e server runs every module). The
// network of the scope is made through the API. Documentation values only: 192.0.2.0/24, MAC
// 00:00:5e:00:53:xx.

import type { Locator, Page } from "@playwright/test";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { gridRow, withKey } from "./support/ui";

/** The network 192.0.2.0/24 with a scope. */
async function arrange(api: Api): Promise<Schemas["Prefix"]> {
  const prefix = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "192.0.2.0/24", description: "Office" })).item!;
  await api.post("/dhcp/scopes", { prefix: prefix.id });
  return prefix;
}

async function rowAction(page: Page, row: Locator, action: string): Promise<void> {
  await row.getByRole("button", { name: /Actions for/ }).click();
  await page.getByTestId("row-menu").locator(`[data-key="${action}"]`).click();
}

test("creates a class, a policy on it and a MAC filter, and deletes them", async ({ page, api, signedIn }) => {
  void signedIn;
  const prefix = await arrange(api);

  // The class: a vendor class prefix match.
  await page.goto("/dhcp/classes");
  await expect(page.getByTestId("page-dhcp-classes")).toBeVisible();
  await expect(page.getByTestId("dhcp-nav").locator('[data-key="classes"]')).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("dhcp-classes-empty")).toBeVisible();
  await page.getByTestId("dhcp-class-create").click();
  const classForm = page.getByTestId("dialog-class-form");
  await classForm.getByTestId("field-name").fill("pxe-clients");
  const match = classForm.getByTestId("match-row").first();
  await match.getByTestId("match-kind").selectOption("vendor_class");
  await match.getByTestId("match-value").fill("PXEClient");
  await match.getByTestId("match-prefix").check();
  await classForm.getByTestId("form-submit").click();
  await expect(classForm).toHaveCount(0);
  const classRow = gridRow(page, "dhcp-classes", "pxe-clients");
  await expect(classRow.getByTestId("class-match")).toHaveText('vendor class starting with "PXEClient"');
  await expect(classRow.getByTestId("class-used-by")).toHaveAttribute("data-value", "0");
  const classes = await api.get<Schemas["Page_DhcpClassItem"]>("/dhcp/classes");
  expect(classes.items[0]?.matches).toEqual([{ vendor_class: { value: "PXEClient", prefix: true } }]);
  const classId = classes.items[0]!.id;

  // The policy of the scope on the class.
  await page.goto("/dhcp/policies");
  await expect(page.getByTestId("page-dhcp-policies")).toBeVisible();
  await expect(page.getByTestId("policies-note")).toBeVisible();
  await page.getByTestId("dhcp-policy-create").click();
  const policyForm = page.getByTestId("dialog-policy-form");
  await policyForm.getByTestId("field-name").fill("pxe-boot");
  await policyForm.getByTestId("field-scope").selectOption(prefix.id);
  const term = policyForm.getByTestId("term-row").first();
  await term.getByTestId("term-class").selectOption(classId);
  await policyForm.getByTestId("field-lease-inherit").uncheck();
  await policyForm.getByTestId("field-lease-default").fill("1");
  await policyForm.getByTestId("field-lease-default-unit").selectOption("hours");
  await policyForm.getByTestId("field-lease-min").fill("10");
  await policyForm.getByTestId("field-lease-min-unit").selectOption("minutes");
  await policyForm.getByTestId("field-lease-max").fill("2");
  await policyForm.getByTestId("field-lease-max-unit").selectOption("hours");
  await policyForm.getByTestId("form-submit").click();
  // WP8.6: a new policy stays open for its options; closing it leaves the policy as created.
  await expect(policyForm.getByTestId("policy-optset")).toBeVisible();
  await policyForm.getByTestId("form-cancel").click();
  await expect(policyForm).toHaveCount(0);
  const policyRow = gridRow(page, "dhcp-policies", "pxe-boot");
  await expect(policyRow.getByTestId("policy-condition-words")).toHaveText("in class pxe-clients");
  await expect(policyRow.getByTestId("policy-scope")).toHaveAttribute("data-key", "192.0.2.0/24");
  await expect(policyRow.getByTestId("policy-enabled")).toHaveAttribute("data-key", "on");
  const policies = await api.get<Schemas["Page_DhcpPolicyItem"]>("/dhcp/policies");
  expect(policies.items[0]?.condition).toEqual({ join: "and", terms: [{ class: classId }] });
  expect(policies.items[0]?.action?.lease).toMatchObject({ default_secs: 3600, min_secs: 600, max_secs: 7200 });

  // A MAC filter.
  await page.goto("/dhcp/filters");
  await expect(page.getByTestId("page-dhcp-filters")).toBeVisible();
  await page.getByTestId("dhcp-filter-create").click();
  const filterForm = page.getByTestId("dialog-filter-form");
  await filterForm.getByTestId("field-mac").fill("00:00:5E:00:53:*");
  await filterForm.getByTestId("field-kind-deny").check();
  await filterForm.getByTestId("field-note").fill("Guests");
  await filterForm.getByTestId("form-submit").click();
  await expect(filterForm).toHaveCount(0);
  const filterRow = gridRow(page, "dhcp-filters", "00:00:5e:00:53:*");
  await expect(filterRow.getByTestId("filter-kind")).toHaveAttribute("data-key", "deny");
  // A second entry for the same pattern is refused under the field.
  await page.getByTestId("dhcp-filter-create").click();
  await filterForm.getByTestId("field-mac").fill("00:00:5e:00:53:*");
  await filterForm.getByTestId("form-submit").click();
  await expect(filterForm.getByTestId("field-error")).toHaveAttribute("data-field", "mac");
  await filterForm.getByTestId("form-cancel").click();

  // The class is named by the policy: its deletion is refused with the server's message.
  await page.goto("/dhcp/classes");
  await expect(gridRow(page, "dhcp-classes", "pxe-clients").getByTestId("class-used-by")).toHaveAttribute("data-value", "1");
  await rowAction(page, gridRow(page, "dhcp-classes", "pxe-clients"), "delete");
  const classDelete = page.getByTestId("dialog-class-delete");
  await classDelete.getByTestId("confirm-ok").click();
  await expect(classDelete.getByTestId("error-notice")).toHaveAttribute("data-code", "dhcp.class.in_use");
  await classDelete.getByTestId("confirm-cancel").click();
  await expect(gridRow(page, "dhcp-classes", "pxe-clients")).toBeVisible();

  // Delete the policy, then the class, then the filter.
  await page.goto("/dhcp/policies");
  await rowAction(page, gridRow(page, "dhcp-policies", "pxe-boot"), "delete");
  await page.getByTestId("dialog-policy-delete").getByTestId("confirm-ok").click();
  await expect(page.getByTestId("dhcp-policies-empty")).toBeVisible();
  await page.goto("/dhcp/classes");
  await rowAction(page, gridRow(page, "dhcp-classes", "pxe-clients"), "delete");
  await page.getByTestId("dialog-class-delete").getByTestId("confirm-ok").click();
  await expect(page.getByTestId("dhcp-classes-empty")).toBeVisible();
  await page.goto("/dhcp/filters");
  await rowAction(page, gridRow(page, "dhcp-filters", "00:00:5e:00:53:*"), "delete");
  await page.getByTestId("dialog-filter-delete").getByTestId("confirm-ok").click();
  await expect(page.getByTestId("dhcp-filters-empty")).toBeVisible();
  expect((await api.get<Schemas["Page_DhcpFilterItem"]>("/dhcp/filters")).items).toEqual([]);
});

test("shows the shared networks and the options with a custom definition", async ({ page, api, signedIn }) => {
  void signedIn;
  const prefix = await arrange(api);

  // A shared network the scope joins; it is not deleted while the scope belongs to it.
  await page.goto("/dhcp/shared-networks");
  await page.getByTestId("dhcp-network-create").click();
  const networkForm = page.getByTestId("dialog-network-form");
  await networkForm.getByTestId("field-name").fill("office-links");
  await networkForm.getByTestId("form-submit").click();
  await expect(networkForm).toHaveCount(0);
  const networks = await api.get<Schemas["Page_SharedNetworkItem"]>("/dhcp/shared-networks");
  await api.patch(`/dhcp/scopes/${prefix.id}`, { shared_network: networks.items[0]!.id });
  await page.reload();
  const networkRow = gridRow(page, "dhcp-networks", "office-links");
  await expect(withKey(networkRow, "network-scope", "192.0.2.0/24")).toBeVisible();
  await rowAction(page, networkRow, "delete");
  const networkDelete = page.getByTestId("dialog-network-delete");
  await networkDelete.getByTestId("confirm-ok").click();
  await expect(networkDelete.getByTestId("error-notice")).toHaveAttribute("data-code", "dhcp.shared_network.in_use");
  await networkDelete.getByTestId("confirm-cancel").click();

  // A custom definition, then a server option of that code.
  await page.goto("/dhcp/options");
  await expect(page.getByTestId("page-dhcp-options")).toBeVisible();
  await page.getByTestId("dhcp-def-create").click();
  const defForm = page.getByTestId("dialog-def-form");
  await defForm.getByTestId("field-code").fill("240");
  await defForm.getByTestId("field-name").fill("site-name");
  await defForm.getByTestId("field-kind").selectOption("string");
  await defForm.getByTestId("form-submit").click();
  await expect(defForm).toHaveCount(0);
  await expect(gridRow(page, "dhcp-option-defs", "dhcp4:240")).toBeVisible();
  const server = page.getByTestId("server-optset");
  await server.getByTestId("optset-add").selectOption("dhcp4|240");
  await withKey(server, "optset-row", "dhcp4:240").getByTestId("optset-value").fill("lab");
  await server.getByTestId("optset-save").click();
  await expect.poll(async () => (await api.get<Schemas["OptionSetItem"]>("/dhcp/option-sets/server")).values.length).toBe(1);

  // The definition is used now: its deletion is refused with the server's message.
  await page.reload();
  await rowAction(page, gridRow(page, "dhcp-option-defs", "dhcp4:240"), "delete");
  const defDelete = page.getByTestId("dialog-def-delete");
  await defDelete.getByTestId("confirm-ok").click();
  await expect(defDelete.getByTestId("error-notice")).toHaveAttribute("data-code", "dhcp.option_def.in_use");
  // The catalog lists the codes the server sets itself.
  await defDelete.getByTestId("confirm-cancel").click();
  // The grid renders only the rows in view: scroll it until the server identifier's row is in.
  const catalog = page.getByTestId("grid-dhcp-catalog");
  const managed = withKey(catalog, "row", "dhcp4:54");
  await expect
    .poll(async () => {
      if ((await managed.count()) > 0) return true;
      await catalog.evaluate((root) => {
        for (const node of [root, ...Array.from(root.querySelectorAll("*"))]) {
          if (node.scrollHeight > node.clientHeight + 1) node.scrollTop += 200;
        }
      });
      return false;
    })
    .toBe(true);
  await managed.scrollIntoViewIfNeeded();
  await expect(managed.getByTestId("catalog-managed")).toBeVisible();
});
