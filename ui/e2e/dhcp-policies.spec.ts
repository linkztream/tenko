// WP8.6: the policy editor with a class, and "why did this client get this value", against the real
// configuration routes and the matcher of WP8.4. A class of UEFI x64 clients is made in the UI with
// the architecture picker; a policy of the scope on it gets a DDNS action, and once created it stays
// open for its options, where option 67 is set; the scope's options tab then asks for a client with
// architecture 7 and shows the class, the policy and option 67 from the policy, and for a BIOS
// client none of them. Swedish rendering of the policies page.
//
// NO FAKES: the DHCP and IPAM routes are the real server's (the e2e server runs every module), and
// the effective view reads the compiled matcher. The network of the scope is made through the API.
// Documentation values only: 192.0.2.0/24, MAC 00:00:5e:00:53:xx.

import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { gridRow, withKey } from "./support/ui";

/** The network 192.0.2.0/24 with a scope. */
async function arrange(api: Api): Promise<Schemas["Prefix"]> {
  const prefix = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "192.0.2.0/24", description: "Lab" })).item!;
  await api.post("/dhcp/scopes", { prefix: prefix.id });
  return prefix;
}

test("a policy on a class sets a boot file, and the effective view says why a client gets it", async ({ page, api, signedIn }) => {
  void signedIn;
  const prefix = await arrange(api);

  // The class: architecture 7 or 9 (UEFI x64), picked from the list of known architectures.
  await page.goto("/dhcp/classes");
  await page.getByTestId("dhcp-class-create").click();
  const classForm = page.getByTestId("dialog-class-form");
  await classForm.getByTestId("field-name").fill("uefi-x64");
  const first = classForm.getByTestId("match-row").first();
  await first.getByTestId("match-kind").selectOption("architecture");
  await first.getByTestId("match-arch").selectOption("7");
  await classForm.getByTestId("match-add").click();
  const second = classForm.getByTestId("match-row").nth(1);
  await second.getByTestId("match-kind").selectOption("architecture");
  await second.getByTestId("match-arch").selectOption("9");
  await classForm.getByTestId("form-submit").click();
  await expect(classForm).toHaveCount(0);
  const classes = await api.get<Schemas["Page_DhcpClassItem"]>("/dhcp/classes");
  const uefi = classes.items.find((c) => c.name === "uefi-x64")!;
  expect(uefi.matches).toEqual([{ architecture: { code: 7 } }, { architecture: { code: 9 } }]);

  // The policy of the scope on the class, with a DDNS action; once created it stays open for its options.
  await page.goto("/dhcp/policies");
  await page.getByTestId("dhcp-policy-create").click();
  const policyForm = page.getByTestId("dialog-policy-form");
  await policyForm.getByTestId("field-name").fill("uefi-boot");
  await policyForm.getByTestId("field-scope").selectOption(prefix.id);
  await policyForm.getByTestId("term-row").first().getByTestId("term-class").selectOption(uefi.id);
  await expect(policyForm.getByTestId("policy-options-new")).toBeVisible();
  await policyForm.getByTestId("field-policy-ddns-on").check();
  await policyForm.getByTestId("policy-ddns").getByTestId("field-ddns-enabled").check();
  await policyForm.getByTestId("form-submit").click();
  const optset = policyForm.getByTestId("policy-optset");
  await expect(optset).toBeVisible();
  await optset.getByTestId("optset-add").selectOption("dhcp4|67");
  await withKey(optset, "optset-row", "dhcp4:67").getByTestId("optset-value").fill("ipxe.efi");
  await optset.getByTestId("optset-save").click();
  await expect(withKey(optset, "optset-row", "dhcp4:67")).toBeVisible();
  await policyForm.getByTestId("form-cancel").click();
  await expect(policyForm).toHaveCount(0);

  const policies = await api.get<Schemas["Page_DhcpPolicyItem"]>("/dhcp/policies");
  const policy = policies.items.find((p) => p.name === "uefi-boot")!;
  expect(policy.condition).toEqual({ join: "and", terms: [{ class: uefi.id }] });
  expect(policy.action?.ddns?.enabled).toBe(true);
  const set = await api.get<Schemas["OptionSetItem"]>(`/dhcp/option-sets/policy:${policy.id}`);
  expect(set.values.map((v) => v.code)).toEqual([67]);
  await expect(gridRow(page, "dhcp-policies", "uefi-boot").getByTestId("policy-condition-words")).toHaveText("in class uefi-x64");

  // Why a UEFI x64 client gets option 67: the class, the policy, the level and its owner.
  await page.goto(`/dhcp/scopes/${prefix.id}/options`);
  await page.getByTestId("field-mac").fill("00:00:5e:00:53:01");
  await page.getByTestId("field-architecture").selectOption("7");
  await page.getByTestId("field-host_name").fill("laptop-7");
  await page.getByTestId("effective-show").click();
  await expect(withKey(page, "effective-class", "uefi-x64")).toBeVisible();
  await expect(withKey(page, "effective-policy", "uefi-boot")).toBeVisible();
  const boot = page.locator('[data-testid="effective-option"][data-code="67"]');
  await expect(boot).toHaveAttribute("data-level", "policy");
  await expect(boot).toHaveAttribute("data-owner", "uefi-boot");
  await expect(boot).toContainText("ipxe.efi");

  // A BIOS client is in no class and gets no boot file from the policy.
  await page.getByTestId("field-architecture").selectOption("0");
  await page.getByTestId("effective-show").click();
  await expect(page.getByTestId("effective-classes-none")).toBeVisible();
  await expect(page.locator('[data-testid="effective-option"][data-code="67"]')).toHaveCount(0);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the policy editor with its four actions in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    await arrange(api);
    await page.goto("/dhcp/policies");
    await page.getByTestId("dhcp-policy-create").click();
    const policyForm = page.getByTestId("dialog-policy-form");
    await policyForm.getByTestId("field-policy-ddns-on").check();
    await expect(policyForm.getByTestId("policy-ddns").getByTestId("field-ddns-enabled")).toBeVisible();
    await expectRendered(page, policyForm, "sv", testInfo, "dhcp-policy-form");
  });
});
