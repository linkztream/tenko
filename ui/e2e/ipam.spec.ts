// Scenario 3: IPAM end to end (IPAM-02, IPAM-06 to IPAM-09, IPAM-18, API-09). An operator
// creates a prefix and takes its next free address, reserves a host, defines a custom field
// and tags an object, acknowledges a plan warning, and brings back what was deleted. Every
// write goes through the plan dialog, and every result is checked in the UI and through the
// public API. Documentation ranges only: 192.0.2.0/24, 2001:db8::/32, MAC 00-00-5E-00-53-xx.
//
// Setup creates the tenant and VRF `default`, so a fresh installation takes its first prefix
// straight from the IPAM view.
// Moving objects and importing spreadsheets belong to other scenarios.

import type { Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import {
  actionsOf,
  confirmPlan,
  historyActions,
  hostByName,
  openRowMenu,
  planChange,
  prefixByCidr,
  rowMenuItem,
} from "./support/ipam";
import { cell, gridRow, withIndex, withKey } from "./support/ui";

/** The hexadecimal digits of a MAC address, whatever its separators and case. */
function macDigits(text: string): string {
  return text.replace(/[^0-9a-f]/gi, "").toLowerCase();
}

test("a fresh installation takes its first prefix without creating a VRF first", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");
  // Setup created the tenant and the VRF `default`; the tenancy page lists the VRF.
  expect((await api.get<Schemas["Page_Vrf"]>("/vrfs")).items.map((v) => v.name)).toEqual(["default"]);
  expect((await api.get<Schemas["Page_Tenant"]>("/tenants")).items.map((t) => t.name)).toEqual(["default"]);
  await page.goto("/ipam/tenants");
  await expect(page.getByTestId("page-ipam-tenancy")).toBeVisible();
  await expect(gridRow(page, "vrfs", "default")).toBeVisible();

  await page.goto("/ipam");
  await expect(page.getByTestId("page-ipam")).toBeVisible();
  await expect(page.getByTestId("ipam-add-prefix")).toBeEnabled();
  await page.getByTestId("ipam-add-prefix").click();
  const form = page.getByTestId("dialog-prefix-form");
  await form.getByTestId("field-cidr").fill("192.0.2.0/24");
  await form.getByTestId("form-submit").click();
  await confirmPlan(page);
  await expect(withKey(page.getByTestId("ipam-tree"), "tree-node", "192.0.2.0/24")).toBeVisible();
  expect((await prefixByCidr(api, "192.0.2.0/24"))?.cidr).toBe("192.0.2.0/24");
});

test("a prefix is created through the plan dialog and its next free address is claimed", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");

  // Create 192.0.2.0/24: the form, then the plan with its summary, then the apply.
  await page.goto("/ipam");
  await expect(page.getByTestId("page-ipam")).toBeVisible();
  await page.getByTestId("ipam-add-prefix").click();
  const form = page.getByTestId("dialog-prefix-form");
  await expect(form).toBeVisible();
  await form.getByTestId("field-cidr").fill("192.0.2.0/24");
  await form.getByTestId("field-description").fill("Lab network");
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("plan-summary")).toBeVisible();
  await expect(planChange(page, "prefix", "create")).toHaveCount(1);
  await expect(page.getByTestId("plan-blocking")).toHaveCount(0);
  // Nothing is written before the plan is confirmed.
  expect(await prefixByCidr(api, "192.0.2.0/24")).toBeUndefined();
  await confirmPlan(page);

  // The tree lists it and the prefix pane opens on it.
  await expect(withKey(page, "tree-node", "192.0.2.0/24")).toBeVisible();
  await expect(withKey(page, "prefix-pane", "192.0.2.0/24")).toBeVisible();
  await expect(page).toHaveURL(/\/ipam\/prefixes\/192\.0\.2\.0\/24$/);

  const created = await prefixByCidr(api, "192.0.2.0/24");
  expect(created).toBeDefined();
  expect(created?.role).toBe("network");
  expect(created?.status).toBe("active");
  expect(created?.meta.description).toBe("Lab network");
  expect(created?.alloc).toBe("lowest");

  // Take the next free address: the preview names it before anything is written.
  await page.getByTestId("prefix-next-free-address").click();
  const claim = page.getByTestId("dialog-next-free-address");
  await expect(claim).toBeVisible();
  await claim.getByTestId("field-dns_name").fill("claimed.example.com");
  await claim.getByTestId("form-submit").click();
  await expect(page.getByTestId("next-free-result")).toContainText("192.0.2.1");
  const before = await api.get<Schemas["Page_AddressRow"]>("/addresses", { prefix: created?.id ?? "" });
  expect(before.items).toHaveLength(0);
  await confirmPlan(page);

  // The address is in the grid of the prefix and in the API.
  const row = gridRow(page, "prefix-addresses", "192.0.2.1");
  await expect(row).toBeVisible();
  await expect(cell(row, "dns_name")).toContainText("claimed.example.com");
  const after = await api.get<Schemas["Page_AddressRow"]>("/addresses", { prefix: created?.id ?? "" });
  expect(after.items.map((a) => a.ip)).toEqual(["192.0.2.1"]);
  expect(after.items[0]?.dns_name).toBe("claimed.example.com");
  expect(after.items[0]?.status).toBe("active");

  // The next one is the next address up: the policy of the prefix is lowest first.
  await page.getByTestId("prefix-next-free-address").click();
  await page.getByTestId("dialog-next-free-address").getByTestId("form-submit").click();
  await expect(page.getByTestId("next-free-result")).toContainText("192.0.2.2");
});

test("a reserved host with a MAC but no DUID is warned about once an IPv6 address is bound to it", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");
  await api.post("/prefixes", { cidr: "192.0.2.0/24" });
  await api.post("/prefixes", { cidr: "2001:db8::/64" });

  // Create the host in reserved mode with one interface and a documentation MAC.
  await page.goto("/ipam/hosts");
  await expect(page.getByTestId("page-hosts")).toBeVisible();
  await page.getByTestId("hosts-create").click();
  const form = page.getByTestId("dialog-host-form");
  await form.getByTestId("field-name").fill("srv01.example.com");
  await withKey(form, "field-mode", "reserved").check();
  await form.getByTestId("field-mac").fill("00-00-5E-00-53-10");
  await form.getByTestId("form-submit").click();
  // A MAC is enough for a reservation while the host has no address yet.
  await expect(planChange(page, "host", "create")).toHaveCount(1);
  await expect(planChange(page, "interface", "create")).toHaveCount(1);
  await expect(page.getByTestId("plan-warnings")).toHaveCount(0);
  await confirmPlan(page);

  await expect(page.getByTestId("page-host")).toBeVisible();
  await expect(page).toHaveURL(/\/ipam\/hosts\/srv01\.example\.com$/);
  const eth0 = gridRow(page, "host-interfaces", "eth0");
  await expect(eth0).toBeVisible();
  expect(macDigits(await cell(eth0, "mac").innerText())).toBe("00005e005310");
  await expect(page.getByTestId("host-identifier-warning")).toHaveCount(0);

  const host = await hostByName(api, "srv01.example.com");
  expect(host?.mode).toBe("reserved");
  const interfaces = await api.get<Schemas["Page_Interface"]>(`/hosts/${host?.id}/interfaces`);
  expect(interfaces.items.map((i) => i.name)).toEqual(["eth0"]);
  const iface = interfaces.items[0];
  expect(macDigits(iface?.mac ?? "")).toBe("00005e005310");
  expect(iface?.duid ?? null).toBeNull();

  // An IPv4 address on the interface is covered by the MAC; an IPv6 address needs a DUID.
  await api.post("/addresses", { ip: "192.0.2.10", interface: iface?.id });
  await api.post("/addresses", { ip: "2001:db8::10", interface: iface?.id });
  await expect(page.getByTestId("host-identifier-warning")).toBeVisible();
  await expect(page.getByTestId("host-identifier-warning")).toHaveAttribute("data-key", "duid");

  // Any write that touches the host previews the same warning, which does not block it.
  await page.getByTestId("host-edit").click();
  await page.getByTestId("dialog-host-form").getByTestId("field-description").fill("Rack 4");
  await page.getByTestId("form-submit").click();
  await expect(page.getByTestId("plan-warnings")).toBeVisible();
  await expect(page.getByTestId("plan-blocking")).toHaveCount(0);
  await expect(page.getByTestId("plan-confirm")).toBeEnabled();
  // Escape in the plan goes back to the form, and once more leaves it: nothing was written.
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("plan-confirm")).toHaveCount(0);
  await expect(page.getByTestId("dialog-host-form")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("dialog-host-form")).toHaveCount(0);
  expect((await hostByName(api, "srv01.example.com"))?.meta.description ?? null).toBeNull();

  // Fix it where the warning points: a DUID on the interface (DUID-LLT of the same MAC).
  await cell(eth0, "name").dblclick();
  const ifaceForm = page.getByTestId("dialog-interface-form");
  await expect(ifaceForm).toBeVisible();
  await ifaceForm.getByTestId("field-duid").fill("00:01:00:01:2b:3c:4d:5e:00:00:5e:00:53:10");
  await ifaceForm.getByTestId("form-submit").click();
  await expect(planChange(page, "interface", "update")).toHaveCount(1);
  await expect(page.getByTestId("plan-warnings")).toHaveCount(0);
  await confirmPlan(page);

  await expect(cell(eth0, "duid")).toContainText("000100012b3c4d5e00005e005310");
  await expect(page.getByTestId("host-identifier-warning")).toHaveCount(0);
  const fixed = await api.get<Schemas["Interface"]>(`/interfaces/${iface?.id}`);
  expect(fixed.duid).toBe("000100012b3c4d5e00005e005310");
  expect(macDigits(fixed.mac ?? "")).toBe("00005e005310");
});

test("a custom field is defined, then a value and tags are set on a host", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");
  const created = await api.post<{ item: Schemas["Host"] }>("/hosts", { name: "nas01.example.com", mode: "static" });
  const hostId = created.item.id;

  // Define an integer field for hosts.
  await page.goto("/ipam/custom-fields");
  await expect(page.getByTestId("page-ipam-custom-fields")).toBeVisible();
  await page.getByTestId("custom-field-create").click();
  const defForm = page.getByTestId("dialog-custom-field-form");
  await defForm.getByTestId("field-key").fill("rack_unit");
  await defForm.getByTestId("field-type").selectOption("integer");
  await defForm.getByTestId("form-submit").click();
  await expect(planChange(page, "custom_field", "create")).toHaveCount(1);
  await confirmPlan(page);
  await expect(gridRow(page, "custom-fields", "rack_unit")).toBeVisible();
  const defs = await api.get<Schemas["ListBody_CustomFieldDef"]>("/custom-fields");
  expect(defs.items).toHaveLength(1);
  expect(defs.items[0]).toMatchObject({ key: "rack_unit", kind: { type: "integer" }, applies_to: ["host"] });

  // Set the value and two tags in the form of the host.
  await page.goto("/ipam/hosts/nas01.example.com");
  await expect(page.getByTestId("page-host")).toBeVisible();
  await expect(page.getByTestId("custom-values")).toHaveCount(0);
  await page.getByTestId("host-edit").click();
  const form = page.getByTestId("dialog-host-form");
  await form.getByTestId("field-custom-rack_unit").fill("12");
  await form.getByTestId("field-tags").fill("edge");
  await form.getByTestId("field-tags").press("Enter");
  await form.getByTestId("field-tags").fill("lab,");
  await expect(form.getByTestId("tags-chips")).toContainText("edge");
  await expect(form.getByTestId("tags-chips")).toContainText("lab");
  await form.getByTestId("form-submit").click();
  await expect(planChange(page, "host", "update")).toHaveCount(1);
  await confirmPlan(page);

  // The host page shows both.
  await expect(page.getByTestId("host-tags")).toContainText("edge");
  await expect(page.getByTestId("host-tags")).toContainText("lab");
  await expect(page.getByTestId("custom-values").locator('[data-key="rack_unit"]')).toHaveText("12");

  // The API has them on the object, typed.
  const host = await api.get<Schemas["Host"]>(`/hosts/${hostId}`);
  expect([...(host.meta.tags ?? [])].sort()).toEqual(["edge", "lab"]);
  expect(host.meta.custom).toEqual({ rack_unit: { type: "integer", value: 12 } });
  const tags = await api.get<Schemas["ListBody_TagCount"]>("/tags");
  expect(tags.items.map((t) => [t.tag, t.count, t.by_kind]).sort()).toEqual([
    ["edge", 1, { host: 1 }],
    ["lab", 1, { host: 1 }],
  ]);

  // The tags page counts them.
  await page.goto("/ipam/tags");
  await expect(page.getByTestId("page-ipam-tags")).toBeVisible();
  await expect(cell(gridRow(page, "tags", "edge"), "count")).toHaveText("1");
  await expect(gridRow(page, "tags", "lab")).toBeVisible();

  // Take one tag away again: the form shows what is stored, the patch replaces the tags.
  await page.goto("/ipam/hosts/nas01.example.com");
  await page.getByTestId("host-edit").click();
  const again = page.getByTestId("dialog-host-form");
  await expect(again.getByTestId("field-custom-rack_unit")).toHaveValue("12");
  await expect(again.getByTestId("tags-chips")).toContainText("lab");
  await again.getByTestId("field-tags").press("Backspace");
  await expect(again.getByTestId("tags-chips")).not.toContainText("lab");
  await again.getByTestId("form-submit").click();
  await expect(planChange(page, "host", "update")).toHaveCount(1);
  await confirmPlan(page);
  await expect(page.getByTestId("host-tags")).not.toContainText("lab");
  await expect(page.getByTestId("host-tags")).toContainText("edge");
  await expect(page.getByTestId("custom-values").locator('[data-key="rack_unit"]')).toHaveText("12");
  const trimmed = await api.get<Schemas["Host"]>(`/hosts/${hostId}`);
  expect(trimmed.meta.tags).toEqual(["edge"]);
  expect(trimmed.meta.custom).toEqual({ rack_unit: { type: "integer", value: 12 } });
  expect((await api.get<Schemas["ListBody_TagCount"]>("/tags")).items.map((t) => t.tag)).toEqual(["edge"]);
});

// The API merges a patch of custom values (`null` removes one); the host form sends the
// cleared value as `null`.
test("clearing a custom value in the host form removes it", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");
  await api.post("/custom-fields", { key: "rack_unit", kind: { type: "integer" }, applies_to: ["host"] });
  const created = await api.post<{ item: Schemas["Host"] }>("/hosts", {
    name: "nas02.example.com",
    mode: "static",
    custom: { rack_unit: { type: "integer", value: 12 } },
  });
  await page.goto("/ipam/hosts/nas02.example.com");
  await expect(page.getByTestId("custom-values").locator('[data-key="rack_unit"]')).toHaveText("12");
  await page.getByTestId("host-edit").click();
  await page.getByTestId("dialog-host-form").getByTestId("field-custom-rack_unit").fill("");
  await page.getByTestId("form-submit").click();
  await confirmPlan(page);
  await expect(page.getByTestId("custom-values")).toHaveCount(0);
  expect((await api.get<Schemas["Host"]>(`/hosts/${created.item.id}`)).meta.custom ?? {}).toEqual({});
});

test("an IPv6 prefix off a nibble boundary needs an acknowledgement before it applies", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");

  await page.goto("/ipam");
  await expect(page.getByTestId("page-ipam")).toBeVisible();
  await page.getByTestId("ipam-add-prefix").click();
  const form = page.getByTestId("dialog-prefix-form");
  await form.getByTestId("field-cidr").fill("2001:db8:0:10::/62");
  await form.getByTestId("form-submit").click();

  // The plan carries a warning that blocks the apply until it is acknowledged.
  await expect(page.getByTestId("plan-summary")).toBeVisible();
  await expect(page.getByTestId("plan-blocking")).toBeVisible();
  const ack = page.getByTestId("plan-ack");
  await expect(ack).toHaveCount(1);
  await expect(ack).toHaveAttribute("data-code", "ipam.prefix.nibble_boundary");
  await expect(ack).not.toBeChecked();
  const confirm = page.getByTestId("plan-confirm");
  await expect(confirm).toBeDisabled();
  expect(await prefixByCidr(api, "2001:db8:0:10::/62")).toBeUndefined();

  // Ticking the box releases the confirm button, which applies the plan with the code.
  await ack.check();
  await expect(confirm).toBeEnabled();
  await confirm.click();
  await expect(confirm).toHaveCount(0);

  await expect(withKey(page, "tree-node", "2001:db8:0:10::/62")).toBeVisible();
  await expect(withKey(page, "prefix-pane", "2001:db8:0:10::/62")).toBeVisible();
  const prefix = await prefixByCidr(api, "2001:db8:0:10::/62");
  expect(prefix?.role).toBe("network");

  // On a nibble boundary the same form needs no acknowledgement.
  await page.getByTestId("ipam-add-prefix").click();
  await page.getByTestId("dialog-prefix-form").getByTestId("field-cidr").fill("2001:db8:0:20::/60");
  await page.getByTestId("form-submit").click();
  await expect(page.getByTestId("plan-summary")).toBeVisible();
  await expect(page.getByTestId("plan-blocking")).toHaveCount(0);
  await expect(page.getByTestId("plan-confirm")).toBeEnabled();
});

test("a host that was changed and deleted comes back from its page", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");
  const created = await api.post<{ item: Schemas["Host"] }>("/hosts", {
    name: "print01.example.com",
    mode: "reserved",
    description: "Front office",
    interfaces: [{ name: "eth0", mac: "00:00:5e:00:53:20" }],
  });
  const id = created.item.id;

  await page.goto("/ipam/hosts/print01.example.com");
  await expect(page.getByTestId("page-host")).toBeVisible();
  await expect(page.getByTestId("host-description")).toHaveText("Front office");

  // Change it.
  await page.getByTestId("host-edit").click();
  await page.getByTestId("dialog-host-form").getByTestId("field-description").fill("Back office");
  await page.getByTestId("form-submit").click();
  await expect(planChange(page, "host", "update")).toHaveCount(1);
  await confirmPlan(page);
  await expect(page.getByTestId("host-description")).toHaveText("Back office");

  // Delete it: the page keeps showing it, now with Restore instead of the editing actions.
  await page.getByTestId("host-delete").click();
  await expect(page.getByTestId("dialog-delete")).toBeVisible();
  await expect(planChange(page, "host", "delete")).toHaveCount(1);
  await confirmPlan(page);
  await expect(page.getByTestId("host-restore")).toBeVisible();
  await expect(page.getByTestId("host-edit")).toHaveCount(0);
  const deleted = await api.get<Schemas["Host"]>(`/hosts/${id}`);
  expect(deleted.meta.deleted).toBeTruthy();
  expect((await api.get<Schemas["Page_Host"]>("/hosts", { q: "print01" })).items).toHaveLength(0);

  // Its history lists what happened, newest first.
  const entries = page.getByTestId("history-entry");
  await expect(entries).toHaveCount(3);
  expect(await actionsOf(entries)).toEqual(["delete", "update", "create"]);

  // Restore it: previewed like any other write, then applied.
  await page.getByTestId("host-restore").click();
  await expect(page.getByTestId("dialog-restore")).toBeVisible();
  await expect(planChange(page, "host", "restore")).toHaveCount(1);
  await confirmPlan(page);
  await expect(page.getByTestId("host-edit")).toBeVisible();
  await expect(page.getByTestId("host-restore")).toHaveCount(0);
  await expect(page.getByTestId("host-description")).toHaveText("Back office");
  await expect(gridRow(page, "host-interfaces", "eth0")).toBeVisible();
  await expect(entries).toHaveCount(4);
  expect(await actionsOf(entries)).toEqual(["restore", "delete", "update", "create"]);

  const restored = await api.get<Schemas["Host"]>(`/hosts/${id}`);
  expect(restored.meta.deleted ?? null).toBeNull();
  expect(restored.meta.description).toBe("Back office");
  expect(await historyActions(api, "hosts", id)).toEqual(["create", "update", "delete", "restore"]);
  const interfaces = await api.get<Schemas["Page_Interface"]>(`/hosts/${id}/interfaces`);
  expect(interfaces.items.map((i) => i.name)).toEqual(["eth0"]);
  expect((await api.get<Schemas["Page_Host"]>("/hosts", { q: "print01" })).items.map((h) => h.name)).toEqual(["print01.example.com"]);
});

test("an address that was changed and deleted is restored from its history", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");
  await api.post("/prefixes", { cidr: "192.0.2.0/24" });
  const created = await api.post<{ item: Schemas["Address"] }>("/addresses", { ip: "192.0.2.20", dns_name: "scanner.example.com" });
  const id = created.item.id;

  await page.goto("/ipam/addresses/192.0.2.20");
  await expect(page.getByTestId("page-ipam-address")).toBeVisible();

  // Change the description through the form.
  await page.getByTestId("address-edit").click();
  await page.getByTestId("dialog-address-form").getByTestId("field-description").fill("Second floor");
  await page.getByTestId("form-submit").click();
  await expect(planChange(page, "address", "update")).toHaveCount(1);
  await confirmPlan(page);
  await expect(page.getByTestId("history-entry")).toHaveCount(2);
  expect((await api.get<Schemas["Address"]>(`/addresses/${id}`)).meta.description).toBe("Second floor");

  // Delete it.
  await page.getByTestId("address-delete").click();
  await expect(page.getByTestId("dialog-delete")).toBeVisible();
  await expect(planChange(page, "address", "delete")).toHaveCount(1);
  await confirmPlan(page);
  await expect(page.getByTestId("address-restore")).toBeVisible();
  await expect(page.getByTestId("address-edit")).toHaveCount(0);
  await expect(page.getByTestId("history-entry")).toHaveCount(3);
  expect((await api.get<Schemas["Address"]>(`/addresses/${id}`)).meta.deleted).toBeTruthy();

  // The history of a deleted object offers the restore as well.
  await page.getByTestId("history-restore").click();
  await expect(page.getByTestId("dialog-restore")).toBeVisible();
  await expect(planChange(page, "address", "restore")).toHaveCount(1);
  await confirmPlan(page);
  await expect(page.getByTestId("address-edit")).toBeVisible();
  await expect(page.getByTestId("address-restore")).toHaveCount(0);
  await expect(page.getByTestId("history-restore")).toHaveCount(0);

  const restored = await api.get<Schemas["Address"]>(`/addresses/${id}`);
  expect(restored.meta.deleted ?? null).toBeNull();
  expect(restored.meta.description).toBe("Second floor");
  expect(restored.dns_name).toBe("scanner.example.com");
  expect(await historyActions(api, "addresses", id)).toEqual(["create", "update", "delete", "restore"]);
});

test("the history dialog of the hosts list restores a deleted host", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");
  const created = await api.post<{ item: Schemas["Host"] }>("/hosts", { name: "old01.example.com", mode: "static" });
  const id = created.item.id;
  await api.patch(`/hosts/${id}`, { description: "Decommission in Q4" });
  await api.delete(`/hosts/${id}`);

  // Deleted hosts show only when asked for.
  await page.goto("/ipam/hosts");
  await expect(page.getByTestId("page-hosts")).toBeVisible();
  await expect(page.getByTestId("grid-empty")).toBeVisible();
  await page.goto("/ipam/hosts?deleted=only");
  const row = gridRow(page, "hosts", "old01.example.com");
  await expect(row).toBeVisible();

  // The row menu opens the history, which lists the three changes.
  await openRowMenu(page, row, "mode");
  await rowMenuItem(page, "history").click();
  const dialog = page.getByTestId("dialog-history");
  await expect(dialog).toBeVisible();
  const entries = dialog.getByTestId("history-entry");
  await expect(entries).toHaveCount(3);
  expect(await actionsOf(entries)).toEqual(["delete", "update", "create"]);

  // Restore from the dialog: the dialog closes and the host is live again.
  await dialog.getByTestId("history-restore").click();
  await expect(page.getByTestId("dialog-restore")).toBeVisible();
  await confirmPlan(page);
  await expect(dialog).toHaveCount(0);
  // The list of deleted hosts follows the live events and loses the row.
  await expect(page.getByTestId("grid-empty")).toBeVisible();
  const restored = await hostByName(api, "old01.example.com");
  expect(restored?.meta.deleted ?? null).toBeNull();
  expect(restored?.meta.description).toBe("Decommission in Q4");
  expect(await historyActions(api, "hosts", id)).toEqual(["create", "update", "delete", "restore"]);

  // Opened again, the history has a fourth entry and no restore action.
  await page.goto("/ipam/hosts");
  await openRowMenu(page, gridRow(page, "hosts", "old01.example.com"), "mode");
  await rowMenuItem(page, "history").click();
  await expect(page.getByTestId("dialog-history").getByTestId("history-entry")).toHaveCount(4);
  await expect(page.getByTestId("history-restore")).toHaveCount(0);
});

// The toast after a delete offers Undo, which restores the object at once. The toast has no
// test hooks yet (contract request: `toast` on the toast and `toast-action` with `data-index`
// on its buttons); until it has, this test cannot find the button without matching its text.
test("Undo in the toast of a delete brings the host back", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe("admin");
  await api.post("/hosts", { name: "undo01.example.com", mode: "static" });
  await page.goto("/ipam/hosts/undo01.example.com");
  await page.getByTestId("host-delete").click();
  await confirmPlan(page);
  await expect(page.getByTestId("host-restore")).toBeVisible();
  await withIndex(page, "toast-action", 0).click();
  await expect(page.getByTestId("host-edit")).toBeVisible();
  expect((await hostByName(api, "undo01.example.com"))?.meta.deleted ?? null).toBeNull();
});
