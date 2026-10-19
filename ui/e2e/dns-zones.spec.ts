// WP4.5: the zones and records of the DNS area. Create a zone, add records, change records in a
// batch with the dry run and its diff before apply, take over an RRset that IPAM keeps, edit the
// SOA and NS on the settings tab, delete the zone; a viewer; Swedish; and what the pages show
// against the real server while it answers the DNS routes with 501 (until WP4.2 lands).
// WP6.2 adds the dynamic update section of the settings tab.
//
// EVERY SCENARIO BUT THE LAST FAKES THE DNS ROUTES (support/dns-mock.ts, which says why): the
// views are proven against the declared contract with the mock service; the rest of the API
// (setup, sign-in, the shell, events) is the real server.

import type { Locator, Page } from "@playwright/test";
import { signInAsViewer } from "./support/accounts";
import { FakeDns } from "./support/dns-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { gridRow } from "./support/ui";

const record = (page: Page, key: string): Locator => gridRow(page, "dns-records", key);

async function addRrset(page: Page, name: string, type: string, data: string): Promise<void> {
  await page.getByTestId("dns-rrset-add").click();
  const dialog = page.getByTestId("dialog-rrset-form");
  await dialog.getByTestId("field-name").fill(name);
  await dialog.getByTestId("field-type").selectOption(type);
  await dialog.getByTestId("field-data").fill(data);
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toHaveCount(0);
}

async function editCell(page: Page, key: string, col: string, value: string): Promise<void> {
  await record(page, key).locator(`[data-col="${col}"]`).dblclick();
  const editor = page.getByTestId("cell-editor");
  await editor.fill(value);
  await editor.press("Enter");
  await expect(editor).toHaveCount(0);
}

test("creates a zone, adds records, changes them in a batch with the diff and deletes the zone", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  await page.goto("/dns");
  await expect(page.getByTestId("grid-dns-zones").getByTestId("row")).toHaveCount(4);
  await expect(gridRow(page, "dns-zones", "lab.example.test").getByTestId("zone-not-served")).toBeVisible();

  // Create: the SOA names follow the zone name.
  await page.getByTestId("dns-zone-create").click();
  const form = page.getByTestId("dialog-zone-form");
  await form.getByTestId("field-name").fill("home.example.test");
  await expect(form.getByTestId("field-soa.mname")).toHaveValue("ns1.home.example.test");
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("page-dns-zone")).toBeVisible();
  await expect(page.getByTestId("zone-name")).toHaveText("home.example.test");
  await expect(page.getByTestId("grid-dns-records").getByTestId("row")).toHaveCount(2);

  // Add records, one RRset at a time: each is written at once.
  await addRrset(page, "printer", "A", "192.0.2.30\n192.0.2.31");
  await expect(record(page, "printer/A/1")).toBeVisible();
  await addRrset(page, "www", "CNAME", "printer");
  await expect(record(page, "www/CNAME/0").locator('[data-col="data"]')).toHaveText("printer.home.example.test");
  const written = fake.sent.filter((s) => s.path.endsWith("/records/batch"));
  expect(written.map((s) => s.query)).toEqual(["", ""]);

  // A batch: nothing is sent until Review, which sends a dry run and shows the diff.
  await page.getByTestId("dns-batch-toggle").check();
  await editCell(page, "printer/A/0", "ttl", "600");
  await addRrset(page, "mail", "A", "192.0.2.25");
  await record(page, "www/CNAME/0").getByRole("button", { name: /Actions for/ }).click();
  await page.getByTestId("row-menu").getByTestId("menu-item").and(page.locator('[data-key="delete"]')).click();
  await page.getByTestId("dialog-rrset-delete").getByTestId("confirm-ok").click();
  await expect(page.getByTestId("dns-batch")).toHaveAttribute("data-count", "3");
  expect(fake.sent.filter((s) => s.path.endsWith("/records/batch"))).toHaveLength(2);
  await page.getByTestId("dns-batch-review").click();
  const diff = page.getByTestId("dialog-batch-diff");
  await expect(diff.getByTestId("plan-summary")).toHaveAttribute("data-count", "3");
  await expect(diff.getByTestId("plan-change")).toHaveCount(3);
  await expect(diff.locator('[data-testid="plan-change"][data-key="mail.home.example.test/A"]')).toHaveAttribute("data-kind", "add");
  await expect(diff.locator('[data-testid="plan-change"][data-key="printer.home.example.test/A"]')).toHaveAttribute("data-kind", "change");
  await expect(diff.locator('[data-testid="plan-change"][data-key="www.home.example.test/CNAME"]')).toHaveAttribute("data-kind", "delete");
  const serial = fake.zone("home.example.test")?.soa_serial;
  expect(fake.sent.at(-1)?.query).toBe("dry_run=true");
  await diff.getByTestId("plan-confirm").click();
  await expect(diff).toHaveCount(0);
  await expect(page.getByTestId("dns-batch")).toHaveAttribute("data-count", "0");
  await expect(record(page, "mail/A/0")).toBeVisible();
  await expect(record(page, "www/CNAME/0")).toHaveCount(0);
  await expect(record(page, "printer/A/0").locator('[data-col="ttl"]')).toHaveText("600");
  expect(fake.zone("home.example.test")?.soa_serial).toBeGreaterThan(serial ?? 0);
  expect(fake.sent.at(-1)?.query).toBe("");
  expect((fake.sent.at(-1)?.body as { changes: unknown[] }).changes).toHaveLength(3);

  // Delete the zone from its page.
  await page.getByTestId("dns-zone-delete").click();
  await page.getByTestId("dialog-zone-delete").getByTestId("confirm-ok").click();
  await expect(page.getByTestId("page-dns")).toBeVisible();
  await expect(page.getByTestId("grid-dns-zones").getByTestId("row")).toHaveCount(4);
  expect(fake.zone("home.example.test")).toBeUndefined();
});

test("keeps an RRset of IPAM read-only until it is taken over", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  await page.goto(`/dns/zones/${fake.zone("example.test")?.id}`);
  const nas = record(page, "nas/A/0");
  await expect(nas.getByTestId("rrset-origin")).toHaveAttribute("data-kind", "ipam");
  await nas.locator('[data-col="data"]').dblclick();
  await expect(page.getByTestId("cell-editor")).toHaveCount(0);
  await nas.getByRole("button", { name: /Actions for/ }).click();
  await page.getByTestId("row-menu").locator('[data-key="takeover"]').click();
  await page.getByTestId("dialog-take-over").getByTestId("confirm-ok").click();
  await expect(nas.getByTestId("rrset-taken-over")).toBeVisible();
  await editCell(page, "nas/A/0", "data", "192.0.2.111");
  await expect(nas.getByTestId("rrset-origin")).toHaveAttribute("data-kind", "manual");
  expect(fake.sent.at(-1)?.body).toMatchObject({ changes: [{ name: "nas.example.test", type: "A", op: "set", take_over: true }] });
});

test("edits the SOA values and the name servers on the settings tab", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  await page.goto(`/dns/zones/${fake.zone("example.test")?.id}/settings`);
  const form = page.getByTestId("zone-settings");
  await expect(form.getByTestId("field-name_servers")).toHaveValue("ns1.example.test");
  await form.getByTestId("field-soa.refresh").fill("7200");
  await form.getByTestId("field-name_servers").fill("ns1, ns2.example.test");
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("toast").first()).toBeVisible();
  expect(fake.zone("example.test")?.soa.refresh).toBe(7200);
  expect(fake.rrsets("example.test").find((s) => s.type === "NS")?.records).toEqual([
    { type: "NS", host: "ns1.example.test" },
    { type: "NS", host: "ns2.example.test" },
  ]);
  await page.getByTestId("zone-tab-history").click();
  await expect(page.getByTestId("zone-serial")).toHaveText(String(fake.zone("example.test")?.soa_serial));
});

// WP6.1: who may transfer the zone and who is notified, saved in the one PATCH of the settings tab.
test("sets an access list and a NOTIFY target on the settings tab and finds them after a reload", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  const internal = fake.state.acls.find((a) => a.name === "internal")?.id ?? "";
  const peers = fake.state.acls.find((a) => a.name === "transfer-peers")?.id ?? "";
  await page.goto(`/dns/zones/${fake.zone("example.test")?.id}/settings`);
  const form = page.getByTestId("zone-settings");
  const transfer = form.getByTestId("zone-transfer");
  await expect(form.getByTestId("field-name_servers")).toHaveValue("ns1.example.test");
  await expect(transfer.getByTestId("transfer-allow")).toHaveText(["transfer-peers"]);
  await transfer.getByTestId("field-allow-add").selectOption(internal);
  await expect(transfer.getByTestId("transfer-allow")).toHaveText(["transfer-peers", "internal"]);
  await transfer.getByTestId("transfer-notify-add").click();
  await transfer.getByTestId("field-notify.0.address").fill("192.0.2.54");
  await transfer.getByTestId("field-notify.0.port").fill("5353");
  await transfer.getByTestId("field-notify.0.key").fill("xfr.example.test");
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("toast").first()).toBeVisible();
  const patches = fake.sent.filter((s) => s.method === "PATCH");
  expect(patches).toHaveLength(1);
  expect(patches[0]?.body).toMatchObject({
    transfer: { allow: [peers, internal], notify: [{ address: "192.0.2.54", port: 5353, key: "xfr.example.test" }], require_tsig: true, xot: false },
  });
  expect(patches[0]?.body).not.toHaveProperty("catalog");

  await page.reload();
  const again = page.getByTestId("zone-settings").getByTestId("zone-transfer");
  await expect(again.getByTestId("transfer-allow")).toHaveText(["transfer-peers", "internal"]);
  await expect(again.getByTestId("field-notify.0.address")).toHaveValue("192.0.2.54");
  await expect(again.getByTestId("field-notify.0.port")).toHaveValue("5353");
  await expect(again.getByTestId("field-notify.0.key")).toHaveValue("xfr.example.test");
});

// WP6.2: the dynamic update section of a primary zone.
test("sets who may update a zone, with TSIG and the IPAM rule, on the settings tab", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  const internal = fake.state.acls.find((a) => a.name === "internal")?.id ?? "";
  await page.goto(`/dns/zones/${fake.zone("example.test")?.id}/settings`);
  const form = page.getByTestId("zone-settings");
  const update = form.getByTestId("zone-update");
  await expect(form.getByTestId("field-name_servers")).toHaveValue("ns1.example.test");
  await expect(update.getByTestId("update-allow-none")).toContainText("nobody may update this zone");
  await expect(update.getByTestId("field-update.require_tsig")).toBeChecked();
  await update.getByTestId("field-update-allow-add").selectOption(internal);
  await expect(update.getByTestId("update-allow")).toHaveText(["internal"]);
  await update.getByTestId("field-update.may_replace_ipam").check();
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("toast").first()).toBeVisible();
  const patches = fake.sent.filter((s) => s.method === "PATCH");
  expect(patches).toHaveLength(1);
  expect(patches[0]?.body).toMatchObject({ update: { allowed: [internal], require_tsig: true, may_replace_ipam: true } });
  expect(patches[0]?.body).not.toHaveProperty("transfer");
  await expect(update.getByTestId("update-allow")).toHaveText(["internal"]);
});

test("offers a viewer the zones to read and nothing to change", async ({ page, api, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  await signInAsViewer(api);
  await page.goto(`/dns/zones/${fake.zone("example.test")?.id}`);
  await expect(record(page, "www/A/0")).toBeVisible();
  await expect(page.getByTestId("dns-rrset-add")).toHaveCount(0);
  await expect(page.getByTestId("dns-zone-delete")).toHaveCount(0);
  await expect(page.locator('[data-testid="dns-nav-link"][data-key="keys"]')).toHaveCount(0);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the zone list, a zone and the create dialog in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    const fake = await FakeDns.install(page);
    await page.goto("/dns");
    await expectRendered(page, page.getByTestId("page-dns"), "sv", testInfo, "dns-zones");
    await page.getByTestId("dns-zone-create").click();
    await expectRendered(page, page.getByTestId("dialog-zone-form"), "sv", testInfo, "dns-zone-form");
    await page.keyboard.press("Escape");
    await page.goto(`/dns/zones/${fake.zone("example.test")?.id}`);
    await expect(record(page, "www/A/0")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dns-zone"), "sv", testInfo, "dns-zone");
  });
});

test("says so against the real server, which answers the DNS routes with 501 until WP4.2 lands", async ({ page, signedIn }) => {
  void signedIn;
  // No fake: the real server answers. The module list still names DNS, or the gate would show
  // the switched-off page instead; once WP4.2 lands this scenario shows the real zone list.
  await page.route(/\/api\/v1\/system\/modules(\?|$)/, async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as { running?: string[] };
    if (Array.isArray(body.running) && !body.running.includes("dns")) body.running.push("dns");
    await route.fulfill({ response, json: body });
  });
  await page.goto("/dns");
  const page501 = page.getByTestId("page-dns");
  await expect(page501).toBeVisible();
  const notBuilt = page.getByTestId("dns-not-built");
  const grid = page.getByTestId("grid-dns-zones");
  await expect(notBuilt.or(grid)).toBeVisible();
  const answer = (await notBuilt.isVisible()) ? "501" : "served";
  test.info().annotations.push({ type: "dns-api", description: answer });
  if (answer === "501") {
    await expect(page.getByTestId("dns-zone-create")).toHaveCount(0);
    await page.goto("/dns/acls");
    await expect(page.getByTestId("dns-not-built")).toBeVisible();
  }
});
