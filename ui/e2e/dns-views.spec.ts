// WP6.4: the views of the DNS area against the real view routes. Create two views (one with a
// client subnet rule, a scope of the zone and a recursion list; one without rules), reorder
// them with the buttons and by dragging, see their rules and scopes in words; a delete refused
// while a forwarding rule names the view, a zone deletion refused while a view names its
// scope; Swedish.
//
// NO FAKES: the view, zone, access list and forwarder routes are the real server's (the e2e
// server runs every module; the view routes need no `dns` role). The zone is made through the
// API with two scopes besides `default`, since the zone settings of the UI do not edit scopes.

import type { Locator, Page } from "@playwright/test";
import type { Api } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { gridRow, withKey } from "./support/ui";

const view = (page: Page, name: string): Locator => gridRow(page, "dns-views", name);

interface Created {
  id: string;
  revision: number;
}

/** A zone `example.test` with the scopes `internal` and `external`, and an access list. */
async function arrange(api: Api): Promise<{ zone: Created; acl: Created }> {
  const zone = await api.post<Created>("/dns/zones", {
    name: "example.test",
    kind: "primary",
    serial: "counter",
    soa: { mname: "ns1.example.test", rname: "hostmaster.example.test" },
    name_servers: ["ns1.example.test"],
    scopes: [{ name: "internal" }, { name: "external" }],
  });
  const acl = await api.post<Created>("/dns/acls", { name: "office", entries: [{ kind: "prefix", prefix: "192.0.2.0/24" }] });
  return { zone, acl };
}

async function rowAction(page: Page, row: Locator, action: string): Promise<void> {
  await row.getByRole("button", { name: /Actions for/ }).click();
  await page.getByTestId("row-menu").locator(`[data-key="${action}"]`).click();
}

/** The names of the views in the grid, in order. */
async function order(page: Page): Promise<string[]> {
  return page
    .getByTestId("grid-dns-views")
    .getByTestId("row")
    .evaluateAll((rows) => rows.map((r) => (r as HTMLElement).dataset.key ?? ""));
}

async function createView(page: Page, fill: (form: Locator) => Promise<void>): Promise<void> {
  await page.getByTestId("dns-view-create").click();
  const form = page.getByTestId("dialog-view-form");
  await fill(form);
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);
}

test("creates two views, reorders them and shows their rules and scopes", async ({ page, api, signedIn }) => {
  void signedIn;
  const { zone, acl } = await arrange(api);
  await page.goto("/dns/views");
  await expect(page.getByTestId("page-dns-views")).toBeVisible();
  await expect(page.getByTestId("dns-nav").locator('[data-key="views"]')).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("dns-views-empty")).toBeVisible();
  await expect(page.getByTestId("view-default")).toBeVisible();

  // The office: a client subnet, the internal scope at 700 and the external at 300, a recursion list.
  await createView(page, async (form) => {
    await form.getByTestId("field-name").fill("office");
    await form.getByTestId("field-rule-kind").selectOption("client_subnet");
    await form.getByTestId("view-rule-add").click();
    await form.getByTestId("field-rule-values").fill("192.0.2.0/24\n2001:db8:10::/48");
    await form.getByTestId("view-scope-add").click();
    await form.getByTestId("view-scope-add").click();
    const [first, second] = [form.getByTestId("view-scope-editor").nth(0), form.getByTestId("view-scope-editor").nth(1)];
    await first.getByTestId("field-scope-zone").selectOption(zone.id);
    await first.getByTestId("field-scope-scope").selectOption("internal");
    await first.getByTestId("field-scope-weight").fill("700");
    await second.getByTestId("field-scope-zone").selectOption(zone.id);
    await second.getByTestId("field-scope-scope").selectOption("external");
    await second.getByTestId("field-scope-weight").fill("300");
    await expect(withKey(form, "view-share", "70")).toBeVisible();
    await expect(withKey(form, "view-share", "30")).toBeVisible();
    await form.getByTestId("field-recursion").selectOption(acl.id);
  });
  // Everyone else: no rules, the external scope; it goes last.
  await createView(page, async (form) => {
    await form.getByTestId("field-name").fill("everyone");
    await form.getByTestId("view-scope-add").click();
    await form.getByTestId("field-scope-zone").selectOption(zone.id);
    await form.getByTestId("field-scope-scope").selectOption("external");
  });
  await expect.poll(() => order(page)).toEqual(["office", "everyone"]);
  const office = view(page, "office");
  await expect(office.getByTestId("view-rule")).toHaveAttribute("data-kind", "client_subnet");
  await expect(withKey(office, "view-scope", "example.test:internal")).toHaveAttribute("data-weight", "700");
  await expect(withKey(office, "view-scope", "example.test:external")).toHaveAttribute("data-weight", "300");
  await expect(office.getByTestId("view-recursion")).toHaveAttribute("data-key", "office");
  await expect(view(page, "everyone").getByTestId("view-every")).toBeVisible();
  await expect(view(page, "everyone").getByTestId("view-order")).toHaveAttribute("data-key", "2");

  // Reorder: everyone up with its button, then the office back to the top by the row menu.
  await view(page, "everyone").getByTestId("view-move-up").click();
  await expect.poll(() => order(page)).toEqual(["everyone", "office"]);
  await expect(view(page, "everyone").getByTestId("view-order")).toHaveAttribute("data-key", "1");
  await rowAction(page, view(page, "office"), "up");
  await expect.poll(() => order(page)).toEqual(["office", "everyone"]);
  // And by dragging the second onto the first. The drop's request is awaited on its own, so a
  // drag that never reached the drop fails here, by name, and not as an order that stayed.
  const dropped = page.waitForResponse((r) => r.request().method() === "PATCH" && r.url().includes("/api/v1/dns/views/"));
  await view(page, "everyone").getByTestId("view-drag").dragTo(view(page, "office").getByTestId("view-order"));
  expect((await dropped).status(), "the drop's change was accepted").toBe(200);
  await expect.poll(() => order(page)).toEqual(["everyone", "office"]);

  // The server kept the order and the rules.
  const stored = await api.get<{ items: { name: string; order: number; rules?: { test: string }[] }[] }>("/dns/views");
  expect(stored.items.map((v) => [v.name, v.order])).toEqual([
    ["everyone", 1],
    ["office", 2],
  ]);
  expect(stored.items[1]?.rules?.[0]?.test).toBe("client_subnet");
});

test("refuses a delete while a forwarding rule names the view, and a zone deletion while a view names its scope", async ({ page, api, signedIn }) => {
  void signedIn;
  const { zone } = await arrange(api);
  const office = await api.post<Created>("/dns/views", {
    name: "office",
    order: 1,
    rules: [{ test: "client_subnet", prefixes: ["192.0.2.0/24"] }],
    scope_map: [{ zone: zone.id, scope: "internal", weight: 1 }],
  });
  await api.post("/dns/forwarders", { suffix: "office.example.net", upstreams: [{ address: "192.0.2.10" }], view: office.id });

  await page.goto("/dns/views");
  await rowAction(page, view(page, "office"), "delete");
  const dialog = page.getByTestId("dialog-view-delete");
  await dialog.getByTestId("confirm-ok").click();
  const refused = dialog.getByTestId("view-in-use");
  await expect(refused).toHaveAttribute("data-code", "dns.view.in_use");
  await expect(withKey(refused, "view-in-use-by", "forwarder:office.example.net")).toBeVisible();
  await dialog.getByTestId("confirm-cancel").click();
  await expect(view(page, "office")).toBeVisible();

  // The zone keeps its scope while the view names it: the zone list refuses the deletion.
  await page.goto("/dns");
  const row = gridRow(page, "dns-zones", "example.test");
  await rowAction(page, row, "delete");
  const zoneDialog = page.getByTestId("dialog-zone-delete");
  await zoneDialog.getByTestId("confirm-ok").click();
  await expect(zoneDialog.getByTestId("error-notice")).toHaveAttribute("data-code", "dns.view.in_use");
  await zoneDialog.getByTestId("confirm-cancel").click();
  await expect(row).toBeVisible();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the views page and its form in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    const { zone } = await arrange(api);
    await api.post("/dns/views", {
      name: "office",
      order: 1,
      rules: [{ test: "transport", transports: ["dot", "doh"] }],
      scope_map: [{ zone: zone.id, scope: "internal", weight: 1 }],
    });
    await page.goto("/dns/views");
    await expect(view(page, "office")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dns-views"), "sv", testInfo, "dns-views");
    await page.getByTestId("dns-view-create").click();
    await expectRendered(page, page.getByTestId("dialog-view-form"), "sv", testInfo, "dns-view-form");
  });
});
