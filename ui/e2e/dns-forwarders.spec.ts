// WP5.5: the forwarding rules of the DNS area. Create the default forwarder with a DoT upstream
// (the well-known resolver offer fills the TLS name), edit its upstreams, delete a rule; the
// local checks and a refusal of the server under the field it names; Swedish; and a rule
// created and deleted against the real forwarder routes of WP5.1.
//
// THE FIRST SCENARIOS FAKE THE RESOLVER ROUTES (support/dns-resolver-mock.ts, which says why);
// the last one runs against the real server.

import type { Locator, Page } from "@playwright/test";
import { FakeResolver, withDns } from "./support/dns-resolver-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { gridRow } from "./support/ui";

const rule = (page: Page, key: string): Locator => gridRow(page, "dns-forwarders", key);

async function rowAction(page: Page, row: Locator, action: string): Promise<void> {
  await row.getByRole("button", { name: /Actions for/ }).click();
  await page.getByTestId("row-menu").locator(`[data-key="${action}"]`).click();
}

test("creates the default forwarder with a DoT upstream, edits it and deletes a rule", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeResolver.install(page);
  await page.goto("/dns/forwarders");
  await expect(page.getByTestId("page-dns-forwarders")).toBeVisible();
  await expect(page.getByTestId("dns-nav").locator('[data-key="forwarders"]')).toHaveAttribute("aria-current", "page");
  await expect(rule(page, "corp.example.test").getByTestId("fwd-upstream")).toHaveCount(2);
  // No root rule yet: the note says where the remaining names go.
  await expect(page.getByTestId("fwd-no-default")).toBeVisible();
  await expect(page.getByTestId("dns-recursion")).toHaveAttribute("data-state", "default");

  await page.getByTestId("dns-forwarder-create").click();
  const form = page.getByTestId("dialog-forwarder-form");
  await form.getByTestId("field-suffix").fill(".");
  await form.getByTestId("field-upstreams").fill("9.9.9.9\n149.112.112.112");
  // Both addresses are Quad9's: DNS over TLS with its certificate name is offered.
  await expect(form.getByTestId("fwd-known")).toHaveAttribute("data-key", "dns.quad9.net");
  await form.getByTestId("fwd-use-dot").click();
  await expect(form.getByTestId("field-transport-dot")).toBeChecked();
  await expect(form.getByTestId("field-tls_name")).toHaveValue("dns.quad9.net");
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);

  const root = rule(page, ".");
  await expect(root.getByTestId("fwd-default")).toBeVisible();
  await expect(root.getByTestId("fwd-transport")).toHaveAttribute("data-kind", "dot");
  await expect(root.locator('[data-testid="fwd-upstream"][data-key="9.9.9.9:853"]')).toBeVisible();
  await expect(page.getByTestId("fwd-no-default")).toHaveCount(0);
  const created = fake.sent.find((s) => s.method === "POST");
  expect(created?.body).toMatchObject({
    suffix: ".",
    transport: "dot",
    tls_name: "dns.quad9.net",
    upstreams: [{ address: "9.9.9.9" }, { address: "149.112.112.112" }],
  });

  // Edit: one more upstream, sent with the revision of the rule.
  await rowAction(page, root, "edit");
  await form.getByTestId("field-upstreams").fill("9.9.9.9\n149.112.112.112\n[2620:fe::fe]:853");
  await form.getByTestId("form-submit").click();
  await expect(root.getByTestId("fwd-upstream")).toHaveCount(3);
  const patch = fake.sent.find((s) => s.method === "PATCH");
  expect(patch?.ifMatch).toMatch(/^"\d+"$/);
  expect(fake.rule(".")?.upstreams).toContainEqual({ address: "2620:fe::fe", port: 853 });

  // Delete the rule of the domain controllers.
  await rowAction(page, rule(page, "corp.example.test"), "delete");
  await page.getByTestId("dialog-forwarder-delete").getByTestId("confirm-ok").click();
  await expect(rule(page, "corp.example.test")).toHaveCount(0);
  expect(fake.rule("corp.example.test")).toBeUndefined();
});

test("checks the rule before it is sent and shows a refusal under its field", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeResolver.install(page);
  await page.goto("/dns/forwarders");
  await expect(rule(page, "corp.example.test")).toBeVisible();
  await page.getByTestId("dns-forwarder-create").click();
  const form = page.getByTestId("dialog-forwarder-form");
  await form.getByTestId("field-suffix").fill("lab.example.test");
  await form.getByTestId("field-transport-dot").check();
  await form.getByTestId("field-upstreams").fill("192.0.2.1\nnot-an-address");
  await form.getByTestId("form-submit").click();
  await expect(form.locator('[data-testid="field-error"][data-field="upstreams"]')).toBeVisible();
  await expect(form.locator('[data-testid="field-error"][data-field="tls_name"]')).toBeVisible();
  expect(fake.sent).toHaveLength(0);

  // The same suffix twice is refused by the server (`dns.forwarder.invalid`, field `suffix`).
  await form.getByTestId("field-suffix").fill("corp.example.test");
  await form.getByTestId("field-transport-plain").check();
  await form.getByTestId("field-upstreams").fill("192.0.2.1");
  await form.getByTestId("form-submit").click();
  await expect(form.locator('[data-testid="field-error"][data-field="suffix"]')).toBeVisible();
  expect(fake.sent.map((s) => s.method)).toEqual(["POST"]);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the forwarders page and its form in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await FakeResolver.install(page);
    await page.goto("/dns/forwarders");
    await expect(rule(page, "corp.example.test")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dns-forwarders"), "sv", testInfo, "dns-forwarders");
    await page.getByTestId("dns-forwarder-create").click();
    await expectRendered(page, page.getByTestId("dialog-forwarder-form"), "sv", testInfo, "dns-forwarder-form");
  });
});

test("creates and deletes a rule against the real forwarder routes", async ({ page, signedIn }) => {
  void signedIn;
  // No fake of the forwarder routes: the real server answers (WP5.1). The module list names
  // DNS so that the area is shown; a server whose module is off answers 404 and the page
  // says so. The annotation `dns-forwarders` notes which answer came.
  await page.route(/\/api\/v1\/system\/modules(\?|$)/, (route) => withDns(route));
  await page.goto("/dns/forwarders");
  await expect(page.getByTestId("page-dns-forwarders")).toBeVisible();
  const off = page.getByTestId("dns-off");
  const grid = page.getByTestId("grid-dns-forwarders");
  await expect(off.or(grid)).toBeVisible();
  const answer = (await off.isVisible()) ? "module_off" : "served";
  test.info().annotations.push({ type: "dns-forwarders", description: answer });
  if (answer !== "served") {
    await expect(page.getByTestId("dns-forwarder-create")).toHaveCount(0);
    return;
  }
  await page.getByTestId("dns-forwarder-create").click();
  const form = page.getByTestId("dialog-forwarder-form");
  await form.getByTestId("field-suffix").fill("e2e.example.test");
  await form.getByTestId("field-upstreams").fill("192.0.2.1\n192.0.2.2:5353");
  await form.getByTestId("form-submit").click();
  const row = rule(page, "e2e.example.test");
  await expect(row.locator('[data-testid="fwd-upstream"][data-key="192.0.2.2:5353"]')).toBeVisible();
  await rowAction(page, row, "delete");
  await page.getByTestId("dialog-forwarder-delete").getByTestId("confirm-ok").click();
  await expect(row).toHaveCount(0);
});
