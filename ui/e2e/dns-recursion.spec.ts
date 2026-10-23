// WP10.4: the operator surface of the recursive resolver. A recurse rule created and turned back
// into a forwarding rule on the forwarders page, the default resolution of a view changed and
// cleared, an operator trust anchor added with its RFC 5011 state, refreshed and removed, a
// negative trust anchor created with a short lifetime, shown expired, and gone from the server's
// list once read again, the infrastructure cache browsed and flushed on the DNS settings page; Swedish.
//
// NO FAKES except the infrastructure cache: the forwarder, view, trust anchor and negative trust
// anchor routes are the real server's (they need no `dns` role). The e2e server has no resolver,
// so the infrastructure cache routes are faked in the browser (support/dns-infra-mock.ts, with
// the reasons and the Rust tests that prove the real behaviour); that scenario's title ends in
// "(faked status)".

import type { Locator, Page } from "@playwright/test";
import { FakeInfra } from "./support/dns-infra-mock";
import { FakeResolver, withDns } from "./support/dns-resolver-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { gridRow } from "./support/ui";

const rule = (page: Page, key: string): Locator => gridRow(page, "dns-forwarders", key);

async function rowAction(page: Page, row: Locator, action: string): Promise<void> {
  await row.getByRole("button", { name: /Actions for/ }).click();
  await page.getByTestId("row-menu").locator(`[data-key="${action}"]`).click();
}

/** A DS of a made-up key for an operator anchor (the digest only has to be 32 octets of hex). */
const DS = "12345 13 2 " + "ab".repeat(32);

test.beforeEach(async ({ page }) => {
  // The module list names DNS so that the area is shown (the e2e server runs every module).
  await page.route(/\/api\/v1\/system\/modules(\?|$)/, (route) => withDns(route));
});

test("creates a recurse rule and turns it into a forwarding rule", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/dns/forwarders");
  await expect(page.getByTestId("grid-dns-forwarders")).toBeVisible();

  await page.getByTestId("dns-forwarder-create").click();
  const form = page.getByTestId("dialog-forwarder-form");
  await form.getByTestId("field-suffix").fill("corp.example.test");
  await form.getByTestId("field-mode-recurse").check();
  // A recurse rule names no upstream, transport or TLS name.
  await expect(form.getByTestId("fwd-recurse-note")).toBeVisible();
  await expect(form.getByTestId("field-upstreams")).toHaveCount(0);
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);

  const row = rule(page, "corp.example.test");
  await expect(row.getByTestId("fwd-transport")).toHaveAttribute("data-kind", "recurse");
  await expect(row.getByTestId("fwd-recurse")).toBeVisible();
  await page.reload();
  await expect(rule(page, "corp.example.test").getByTestId("fwd-transport")).toHaveAttribute("data-kind", "recurse");

  // Back to forwarding, with an upstream and validation switched off (the escape hatch).
  await rowAction(page, rule(page, "corp.example.test"), "edit");
  await expect(form.getByTestId("field-mode-recurse")).toBeChecked();
  await form.getByTestId("field-mode-forward").check();
  await form.getByTestId("field-upstreams").fill("192.0.2.53");
  await form.getByTestId("field-validate").uncheck();
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);
  const forwarded = rule(page, "corp.example.test");
  await expect(forwarded.getByTestId("fwd-transport")).toHaveAttribute("data-kind", "plain");
  await expect(forwarded.getByTestId("fwd-unvalidated")).toBeVisible();
  await expect(forwarded.getByTestId("fwd-upstream")).toHaveAttribute("data-key", "192.0.2.53:53");
});

test("changes the default resolution of a view and clears it", async ({ page, api, signedIn }) => {
  void signedIn;
  await api.post("/dns/views", { name: "guests", order: 1, rules: [{ test: "client_subnet", prefixes: ["198.51.100.0/24"] }] });
  await page.goto("/dns/forwarders");
  const block = page.getByTestId("fwd-resolution");
  await expect(block).toBeVisible();
  // The implicit default view follows the profile, which recurses.
  await expect(block.getByTestId("fwd-resolution-default")).toHaveAttribute("data-effective", "recurse");
  const guests = block.locator('[data-testid="fwd-resolution-view"][data-key="guests"]');
  await expect(guests).toHaveAttribute("data-choice", "default");

  await guests.getByTestId("fwd-resolution-select").selectOption("refuse");
  await expect(guests).toHaveAttribute("data-choice", "refuse");
  await page.reload();
  await expect(guests).toHaveAttribute("data-effective", "refuse");
  const view = (await api.get<{ items: { name: string; resolution?: string | null }[] }>("/dns/views")).items.find((v) => v.name === "guests");
  expect(view?.resolution).toBe("refuse");

  await guests.getByTestId("fwd-resolution-select").selectOption("default");
  await expect(guests).toHaveAttribute("data-choice", "default");
  await expect(guests).toHaveAttribute("data-effective", "recurse");

  // A root rule covers every name: the block says the default is not reached there.
  await expect(block.getByTestId("fwd-resolution-root")).toHaveCount(0);
  await api.post("/dns/forwarders", { suffix: ".", upstreams: [{ address: "192.0.2.53" }] });
  await page.reload();
  await expect(block.getByTestId("fwd-resolution-root")).toBeVisible();
});

test("adds an operator trust anchor, shows its state, refreshes and removes it", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/dns/recursion");
  const section = page.getByTestId("dns-recursion-anchors");
  await expect(section).toBeVisible();

  await section.getByTestId("dns-anchor-add").click();
  const form = page.getByTestId("dialog-anchor-add");
  // The local check first: a DS needs its four fields.
  await form.getByTestId("field-anchor-zone").fill("corp.example.test");
  await form.getByTestId("field-anchor-key").fill("12345 13");
  await form.getByTestId("form-submit").click();
  await expect(form.locator('[data-testid="field-error"][data-field="anchor-key"]')).toBeVisible();
  await form.getByTestId("field-anchor-key").fill(DS);
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);

  const anchor = section.locator('[data-testid="dns-anchor"][data-key="corp.example.test"]');
  const key = anchor.locator('[data-testid="dns-anchor-key"][data-key="12345"]');
  await expect(key).toBeVisible();
  const state = await key.getAttribute("data-state");
  expect(["start", "add_pend", "valid"]).toContain(state);
  test.info().annotations.push({ type: "dns-anchor-state", description: state ?? "" });
  await expect(key.getByTestId("dns-anchor-state")).not.toHaveText("");

  await anchor.getByTestId("dns-anchor-refresh").click();
  await expect(page.getByTestId("toast").filter({ hasText: "corp.example.test" })).toBeVisible();

  await anchor.getByTestId("dns-anchor-remove").click();
  const confirm = page.getByTestId("dialog-anchor-remove");
  await confirm.getByRole("button", { name: "Remove the anchor" }).click();
  await expect(anchor).toHaveCount(0);
});

test("creates a negative trust anchor that expires", async ({ page, signedIn }) => {
  void signedIn;
  test.setTimeout(150_000);
  await page.goto("/dns/recursion");
  const section = page.getByTestId("dns-recursion-ntas");
  await expect(section.getByTestId("dns-nta-none")).toBeVisible();

  await section.getByTestId("dns-nta-add").click();
  const form = page.getByTestId("dialog-nta-add");
  await form.getByTestId("field-nta-zone").fill("broken.example.test");
  // More than seven days is refused before anything is sent.
  await form.getByTestId("field-nta-lifetime").fill("8d");
  await form.getByTestId("field-nta-reason").fill("The zone's operator let its signatures expire.");
  await form.getByTestId("form-submit").click();
  await expect(form.locator('[data-testid="field-error"][data-field="nta-expires"]')).toBeVisible();
  await form.getByTestId("field-nta-lifetime").fill("6s");
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);

  const nta = section.locator('[data-testid="dns-nta"][data-key="broken.example.test"]');
  await expect(nta).toHaveAttribute("data-state", "active");
  await expect(nta).toContainText("signatures expire");
  // Past its expiry the row says so at once ...
  await expect(nta).toHaveAttribute("data-state", "expired", { timeout: 20_000 });
  await expect(nta.getByTestId("dns-nta-expired")).toBeVisible();
  // ... and the server lists only the living ones, so it is gone once read again (the leader
  // service deletes the row at its next pass).
  await expect(async () => {
    await page.reload();
    await expect(page.getByTestId("dns-recursion-ntas").getByTestId("dns-nta-none")).toBeVisible({ timeout: 3_000 });
  }).toPass({ timeout: 100_000, intervals: [5_000] });
});

test("browses the infrastructure cache and flushes a zone (faked status)", async ({ page, signedIn }) => {
  void signedIn;
  await FakeResolver.install(page);
  const infra = await FakeInfra.install(page);
  await page.goto("/settings/dns");
  const section = page.getByTestId("dns-infra");
  await expect(section).toBeVisible();
  // Nothing is read until asked.
  expect(infra.requests).toEqual([]);

  await section.getByTestId("dns-infra-show").click();
  const cuts = section.getByTestId("dns-infra-cut");
  await expect(cuts).toHaveCount(4);
  await expect(cuts.first()).toHaveAttribute("data-key", "example.org");
  const address = section.locator('[data-testid="dns-infra-cut"][data-key="example.test"] [data-testid="dns-infra-address"]');
  await expect(address).toHaveAttribute("data-key", "192.0.2.10");
  await expect(address.locator('[data-col="srtt"]')).toContainText("ms");

  await section.getByTestId("field-infra-suffix").fill("example.test");
  await section.getByTestId("field-infra-suffix").press("Enter");
  await expect(cuts).toHaveCount(2);
  expect(infra.requests.at(-1)?.query.suffix).toBe("example.test");

  await section.getByTestId("dns-infra-flush").click();
  await page.getByTestId("dns-infra-flush-dialog").getByRole("button", { name: "Flush" }).click();
  await expect(section.getByTestId("dns-infra-empty")).toBeVisible();
  expect(infra.requests.some((r) => r.method === "POST" && r.query.suffix === "example.test")).toBe(true);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the recursion page and its forms in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/dns/recursion");
    await expect(page.getByTestId("dns-recursion-anchors")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-dns-recursion"), "sv", testInfo, "dns-recursion");
    await page.getByTestId("dns-nta-add").click();
    await expectRendered(page, page.getByTestId("dialog-nta-add"), "sv", testInfo, "dns-nta-form");
  });
});
