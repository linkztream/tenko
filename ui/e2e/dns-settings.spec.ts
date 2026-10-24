// WP5.5: the DNS settings of the node (/settings/dns, read-only). With the dns role: the
// listeners, the cache figures with their tenko.toml keys, the query log; without the role and
// with the module off: the notice that says what to set; Swedish; and what the page shows
// against the real server, whose one node does not run the dns role.
//
// THE FIRST SCENARIOS FAKE THE NODE'S DNS STATUS (support/dns-resolver-mock.ts, which says why);
// the last one runs against the real server.

import { FakeResolver } from "./support/dns-resolver-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

test("shows the effective settings and figures of a node with the dns role", async ({ page, signedIn }) => {
  void signedIn;
  await FakeResolver.install(page);
  await page.goto("/settings/dns");
  await expect(page.getByTestId("page-dns-settings")).toBeVisible();
  await expect(page.getByTestId("settings-nav").locator('[data-key="dns"]')).toBeVisible();
  const listeners = page.getByTestId("dns-settings-listener");
  await expect(listeners).toHaveCount(2);
  await expect(listeners.first()).toHaveAttribute("data-kind", "udp");
  await expect(page.getByTestId("dns-settings-tls")).toHaveAttribute("data-dot", "false");

  const entries = page.locator('[data-testid="dns-setting"][data-key="cache_entries"]');
  await expect(entries).toHaveAttribute("data-value", "1234");
  await expect(entries.getByTestId("dns-setting-key")).toHaveText("[dns.cache] entries");
  await expect(page.locator('[data-testid="dns-setting"][data-key="cache_hit_ratio"]')).toHaveAttribute("data-value", "0.84");
  await expect(page.getByTestId("dns-settings-cache").getByTestId("dns-setting-doc")).toContainText("dns-resolver.md");
  await expect(page.getByTestId("dns-settings-no-role")).toHaveCount(0);

  await page.getByTestId("dns-settings-forwarders").click();
  await expect(page.getByTestId("page-dns-forwarders")).toBeVisible();
});

test("says what to set when the node has no dns role or the module is off", async ({ page, signedIn }) => {
  void signedIn;
  await FakeResolver.install(page, { node: "not_dns" });
  await page.goto("/settings/dns");
  await expect(page.getByTestId("dns-settings-no-role")).toBeVisible();
  await expect(page.getByTestId("dns-setting")).toHaveCount(0);
});

test("says so when the DNS module is switched off", async ({ page, signedIn }) => {
  void signedIn;
  await FakeResolver.install(page, { node: "module_off" });
  await page.goto("/settings/dns");
  const off = page.getByTestId("dns-settings-off");
  await expect(off).toBeVisible();
  await expect(off.getByTestId("dns-modules-link")).toHaveAttribute("href", "/settings");
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the DNS settings in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await FakeResolver.install(page);
    await page.goto("/settings/dns");
    await expect(page.getByTestId("dns-settings-listener")).toHaveCount(2);
    await expectRendered(page, page.getByTestId("page-dns-settings"), "sv", testInfo, "dns-settings");
  });
});

test("says so against the real server, whose one node does not run the dns role", async ({ page, signedIn }) => {
  void signedIn;
  // No fake: the controller of the e2e server has no dns role, so the node answers 409
  // `dns.node.not_dns` with the module on and 404 with it off; a server not yet in a cluster
  // has no node id. The annotation `dns-settings` notes which answer came.
  await page.goto("/settings/dns");
  await expect(page.getByTestId("page-dns-settings")).toBeVisible();
  const noRole = page.getByTestId("dns-settings-no-role");
  const off = page.getByTestId("dns-settings-off");
  const noNode = page.getByTestId("dns-settings-no-node");
  await expect(noRole.or(off).or(noNode)).toBeVisible();
  const answer = (await noRole.isVisible()) ? "not_dns" : (await off.isVisible()) ? "module_off" : "no_node";
  test.info().annotations.push({ type: "dns-settings", description: answer });
  await expect(page.getByTestId("dns-setting")).toHaveCount(0);
});
