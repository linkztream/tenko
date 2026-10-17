// WP4.5: the zone file import and export of the DNS area. Choose a zone file, preview what it
// adds, replaces and removes with the records per type and the loss report, apply it as a job,
// export the zone as a download and import that export again without a change; a file that does
// not parse; Swedish.
//
// THESE SCENARIOS FAKE THE DNS ROUTES and the import job (support/dns-mock.ts, which says why);
// the rest of the API is the real server.

import { readFile } from "node:fs/promises";
import { FakeDns } from "./support/dns-mock";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { gridRow } from "./support/ui";

const ZONE_FILE = [
  "$ORIGIN example.test.",
  "$TTL 1800",
  "; the file's own SOA is replaced by the zone's",
  "@        IN SOA ns1 hostmaster ( 2026101799 3600 900",
  "                                1209600 300 )",
  "printer  IN A     192.0.2.30",
  "         IN A     192.0.2.31",
  "www      600 IN A 192.0.2.80",
  "wiki     IN CNAME www",
  "_sip._udp IN SRV  10 60 5060 printer",
  "legacy   IN HINFO \"pc\" \"os\"",
  "",
].join("\n");

const fact = (page: import("@playwright/test").Page, key: string) => page.locator(`[data-testid="import-fact"][data-key="${key}"]`);

test("imports a zone file through the preview and a job, then exports the zone", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  const zone = fake.zone("example.test");
  await page.goto(`/dns/zones/${zone?.id}`);
  await page.getByTestId("dns-zone-import").click();
  await expect(page.getByTestId("page-dns-import")).toBeVisible();

  await page.getByTestId("import-file-input").setInputFiles({ name: "example.test.zone", mimeType: "text/plain", buffer: Buffer.from(ZONE_FILE) });
  await expect(page.getByTestId("import-file")).toHaveAttribute("data-key", "example.test.zone");
  await page.getByTestId("import-preview").click();

  const report = page.getByTestId("import-preview-report");
  await expect(fact(page, "added")).toHaveAttribute("data-count", "3");
  await expect(fact(page, "replaced")).toHaveAttribute("data-count", "1");
  await expect(fact(page, "removed")).toHaveAttribute("data-count", "0");
  await expect(report.locator('[data-testid="import-type"][data-key="A"]')).toHaveAttribute("data-count", "3");
  await expect(report.locator('[data-testid="import-type"][data-key="SRV"]')).toHaveAttribute("data-count", "1");
  await expect(report.getByTestId("import-loss")).toHaveCount(2);
  await expect(report.locator('[data-testid="import-loss"][data-code="dns.import.unsupported_type"]')).toBeVisible();
  // The preview is a dry run: nothing is written yet.
  expect(fake.rrsets("example.test").some((s) => s.name === "printer.example.test")).toBe(false);
  expect(fake.sent.at(-1)?.query).toBe("dry_run=true");

  await report.getByTestId("import-apply").click();
  const result = page.getByTestId("import-result");
  await expect(result).toHaveAttribute("data-state", "done");
  await expect(result.getByTestId("import-serial")).toHaveAttribute("data-key", String(fake.zone("example.test")?.soa_serial));
  expect(fake.sent.at(-1)).toMatchObject({ query: "", body: { zone_file: ZONE_FILE, replace: false } });

  await result.getByTestId("import-open-zone").click();
  await expect(gridRow(page, "dns-records", "printer/A/1")).toBeVisible();
  await expect(gridRow(page, "dns-records", "_sip._udp/SRV/0").locator('[data-col="data"]')).toHaveText("10 60 5060 printer.example.test");

  // Export: a download of the zone file in canonical order.
  const download = page.waitForEvent("download");
  await page.getByTestId("dns-zone-export").click();
  const file = await download;
  expect(file.suggestedFilename()).toBe("example.test.zone");
  const exported = await readFile((await file.path()) ?? "", "utf8");
  expect(exported.startsWith("$ORIGIN example.test.\n$TTL 3600\n")).toBe(true);
  expect(exported).toContain("printer.example.test.\t1800\tIN\tA\t192.0.2.30");

  // The export imports again without a change.
  await page.getByTestId("dns-zone-import").click();
  await page.getByTestId("field-zone_file").fill(exported);
  await page.getByTestId("import-preview").click();
  await expect(fact(page, "added")).toHaveAttribute("data-count", "0");
  await expect(fact(page, "replaced")).toHaveAttribute("data-count", "0");
  await expect(fact(page, "removed")).toHaveAttribute("data-count", "0");
});

test("says on which line a zone file does not parse", async ({ page, signedIn }) => {
  void signedIn;
  const fake = await FakeDns.install(page);
  await page.goto(`/dns/import/${fake.zone("example.test")?.id}`);
  await page.getByTestId("field-zone_file").fill("$ORIGIN example.test.\n$INCLUDE other.zone\n");
  await page.getByTestId("import-preview").click();
  const notice = page.getByTestId("error-notice");
  await expect(notice).toHaveAttribute("data-code", "dns.zonefile.invalid");
  await expect(notice).toContainText("2");
  await expect(page.locator('[data-testid="import-step"][aria-current="step"]')).toHaveAttribute("data-key", "upload");
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the import steps and the preview in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    const fake = await FakeDns.install(page);
    await page.goto(`/dns/import/${fake.zone("example.test")?.id}`);
    await expectRendered(page, page.getByTestId("page-dns-import"), "sv", testInfo, "dns-import");
    await page.getByTestId("field-zone_file").fill(ZONE_FILE);
    await page.getByTestId("import-preview").click();
    await expectRendered(page, page.getByTestId("import-preview-report"), "sv", testInfo, "dns-import-preview");
  });
});
