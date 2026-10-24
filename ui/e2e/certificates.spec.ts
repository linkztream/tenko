// The certificates page (/settings/certificates, OPS-22, TGL-08) against the real server.
//
// Arrangement: the e2e server runs `tls.mode = "plain"` under Lab, or with the `internal_ca`
// transport the product default under Home. It has no imported files (the test server writes
// no certificate of its own), so the imported-files view with a pending certificate answers
// `GET /system/tls` in the browser (`fakeImported`); the Rust tests of `routes/system/tls.rs`
// and `tls_service.rs` prove the real behaviour of the pending state.
//
// Scenarios:
// - Plain HTTP under Lab: the mode, the notice and no certificate; the API agrees.
// - The internal CA: the certificate in use with its names, chain length and fingerprint, the
//   CA root with its fingerprint and the download link, which serves the PEM; the page shows what
//   the API answers.
// - The page reads when it opens and on Refresh only, never on its own.
// - A newer certificate on disk under Standard, where a replaced certificate is not accepted
//   (faked `GET /system/tls` and status): the pending notice and the certificate, with the days
//   left of the certificate in use in the warning style (faked imported files).
// - axe finds nothing on the page, Swedish.

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";
import type { Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

type Details = Schemas["TlsDetails"];

/**
 * Runs axe-core in the page and answers the ids of the rules a part of it violates. The script is
 * evaluated through the browser's debugging protocol, since the page's CSP refuses injected tags.
 */
async function axeViolations(page: Page, selector: string): Promise<string[]> {
  await page.evaluate(await readFile(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8"));
  return page.evaluate(async (scope) => {
    const axe = (window as unknown as { axe: { run(context: string): Promise<{ violations: { id: string }[] }> } }).axe;
    return (await axe.run(scope)).violations.map((v) => v.id);
  }, selector);
}

const DAY = 86_400_000;

function certificate(days: number, sha256: string): Schemas["TlsCertificate"] {
  const now = Date.now();
  return {
    subject: "CN=ddi.example.test",
    issuer: "CN=Example Issuing CA R1",
    dns_names: ["ddi.example.test"],
    ip_addresses: ["192.0.2.10"],
    not_before: new Date(now + days * DAY - 90 * DAY).toISOString(),
    not_after: new Date(now + days * DAY).toISOString(),
    days_left: days,
    state: days < 30 ? "warning" : "valid",
    chain_len: 2,
    sha256,
  };
}

/** Answers the TLS route and the status of the browser with imported files and a pending certificate. */
async function fakeImported(page: Page): Promise<void> {
  const served = "7c1f3a9e5b2d4086a3c1e9d8f7b6a5c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7";
  const pending = "b4e2a1d09c8f7e6d5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f";
  const details: Details = {
    mode: "imported",
    min_version: "1.2",
    hsts: true,
    certificate: certificate(12, served),
    loaded_at: new Date(Date.now() - 3 * DAY).toISOString(),
    last_error: null,
    pending: { certificate: certificate(90, pending), detected_at: new Date(Date.now() - 20 * 60_000).toISOString() },
    imported: { cert_path: "/etc/tenko/tls/fullchain.pem", key_path: "/etc/tenko/tls/privkey.pem", watch_interval_secs: 5, accept_external_replacement: false },
    internal_ca: null,
    reverse_proxy: null,
  };
  await page.route("**/api/v1/system/tls", (route) => route.fulfill({ json: details }));
  await page.route("**/api/v1/system/status", async (route) => {
    const response = await route.fetch();
    const status = (await response.json()) as Schemas["SystemStatus"];
    status.warnings = [
      ...status.warnings,
      { code: "sys.tls.certificate_expiry", detail: "the server certificate is warning: 12 days left", params: { state: "warning", days_left: "12" } },
      { code: "sys.tls.certificate_pending", detail: "a newer certificate is on disk", params: {} },
    ];
    await route.fulfill({ response, json: status });
  });
}

test("plain HTTP under Lab shows the mode and the notice, and no certificate", async ({ page, api, signedIn }) => {
  void signedIn;
  const details = await api.get<Details>("/system/tls");
  expect(details.mode).toBe("plain");
  expect(details.certificate ?? null).toBeNull();
  await page.goto("/settings/certificates");
  await expect(page.getByTestId("page-certificates")).toBeVisible();
  await expect(page.getByTestId("certificates-mode")).toHaveAttribute("data-mode", "plain");
  await expect(page.getByTestId("certificates-plain")).toBeVisible();
  await expect(page.getByTestId("certificates-served")).toHaveCount(0);
  await expect(page.getByTestId("settings-nav").getByTestId("settings-nav-link").filter({ hasText: "Certificates" })).toHaveAttribute("aria-current", "page");
});

test.describe("with the internal CA", () => {
  test.use({ transport: "internal_ca" });

  test("shows the certificate in use and the CA root with its download", async ({ page, api, signedIn }) => {
    void signedIn;
    const details = await api.get<Details>("/system/tls");
    expect(details.mode).toBe("internal_ca");
    const cert = details.certificate!;
    expect(cert.days_left).toBeGreaterThan(30);
    await page.goto("/settings/certificates");
    await expect(page.getByTestId("certificates-mode")).toHaveAttribute("data-mode", "internal_ca");
    await expect(page.getByTestId("cert-subject")).toHaveText(cert.subject);
    await expect(page.getByTestId("cert-days")).toHaveAttribute("data-state", "valid");
    await expect(page.getByTestId("cert-chain")).toHaveText("1 certificate");
    await expect(page.getByTestId("cert-fingerprint")).toHaveText(cert.sha256.match(/.{1,8}/g)!.join(" "));
    await expect(page.getByTestId("certificates-expiring")).toHaveCount(0);
    await expect(page.getByTestId("ca-fingerprint")).toHaveText(details.internal_ca!.root_sha256!.match(/.{1,8}/g)!.join(" "));
    const link = page.getByTestId("ca-root-download");
    await expect(link).toHaveAttribute("href", "/api/v1/system/ca-root");
    const root = await page.request.get("/api/v1/system/ca-root");
    expect(root.status()).toBe(200);
    expect(await root.text()).toContain("BEGIN CERTIFICATE");
  });

  test("reads when it opens and on Refresh, never on its own", async ({ page, signedIn }) => {
    void signedIn;
    const reads: string[] = [];
    page.on("request", (request) => {
      if (request.url().endsWith("/api/v1/system/tls")) reads.push(request.url());
    });
    await page.goto("/settings/certificates");
    await expect(page.getByTestId("cert-subject")).toBeVisible();
    expect(reads).toHaveLength(1);
    await page.waitForTimeout(2_000);
    expect(reads).toHaveLength(1);
    await page.getByTestId("certificates-refresh").click();
    await expect.poll(() => reads.length).toBe(2);
    await expect(page.getByTestId("cert-subject")).toBeVisible();
  });

  test("passes axe", async ({ page, signedIn }) => {
    void signedIn;
    await page.goto("/settings/certificates");
    await expect(page.getByTestId("cert-subject")).toBeVisible();
    expect(await axeViolations(page, "[data-testid='page-certificates']")).toEqual([]);
  });
});

test("a newer certificate on disk is pending where a replacement is not accepted (faked imported files)", async ({ page, signedIn }) => {
  void signedIn;
  await fakeImported(page);
  await page.goto("/settings/certificates");
  await expect(page.getByTestId("certificates-mode")).toHaveAttribute("data-mode", "imported");
  await expect(page.getByTestId("imported-accept")).toHaveAttribute("data-accepted", "false");
  await expect(page.getByTestId("imported-cert-path")).toHaveText("/etc/tenko/tls/fullchain.pem");
  await expect(page.getByTestId("certificates-pending-notice")).toHaveAttribute("data-code", "sys.tls.certificate_pending");
  await expect(page.getByTestId("pending-days")).toHaveText("90 days");
  await expect(page.getByTestId("cert-days")).toHaveText("12 days");
  await expect(page.getByTestId("cert-days")).toHaveClass(/discrepancy/);
  await expect(page.getByTestId("certificates-expiring")).toHaveAttribute("data-code", "sys.tls.certificate_expiry");
  expect(await axeViolations(page, "[data-testid='page-certificates']")).toEqual([]);
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE", transport: "internal_ca" });

  test("renders the certificates page in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/settings/certificates");
    await expect(page.getByTestId("cert-subject")).toBeVisible();
    await expectRendered(page, page.getByTestId("page-certificates"), "sv", testInfo, "certificates");
  });
});
