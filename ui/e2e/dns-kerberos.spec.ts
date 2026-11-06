// WP13.3: the Kerberos account of secure dynamic updates (/dns/kerberos, DNS-28, E45) against the
// real server. The adopt walks its three steps, shows the values for the PowerShell block as
// text, and reports that no KDC answered (the lab's directory is not here) without keeping the
// one-time password; a keytab written by ktutil imports, the status shows the imported account
// with its key versions and the self-test's finding with its fix, the self-test runs again, and
// the account is removed after a confirmation; Swedish.
//
// NO FAKES: the account routes are the real server's. The KDC listed is a closed port on the
// loopback address, so every exchange fails at once; the round of deploy/compose/lab-ad/account
// runs the same flows against a Samba AD domain controller.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";

const here = path.dirname(fileURLToPath(import.meta.url));
const KEYTAB = path.resolve(here, "../../crates/tenko-krb/tests/fixtures/keytabs/computer-tenko-dns.keytab");
const NO_KDC = "127.0.0.1:1";

test("adopts step by step and reports a KDC that does not answer", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/dns/kerberos");
  await page.getByTestId("kerberos-choose-adopt").click();
  const form = page.getByTestId("kerberos-adopt");
  await form.getByTestId("field-realm").fill("corp.example.test");
  await form.getByTestId("field-kdcs").fill(NO_KDC);
  await form.getByTestId("kerberos-next").click();
  await form.getByTestId("field-name").fill("tenko-dns");
  await form.getByTestId("field-spns").fill("DNS/tenko1.corp.example.test");
  const block = form.getByTestId("kerberos-block-values");
  await expect(block.getByTestId("block-name")).toHaveText("TENKO-DNS");
  await expect(block.getByTestId("block-realm")).toHaveText("CORP.EXAMPLE.TEST");
  await expect(block).not.toContainText("New-ADComputer");
  await form.getByTestId("kerberos-next").click();
  await form.getByTestId("field-password").fill("One-Time-Pass-1");
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("error-notice")).toHaveAttribute("data-code", "dns.krb.kdc.unreachable");
  await expect(form.getByTestId("field-password")).toHaveValue("");
  await expect(page.getByText("One-Time-Pass-1")).toHaveCount(0);
  // Nothing was stored.
  await page.reload();
  await expect(page.getByTestId("kerberos-setup")).toBeVisible();
});

test("imports a keytab, shows the account and its finding, and removes it", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/dns/kerberos");
  await page.getByTestId("kerberos-choose-import").click();
  const form = page.getByTestId("kerberos-import");
  await form.getByTestId("field-realm").fill("CORP.EXAMPLE.TEST");
  await form.getByTestId("field-kdcs").fill(NO_KDC);
  await form.getByTestId("field-keytab").setInputFiles(KEYTAB);
  await expect(form).toContainText("computer-tenko-dns.keytab is read");
  await form.getByTestId("field-spns").fill("DNS/tenko1.corp.example.test");
  await form.getByTestId("form-submit").click();

  const status = page.getByTestId("kerberos-status");
  await expect(status.getByTestId("kerberos-principal")).toHaveText("TENKO-DNS$@CORP.EXAMPLE.TEST");
  await expect(status.getByTestId("kerberos-owner")).toContainText("imported from a keytab");
  await expect(status.getByTestId("kerberos-version")).toHaveCount(2);
  await expect(status.locator('[data-testid="kerberos-version"][data-kvno="3"]')).toHaveAttribute("data-state", "current");
  await expect(status.locator('[data-testid="kerberos-version"][data-kvno="2"]')).toHaveAttribute("data-state", "previous");
  await expect(status.getByTestId("kerberos-rotate")).toHaveCount(0);
  // The self-test could not reach a KDC: the finding with its fix.
  const fix = status.getByTestId("kerberos-finding-fix");
  await expect(fix).toHaveAttribute("data-code", "dns.gss.self_test_failed");
  await expect(fix).toContainText("No KDC answered");
  // No key of the keytab is on the page (version 3's AES-256 key starts with 33bf225e).
  await expect(page.getByText(/33bf225e/)).toHaveCount(0);

  // The self-test again: 503, the finding stays.
  await status.getByTestId("kerberos-check").click();
  await expect(page.getByTestId("error-notice")).toHaveAttribute("data-code", "dns.krb.kdc.unreachable");
  await expect(status.getByTestId("kerberos-finding")).toHaveCount(1);

  await status.getByTestId("kerberos-delete").click();
  const dialog = page.getByTestId("dialog-kerberos-delete");
  await expect(dialog).toContainText("TENKO-DNS$@CORP.EXAMPLE.TEST");
  await dialog.getByTestId("confirm-ok").click();
  await expect(page.getByTestId("kerberos-setup")).toBeVisible();
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the set-up and the adopt steps in Swedish", async ({ page, signedIn }, testInfo) => {
    void signedIn;
    await page.goto("/dns/kerberos");
    await expectRendered(page, page.getByTestId("page-dns-kerberos"), "sv", testInfo, "dns-kerberos");
    await page.getByTestId("kerberos-choose-adopt").click();
    await expectRendered(page, page.getByTestId("kerberos-adopt"), "sv", testInfo, "dns-kerberos-adopt");
  });
});
