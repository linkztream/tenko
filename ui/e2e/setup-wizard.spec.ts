// Scenario 1: the first-run wizard end to end (API-10, OPS-22). The setup token comes from
// the server's standard output, as an operator reads it from the console.
//
// - Over HTTPS with the internal CA (Home profile): the wizard completes and the CA root the
//   UI offers is the file the server wrote to its data directory.
// - Under the Lab profile over plain HTTP: the Lab warning needs an acknowledgement, a
//   passkey added on the result step (virtual platform authenticator) brings the recovery
//   codes, which must be confirmed before the application opens; there is no CA root.

import type { Locator, Page } from "@playwright/test";
import { ADMIN, type Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { withKey } from "./support/ui";
import { addPlatformAuthenticator } from "./support/webauthn";

/** Continues to the next step and waits until the wizard shows `step`. */
async function next(page: Page, card: Locator, step: string): Promise<void> {
  await expect(page.getByTestId("setup-blocker")).toHaveCount(0);
  await page.getByTestId("setup-next").click();
  await expect(card).toHaveAttribute("data-key", step);
}

/** Walks the seven steps with the administrator of the tests and finishes. */
async function completeWizard(page: Page, token: string, profile: "home" | "lab"): Promise<Locator> {
  const card = page.getByTestId("setup-card");
  await expect(card).toHaveAttribute("data-key", "welcome");
  await page.getByTestId("field-setup-token").fill(token);
  await next(page, card, "profile");

  await withKey(page, "setup-profile", profile).check();
  if (profile === "lab") {
    // Continue stays blocked until the Lab warning is acknowledged.
    await expect(page.getByTestId("setup-blocker")).toBeVisible();
    await page.getByTestId("field-lab-ack").check();
  }
  await next(page, card, "admin");

  await page.getByTestId("field-user-name").fill(ADMIN.name);
  await page.getByTestId("field-display-name").fill(ADMIN.displayName);
  await page.getByTestId("field-password").fill(ADMIN.password);
  // The live password check against the profile's PIN preset clears the blocker.
  await next(page, card, "host");

  await page.getByTestId("field-host-name").fill("localhost");
  if (profile === "lab") {
    await withKey(page, "setup-tls", "plain").check();
  } else {
    await expect(withKey(page, "setup-tls", "internal_ca")).toBeChecked();
    // Plain HTTP is a Lab-only choice (TGL-08).
    await expect(withKey(page, "setup-tls", "plain")).toBeDisabled();
  }
  await next(page, card, "disk");
  await next(page, card, "roles");

  // The node reports no networks to probe, so the probe role is left out.
  await withKey(page, "setup-role", "probe").uncheck();
  await expect(withKey(page, "setup-role", "controller")).toBeChecked();
  await next(page, card, "done");

  await page.getByTestId("setup-next").click();
  await expect(card).toHaveAttribute("data-key", "result");
  return card;
}

function hex(text: string): string {
  return text.replace(/[^0-9a-f]/gi, "").toUpperCase();
}

test.describe("first-run wizard over HTTPS with the internal CA", () => {
  test.use({ transport: "internal_ca" });

  test("sets up the installation; the CA root offered is the data directory's", async ({ page, server, api }) => {
    expect(server.setupToken).toMatch(/^[A-Z0-9]{5}(-[A-Z0-9]{5}){3}$/);
    expect(server.caFingerprint).toMatch(/^[0-9A-Fa-f:]{64,}$/);
    await page.goto("/");
    await expect(page.getByTestId("page-setup")).toBeVisible();
    await completeWizard(page, server.setupToken, "home");

    // Without a passkey or an authenticator app there are no recovery codes yet.
    await expect(page.getByTestId("recovery-codes")).toHaveCount(0);
    await page.getByTestId("setup-open").click();
    await expect(page.getByTestId("page-dashboard")).toBeVisible();

    const session = await api.session();
    expect(session.user.name).toBe(ADMIN.name);
    expect(session.profile).toBe("home");
    expect(session.strength).toBe("pin");
    expect((await api.get<Schemas["SetupState"]>("/setup")).open).toBe(false);

    // The account page offers the CA root while the internal CA serves; it is the PEM of
    // <data_dir>/tls/ca-root.pem.
    await page.goto("/account");
    await expect(page.getByTestId("page-account")).toBeVisible();
    const link = page.getByTestId("ca-root-download");
    await expect(link).toBeVisible();
    const href = await link.getAttribute("href");
    expect(href).toBe("/api/v1/system/ca-root");
    const download = await page.request.get(href ?? "");
    expect(download.status()).toBe(200);
    expect(await download.text()).toBe(await server.caRootPem());
  });

  // POST /setup answers `ca_fingerprint` in internal CA mode; the result step shows it
  // with the CA root link.
  test("the result step shows the CA fingerprint and the CA root link", async ({ page, server }) => {
    await page.goto("/setup");
    await completeWizard(page, server.setupToken, "home");
    const link = page.getByTestId("ca-root-download");
    await expect(link).toBeVisible();
    const download = await page.request.get((await link.getAttribute("href")) ?? "");
    expect(await download.text()).toBe(await server.caRootPem());
    expect(hex(await page.getByTestId("setup-ca-fingerprint").innerText())).toBe(hex(server.caFingerprint));
  });
});

test.describe("first-run wizard under the Lab profile over plain HTTP", () => {
  test("acknowledges Lab, adds a passkey, confirms the recovery codes", async ({ page, server, api }) => {
    const authenticator = await addPlatformAuthenticator(page);
    await page.goto("/setup");
    await expect(page.getByTestId("page-setup")).toBeVisible();
    await completeWizard(page, server.setupToken, "lab");
    await expect(page.getByTestId("ca-root-download")).toHaveCount(0);

    // A passkey on the result step creates the recovery codes, shown once.
    await page.getByTestId("setup-passkey-add").click();
    const codes = page.getByTestId("recovery-codes");
    await expect(codes).toBeVisible();
    expect((await codes.innerText()).split(/\s+/).filter(Boolean).length).toBeGreaterThanOrEqual(8);
    expect(await authenticator.credentials()).toHaveLength(1);

    // Opening is refused until the codes are confirmed as saved.
    const open = page.getByTestId("setup-open");
    await expect(open).toHaveAttribute("aria-disabled", "true");
    await expect(page.getByTestId("setup-blocker")).toBeVisible();
    await page.getByTestId("recovery-saved").check();
    await expect(open).toHaveAttribute("aria-disabled", "false");
    await open.click();
    await expect(page.getByTestId("page-dashboard")).toBeVisible();

    const session = await api.session();
    expect(session.profile).toBe("lab");
    expect(session.banner.lab).toBe(true);
    const credentials = await api.get<Schemas["Page_CredentialInfo"]>("/auth/webauthn/credentials");
    expect(credentials.items).toHaveLength(1);
    expect((await page.request.get("/api/v1/system/ca-root")).status()).toBe(404);
  });
});
