// Scenario 2: sign-in with a password and TOTP, then a passkey (E2, IAM-03, IAM-06). The
// TOTP codes are computed from the secret the enrolment shows (RFC 6238); the passkey lives
// on Chromium's virtual platform authenticator with user verification. Plain HTTP on
// localhost is a secure context, so the relying party is `localhost`. The last test repeats
// the passkey sign-in over HTTPS with the internal CA (TLS mode a of OPS-22).
//
// What stays manual for E2: a hardware security key, the imported-certificate and the
// reverse-proxy TLS modes on the configured host name, and the browsers' own UI.

import { ADMIN } from "./support/api";
import { expect, test } from "./support/fixtures";
import { Authenticator, totpAt, totpStep } from "./support/totp";
import { acknowledgeRecoveryCodes, signOut, withKey } from "./support/ui";
import { addPlatformAuthenticator } from "./support/webauthn";

test("password with TOTP, then a passkey enrolled and used to sign in", async ({ page, api, signedIn }) => {
  expect(signedIn.session.strength).toBe("pin");

  // Enrol the authenticator app from the account page.
  await page.goto("/account");
  await expect(page.getByTestId("page-account")).toBeVisible();
  await expect(withKey(page, "account-totp-status", "off")).toBeVisible();
  await page.getByTestId("account-totp-setup").click();
  await expect(page.getByTestId("qr-code")).toBeVisible();
  const secret = (await page.getByTestId("account-totp-secret").innerText()).replace(/\s+/g, "");
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  const app = new Authenticator(secret);
  await page.getByTestId("field-totp-code").fill(app.code());
  await page.getByTestId("account-totp-verify").click();
  // The first second factor brings the recovery codes, shown once.
  const codes = await acknowledgeRecoveryCodes(page);
  expect(codes.length).toBeGreaterThanOrEqual(8);
  await expect(withKey(page, "account-totp-status", "on")).toBeVisible();

  // Sign out; sign in with the PIN, then a wrong code, then the right one.
  await signOut(page);
  await page.getByTestId("signin-use-password").click();
  const passwordForm = page.getByTestId("signin-password-form");
  await passwordForm.getByTestId("field-user-name").fill(ADMIN.name);
  await passwordForm.getByTestId("field-password").fill(ADMIN.password);
  await passwordForm.getByTestId("form-submit").click();
  const codeForm = page.getByTestId("signin-code-form");
  await expect(codeForm).toBeVisible();
  await expect(withKey(codeForm, "signin-method", "recovery")).toBeVisible();
  const stale = totpAt(secret, totpStep(Date.now() / 1000) - 20);
  await codeForm.getByTestId("field-code").fill(stale);
  await codeForm.getByTestId("form-submit").click();
  await expect(page.getByTestId("signin-error")).toBeVisible();
  await codeForm.getByTestId("field-code").fill(app.code());
  await codeForm.getByTestId("form-submit").click();
  await expect(page.getByTestId("page-dashboard")).toBeVisible();
  expect((await api.session()).strength).toBe("password_totp");

  // Enrol a passkey on the platform authenticator.
  const authenticator = await addPlatformAuthenticator(page);
  await page.goto("/account");
  await page.getByTestId("field-passkey-label").fill("Test laptop");
  await page.getByTestId("account-passkey-add").click();
  await expect(withKey(page, "account-passkey", "Test laptop")).toBeVisible();
  const stored = await authenticator.credentials();
  expect(stored).toHaveLength(1);
  expect(stored[0]?.isResidentCredential).toBe(true);
  expect(stored[0]?.rpId).toBe("localhost");

  // Sign out and back in with the passkey alone: a discoverable credential, no user name.
  await signOut(page);
  await page.getByTestId("signin-passkey").click();
  await expect(page.getByTestId("page-dashboard")).toBeVisible();
  const session = await api.session();
  expect(session.strength).toBe("passkey");
  expect(session.user.name).toBe(ADMIN.name);
  expect((await authenticator.credentials())[0]?.signCount).toBeGreaterThan(0);
});

test("a TOTP code cannot be used twice", async ({ api, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const { authenticator } = await api.enrolTotp();
  const first = await api.loginPassword();
  expect(first.status).toBe("second_factor");
  if (first.status !== "second_factor") return;
  const code = authenticator.code();
  const accepted = await api.request.post(`${api.origin}/api/v1/auth/login/totp`, {
    headers: { Origin: api.origin },
    data: { challenge_id: first.challenge_id, code },
  });
  expect(accepted.status()).toBe(200);
  const again = await api.loginPassword();
  if (again.status !== "second_factor") throw new Error("expected a second factor");
  const replayed = await api.request.post(`${api.origin}/api/v1/auth/login/totp`, {
    headers: { Origin: api.origin },
    data: { challenge_id: again.challenge_id, code },
  });
  expect(replayed.status()).toBe(401);
});

test("the monospace font is served hashed with a long-lived cache header", async ({ page }) => {
  const font = page.waitForResponse((r) => /\/assets\/jetbrains-mono-latin-[\w-]+\.woff2$/.test(r.url()));
  await page.goto("/");
  const response = await font;
  expect(response.status()).toBe(200);
  expect(response.headers()["cache-control"]).toBe("public, max-age=31536000, immutable");
});

test.describe("over HTTPS with the internal CA", () => {
  test.use({ transport: "internal_ca" });

  test("a passkey signs in on the configured host name", async ({ page, api, server, signedIn }) => {
    expect(server.url.startsWith("https://localhost:")).toBe(true);
    expect(signedIn.session.profile).toBe("home");
    const authenticator = await addPlatformAuthenticator(page);
    await page.goto("/account");
    await page.getByTestId("field-passkey-label").fill("Office laptop");
    await page.getByTestId("account-passkey-add").click();
    await expect(withKey(page, "account-passkey", "Office laptop")).toBeVisible();
    // The first factor besides the PIN brings the recovery codes.
    await acknowledgeRecoveryCodes(page);
    expect((await authenticator.credentials())[0]?.rpId).toBe("localhost");

    await signOut(page);
    await page.getByTestId("signin-passkey").click();
    await expect(page.getByTestId("page-dashboard")).toBeVisible();
    expect((await api.session()).strength).toBe("passkey");
  });
});
