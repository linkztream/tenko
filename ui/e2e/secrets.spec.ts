// WP2.11: operator secrets end to end (IAM-07, IAM-15, IAM-16, API-11, TGL-24; docs/secrets.md).
// Five tests, each with its own server and its own arrangement.
//
// - The PIN rule: a PIN session cannot store a secret, and with a stronger session the store
//   is still refused while an operator signs in with a PIN alone (409 `vault.pin_coupling`,
//   section 2); disabling that account lets the same form succeed.
// - Create and reveal under the rule of the Lab profile (`step_up: session`): the lists, the
//   detail and the API never show the value; the reveal dialog copies it, shows it on
//   request, clears the clipboard once the time the server names has passed (the page clock
//   of the browser is moved forward, so nothing waits 30 seconds), and the audit log has the
//   create and reveal records without the value (section 3, section 4).
// - The step-up of TGL-24: with the rule set to `passkey`, a reveal from a password-and-TOTP
//   session asks for a passkey in the dialog, the virtual platform authenticator answers, the
//   reveal repeats and succeeds in a new session of passkey strength.
// - Host credentials and the hand-off (section 5), with the host binding of TGL-24 on: binding a
//   secret to a host, the secrets page that cannot reveal it, the reveal from the host view
//   that names the host, the `ssh://` link the page hands to the operating system, the
//   downloaded `.rdp` file (the same text as the API, no password in it), and unbinding, which
//   also takes the user name out of the hand-off.
// - Swedish: the secrets page, its reveal and edit dialogs and the credentials of a host.
//
// Arrangement: setup and the first sign-in come from the fixtures (a PIN session). Tests that
// reveal replace it with a password-and-TOTP session through the API (`strongSession`; the
// browser shares the cookie). Prefixes, hosts, addresses, and the secrets of the tests that do
// not create one in the form come through the API. Secret writes are not jobs (docs/secrets.md
// section 7), so no job page is involved in this area.
//
// What stays manual: the 30 seconds of a real clipboard clearing and a clipboard that the
// browser refuses (component tests of the dialog and of clipboard.ts), the Standard profile's
// five-minute freshness (it needs a session older than that), the Hardened host binding (Rust
// tests), a connector that references a secret (connector scenarios), a hardware security key,
// and the operating system's own handling of `ssh://` links and `.rdp` files. The TGL-24
// editor on /settings/security has no test id on its edit and save buttons, so the rule is
// changed through `PATCH /settings/security`, before the first secret is stored: once the vault
// holds one, the server refuses every change of the settings in a profile where a PIN may stand
// alone with optional MFA (409 `settings.pin_coupling`, docs/secrets.md section 2).

import { readFile } from "node:fs/promises";
import type { Locator, Page, Response } from "@playwright/test";
import type { Api, Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import type { TenkoServer } from "./support/server";
import type { Authenticator } from "./support/totp";
import { withId, withKey } from "./support/ui";
import { addPlatformAuthenticator } from "./support/webauthn";

type Secret = Schemas["OperatorSecretView"];
type AuditRecord = Schemas["AuditRecord"];
type Problem = Schemas["ProblemDetails"];

/** An invented value; distinctive, so a leak into a list, a log or a page is easy to find. */
const NAS = {
  name: "NAS admin",
  kind: "password",
  username: "admin",
  tags: ["example", "nas"],
  notes: "Rack 2, front panel",
  value: "Zq7-example-nas-secret-31337",
} as const;

/** The invented PIN of the operator who keeps the vault closed (digits only, as the PIN preset wants). */
const OPERATOR_PIN = "482916";

const HOST = "nas01.example.test";

const isCreate = (response: Response): boolean =>
  new URL(response.url()).pathname === "/api/v1/secrets" && response.request().method() === "POST";

const isReveal = (id: string) => (response: Response): boolean =>
  new URL(response.url()).pathname === `/api/v1/secrets/${id}/reveal` && response.request().method() === "POST";

async function problemOf(response: Response): Promise<Problem> {
  return (await response.json()) as Problem;
}

/**
 * Replaces the PIN session of the browser context by one of password-and-TOTP strength: a PIN
 * session never reveals, and a secret needs a session that may reveal (docs/secrets.md
 * section 2). The browser shares the cookie; load a page afterwards.
 */
async function strongSession(api: Api): Promise<Authenticator> {
  const { authenticator } = await api.enrolTotp();
  const session = await api.signIn(authenticator);
  expect(session.strength).toBe("password_totp");
  return authenticator;
}

/** Stores a secret through the API, as the form does (no `Idempotency-Key`). */
async function createSecret(api: Api, fields: { name: string; value: string; username?: string; tags?: string[] }): Promise<Secret> {
  return api.post<Secret>("/secrets", { kind: "password", ...fields }, { idempotencyKey: null });
}

/** The records of one audit action, oldest first. */
async function auditOf(api: Api, action: string): Promise<AuditRecord[]> {
  return (await api.get<Schemas["Page_AuditRecord"]>("/audit", { action, order: "asc", limit: 1000 })).items;
}

/** The creates of operator secrets (the log also has the creates of the system secrets, such as TOTP seeds). */
async function operatorCreates(api: Api): Promise<AuditRecord[]> {
  return (await auditOf(api, "vault.secret.create")).filter((record) => contextOf(record).class === "operator");
}

/** The whole audit log as one text, to look for a value that must not be in it. */
async function wholeLog(api: Api): Promise<string> {
  return JSON.stringify((await api.get<Schemas["Page_AuditRecord"]>("/audit", { order: "asc", limit: 1000 })).items);
}

function contextOf(record: AuditRecord): Record<string, string> {
  return record.draft.details?.context ?? {};
}

async function grantClipboard(page: Page, server: TenkoServer): Promise<void> {
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: server.url });
}

async function clipboardText(page: Page): Promise<string> {
  return page.evaluate(() => navigator.clipboard.readText());
}

/** Types the metadata and the value of a new secret into the form. */
async function fillSecretForm(form: Locator, fields: { name: string; username?: string; tags?: string; notes?: string; value: string }): Promise<void> {
  await form.getByTestId("field-name").fill(fields.name);
  await form.getByTestId("field-kind").selectOption(NAS.kind);
  if (fields.username) await form.getByTestId("field-username").fill(fields.username);
  if (fields.tags) await form.getByTestId("field-tags").fill(fields.tags);
  if (fields.notes) await form.getByTestId("field-notes").fill(fields.notes);
  await form.getByTestId("field-value").fill(fields.value);
}

/**
 * Keeps the `ssh://` links that the page hands to the operating system (a temporary link that
 * is clicked) and stops the navigation, so no handler is started. Returns a reader of the
 * links so far.
 */
async function captureSshLinks(page: Page): Promise<() => Promise<string[]>> {
  await page.evaluate(() => {
    const links: string[] = [];
    Object.assign(window, { sshLinks: links });
    document.addEventListener(
      "click",
      (event) => {
        const href = (event.target as Element | null)?.closest("a")?.getAttribute("href");
        if (href?.startsWith("ssh:")) {
          event.preventDefault();
          links.push(href);
        }
      },
      true,
    );
  });
  return () => page.evaluate(() => [...(window as unknown as { sshLinks: string[] }).sshLinks]);
}

/** The prefixes, the host `nas01.example.test` and its two addresses; returns the host id. */
async function arrangeHost(api: Api): Promise<string> {
  await api.post("/prefixes", { cidr: "192.0.2.0/24" });
  await api.post("/prefixes", { cidr: "2001:db8::/64" });
  const created = await api.post<Schemas["WriteResponse_Host"]>("/hosts", {
    name: HOST,
    mode: "static",
    interfaces: [{ name: "eth0" }],
  });
  const host = created.item!.id;
  const interfaces = await api.get<Schemas["Page_Interface"]>(`/hosts/${host}/interfaces`);
  const eth0 = interfaces.items[0]!.id;
  // The first address has a DNS name, the second has none: the page offers both as targets.
  await api.post("/addresses", { ip: "192.0.2.10", dns_name: HOST, interface: eth0 });
  await api.post("/addresses", { ip: "2001:db8::10", interface: eth0 });
  return host;
}

test("a secret is refused for a PIN session and while an operator signs in with a PIN alone", async ({ page, api, signedIn }) => {
  expect(signedIn.session.strength).toBe("pin");
  await page.goto("/secrets");
  await expect(page.getByTestId("page-secrets")).toBeVisible();
  await expect(page.getByTestId("secrets-empty")).toBeVisible();

  // The administrator's own session is a PIN session, which never reveals and so cannot store.
  await page.getByTestId("secrets-create").click();
  const form = page.getByTestId("dialog-secret-form");
  await fillSecretForm(form, { name: NAS.name, username: NAS.username, value: NAS.value });
  const [byPin] = await Promise.all([page.waitForResponse(isCreate), form.getByTestId("form-submit").click()]);
  expect(byPin.status()).toBe(403);
  const stepUp = await problemOf(byPin);
  expect(stepUp.code).toBe("auth.step_up_required");
  expect(stepUp.params?.required).toBe("password");
  // The dialog stays open, takes the typed value out of the form and shows no secret.
  await expect(form).toBeVisible();
  await expect(form.getByTestId("field-value")).toHaveValue("");
  await expect(page.getByTestId("secret")).toHaveCount(0);
  expect((await api.get<Schemas["Page_OperatorSecretView"]>("/secrets")).items).toHaveLength(0);
  await form.getByTestId("form-cancel").click();
  await expect(form).toHaveCount(0);

  // A stronger session for the administrator; an operator who signs in with a PIN alone.
  await strongSession(api);
  const olga = await api.post<Schemas["UserInfo"]>(
    "/users",
    { name: "olga", roles: ["operator"], password: OPERATOR_PIN },
    { idempotencyKey: null },
  );
  await page.goto("/secrets");
  await expect(page.getByTestId("secrets-empty")).toBeVisible();
  await page.getByTestId("secrets-create").click();
  await fillSecretForm(form, { name: NAS.name, username: NAS.username, value: NAS.value });
  const [coupled] = await Promise.all([page.waitForResponse(isCreate), form.getByTestId("form-submit").click()]);
  expect(coupled.status()).toBe(409);
  const refusal = await problemOf(coupled);
  expect(refusal.code).toBe("vault.pin_coupling");
  expect(refusal.params?.accounts).toBe("olga");
  // The dialog says why and names the account.
  await expect(form.getByTestId("secret-pin-coupling")).toBeVisible();
  await expect(form.getByTestId("secret-pin-coupling")).toContainText("olga");
  expect((await api.get<Schemas["Page_OperatorSecretView"]>("/secrets")).items).toHaveLength(0);
  expect(await operatorCreates(api)).toHaveLength(0);

  // A disabled account does not count (docs/secrets.md section 2): the same dialog now stores it.
  await api.patch(`/users/${olga.id}`, { disabled: true });
  await form.getByTestId("field-value").fill(NAS.value);
  const [stored] = await Promise.all([page.waitForResponse(isCreate), form.getByTestId("form-submit").click()]);
  expect(stored.status()).toBe(201);
  const secret = (await stored.json()) as Secret;
  await expect(form).toHaveCount(0);
  await expect(page).toHaveURL(new RegExp(`/secrets/${secret.id}$`));
  await expect(page.getByTestId("secret-detail")).toHaveAttribute("data-key", NAS.name);
  const listed = await api.get<Schemas["Page_OperatorSecretView"]>("/secrets");
  expect(listed.items.map((item) => item.id)).toEqual([secret.id]);
});

test("a secret is created and revealed: the value reaches the clipboard, and no list, API answer or audit record shows it", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.strength).toBe("pin");
  await strongSession(api);
  // The clock of the page is faked so the 30 seconds of the clipboard can be skipped.
  await page.clock.install();
  await grantClipboard(page, server);
  await page.goto("/secrets");
  await expect(page.getByTestId("secrets-empty")).toBeVisible();

  // Create it through the form.
  await page.getByTestId("secrets-create").click();
  const form = page.getByTestId("dialog-secret-form");
  await fillSecretForm(form, { name: NAS.name, username: NAS.username, tags: NAS.tags.join(", "), notes: NAS.notes, value: NAS.value });
  const [creation] = await Promise.all([page.waitForResponse(isCreate), form.getByTestId("form-submit").click()]);
  expect(creation.status()).toBe(201);
  const secret = (await creation.json()) as Secret;
  await expect(form).toHaveCount(0);
  await expect(page).toHaveURL(new RegExp(`/secrets/${secret.id}$`));

  // The list and the detail show the metadata, not the value.
  const row = withId(page, "secret", secret.id);
  await expect(row).toHaveAttribute("data-key", NAS.name);
  const detail = page.getByTestId("secret-detail");
  await expect(detail).toHaveAttribute("data-id", secret.id);
  await expect(detail.getByTestId("secret-username")).toHaveText(NAS.username);
  await expect(detail.getByTestId("secret-notes")).toHaveText(NAS.notes);
  await expect(detail.getByTestId("secret-unused")).toBeVisible();
  await expect(row.getByTestId("secret-last-reveal")).toHaveCount(0);
  // The row carries the user name and the tags that were typed, and nothing of the value.
  await expect(row).toContainText(NAS.username);
  for (const tag of NAS.tags) await expect(row).toContainText(tag);
  expect(await page.content()).not.toContain(NAS.value);

  // The API agrees: the record is metadata only, in the list and on its own.
  const listed = await api.get<Schemas["Page_OperatorSecretView"]>("/secrets");
  const one = await api.get<Secret>(`/secrets/${secret.id}`);
  expect(listed.items.map((item) => item.id)).toEqual([secret.id]);
  expect(one).toMatchObject({
    name: NAS.name,
    kind: NAS.kind,
    username: NAS.username,
    tags: NAS.tags,
    notes: NAS.notes,
    origin: "manual",
    hosts: [],
  });
  expect(one.last_revealed ?? null).toBeNull();
  expect(JSON.stringify([listed, one])).not.toContain(NAS.value);

  // The create is in the audit log, without the value.
  const created = await operatorCreates(api);
  expect(created).toHaveLength(1);
  expect(created[0]!.draft.outcome).toEqual({ kind: "success" });
  expect(created[0]!.draft.objects).toContainEqual({ kind: "secret", id: secret.id });
  expect(created[0]!.principal).toMatchObject({ kind: "user", strength: "password_totp" });
  expect(JSON.stringify(created)).not.toContain(NAS.value);

  // Reveal it from the list: one click, the value goes to the clipboard.
  const [revealed] = await Promise.all([page.waitForResponse(isReveal(secret.id)), row.getByTestId("secret-reveal").click()]);
  expect(revealed.status()).toBe(200);
  const answer = (await revealed.json()) as Schemas["RevealedSecret"];
  expect(answer.value).toBe(NAS.value);
  expect(answer.username).toBe(NAS.username);
  const dialog = page.getByTestId("dialog-reveal");
  const status = dialog.getByTestId("reveal-status");
  await expect(status).toHaveAttribute("data-state", "copied");
  const countdown = dialog.getByTestId("reveal-countdown");
  await expect(countdown).toBeVisible();
  const seconds = Number(await countdown.getAttribute("data-seconds"));
  expect(seconds).toBeGreaterThan(0);
  expect(seconds).toBeLessThanOrEqual(answer.clear_after_secs);
  expect(await clipboardText(page)).toBe(NAS.value);
  await expect(dialog.getByTestId("reveal-username")).toHaveText(NAS.username);
  await expect(dialog.getByTestId("reveal-audit")).toBeVisible();

  // The value is not on the page until it is asked for.
  await expect(dialog.getByTestId("reveal-value")).toHaveCount(0);
  await dialog.getByTestId("reveal-show").click();
  await expect(dialog.getByTestId("reveal-value")).toHaveText(NAS.value);
  await dialog.getByTestId("reveal-show").click();
  await expect(dialog.getByTestId("reveal-value")).toHaveCount(0);

  // The time the server named passes: the clipboard is cleared and the dialog forgets the value.
  await page.clock.fastForward((answer.clear_after_secs + 1) * 1000);
  await expect(status).toHaveAttribute("data-state", "cleared");
  await expect(dialog.getByTestId("reveal-show")).toHaveCount(0);
  await expect(dialog.getByTestId("reveal-countdown")).toHaveCount(0);
  expect(await clipboardText(page)).toBe("");

  await dialog.getByTestId("reveal-close").click();
  await expect(dialog).toHaveCount(0);

  // The list and the detail show who revealed it last; the API has it too.
  await expect(row.getByTestId("secret-last-reveal")).toBeVisible();
  await expect(detail.getByTestId("secret-last-reveal")).toBeVisible();
  const after = await api.get<Secret>(`/secrets/${secret.id}`);
  expect(after.last_revealed?.user_name).toBe("admin");
  expect(after.last_revealed?.host ?? null).toBeNull();

  // The reveal is in the audit log: who, which secret, no host, no value.
  const reveals = await auditOf(api, "vault.secret.reveal");
  expect(reveals).toHaveLength(1);
  const reveal = reveals[0]!;
  expect(reveal.draft.outcome).toEqual({ kind: "success" });
  expect(reveal.principal).toMatchObject({ kind: "user", id: signedIn.session.user.id, strength: "password_totp" });
  expect(reveal.draft.objects).toEqual([{ kind: "secret", id: secret.id }]);
  expect(contextOf(reveal)).toMatchObject({ name: NAS.name, kind: NAS.kind });
  expect(JSON.stringify(reveal)).not.toContain(NAS.value);
  expect(await wholeLog(api)).not.toContain(NAS.value);
});

test("a reveal that needs a passkey asks for it in the dialog and succeeds in a new passkey session", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.strength).toBe("pin");
  await strongSession(api);
  await grantClipboard(page, server);

  // TGL-24: from now on a reveal needs a passkey sign-in within the last five minutes. It is set
  // before the first secret exists: with a secret in the vault the server refuses every change
  // of the settings in a profile where a PIN may stand alone (`settings.pin_coupling`).
  const changed = await api.patch<Schemas["SecuritySettingsView"]>("/settings/security", {
    secret_reveal: { step_up: "passkey", bound_host_only: false },
  });
  expect(changed.settings.secret_reveal).toEqual({ step_up: "passkey", bound_host_only: false });
  const secret = await createSecret(api, { name: NAS.name, value: NAS.value, username: NAS.username });

  // A passkey on the virtual platform authenticator.
  const authenticator = await addPlatformAuthenticator(page);
  await page.goto("/account");
  await expect(page.getByTestId("page-account")).toBeVisible();
  await page.getByTestId("field-passkey-label").fill("Test laptop");
  await page.getByTestId("account-passkey-add").click();
  await expect(withKey(page, "account-passkey", "Test laptop")).toBeVisible();
  const signCount = (await authenticator.credentials())[0]!.signCount;

  const before = await api.session();
  expect(before.strength).toBe("password_totp");

  // The reveal of a password-and-TOTP session asks for the step-up where it is.
  await page.goto("/secrets");
  const row = withId(page, "secret", secret.id);
  await expect(row).toBeVisible();
  await row.getByTestId("secret-reveal").click();
  const dialog = page.getByTestId("dialog-reveal");
  const stepUp = dialog.getByTestId("reveal-stepup");
  await expect(stepUp).toBeVisible();
  await expect(stepUp).toHaveAttribute("data-required", "passkey");
  await expect(stepUp.getByTestId("field-stepup-password")).toHaveCount(0);
  await expect(dialog.getByTestId("reveal-value")).toHaveCount(0);

  // The passkey signs in again; the dialog repeats the reveal and succeeds.
  await stepUp.getByTestId("reveal-stepup-passkey").click();
  const status = dialog.getByTestId("reveal-status");
  await expect(status).toHaveAttribute("data-state", "copied");
  await expect(stepUp).toHaveCount(0);
  await dialog.getByTestId("reveal-show").click();
  await expect(dialog.getByTestId("reveal-value")).toHaveText(NAS.value);
  expect(await clipboardText(page)).toBe(NAS.value);
  expect((await authenticator.credentials())[0]!.signCount).toBeGreaterThan(signCount);

  // The new session is a passkey session of the same account; the old one is gone.
  const after = await api.session();
  expect(after.strength).toBe("passkey");
  expect(after.user.id).toBe(before.user.id);
  expect(after.session_id).not.toBe(before.session_id);
  const sessions = await api.get<Schemas["Page_SessionSummary"]>("/auth/sessions");
  expect(sessions.items.map((item) => item.id)).not.toContain(before.session_id);
  expect(sessions.items.find((item) => item.current)?.strength).toBe("passkey");

  // The audit log has the refusal and then the reveal.
  const reveals = await auditOf(api, "vault.secret.reveal");
  expect(reveals.map((record) => record.draft.outcome.kind)).toEqual(["denied", "success"]);
  expect(contextOf(reveals[0]!).code).toBe("auth.step_up_required");
  expect(reveals[1]!.principal).toMatchObject({ kind: "user", id: before.user.id, strength: "passkey" });
  expect(await wholeLog(api)).not.toContain(NAS.value);
});

test("a secret is bound to a host, revealed from its page, handed off over SSH and RDP, and unbound", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.strength).toBe("pin");
  await strongSession(api);
  // TGL-24 with the host binding of the Hardened profile: a secret is revealed only from the
  // view of a host it is bound to. Set before the first secret exists (see the test above).
  await api.patch("/settings/security", { secret_reveal: { step_up: "session", bound_host_only: true } });
  const secret = await createSecret(api, { name: NAS.name, value: NAS.value, username: NAS.username });
  const host = await arrangeHost(api);
  await grantClipboard(page, server);

  await page.goto(`/ipam/hosts/${HOST}`);
  await expect(page.getByTestId("page-host")).toBeVisible();
  const credentials = page.getByTestId("host-credentials");
  await expect(credentials.getByTestId("credentials-empty")).toBeVisible();

  // Bind the secret as the administrative login of the host.
  await credentials.getByTestId("credential-bind").click();
  const bind = page.getByTestId("dialog-credential-bind");
  await bind.getByTestId("field-secret").selectOption(secret.id);
  await bind.getByTestId("field-role").selectOption("admin");
  await bind.getByTestId("form-submit").click();
  await expect(bind).toHaveCount(0);
  const credential = withId(credentials, "credential", secret.id);
  await expect(credential).toHaveAttribute("data-key", NAS.name);
  await expect(credential).toHaveAttribute("data-role", "admin");

  const bound = await api.get<Schemas["HostCredentialsView"]>(`/hosts/${host}/credentials`);
  expect(bound.items.map((item) => [item.secret.id, item.role])).toEqual([[secret.id, "admin"]]);
  expect(JSON.stringify(bound)).not.toContain(NAS.value);
  const bindings = await auditOf(api, "vault.host.credentials");
  expect(bindings).toHaveLength(1);
  expect(bindings[0]!.draft.outcome).toEqual({ kind: "success" });
  expect(bindings[0]!.draft.objects).toContainEqual({ kind: "host", id: host });
  expect(bindings[0]!.draft.objects).toContainEqual({ kind: "secret", id: secret.id });
  const added = bindings[0]!.draft.details?.changes ?? [];
  expect(added).toHaveLength(1);
  expect(added[0]).toMatchObject({ field: "role", new: "admin" });
  expect(added[0]!.old ?? null).toBeNull();

  // The secret lists the host that binds it, and the secrets page cannot reveal it: no host is in view.
  expect((await api.get<Secret>(`/secrets/${secret.id}`)).hosts).toEqual([{ host, role: "admin" }]);
  await page.goto(`/secrets/${secret.id}`);
  await expect(withKey(page.getByTestId("secret-references"), "secret-host", HOST)).toBeVisible();
  const refusal = page.getByTestId("dialog-reveal");
  const [refused] = await Promise.all([
    page.waitForResponse(isReveal(secret.id)),
    withId(page, "secret", secret.id).getByTestId("secret-reveal").click(),
  ]);
  expect(refused.status()).toBe(403);
  expect((await problemOf(refused)).code).toBe("vault.reveal.host_required");
  await expect(refusal.getByTestId("reveal-status")).toHaveAttribute("data-state", "failed");
  await expect(refusal.getByTestId("reveal-value")).toHaveCount(0);
  await refusal.getByTestId("reveal-close").click();
  await expect(refusal).toHaveCount(0);

  // Reveal from the host view: the reveal names the host.
  await page.goto(`/ipam/hosts/${HOST}`);
  await expect(credential).toBeVisible();
  const [revealed] = await Promise.all([page.waitForResponse(isReveal(secret.id)), credential.getByTestId("credential-copy").click()]);
  expect(revealed.status()).toBe(200);
  expect(revealed.request().postDataJSON()).toEqual({ host });
  const dialog = page.getByTestId("dialog-reveal");
  await expect(dialog.getByTestId("reveal-status")).toHaveAttribute("data-state", "copied");
  await expect(dialog.getByTestId("reveal-username")).toHaveText(NAS.username);
  await dialog.getByTestId("reveal-show").click();
  await expect(dialog.getByTestId("reveal-value")).toHaveText(NAS.value);
  expect(await clipboardText(page)).toBe(NAS.value);
  await dialog.getByTestId("reveal-close").click();
  await expect(dialog).toHaveCount(0);

  const reveals = await auditOf(api, "vault.secret.reveal");
  expect(reveals.map((record) => record.draft.outcome.kind)).toEqual(["denied", "success"]);
  expect(contextOf(reveals[0]!).code).toBe("vault.reveal.host_required");
  expect(reveals[0]!.draft.objects).toEqual([{ kind: "secret", id: secret.id }]);
  expect(reveals[1]!.draft.objects).toContainEqual({ kind: "host", id: host });
  expect(reveals[1]!.draft.objects).toContainEqual({ kind: "secret", id: secret.id });
  expect(contextOf(reveals[1]!).host).toBe(host);
  expect((await api.get<Secret>(`/secrets/${secret.id}`)).last_revealed?.host).toBe(host);

  // The hand-off: one row per address, the DNS name where there is one.
  const connect = page.getByTestId("host-connect");
  await expect(connect.getByTestId("remote-target")).toHaveCount(2);
  await expect(withKey(connect, "remote-target", HOST)).toBeVisible();
  await expect(withKey(connect, "remote-target", "2001:db8::10")).toBeVisible();

  // SSH: the page hands `ssh://user@target` to the operating system.
  const sshLinks = await captureSshLinks(page);
  await withKey(connect, "host-ssh", HOST).click();
  await expect.poll(sshLinks).toEqual([`ssh://admin@${HOST}`]);
  const ssh = await api.get<Schemas["SshHandoff"]>(`/hosts/${host}/remote`, { protocol: "ssh", address: HOST });
  expect(ssh).toMatchObject({ uri: `ssh://admin@${HOST}`, host: HOST, port: 22, username: "admin" });

  // RDP: a file download with the target, the port and the user name, and no password.
  const [download] = await Promise.all([page.waitForEvent("download"), withKey(connect, "host-rdp", HOST).click()]);
  expect(download.suggestedFilename()).toBe(`${HOST}.rdp`);
  const file = await readFile(await download.path(), "utf8");
  const lines = file.split("\r\n");
  expect(lines).toContain(`full address:s:${HOST}:3389`);
  expect(lines).toContain(`username:s:${NAS.username}`);
  expect(lines).toContain("prompt for credentials:i:1");
  expect(lines.at(-1)).toBe("");
  expect(file.replaceAll("\r\n", "")).not.toContain("\n");
  expect(file).not.toMatch(/password/i);
  expect(file).not.toContain(NAS.value);
  const rdp = await api.text(`/hosts/${host}/remote?${new URLSearchParams({ protocol: "rdp", address: HOST })}`);
  expect(file).toBe(rdp);
  // Without an address the API picks the same first target.
  expect(await api.text(`/hosts/${host}/remote?protocol=rdp`)).toBe(rdp);

  // An IPv6 address without a DNS name is a target of its own, in brackets.
  const [download6] = await Promise.all([page.waitForEvent("download"), withKey(connect, "host-rdp", "2001:db8::10").click()]);
  const file6 = await readFile(await download6.path(), "utf8");
  expect(file6.split("\r\n")).toContain("full address:s:[2001:db8::10]:3389");
  expect(file6.split("\r\n")).toContain(`username:s:${NAS.username}`);

  // Unbind: the row goes, the secret keeps existing, and the hand-off loses the user name.
  await credential.getByTestId("credential-unbind").click();
  await page.getByTestId("dialog-confirm").getByTestId("confirm-ok").click();
  await expect(credential).toHaveCount(0);
  await expect(credentials.getByTestId("credentials-empty")).toBeVisible();
  const unbound = await api.get<Schemas["HostCredentialsView"]>(`/hosts/${host}/credentials`);
  expect(unbound.items).toEqual([]);
  expect((await api.get<Secret>(`/secrets/${secret.id}`)).hosts).toEqual([]);
  const changes = await auditOf(api, "vault.host.credentials");
  expect(changes).toHaveLength(2);
  const removed = changes[1]!.draft.details?.changes ?? [];
  expect(removed).toHaveLength(1);
  expect(removed[0]).toMatchObject({ field: "role", old: "admin" });
  expect(removed[0]!.new ?? null).toBeNull();

  await withKey(connect, "host-ssh", HOST).click();
  await expect.poll(sshLinks).toEqual([`ssh://admin@${HOST}`, `ssh://${HOST}`]);
  const plain = await api.get<Schemas["SshHandoff"]>(`/hosts/${host}/remote`, { protocol: "ssh", address: HOST });
  expect(plain.uri).toBe(`ssh://${HOST}`);
  expect(plain.username ?? null).toBeNull();
  expect(await wholeLog(api)).not.toContain(NAS.value);
});

test.describe("a Swedish browser", () => {
  test.use({ locale: "sv-SE" });

  test("shows the secrets page, its dialogs and the credentials of a host in Swedish", async ({ page, api, server, signedIn }, testInfo) => {
    expect(signedIn.session.strength).toBe("pin");
    await strongSession(api);
    const secret = await createSecret(api, { name: NAS.name, value: NAS.value, username: NAS.username, tags: [...NAS.tags] });
    const host = await arrangeHost(api);
    await api.put(`/hosts/${host}/credentials`, { credentials: [{ secret: secret.id, role: "admin" }] });
    await grantClipboard(page, server);

    // The secret with its detail and the host that uses it.
    await page.goto(`/secrets/${secret.id}`);
    const row = withId(page, "secret", secret.id);
    await expect(row).toBeVisible();
    await expect(page.getByTestId("secret-detail")).toBeVisible();
    await expect(withKey(page.getByTestId("secret-references"), "secret-host", HOST)).toBeVisible();
    await expectRendered(page, page.getByTestId("page-secrets"), "sv", testInfo, "secrets");

    // The reveal dialog with the value shown.
    await row.getByTestId("secret-reveal").click();
    const reveal = page.getByTestId("dialog-reveal");
    await expect(reveal.getByTestId("reveal-status")).toHaveAttribute("data-state", "copied");
    await reveal.getByTestId("reveal-show").click();
    await expect(reveal.getByTestId("reveal-value")).toHaveText(NAS.value);
    await expectRendered(page, reveal, "sv", testInfo, "secrets-reveal");
    await reveal.getByTestId("reveal-close").click();
    await expect(reveal).toHaveCount(0);

    // The form of an existing secret.
    await row.getByTestId("secret-edit").click();
    const edit = page.getByTestId("dialog-secret-form");
    await expect(edit).toBeVisible();
    await expectRendered(page, edit, "sv", testInfo, "secrets-edit");
    await edit.getByTestId("form-cancel").click();
    await expect(edit).toHaveCount(0);

    // The credentials of the host.
    await page.goto(`/ipam/hosts/${HOST}`);
    const credentials = page.getByTestId("host-credentials");
    await expect(withId(credentials, "credential", secret.id)).toBeVisible();
    await expectRendered(page, credentials, "sv", testInfo, "host-credentials");
  });
});
