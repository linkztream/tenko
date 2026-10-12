// WP3.11: the audit export page (IAM-18, TGL-21; docs/audit-export.md) against the real server.
//
// Arrangement: the test server runs on the loopback with the Lab profile and the default export
// directory `<data_dir>/audit-export`. A file sink writes there, which is local and safe; the
// syslog sink points at 127.0.0.1 only. Nothing leaves the machine.
//
// Scenarios:
// - A file sink in JSON lines: added in the dialog after a test message, the sink delivers
//   (state ok, lag 0) and the file in the export directory holds the audit records as JSON lines
//   with their sequence numbers; an invalid file name is refused by the form, a taken name by
//   the server.
// - A syslog UDP sink to 127.0.0.1: the test message is handed over and a listener on the
//   loopback receives it (RFC 5424, MSGID `test`); the saved sink delivers.
// - A syslog TCP sink to a closed loopback port fails: the test shows the error code and the
//   saved sink shows its error in the table.
// - TGL-21: requiring the export without a sink is refused with `audit.export.required`; with
//   an enabled sink the policy is met, and removing the last sink is refused in the dialog.
// - A stale `If-Match` is refused with `audit.export.conflict` and the page shows the newer
//   settings after a change made elsewhere.
// - Keyboard and axe: the dialog opens and closes with the keyboard and keeps focus inside;
//   axe finds nothing on the page and in the dialog.
// - Swedish: the page and the sink dialog.

import { createSocket } from "node:dgram";
import { readdir, readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { ApiError, type Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { freePort } from "./support/server";

type View = Schemas["AuditExportView"];

/** Opens the page and the dialog of a new sink. */
async function openDialog(page: Page) {
  await page.goto("/settings/audit-export");
  await expect(page.getByTestId("audit-export-sinks")).toBeVisible();
  await page.getByTestId("audit-export-add").click();
  const dialog = page.getByTestId("dialog-audit-sink");
  await expect(dialog).toBeVisible();
  return dialog;
}

/** The rows of the sink table by name. */
function sinkRow(page: Page, name: string) {
  return page.locator(`[data-testid="audit-export-sink"][data-key="${name}"]`);
}

test("adds a file sink, tests it and finds the audit records in the export directory", async ({ page, api, server, signedIn }) => {
  void signedIn;
  const dialog = await openDialog(page);
  await expect(page.getByTestId("audit-export-empty")).toBeVisible();
  await dialog.getByTestId("field-transport-file").check();
  await expect(dialog.getByTestId("field-format")).toHaveValue("json");
  await dialog.getByTestId("field-name").fill("Shipper");

  // The file is a plain name inside the export directory: a path is refused by the form.
  await dialog.getByTestId("field-file").fill("../audit.jsonl");
  await dialog.getByTestId("form-submit").click();
  await expect(dialog.getByTestId("field-file")).toHaveAttribute("aria-invalid", "true");
  await expect(dialog).toBeVisible();

  await dialog.getByTestId("field-file").fill("audit.jsonl");
  await dialog.getByTestId("field-max_mib").fill("16");
  await dialog.getByTestId("field-keep").fill("3");
  await dialog.getByTestId("audit-export-test").click();
  const result = dialog.getByTestId("audit-export-test-result");
  await expect(result).toHaveAttribute("data-delivered", "true");
  await expect(result).toContainText("ms");
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeHidden();

  const row = sinkRow(page, "Shipper");
  await expect(row).toContainText("audit.jsonl");
  await expect(row.getByTestId("audit-export-state")).toHaveAttribute("data-state", "ok", { timeout: 60_000 });
  await expect(row.getByTestId("audit-export-lag")).toHaveText("0", { timeout: 60_000 });

  const view = await api.get<View>("/settings/audit-export");
  expect(view.sinks).toHaveLength(1);
  const sink = view.sinks[0]!;
  expect(sink.target).toMatchObject({ kind: "file", file: "audit.jsonl", max_bytes: 16 * 1024 * 1024, keep: 3 });
  expect(sink.format).toBe("json");
  expect(view.policy.satisfied).toBe(true);

  // A new sink exports the whole log from record 1: the file holds JSON lines with the sequence
  // numbers of the audit records, and the delivered position of the sink is inside the log.
  await expect
    .poll(async () => (await readFile(join(server.dataDir, "audit-export", "audit.jsonl"), "utf8")).split("\n").filter(Boolean).length, { timeout: 60_000 })
    .toBeGreaterThan(0);
  const lines = (await readFile(join(server.dataDir, "audit-export", "audit.jsonl"), "utf8")).split("\n").filter(Boolean);
  for (const line of lines) expect(() => JSON.parse(line) as unknown).not.toThrow();
  const after = await api.get<View>("/settings/audit-export");
  expect(after.sinks[0]!.status.delivered.seq).toBeGreaterThan(0);
  expect(after.sinks[0]!.status.delivered.seq).toBeLessThanOrEqual(after.store_head);
  expect(await readdir(join(server.dataDir, "audit-export"))).toContain("audit.jsonl");
});

test("sends syslog over UDP to a listener on the loopback", async ({ page, api, signedIn }) => {
  void signedIn;
  const socket = createSocket("udp4");
  const received: string[] = [];
  socket.on("message", (message) => received.push(message.toString("utf8")));
  await new Promise<void>((resolve) => socket.bind(0, "127.0.0.1", resolve));
  const port = socket.address().port;
  try {
    const dialog = await openDialog(page);
    await dialog.getByTestId("field-transport-udp").check();
    await expect(dialog.getByTestId("field-port")).toHaveValue("514");
    await expect(dialog.getByTestId("field-ca_pem")).toHaveCount(0);
    await dialog.getByTestId("field-name").fill("Loopback UDP");
    await dialog.getByTestId("field-host").fill("127.0.0.1");
    await dialog.getByTestId("field-port").fill(String(port));
    await dialog.getByTestId("field-facility").selectOption("local0");
    await dialog.getByTestId("audit-export-test").click();
    await expect(dialog.getByTestId("audit-export-test-result")).toHaveAttribute("data-delivered", "true");
    // The test message is an RFC 5424 message with the MSGID `test`; it is not a chain record.
    await expect.poll(() => received.length, { timeout: 15_000 }).toBeGreaterThan(0);
    expect(received.some((message) => /^<\d+>1 .* test /.test(message) || message.includes(" test "))).toBe(true);

    await dialog.getByTestId("form-submit").click();
    await expect(dialog).toBeHidden();
    const row = sinkRow(page, "Loopback UDP");
    await expect(row).toContainText(`127.0.0.1:${port}`);
    await expect(row.getByTestId("audit-export-state")).toHaveAttribute("data-state", /^(ok|pending)$/, { timeout: 30_000 });
    const view = await api.get<View>("/settings/audit-export");
    expect(view.sinks[0]!.target).toMatchObject({ kind: "syslog", transport: "udp", host: "127.0.0.1", port, facility: "local0" });
    // The sink exports from record 1: records arrive at the listener (UDP: best effort on the loopback).
    await expect.poll(() => received.length, { timeout: 30_000 }).toBeGreaterThan(1);
  } finally {
    socket.close();
  }
});

test("shows a TCP sink to a closed loopback port as failing, with the error code", async ({ page, api, signedIn }) => {
  void signedIn;
  const closed = await freePort();
  const dialog = await openDialog(page);
  await dialog.getByTestId("field-transport-tcp").check();
  await dialog.getByTestId("field-name").fill("Closed");
  await dialog.getByTestId("field-host").fill("127.0.0.1");
  await dialog.getByTestId("field-port").fill(String(closed));
  await dialog.getByTestId("audit-export-test").click();
  const result = dialog.getByTestId("audit-export-test-result");
  await expect(result).toHaveAttribute("data-delivered", "false");
  await expect(result).toHaveAttribute("data-code", "audit.export.connect");
  await dialog.getByTestId("form-submit").click();
  await expect(dialog).toBeHidden();

  const row = sinkRow(page, "Closed");
  await expect(row.getByTestId("audit-export-state")).toHaveAttribute("data-state", /^(failing|alarm)$/, { timeout: 60_000 });
  await expect(row.getByTestId("audit-export-error")).toHaveAttribute("data-code", "audit.export.connect");
  const view = await api.get<View>("/settings/audit-export");
  expect(view.sinks[0]!.status.last_error?.code).toBe("audit.export.connect");
  expect(view.sinks[0]!.status.failing_since).toBeTruthy();

  // A stored sink is tested by its id from the dialog, with the same outcome.
  await row.getByTestId("audit-export-edit").click();
  const edit = page.getByTestId("dialog-audit-sink");
  await edit.getByTestId("audit-export-test").click();
  await expect(edit.getByTestId("audit-export-test-result")).toHaveAttribute("data-delivered", "false");
});

test("the server refuses invalid sinks and shows its field errors in the dialog", async ({ page, api, signedIn }) => {
  void signedIn;
  await api.put("/settings/audit-export", {
    sinks: [{ name: "Existing", target: { kind: "file", file: "existing.jsonl" }, format: "json" }],
  });
  const dialog = await openDialog(page);
  await dialog.getByTestId("field-transport-file").check();
  // The same name, whatever its case, is taken.
  await dialog.getByTestId("field-name").fill("existing");
  await dialog.getByTestId("field-file").fill("other.jsonl");
  await dialog.getByTestId("form-submit").click();
  await expect(page.getByTestId("error-notice")).toHaveAttribute("data-code", "audit.export.invalid");
  await expect(dialog.getByTestId("field-name")).toHaveAttribute("aria-invalid", "true");
  expect((await api.get<View>("/settings/audit-export")).sinks).toHaveLength(1);

  // A host the form accepts but the server does not.
  await dialog.getByTestId("field-transport-udp").check();
  await dialog.getByTestId("field-name").fill("Bad host");
  await dialog.getByTestId("field-host").fill("not a host");
  await dialog.getByTestId("form-submit").click();
  await expect(dialog.getByTestId("field-host")).toHaveAttribute("aria-invalid", "true");
  await dialog.getByTestId("form-cancel").click();
  await expect(dialog).toBeHidden();
  expect((await api.get<View>("/settings/audit-export")).sinks).toHaveLength(1);
});

test("TGL-21: the export cannot be required without a sink, and the last sink cannot be removed", async ({ page, api, signedIn }) => {
  void signedIn;
  // No sink is enabled: requiring the export is refused with its code.
  const refused = await api.patch("/settings/security", { audit_export: "required" }).catch((error: unknown) => error);
  expect(refused).toBeInstanceOf(ApiError);
  expect((refused as ApiError).status).toBe(409);
  expect((refused as ApiError).body).toContain("audit.export.required");

  await api.put("/settings/audit-export", {
    sinks: [{ name: "Shipper", target: { kind: "file", file: "audit.jsonl" }, format: "json" }],
  });
  await api.patch("/settings/security", { audit_export: "required" });

  await page.goto("/settings/audit-export");
  const policy = page.getByTestId("audit-export-policy");
  await expect(policy).toHaveAttribute("data-required", "true");
  await expect(policy).toHaveAttribute("data-satisfied", "true");
  await expect(page.getByTestId("audit-export-required")).toHaveCount(0);

  // Pausing or removing the last enabled sink is refused by the server; the dialog says why.
  await page.getByTestId("audit-export-toggle").click();
  await expect(page.getByTestId("error-notice")).toHaveAttribute("data-code", "audit.export.required");
  await expect(page.getByTestId("error-notice")).toContainText("Enable an export sink first");
  await page.getByTestId("audit-export-remove").click();
  const confirm = page.getByTestId("dialog-confirm");
  await expect(confirm).toContainText("the profile requires one");
  await confirm.getByTestId("confirm-ok").click();
  await expect(confirm.getByTestId("error-notice")).toHaveAttribute("data-code", "audit.export.required");
  await confirm.getByTestId("confirm-cancel").click();
  const view = await api.get<View>("/settings/audit-export");
  expect(view.sinks).toHaveLength(1);
  expect(view.sinks[0]!.enabled).toBe(true);
  expect(view.policy).toMatchObject({ audit_export: "required", required: true, satisfied: true });
});

test("a stale revision is refused and the page shows the settings written elsewhere", async ({ page, api, server, signedIn }) => {
  void signedIn;
  await api.put("/settings/audit-export", {
    sinks: [{ name: "First", target: { kind: "file", file: "first.jsonl" }, format: "json" }],
  });
  await page.goto("/settings/audit-export");
  await expect(sinkRow(page, "First")).toBeVisible();
  const stale = await api.get<View>("/settings/audit-export");

  // Another administrator adds a sink after the page was read.
  await api.put("/settings/audit-export", {
    sinks: [
      { id: stale.sinks[0]!.id, name: "First", target: { kind: "file", file: "first.jsonl" }, format: "json" },
      { name: "Second", target: { kind: "file", file: "second.jsonl" }, format: "json" },
    ],
  });
  // The old revision is refused with its code and the current one.
  const response = await api.request.put(`${server.url}/api/v1/settings/audit-export`, {
    headers: { Origin: server.url, "If-Match": `"${stale.revision}"` },
    data: { sinks: [] },
  });
  expect(response.status()).toBe(409);
  expect(((await response.json()) as { code: string }).code).toBe("audit.export.conflict");
  const current = await api.get<View>("/settings/audit-export");
  expect(current.sinks.map((s) => s.name)).toEqual(["First", "Second"]);

  // The page follows the change (the live query) and keeps both sinks after its own write.
  await expect(sinkRow(page, "Second")).toBeVisible();
  await sinkRow(page, "First").getByTestId("audit-export-toggle").click();
  await expect(sinkRow(page, "First").getByTestId("audit-export-state")).toHaveAttribute("data-state", "disabled");
  const after = await api.get<View>("/settings/audit-export");
  expect(after.sinks.map((s) => [s.name, s.enabled])).toEqual([
    ["First", false],
    ["Second", true],
  ]);
});

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

test("the sink dialog works with the keyboard, keeps focus inside and passes axe", async ({ page, signedIn }) => {
  void signedIn;
  await page.goto("/settings/audit-export");
  await expect(page.getByTestId("audit-export-sinks")).toBeVisible();
  expect(await axeViolations(page, "[data-testid='page-audit-export']")).toEqual([]);
  await page.getByTestId("audit-export-add").focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByTestId("dialog-audit-sink");
  await expect(dialog).toBeVisible();
  expect(await axeViolations(page, "[data-testid='dialog-audit-sink']")).toEqual([]);
  for (let i = 0; i < 40; i += 1) {
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => !!document.activeElement?.closest("[data-testid='dialog-audit-sink']"))).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(page.getByTestId("audit-export-add")).toBeFocused();
});

test("the alarm delay is saved with the sinks unchanged", async ({ page, api, signedIn }) => {
  void signedIn;
  await api.put("/settings/audit-export", {
    sinks: [{ name: "Shipper", target: { kind: "file", file: "audit.jsonl" }, format: "json" }],
  });
  await page.goto("/settings/audit-export");
  const field = page.getByTestId("field-alert_after_secs");
  await expect(field).toHaveValue("300");
  await field.fill("5");
  await page.getByTestId("audit-export-alert-save").click();
  await expect(page.getByText(/Enter a whole number of seconds/)).toBeVisible();
  await field.fill("120");
  await page.getByTestId("audit-export-alert-save").click();
  await expect.poll(async () => (await api.get<View>("/settings/audit-export")).alert_after_secs).toBe(120);
  expect((await api.get<View>("/settings/audit-export")).sinks).toHaveLength(1);
});

test("a listener that closes the connection makes a TLS sink fail with a TLS or connect error", async ({ page, api, signedIn }) => {
  void signedIn;
  // A plain TCP listener on the loopback that accepts and closes: not a TLS receiver.
  const listener = createServer((socket) => socket.destroy());
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const port = (listener.address() as { port: number }).port;
  try {
    const dialog = await openDialog(page);
    await dialog.getByTestId("field-name").fill("Not TLS");
    await dialog.getByTestId("field-host").fill("127.0.0.1");
    await dialog.getByTestId("field-port").fill(String(port));
    await dialog.getByTestId("audit-export-test").click();
    const result = dialog.getByTestId("audit-export-test-result");
    await expect(result).toHaveAttribute("data-delivered", "false");
    await expect(result).toHaveAttribute("data-code", /^audit\.export\.(tls|connect|send)$/);
    await dialog.getByTestId("form-cancel").click();
    expect((await api.get<View>("/settings/audit-export")).sinks).toHaveLength(0);
  } finally {
    listener.close();
  }
});

test.describe("in Swedish", () => {
  test.use({ locale: "sv-SE" });

  test("renders the page and the sink dialog in Swedish", async ({ page, api, signedIn }, testInfo) => {
    void signedIn;
    await api.put("/settings/audit-export", {
      sinks: [{ name: "Shipper", target: { kind: "file", file: "audit.jsonl" }, format: "json" }],
    });
    await page.goto("/settings/audit-export");
    await expect(sinkRow(page, "Shipper")).toBeVisible();
    await expect(page.getByTestId("audit-export-add")).toHaveText("Lägg till exportmål");
    await expectRendered(page, page.getByTestId("page-audit-export"), "sv", testInfo, "audit-export");
    await page.getByTestId("audit-export-add").click();
    const dialog = page.getByTestId("dialog-audit-sink");
    await expect(dialog).toBeVisible();
    await dialog.getByTestId("field-transport-tls").check();
    await expectRendered(page, dialog, "sv", testInfo, "audit-export-dialog");
  });
});
