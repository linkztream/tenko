// Scenario 4: the import wizard end to end, the browser half of exit criterion E1 (IPAM-11,
// MIG-14). The workbook `ip-plan.xlsx` of the Rust fixtures is uploaded through the file
// input, read with the suggested mapping, previewed as a full page with its loss report and
// proposals, applied as a job and followed to the result. The counts shown are compared with
// `ip-plan.expected.json` and with what the API holds after the apply; the three CSV
// exports are downloaded from the upload page.
//
// Credential columns are stored as operator secrets, which needs a session of password
// strength or more (IAM-07): the main test raises the PIN session of `signedIn` with an
// authenticator app first. A second test shows the blocker of the PIN session and the
// choice to skip credentials; a third one the acknowledgement of a plan warning.
//
// What the fixture does not exercise: no warning of the workbook needs an acknowledgement,
// so `import-ack` appears in the third test only (a network on a nibble boundary).

import type { Download, Locator, Page } from "@playwright/test";
import { ApiError, type Api, type Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { fixturePath, listAll, loadExpected, parseCsv, raiseSession, type Expected } from "./support/import";
import { cell, withKey } from "./support/ui";

type Preview = Schemas["ImportPreview"];
type View = Schemas["ImportView"];
type Row = Schemas["PreviewRow"];
type ItemKey = Schemas["ItemKey"];

const WORKBOOK = "ip-plan.xlsx";
const ACTIONS = ["create", "update", "unchanged", "kept"] as const;

/** The import id the wizard keeps in the URL. */
function importId(page: Page): string {
  const id = new URL(page.url()).searchParams.get("id");
  if (!id) throw new Error(`no import id in ${page.url()}`);
  return id;
}

/** Opens the wizard, uploads `file` (a path, or a name and content) and waits for the mapping step. */
async function upload(page: Page, file: string | { name: string; mimeType: string; buffer: Buffer }): Promise<string> {
  await page.goto("/ipam/import");
  await expect(page.getByTestId("page-import")).toBeVisible();
  await expect(withKey(page, "import-step", "upload")).toHaveAttribute("aria-current", "step");
  await expect(page.getByTestId("import-upload")).toBeVisible();
  await page.getByTestId("import-file-input").setInputFiles(file);
  await page.getByTestId("import-upload-start").click();
  await expect(page.getByTestId("import-mapping")).toBeVisible();
  await expect(withKey(page, "import-step", "mapping")).toHaveAttribute("aria-current", "step");
  return importId(page);
}

/** Saves the mapping and waits for the preview page with its summary. */
async function openPreview(page: Page): Promise<Locator> {
  await page.getByTestId("import-preview").click();
  await expect(page.getByTestId("import-preview-page")).toBeVisible();
  await expect(withKey(page, "import-step", "preview")).toHaveAttribute("aria-current", "step");
  const summary = page.getByTestId("import-summary");
  await expect(summary).toBeVisible();
  return summary;
}

/** Applies from the preview page and waits for the finished result. */
async function applyAndWaitForResult(page: Page): Promise<Locator> {
  const apply = page.getByTestId("import-apply");
  await expect(apply).toBeEnabled();
  await apply.click();
  const result = page.getByTestId("import-result");
  await expect(result).toBeVisible();
  // The job runs in chunks; the result step shows what was created once it succeeded.
  await expect(withKey(page, "import-step", "done")).toHaveAttribute("aria-current", "step");
  await expect(page.getByTestId("import-created")).toBeVisible();
  await expect(page.getByTestId("import-again")).toBeVisible();
  return result;
}

/** The numbers of the counts table: `kind:action` to count, zeros left out. */
async function shownCounts(summary: Locator): Promise<Record<string, number>> {
  const counts: Record<string, number> = {};
  for (const row of await summary.getByTestId("import-count").all()) {
    const kind = await row.getAttribute("data-key");
    for (const action of ACTIONS) {
      const value = Number((await cell(row, action).innerText()).trim());
      if (value > 0) counts[`${kind}:${action}`] = value;
    }
  }
  return counts;
}

function apiCounts(preview: Preview): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const entry of preview.summary.counts) {
    if (entry.count > 0) counts[`${entry.kind}:${entry.action}`] = entry.count;
  }
  return counts;
}

async function textOf(locator: Locator): Promise<number> {
  return Number((await locator.innerText()).trim());
}

/** The column and row of a source location as the loss report writes it: C3. */
function where(entry: { row?: number | null; column?: string | null }): string {
  return `${entry.column ?? ""}${entry.row ?? ""}`;
}

function sorted<T>(values: T[]): T[] {
  return [...values].sort();
}

/** The mapping page shows the suggested mapping of `ip-plan.xlsx`: ten sheets, their kinds, networks and columns. */
async function expectSuggestedMapping(page: Page, expected: Expected, view: View): Promise<void> {
  const mapping = page.getByTestId("import-mapping");
  await expect(mapping.getByTestId("import-sheet")).toHaveCount(expected.sheets.length);
  await expect(mapping.getByTestId("import-option-conflict")).toHaveValue(expected.mapping.options.conflict);
  if (expected.mapping.options.credentials === "import") {
    await expect(mapping.getByTestId("import-option-credentials")).toBeChecked();
  } else {
    await expect(mapping.getByTestId("import-option-credentials")).not.toBeChecked();
  }

  for (const want of expected.mapping.sheets) {
    const sheet = withKey(mapping, "import-sheet", want.sheet);
    await expect(sheet, `sheet ${want.sheet}`).toBeVisible();
    await expect(sheet.getByTestId("import-sheet-kind"), `kind of ${want.sheet}`).toHaveValue(want.kind);
    if (want.kind === "network") {
      await expect(sheet.getByTestId("import-sheet-cidr"), `network of ${want.sheet}`).toHaveValue(want.cidr ?? "");
    } else {
      await expect(sheet.getByTestId("import-sheet-cidr")).toHaveCount(0);
    }
    await expect(sheet.getByTestId("import-sheet-header-row"), `header row of ${want.sheet}`).toHaveValue(
      want.header_row === undefined ? "" : String(want.header_row),
    );

    // A sheet without columns (the empty one) shows no column table.
    const columns = sheet.getByTestId("import-column");
    const analysed = view.sheets.find((s) => s.sheet === want.sheet)?.columns.length ?? 0;
    await expect(columns, `columns of ${want.sheet}`).toHaveCount(analysed);
    if (want.columns.length === 0) {
      await expect(columns, `columns of ${want.sheet}`).toHaveCount(0);
      continue;
    }
    const mapped = new Map(want.columns.map((c) => [c.column, c]));
    for (const row of await columns.all()) {
      const letter = (await row.getAttribute("data-key")) ?? "";
      const target = mapped.get(letter);
      await expect(row.getByTestId("import-column-target"), `column ${letter} of ${want.sheet}`).toHaveValue(
        target?.target ?? "ignore",
      );
    }
    for (const column of want.columns) {
      const row = withKey(sheet, "import-column", column.column);
      await expect(row, `column ${column.column} of ${want.sheet}`).toBeVisible();
      if (column.interface !== undefined) {
        await expect(row.getByTestId("import-column-interface")).toHaveValue(column.interface);
      }
    }
  }
}

/** Reads a download as text; the file name is the one the link offers. */
async function downloadText(download: Download): Promise<string> {
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

/** Clicks an export link and returns the CSV it downloads. */
async function exportCsv(page: Page, kind: "prefixes" | "addresses" | "hosts"): Promise<string[][]> {
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByTestId(`export-${kind}`).click()]);
  expect(download.suggestedFilename()).toBe(`${kind}.csv`);
  return parseCsv(await downloadText(download));
}

/** What the API holds: the natural keys of prefixes, hosts and addresses. */
async function stored(api: Api): Promise<{ prefixes: string[]; hosts: string[]; addresses: string[] }> {
  const prefixes = await listAll<Schemas["Prefix"]>(api, "/prefixes");
  const hosts = await listAll<Schemas["Host"]>(api, "/hosts");
  const addresses = await listAll<Schemas["Address"]>(api, "/addresses");
  return {
    prefixes: sorted(prefixes.map((p) => p.cidr)),
    hosts: sorted(hosts.map((h) => h.name)),
    addresses: sorted(addresses.map((a) => a.ip)),
  };
}

/** Every source row of the latest preview, page by page through `GET /imports/{id}/rows`. */
async function allRows(api: Api, id: string): Promise<Row[]> {
  const rows: Row[] = [];
  let cursor: string | null | undefined;
  do {
    const page: Schemas["ImportRowsPage"] = await api.get(`/imports/${id}/rows`, cursor ? { limit: 1000, cursor } : { limit: 1000 });
    rows.push(...page.items);
    cursor = page.next_cursor;
  } while (cursor);
  return rows;
}

/** The label the wizard shows for an item (`itemLabel` of the preview step). */
function label(key: ItemKey): string {
  switch (key.kind) {
    case "vlan":
      return key.site ? `${key.vid} (${key.site})` : String(key.vid);
    case "prefix":
      return `${key.cidr} (${key.vrf})`;
    case "address":
      return `${key.ip} (${key.vrf})`;
    case "interface":
      return `${key.host} ${key.name}`;
    case "host":
      return key.name;
    case "credential":
      return key.host;
  }
}

/** Where the result step links a created item, decoded; null for kinds it does not link. */
function linkOf(key: ItemKey): string | null {
  switch (key.kind) {
    case "prefix":
      return `/ipam/prefixes/${key.cidr}`;
    case "address":
      return `/ipam/addresses/${key.ip}`;
    case "host":
      return `/ipam/hosts/${key.name}`;
    case "interface":
    case "credential":
      return `/ipam/hosts/${key.host}`;
    default:
      return null;
  }
}

/** The distinct items the rows create, by `kind:label` as the page keys them. */
function createdItems(rows: Row[]): Map<string, ItemKey> {
  const items = new Map<string, ItemKey>();
  for (const row of rows) {
    for (const item of row.items) {
      if (item.action === "create") items.set(`${item.key.kind}:${label(item.key)}`, item.key);
    }
  }
  return items;
}

/** The labels of the change group `kind:create` of the page. */
async function changeLabels(changes: Locator, kind: string): Promise<string[]> {
  return withKey(changes, "import-group", `${kind}:create`)
    .getByTestId("import-change")
    .evaluateAll((items) => items.map((item) => item.getAttribute("data-key") ?? ""));
}

test("imports the IP plan workbook: mapping, preview, loss report, apply, job, exports", async ({ page, api, signedIn }) => {
  const expected = loadExpected();
  expect(expected.model.prefixes).toHaveLength(10);
  expect(expected.model.hosts).toHaveLength(40);
  expect(expected.model.addresses).toHaveLength(55);
  expect(expected.model.credentials).toHaveLength(9);
  expect(expected.loss.entries).toHaveLength(13);
  expect(expected.proposals).toHaveLength(2);

  // Operator secrets need a session of password strength or more.
  expect(signedIn.session.strength).toBe("pin");
  const raised = await raiseSession(api);
  expect(raised.strength).toBe("password_totp");

  // Upload.
  const id = await upload(page, fixturePath(WORKBOOK));
  const view = await api.get<View>(`/imports/${id}`);
  expect(view.state).toBe("uploaded");
  expect(view.files.map((f) => f.name)).toEqual([WORKBOOK]);
  expect(view.sheets.map((s) => s.sheet)).toEqual(expected.sheets.map((s) => s.sheet));

  // Mapping: the suggestion is what the fixture expects.
  await expectSuggestedMapping(page, expected, view);

  // Preview.
  const summary = await openPreview(page);
  const preview = await api.get<Preview>(`/imports/${id}/preview`, { rows: 200 });
  expect(preview.can_apply).toBe(true);
  expect(preview.blockers).toEqual([]);
  expect(preview.plan_error ?? null).toBeNull();

  // The counts of the expected objects, on the page and in the API.
  const shown = await shownCounts(summary);
  expect(shown).toEqual(apiCounts(preview));
  const interfaces = expected.model.hosts.reduce((n, h) => n + (h.interfaces?.length ?? 0), 0);
  expect(shown).toMatchObject({
    "prefix:create": expected.model.prefixes.length,
    "host:create": expected.model.hosts.length,
    "interface:create": interfaces,
    "address:create": expected.model.addresses.length,
    "credential:create": expected.model.credentials.length,
  });
  expect(Object.keys(shown).every((key) => key.endsWith(":create"))).toBe(true);
  await expect(withKey(summary, "import-count", "prefix")).toBeVisible();

  // Rows by outcome: the sums of the per-sheet counts of the fixture.
  const sum = (field: "rows" | "imported" | "free" | "skipped") => expected.sheets.reduce((n, s) => n + s[field], 0);
  await expect(page.getByTestId("import-rows-total")).toHaveText(String(sum("rows")));
  await expect(page.getByTestId("import-rows-imported")).toHaveText(String(sum("imported")));
  await expect(page.getByTestId("import-rows-free")).toHaveText(String(sum("free")));
  await expect(page.getByTestId("import-rows-skipped")).toHaveText(String(sum("skipped")));
  expect(await textOf(page.getByTestId("import-rows-imported"))).toBe(preview.summary.rows.imported);
  expect(preview.total_rows).toBe(sum("rows"));

  // Rows, imported, free and skipped per sheet, in the API and on the page.
  expect(preview.sheets).toHaveLength(expected.sheets.length);
  for (const want of expected.sheets) {
    const got = preview.sheets.find((s) => s.sheet === want.sheet);
    expect(got, `sheet ${want.sheet}`).toBeDefined();
    expect({ kind: got?.kind, cidr: got?.cidr ?? undefined, rows: got?.rows, free: got?.free, imported: got?.imported, skipped: got?.skipped }).toEqual({
      kind: want.kind,
      cidr: want.cidr,
      rows: want.rows,
      free: want.free,
      imported: want.imported,
      skipped: want.skipped,
    });
  }

  const outcomes = page.getByTestId("import-outcomes");
  await expect(outcomes).toBeVisible();
  await expect(outcomes.getByTestId("import-outcome")).toHaveCount(expected.sheets.length);
  for (const want of expected.sheets) {
    const row = withKey(outcomes, "import-outcome", want.sheet);
    await expect(row, `outcome of ${want.sheet}`).toHaveAttribute("data-kind", want.kind);
    await expect(cell(row, "cidr"), `network of ${want.sheet}`).toHaveText(want.cidr ?? "");
    for (const field of ["rows", "imported", "free", "skipped"] as const) {
      await expect(cell(row, field), `${field} of ${want.sheet}`).toHaveText(String(want[field]));
    }
    // The loss report entries of the sheet, by severity.
    let notes = 0;
    for (const severity of ["error", "warning", "info"]) notes += await textOf(cell(row, severity));
    expect(notes, `loss entries of ${want.sheet}`).toBe(expected.loss.entries.filter((e) => e.location.sheet === want.sheet).length);
  }

  // The loss report: 13 entries, with the codes and places of the fixture.
  const loss = page.getByTestId("import-loss");
  await expect(loss).toBeVisible();
  const entries = loss.getByTestId("import-loss-entry");
  await expect(entries).toHaveCount(expected.loss.entries.length);
  const shownCodes = await entries.evaluateAll((rows) => rows.map((row) => row.getAttribute("data-code") ?? ""));
  expect(sorted(shownCodes)).toEqual(sorted(expected.loss.entries.map((e) => e.code)));
  const apiEntries = preview.loss.flatMap((s) => s.entries.map((e) => ({ sheet: s.sheet ?? null, at: where(e), code: e.code })));
  expect(sorted(apiEntries.map((e) => JSON.stringify(e)))).toEqual(
    sorted(
      expected.loss.entries.map((e) =>
        JSON.stringify({ sheet: e.location.sheet, at: where(e.location), code: e.code }),
      ),
    ),
  );
  expect(preview.summary.loss.error + preview.summary.loss.warning + preview.summary.loss.info).toBe(expected.loss.entries.length);

  // The proposals: two networks the workbook implies, accepted by default.
  const proposals = page.getByTestId("import-proposals");
  await expect(proposals).toBeVisible();
  await expect(proposals.getByTestId("import-proposal")).toHaveCount(expected.proposals.length);
  for (const want of expected.proposals) {
    const item = withKey(proposals, "import-proposal", want.cidr);
    await expect(item).toBeVisible();
    await expect(item.getByTestId("import-proposal-accept")).toBeChecked();
    const got = preview.proposals.find((p) => p.cidr === want.cidr);
    expect(got?.accepted).toBe(want.accepted);
    expect(got?.addresses).toEqual(want.addresses);
  }

  // The rows: the preview brings the first page, the rest comes through the rows endpoint
  // until nothing is left to load.
  const rows = await allRows(api, id);
  expect(rows).toHaveLength(preview.total_rows);
  const more = page.getByTestId("import-rows-more");
  for (let pages = 0; (await more.count()) > 0; pages += 1) {
    expect(pages, "the rows load in a few pages").toBeLessThan(10);
    await Promise.all([
      page.waitForResponse((response) => response.url().includes(`/imports/${id}/rows`) && response.ok()),
      more.click(),
    ]);
    await expect.poll(async () => (await more.count()) === 0 || (await more.isEnabled())).toBe(true);
  }
  await expect(page.getByTestId("grid-import-rows")).toBeVisible();

  // The changes, grouped by kind and action, now cover every row.
  const created = createdItems(rows);
  const changes = page.getByTestId("import-changes");
  await expect(changes).toBeVisible();
  for (const kind of ["prefix", "host", "interface", "address"]) {
    const wanted = [...created.keys()].filter((key) => key.startsWith(`${kind}:`)).map((key) => key.slice(kind.length + 1));
    expect(sorted(await changeLabels(changes, kind)), `${kind} creates`).toEqual(sorted(wanted));
  }
  expect(sorted(await changeLabels(changes, "host"))).toEqual(sorted(expected.model.hosts.map((h) => h.name)));
  expect(sorted(await changeLabels(changes, "address"))).toEqual(sorted(expected.model.addresses.map((a) => `${a.ip} (default)`)));

  // Nothing needs an acknowledgement and nothing blocks the apply; the credentials are allowed.
  await expect(page.getByTestId("import-ack")).toHaveCount(0);
  await expect(page.getByTestId("import-blockers")).toHaveCount(0);
  await expect(page.getByTestId("import-credentials")).toBeVisible();
  expect(preview.credentials).toMatchObject({ hosts: expected.model.credentials.length, new: 9, changed: 0, unchanged: 0, allowed: true });

  // Apply: the job runs and the result links to it.
  const result = await applyAndWaitForResult(page);

  // Every created item is listed with a link to where it can be seen (credentials go to the
  // vault and are not listed). Past the first fifty the rest come with "show all".
  const linked = [...created.entries()].filter(([, key]) => key.kind !== "credential");
  expect(linked.length).toBeGreaterThan(50);
  await result.getByTestId("import-created-all").click();
  const shownLinks = await result
    .getByTestId("import-created")
    .getByTestId("import-created-item")
    .evaluateAll((items) => items.map((item) => ({ key: item.getAttribute("data-key") ?? "", href: item.querySelector("a")?.getAttribute("href") ?? null })));
  expect(sorted(shownLinks.map((link) => link.key))).toEqual(sorted(linked.map(([key]) => key)));
  for (const link of shownLinks) {
    const key = created.get(link.key);
    expect(link.href, `${link.key} has a link`).not.toBeNull();
    expect(decodeURIComponent((link.href ?? "").split("?")[0] ?? ""), link.key).toBe(key ? linkOf(key) : null);
  }
  const jobLink = result.getByTestId("import-open-job");
  const href = (await jobLink.getAttribute("href")) ?? "";
  expect(href).toMatch(/^\/jobs\/[0-9a-f-]{36}$/);
  const jobId = href.slice("/jobs/".length);
  const detail = await api.waitForJob(jobId);
  expect(detail.job.state).toBe("succeeded");
  expect(detail.job.spec.kind).toBe("import.apply");
  expect((await api.get<View>(`/imports/${id}`)).state).toBe("applied");

  await jobLink.click();
  await expect(page.getByTestId("page-job")).toBeVisible();
  await expect(page.getByTestId("job-steps")).toBeVisible();
  const steps = page.getByTestId("job-step");
  await expect(steps).toHaveCount(detail.job.steps.length);
  for (const step of await steps.all()) {
    await expect(step).toHaveAttribute("data-state", /^(done|skipped)$/);
  }
  await expect(page.getByTestId("job-error")).toHaveCount(0);

  // What the API holds now is what the fixture expects.
  const held = await stored(api);
  expect(held.prefixes).toEqual(sorted(expected.model.prefixes.map((p) => p.cidr)));
  expect(held.hosts).toEqual(sorted(expected.model.hosts.map((h) => h.name)));
  expect(held.addresses).toEqual(sorted(expected.model.addresses.map((a) => a.ip)));

  // The preview of the same import now finds everything in place, credentials included. The
  // two proposed networks exist by now, so the workbook no longer proposes them and they
  // are not items of the import any more.
  const again = await api.get<Preview>(`/imports/${id}/preview`, { rows: 200 });
  expect(again.proposals).toEqual([]);
  expect(apiCounts(again)).toEqual({
    "prefix:unchanged": expected.model.prefixes.length - expected.proposals.length,
    "host:unchanged": expected.model.hosts.length,
    "interface:unchanged": interfaces,
    "address:unchanged": expected.model.addresses.length,
    "credential:unchanged": expected.model.credentials.length,
  });
  expect(again.credentials).toMatchObject({ hosts: 9, new: 0, changed: 0, unchanged: 9 });

  // Back on the upload page, the CSV exports hold one header line and one line per object.
  await page.goto(`/ipam/import?id=${id}`);
  await expect(page.getByTestId("import-result")).toBeVisible();
  await page.getByTestId("import-again").click();
  await expect(page.getByTestId("import-upload")).toBeVisible();
  const panel = page.getByTestId("import-export");
  await expect(panel).toBeVisible();
  const exported: string[] = [];
  for (const [kind, objects] of [
    ["prefixes", expected.model.prefixes.length],
    ["addresses", expected.model.addresses.length],
    ["hosts", expected.model.hosts.length],
  ] as const) {
    const records = await exportCsv(page, kind);
    expect(records.length, `${kind}.csv: one header line and one line per object`).toBe(objects + 1);
    const width = records[0]?.length ?? 0;
    expect(width).toBeGreaterThan(1);
    expect(records.every((record) => record.length === width)).toBe(true);
    exported.push(records.flat().join("\n"));
  }
  // The passwords of the workbook are in the vault and never leave through an export.
  for (const secret of ["example-gw-pass", "example-idrac-1"]) {
    expect(exported.join("\n")).not.toContain(secret);
  }
});

test("a PIN session cannot store credentials; skipping them lets the import through", async ({ page, api, signedIn }) => {
  const expected = loadExpected();
  expect(signedIn.session.strength).toBe("pin");

  const id = await upload(page, fixturePath(WORKBOOK));
  await expect(page.getByTestId("import-option-credentials")).toBeChecked();
  await openPreview(page);

  // The server blocks the apply and the page says why.
  const blockers = page.getByTestId("import-blockers");
  await expect(blockers).toBeVisible();
  await expect(withKey(blockers, "import-blocker", "import.credentials.vault_required")).toBeVisible();
  await expect(page.getByTestId("import-apply")).toBeDisabled();
  await expect(page.getByTestId("import-credentials")).toBeVisible();
  const blocked = await api.get<Preview>(`/imports/${id}/preview`, { rows: 200 });
  expect(blocked.can_apply).toBe(false);
  expect(blocked.blockers).toContain("import.credentials.vault_required");
  expect(blocked.credentials.allowed).toBe(false);
  expect(blocked.credentials.hosts).toBe(expected.model.credentials.length);

  // The API refuses the apply as well, with the stable code.
  const refused = await api.post<{ job_id: string }>(`/imports/${id}/apply`, { acknowledge: [] }).catch((error: unknown) => error);
  expect(refused).toBeInstanceOf(ApiError);
  expect((refused as ApiError).status).toBe(403);
  expect((refused as ApiError).code).toBe("import.credentials.vault_required");

  // Back to the mapping, leave the credentials out, preview again.
  await page.getByTestId("import-back").click();
  await expect(page.getByTestId("import-mapping")).toBeVisible();
  const credentials = page.getByTestId("import-option-credentials");
  await expect(credentials).toBeChecked();
  await credentials.uncheck();
  await openPreview(page);
  await expect(page.getByTestId("import-blockers")).toHaveCount(0);
  const skipped = await api.get<Preview>(`/imports/${id}/preview`, { rows: 200 });
  expect(skipped.can_apply).toBe(true);
  expect(apiCounts(skipped)["credential:create"]).toBeUndefined();

  await applyAndWaitForResult(page);
  const job = await api.waitForJob(((await api.get<View>(`/imports/${id}`)).job_id as string));
  expect(job.job.state).toBe("succeeded");
  const held = await stored(api);
  expect(held.prefixes).toEqual(sorted(expected.model.prefixes.map((p) => p.cidr)));
  expect(held.hosts).toEqual(sorted(expected.model.hosts.map((h) => h.name)));
  expect(held.addresses).toEqual(sorted(expected.model.addresses.map((a) => a.ip)));
});

test("a plan warning needs an acknowledgement before the import can be applied", async ({ page, api, signedIn }) => {
  expect(signedIn.session.strength).toBe("pin");
  // A network that does not end on a nibble boundary (documentation range, RFC 3849).
  const csv = "network,description\r\n2001:db8:4::/46,Documentation site\r\n";
  const id = await upload(page, { name: "networks.csv", mimeType: "text/csv", buffer: Buffer.from(csv) });
  await openPreview(page);

  const apply = page.getByTestId("import-apply");
  await expect(apply).toBeDisabled();
  await expect(withKey(page.getByTestId("import-blockers"), "import-blocker", "ipam.plan.unacknowledged")).toBeVisible();
  const ack = page.getByTestId("import-ack");
  await expect(ack).toHaveCount(1);
  await expect(ack).toHaveAttribute("data-code", "ipam.prefix.nibble_boundary");
  await expect(ack).not.toBeChecked();

  // Un-acknowledging again blocks it again.
  await ack.check();
  await expect(apply).toBeEnabled();
  await expect(page.getByTestId("import-blockers")).toHaveCount(0);
  await ack.uncheck();
  await expect(apply).toBeDisabled();
  await ack.check();

  await applyAndWaitForResult(page);
  const prefixes = await listAll<Schemas["Prefix"]>(api, "/prefixes");
  expect(prefixes.map((p) => p.cidr)).toContain("2001:db8:4::/46");
  expect((await api.get<View>(`/imports/${id}`)).state).toBe("applied");
});

test("an import resumes from its URL and can be discarded", async ({ page, api, signedIn }) => {
  expect(signedIn.session.strength).toBe("pin");
  const id = await upload(page, fixturePath(WORKBOOK));

  // A reload keeps the import: the id is in the URL and the wizard resumes at the mapping.
  await page.reload();
  await expect(page.getByTestId("import-mapping")).toBeVisible();
  await expect(page.getByTestId("import-sheet")).toHaveCount(loadExpected().sheets.length);
  expect(importId(page)).toBe(id);

  // Discarding removes the staged upload and returns to the upload step.
  await page.getByTestId("import-discard").click();
  await expect(page.getByTestId("import-upload")).toBeVisible();
  await expect(withKey(page, "import-step", "upload")).toHaveAttribute("aria-current", "step");
  expect(new URL(page.url()).searchParams.has("id")).toBe(false);
  const gone = await api.request.get(`${api.origin}/api/v1/imports/${id}`);
  expect(gone.status()).toBe(404);
});
