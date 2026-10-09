// Scenario 6: the audit view over the real server (IAM-18). A few writes through the API (two
// prefixes, a host, an update of a prefix) leave records; the view lists them, shows the state
// of the hash chain (the same as `GET /audit/verify`, also after a new write and after a
// check on demand), and opens the record of the update with its before and after, its
// objects and the two hashes that chain it to the record before it.
//
// What stays manual: breaking the chain. A tampered store is a Rust-side test of the
// verification (the API offers no way to alter a record), so the broken-chain alert of the
// view is covered by its component tests, not here.

import { ADMIN, type Api, type Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { cell, gridRow, withId, withKey } from "./support/ui";

type AuditPage = Schemas["Page_AuditRecord"];

/** All records of the log, oldest first. */
async function records(api: Api): Promise<Schemas["AuditRecord"][]> {
  return (await api.get<AuditPage>("/audit", { order: "asc", limit: 1000 })).items;
}

/** The first twelve digits of a digest, as the chain status shows its head. */
function short(hash: string): string {
  return hash.slice(0, 12);
}

test("the audit view lists the writes, agrees with the chain check and opens the record of an update", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);

  // A few writes: a prefix, a host, and an update of the prefix (its description).
  const prefix = await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "192.0.2.0/24", description: "Office" });
  const prefixItem = prefix.item!;
  await api.post<Schemas["WriteResponse_Host"]>("/hosts", { name: "printer", mode: "static" });
  await api.patch<Schemas["WriteResponse_Prefix"]>(`/prefixes/${prefixItem.id}`, { description: "Office LAN" }, prefixItem.meta.revision);

  const log = await records(api);
  const created = log.find((r) => r.draft.action === "ipam.prefix.create");
  const hostCreated = log.find((r) => r.draft.action === "ipam.host.create");
  const updated = log.find((r) => r.draft.action === "ipam.prefix.update");
  expect(created && hostCreated && updated).toBeTruthy();
  expect(updated!.draft.objects).toContainEqual({ kind: "prefix", id: prefixItem.id });
  expect(created!.seq).toBeLessThan(hostCreated!.seq);
  expect(hostCreated!.seq).toBeLessThan(updated!.seq);

  // The log lists every record, newest first, with the action and the sequence number.
  await page.goto("/audit");
  await expect(page.getByTestId("page-audit")).toBeVisible();
  const grid = page.getByTestId("grid-audit");
  await expect(grid.getByTestId("row")).toHaveCount(log.length);
  for (const record of [created!, hostCreated!, updated!]) {
    const row = gridRow(page, "audit", String(record.seq));
    await expect(row).toBeVisible();
    await expect(row).toHaveAttribute("data-id", String(record.seq));
    await expect(cell(row, "seq")).toHaveText(String(record.seq));
    await expect(cell(row, "action")).toHaveText(record.draft.action);
  }
  const keys = await grid.getByTestId("row").evaluateAll((rows) => rows.map((row) => Number(row.getAttribute("data-key"))));
  expect(keys).toEqual(log.map((r) => r.seq).reverse());

  // The chain state agrees with the check of the server.
  const verified = await api.get<Schemas["AuditVerifyReport"]>("/audit/verify");
  expect(verified.intact).toBe(true);
  expect(verified.head.seq).toBe(log[log.length - 1]!.seq);
  const chain = page.getByTestId("audit-chain");
  await expect(chain).toHaveAttribute("data-state", "intact");
  const head = chain.getByTestId("audit-chain-head");
  await expect(head).toHaveAttribute("data-key", String(verified.head.seq));
  await expect(head).toHaveText(short(verified.head.hash));

  // "Verify again" asks the server and shows what it answered.
  const [response] = await Promise.all([
    page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/audit/verify" && r.request().method() === "GET"),
    page.getByTestId("audit-verify").click(),
  ]);
  const again = (await response.json()) as Schemas["AuditVerifyReport"];
  expect(again.intact).toBe(true);
  await expect(chain).toHaveAttribute("data-state", "intact");
  await expect(head).toHaveAttribute("data-key", String(again.head.seq));

  // A write while the page is open: new records join the log and the chain head follows.
  await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: "198.51.100.0/24", description: "Printers" });
  const grown = await records(api);
  expect(grown.length).toBeGreaterThan(log.length);
  const newest = grown[grown.length - 1]!;
  expect(newest.draft.action).toBe("ipam.prefix.create");
  await expect(gridRow(page, "audit", String(newest.seq))).toBeVisible();
  await expect(head).toHaveAttribute("data-key", String(newest.seq));
  const grownCheck = await api.get<Schemas["AuditVerifyReport"]>("/audit/verify");
  expect(grownCheck.intact).toBe(true);
  expect(grownCheck.head.seq).toBe(newest.seq);
  await expect(chain).toHaveAttribute("data-state", "intact");
  await expect(head).toHaveText(short(grownCheck.head.hash));

  // Narrow the log to the update and open its record.
  await page.getByTestId("audit-filter-action").fill("ipam.prefix.update");
  await expect(grid.getByTestId("row")).toHaveCount(1);
  const updateRow = gridRow(page, "audit", String(updated!.seq));
  await expect(updateRow).toBeVisible();
  await cell(updateRow, "action").click();
  await expect(page.getByTestId("page-audit-record")).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`/audit/${updated!.seq}$`));

  // The record as the API has it.
  const record = await api.get<Schemas["AuditRecord"]>(`/audit/${updated!.seq}`);
  expect(record.seq).toBe(updated!.seq);
  expect(record.draft.action).toBe("ipam.prefix.update");
  const changes = record.draft.details?.changes ?? [];
  expect(changes).toEqual([{ field: "meta.description", old: "Office", new: "Office LAN" }]);

  // Its before and after, one row per changed field.
  const table = page.getByTestId("audit-changes");
  await expect(table).toBeVisible();
  await expect(table.getByTestId("audit-change")).toHaveCount(changes.length);
  for (const change of changes) {
    const row = withKey(table, "audit-change", change.field);
    await expect(row).toBeVisible();
    await expect(cell(row, "old")).toHaveText(change.old!);
    await expect(cell(row, "new")).toHaveText(change.new!);
  }

  // The objects the record names, and the two hashes of the chain.
  const objects = page.getByTestId("audit-objects");
  await expect(objects.getByTestId("audit-object")).toHaveCount(record.draft.objects?.length ?? 0);
  await expect(withId(objects, "audit-object", prefixItem.id)).toHaveAttribute("data-kind", "prefix");
  await expect(page.getByTestId("audit-hash")).toHaveText(record.hash);
  await expect(page.getByTestId("audit-prev-hash")).toHaveText(record.prev);

  // The previous record is the one the chain points at: its hash is this record's `prev`.
  const before = await api.get<Schemas["AuditRecord"]>(`/audit/${updated!.seq - 1}`);
  expect(before.hash).toBe(record.prev);
  await page.getByTestId("audit-prev").click();
  await expect(page).toHaveURL(new RegExp(`/audit/${updated!.seq - 1}$`));
  await expect(page.getByTestId("audit-hash")).toHaveText(before.hash);
  await expect(page.getByTestId("audit-hash")).not.toHaveText(record.hash);
  await page.getByTestId("audit-next").click();
  await expect(page).toHaveURL(new RegExp(`/audit/${updated!.seq}$`));
  await expect(page.getByTestId("audit-prev-hash")).toHaveText(before.hash);
});
