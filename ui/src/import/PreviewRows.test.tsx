// The preview page of an import with more source rows than one page lists: the outcome of
// every sheet, the row list page by page with its total, the notice when the list stops at
// the server's limit, and every row loaded before apply so the result links to everything.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { importRecords } from "../api/mock/import-store";
import { filesForm, releaseNodeFormData, testFile, useNodeFormData } from "../api/mock/import-testkit";
import { ipamState } from "../api/mock/ipam/api";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { MAX_PREVIEW_ROWS, PREVIEW_ROWS, type ImportPreview, type PreviewRow } from "./api";
import { INITIAL, reduce, type WizardState } from "./model";
import { itemLabel, lossCounts, PreviewStep, rowPlace } from "./steps/PreviewStep";
import Wizard from "./Wizard";

/** A list of 260 IPv6 addresses with host names, in the seeded 2001:db8:0:10::/64. */
const ROWS = 260;
const BIG_CSV = ["IP,Name", ...Array.from({ length: ROWS }, (_, i) => `2001:db8:0:10::${(0x1000 + i).toString(16)},node${String(i + 1).padStart(3, "0")}`)].join("\r\n");

const SLOW = { timeout: 15_000 };

beforeAll(useNodeFormData);
afterAll(releaseNodeFormData);
beforeEach(async () => {
  await signInAlex();
});

function open() {
  return renderRoute(Wizard, { url: "/ipam/import", path: "/ipam/import" });
}

async function uploadAndPreview(name: string, content: string) {
  const input = await screen.findByTestId("import-file-input");
  fireEvent.change(input, { target: { files: [testFile(name, content)] } });
  const start = await screen.findByTestId("import-upload-start");
  await waitFor(() => expect((start as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(start);
  await screen.findByTestId("import-mapping");
  fireEvent.click(await screen.findByTestId("import-preview"));
  await screen.findByTestId("import-summary", {}, SLOW);
}

/** The preview the server gives for the one staged import, with every row it can list. */
async function serverPreview(): Promise<ImportPreview> {
  const [id] = [...importRecords().keys()];
  if (!id) throw new Error("no import");
  return api.get("/api/v1/imports/{id}/preview", { path: { id }, query: { rows: MAX_PREVIEW_ROWS } });
}

/** The `rows` of every preview request so far. */
function previewRequests(spy: { mock: { calls: unknown[][] } }): number[] {
  return spy.mock.calls
    .map(([url]) => new URL(String(url), "http://localhost"))
    .filter((u) => u.pathname.endsWith("/preview"))
    .map((u) => Number(u.searchParams.get("rows")));
}

describe("preview of a large import", () => {
  it("shows the outcome of every sheet above the changes, with its loss counts", async () => {
    const view = await api.post("/api/v1/imports", { body: filesForm([testFile("ip-plan.xlsx", "x")]), idempotencyKey: null });
    renderRoute(Wizard, { url: `/ipam/import?id=${view.id}`, path: "/ipam/import" });
    fireEvent.click(await screen.findByTestId("import-preview"));
    await screen.findByTestId("import-summary", {}, SLOW);
    const expected = await api.get("/api/v1/imports/{id}/preview", { path: { id: view.id }, query: { rows: 1 } });

    const section = await screen.findByTestId("import-outcomes");
    const rows = within(section).getAllByTestId("import-outcome");
    expect(rows.map((r) => r.dataset.key)).toEqual(expected.sheets.map((s) => s.sheet));
    for (const outcome of expected.sheets) {
      const row = rows.find((r) => r.dataset.key === outcome.sheet)!;
      const cell = (col: string) => row.querySelector(`[data-col="${col}"]`)?.textContent;
      expect(row.dataset.kind).toBe(outcome.kind);
      expect(cell("cidr")).toBe(outcome.cidr ?? "");
      expect([cell("rows"), cell("imported"), cell("free"), cell("skipped")]).toEqual(
        [outcome.rows, outcome.imported, outcome.free, outcome.skipped].map(String),
      );
      const loss = lossCounts(expected.loss, outcome.sheet);
      expect([cell("error"), cell("warning"), cell("info")]).toEqual([loss.error, loss.warning, loss.info].map(String));
    }
    // The unparsable address of the 203.0.113.0 sheet counts as one of its loss entries.
    const lab = rows.find((r) => r.dataset.key === "203.0.113.0")!;
    expect(Number(lab.querySelector('[data-col="error"]')?.textContent) + Number(lab.querySelector('[data-col="warning"]')?.textContent)).toBeGreaterThan(0);
    // Above the changes.
    expect(section.compareDocumentPosition(screen.getByTestId("import-changes")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("lists every source row page by page and shows the total", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await uploadAndPreview("nodes.csv", BIG_CSV);
    const count = screen.getByTestId("import-rows-count");
    expect(count.textContent).toBe(`${PREVIEW_ROWS} of ${ROWS} rows listed`);
    const grid = screen.getByTestId("grid-import-rows");
    expect(within(grid).getByTestId("grid-foot").textContent).toContain(String(PREVIEW_ROWS));
    const first = within(grid).getAllByTestId("row")[0]!;
    expect(first.dataset.key).toBe("nodes!2");
    expect(first.textContent).toContain("2001:db8:0:10::1000");

    const more = screen.getByTestId("import-rows-more");
    expect(more.textContent).toBe(`Show ${ROWS - PREVIEW_ROWS} more rows`);
    fireEvent.click(more);
    await waitFor(() => expect(count.textContent).toBe(`${ROWS} of ${ROWS} rows listed`));
    expect(screen.queryByTestId("import-rows-more")).toBeNull();
    expect(screen.queryByTestId("import-rows-limit")).toBeNull();
    expect(within(grid).getByTestId("grid-foot").textContent).toContain(String(ROWS));
    expect(previewRequests(spy)).toEqual([PREVIEW_ROWS, ROWS]);
    // The grouped changes cover every row now.
    const hosts = screen.getAllByTestId("import-group").find((g) => g.dataset.key === "host:create")!;
    expect(within(hosts).getAllByTestId("import-change")).toHaveLength(ROWS);
  });

  it("loads every row before apply, so the result links to everything the import creates", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await uploadAndPreview("nodes.csv", BIG_CSV);
    const all = await serverPreview();
    expect(all.rows).toHaveLength(ROWS);
    const expected = new Set(
      all.rows.flatMap((r: PreviewRow) => r.items.filter((i) => i.action === "create" && i.key.kind !== "credential").map((i) => `${i.key.kind}:${itemLabel(i.key)}`)),
    );
    spy.mockClear();

    const apply = screen.getByTestId("import-apply") as HTMLButtonElement;
    await waitFor(() => expect(apply.disabled).toBe(false));
    fireEvent.click(apply);
    const result = await screen.findByTestId("import-result", {}, SLOW);
    await waitFor(() => expect(within(result).getByTestId("import-again")).toBeTruthy(), SLOW);

    // The full row list was read before the apply request went out.
    const calls = spy.mock.calls.map(([url, init]) => `${String(init?.method ?? "GET")} ${new URL(String(url), "http://localhost").pathname}`);
    const read = calls.findIndex((c) => c.startsWith("GET") && c.endsWith("/preview"));
    const applied = calls.findIndex((c) => c.startsWith("POST") && c.endsWith("/apply"));
    expect(read).toBeGreaterThanOrEqual(0);
    expect(read).toBeLessThan(applied);
    expect(previewRequests(spy)[0]).toBe(ROWS);

    fireEvent.click(within(result).getByTestId("import-created-all"));
    const items = within(result).getAllByTestId("import-created-item").map((li) => li.dataset.key);
    expect(new Set(items)).toEqual(expected);
    expect(items).toContain("host:node260");
    expect([...ipamState().data.host.values()].some((h) => h.name === "node260")).toBe(true);
  });
});

describe("row list limits", () => {
  const row = (i: number): PreviewRow => ({ location: { sheet: "big", row: i + 2 }, status: "imported", items: [] });
  const state = (listed: number, total: number): WizardState => {
    const preview: ImportPreview = {
      id: "imp-1",
      base_revision: 7,
      summary: { counts: [], lines: [], rows: { total, free: 0, imported: total, skipped: 0 }, loss: { info: 0, warning: 0, error: 0 }, chunks: 1 },
      sheets: [{ sheet: "big", kind: "list", rows: total, imported: total, free: 0, skipped: 0 }],
      rows: Array.from({ length: listed }, (_, i) => row(i)),
      total_rows: total,
      loss: [],
      proposals: [],
      credentials: { hosts: 0, new: 0, changed: 0, unchanged: 0, statement: "", allowed: true },
      warnings: [],
      can_apply: true,
      blockers: [],
    };
    return { ...INITIAL, step: "preview", preview };
  };
  const show = (s: WizardState) =>
    renderRoute(() => <PreviewStep state={s} busy={false} onAcknowledge={() => {}} onMappingChange={() => {}} onBack={() => {}} onApply={() => {}} />);

  it("says the list stops at the server's limit while the counts cover every row", () => {
    show(state(MAX_PREVIEW_ROWS, 1500));
    expect(screen.getByTestId("import-rows-count").textContent).toBe("1,000 of 1,500 rows listed");
    expect(screen.queryByTestId("import-rows-more")).toBeNull();
    expect(screen.getByTestId("import-rows-limit").textContent).toMatch(/first 1,000 rows.*all 1,500/);
  });

  it("offers the next page while rows are missing", () => {
    show(state(PREVIEW_ROWS, 1500));
    expect(screen.getByTestId("import-rows-more").textContent).toBe(`Show ${PREVIEW_ROWS} more rows`);
    expect(screen.getByTestId("import-rows-limit")).toBeTruthy();
  });

  it("writes the place of a row as sheet and row", () => {
    expect(rowPlace(row(0))).toBe("big!2");
    expect(rowPlace({ location: { sheet: "Index" }, status: "skipped", items: [] })).toBe("Index");
  });

  it("merges a longer page of the same preview and takes a new preview whole", () => {
    const s = state(PREVIEW_ROWS, 450);
    const longer = state(400, 450).preview!;
    const merged = reduce(s, { type: "rows", preview: longer });
    expect(merged.preview?.rows).toHaveLength(400);
    expect(merged.preview?.sheets).toBe(s.preview?.sheets);
    // A shorter answer never drops rows already listed.
    expect(reduce(merged, { type: "rows", preview: s.preview! }).preview?.rows).toHaveLength(400);
    // The store changed: the new preview replaces the old one.
    const fresh = { ...state(PREVIEW_ROWS, 451).preview!, base_revision: 8 };
    expect(reduce(merged, { type: "rows", preview: fresh }).preview).toBe(fresh);
  });
});
