// The preview page of an import with more source rows than one page lists: the outcome of
// every sheet, the row list page by page (GET /imports/{id}/rows and its cursor) with its
// total, a fresh preview when the stored one is out of date, and every row loaded before
// apply so the result links to everything.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { importRecords } from "../api/mock/import-store";
import { filesForm, releaseNodeFormData, testFile, useNodeFormData } from "../api/mock/import-testkit";
import { ipamState } from "../api/mock/ipam/api";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { MAX_ROWS_PAGE, PREVIEW_ROWS, type ImportPreview, type ImportRowsPage, type PreviewRow } from "./api";
import { allRowsListed, INITIAL, nextRows, reduce, rowsRequest, type WizardState } from "./model";
import { itemLabel, lossCounts, PreviewStep, rowPlace } from "./steps/PreviewStep";
import Wizard from "./Wizard";

/** A list of 450 IPv6 addresses with host names, in the seeded 2001:db8:0:10::/64. */
const ROWS = 450;
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
  return api.get("/api/v1/imports/{id}/preview", { path: { id }, query: { rows: MAX_ROWS_PAGE } });
}

/** Every request to the rows endpoint so far: its limit and whether it carried a cursor. */
function rowsRequests(spy: { mock: { calls: unknown[][] } }): string[] {
  return spy.mock.calls
    .map(([url]) => new URL(String(url), "http://localhost"))
    .filter((u) => u.pathname.endsWith("/rows"))
    .map((u) => `${u.searchParams.get("limit")}${u.searchParams.has("cursor") ? "+cursor" : ""}`);
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

    // The preview carries no cursor: the first page more reads from the first row, the next
    // one follows the cursor. The preview is not requested again.
    fireEvent.click(screen.getByTestId("import-rows-more"));
    await waitFor(() => expect(count.textContent).toBe(`${2 * PREVIEW_ROWS} of ${ROWS} rows listed`));
    const more = screen.getByTestId("import-rows-more");
    expect(more.textContent).toBe(`Show ${ROWS - 2 * PREVIEW_ROWS} more rows`);
    fireEvent.click(more);
    await waitFor(() => expect(count.textContent).toBe(`${ROWS} of ${ROWS} rows listed`));
    expect(screen.queryByTestId("import-rows-more")).toBeNull();
    expect(within(grid).getByTestId("grid-foot").textContent).toContain(String(ROWS));
    expect(previewRequests(spy)).toEqual([PREVIEW_ROWS]);
    expect(rowsRequests(spy)).toEqual([`${2 * PREVIEW_ROWS}`, `${PREVIEW_ROWS}+cursor`]);
    // The rows arrive in source order, once each.
    const all = await serverPreview();
    expect(within(grid).getAllByTestId("row")[0]?.dataset.key).toBe(rowPlace(all.rows[0]!));
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

    // The full row list was read before the apply request went out, from the rows endpoint.
    const calls = spy.mock.calls.map(([url, init]) => `${String(init?.method ?? "GET")} ${new URL(String(url), "http://localhost").pathname}`);
    const read = calls.findIndex((c) => c.startsWith("GET") && c.endsWith("/rows"));
    const applied = calls.findIndex((c) => c.startsWith("POST") && c.endsWith("/apply"));
    expect(read).toBeGreaterThanOrEqual(0);
    expect(read).toBeLessThan(applied);
    expect(previewRequests(spy)).toEqual([]);
    expect(rowsRequests(spy)).toEqual([String(MAX_ROWS_PAGE)]);

    fireEvent.click(within(result).getByTestId("import-created-all"));
    const items = within(result).getAllByTestId("import-created-item").map((li) => li.dataset.key);
    expect(new Set(items)).toEqual(expected);
    expect(items).toContain("host:node260");
    expect([...ipamState().data.host.values()].some((h) => h.name === "node260")).toBe(true);
  });
});

describe("paging after the preview changed", () => {
  it("walks the cursor to the end before apply when a page past the preview was read", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await uploadAndPreview("nodes.csv", BIG_CSV);
    fireEvent.click(screen.getByTestId("import-rows-more"));
    await waitFor(() => expect(screen.getByTestId("import-rows-count").textContent).toBe(`${2 * PREVIEW_ROWS} of ${ROWS} rows listed`));
    spy.mockClear();
    const apply = screen.getByTestId("import-apply") as HTMLButtonElement;
    await waitFor(() => expect(apply.disabled).toBe(false));
    fireEvent.click(apply);
    await screen.findByTestId("import-result", {}, SLOW);
    expect(rowsRequests(spy)).toEqual([`${MAX_ROWS_PAGE}+cursor`]);
    expect(previewRequests(spy)).toEqual([]);
  });

  it("previews again and starts over when the mapping changed since the preview", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await uploadAndPreview("nodes.csv", BIG_CSV);
    const [id] = [...importRecords().keys()];
    const view = await api.get("/api/v1/imports/{id}", { path: { id: id! } });
    // Another tab changes the mapping: the stored rows belong to the old one (409 import.preview.stale).
    await api.put("/api/v1/imports/{id}/mapping", { path: { id: id! }, body: { ...view.mapping, options: { ...view.mapping.options, conflict: "skip" } } });
    fireEvent.click(screen.getByTestId("import-rows-more"));
    await waitFor(() => expect(previewRequests(spy)).toEqual([PREVIEW_ROWS, PREVIEW_ROWS]));
    const count = screen.getByTestId("import-rows-count");
    await waitFor(() => expect(count.textContent).toBe(`${PREVIEW_ROWS} of ${ROWS} rows listed`));
    expect(screen.queryByRole("alert")).toBeNull();
    // Paging works again on the new preview, from the first row.
    fireEvent.click(screen.getByTestId("import-rows-more"));
    await waitFor(() => expect(count.textContent).toBe(`${2 * PREVIEW_ROWS} of ${ROWS} rows listed`));
  });

  it("previews again when the stored preview was computed anew in between", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await uploadAndPreview("nodes.csv", BIG_CSV);
    const [id] = [...importRecords().keys()];
    // The store changes and another tab previews: the stored rows have a new base revision.
    await api.post("/api/v1/prefixes", { body: { cidr: "203.0.113.240/29", vrf: ipamState().data.vrf.values().next().value!.id } as never });
    const fresh = await api.get("/api/v1/imports/{id}/preview", { path: { id: id! }, query: { rows: 1 } });
    fireEvent.click(screen.getByTestId("import-rows-more"));
    await waitFor(() => expect(previewRequests(spy).filter((n) => n === PREVIEW_ROWS)).toHaveLength(2));
    await waitFor(() => expect(screen.getByTestId("import-rows-count").textContent).toBe(`${PREVIEW_ROWS} of ${ROWS} rows listed`));
    expect(fresh.base_revision).toBeGreaterThan(0);
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

  it("reaches every row, beyond the 1,000 one request lists", () => {
    show({ ...state(MAX_ROWS_PAGE, 1500), rowsCursor: "c1" });
    expect(screen.getByTestId("import-rows-count").textContent).toBe("1,000 of 1,500 rows listed");
    expect(screen.getByTestId("import-rows-more").textContent).toBe(`Show ${PREVIEW_ROWS} more rows`);
    expect(screen.queryByTestId("import-rows-limit")).toBeNull();
  });

  it("offers the next page while rows are missing and nothing when all are listed", () => {
    const view = show(state(PREVIEW_ROWS, 250));
    expect(screen.getByTestId("import-rows-more").textContent).toBe("Show 50 more rows");
    view.unmount();
    show(state(250, 250));
    expect(screen.queryByTestId("import-rows-more")).toBeNull();
  });

  it("writes the place of a row as sheet and row", () => {
    expect(rowPlace(row(0))).toBe("big!2");
    expect(rowPlace({ location: { sheet: "Index" }, status: "skipped", items: [] })).toBe("Index");
  });

  const page = (from: number, to: number, next: string | null, base = 7, total = 450): ImportRowsPage => ({
    items: Array.from({ length: to - from }, (_, i) => row(from + i)),
    next_cursor: next,
    total_rows: total,
    base_revision: base,
  });

  it("asks for the first page past the preview from the first row, then follows the cursor", () => {
    let s = state(PREVIEW_ROWS, 450);
    expect(rowsRequest(s)).toEqual({ limit: 2 * PREVIEW_ROWS });
    expect(nextRows(s)).toBe(2 * PREVIEW_ROWS);
    s = reduce(s, { type: "rows", page: page(0, 400, "c400"), fromStart: true });
    expect(s.preview?.rows).toHaveLength(400);
    expect(s.rowsCursor).toBe("c400");
    expect(rowsRequest(s)).toEqual({ limit: PREVIEW_ROWS, cursor: "c400" });
    expect(rowsRequest(s, MAX_ROWS_PAGE)).toEqual({ limit: MAX_ROWS_PAGE, cursor: "c400" });
    expect(nextRows(s)).toBe(450);
    s = reduce(s, { type: "rows", page: page(400, 450, null), fromStart: false });
    expect(s.preview?.rows.map((r) => r.location.row)).toEqual(Array.from({ length: 450 }, (_, i) => i + 2));
    expect(allRowsListed(s)).toBe(true);
    expect(rowsRequest(s)).toBeNull();
    expect(nextRows(s)).toBe(0);
  });

  it("ignores a page of another preview and starts over with a new preview", () => {
    const s = reduce(state(PREVIEW_ROWS, 450), { type: "rows", page: page(0, 400, "c400"), fromStart: true });
    expect(reduce(s, { type: "rows", page: page(400, 450, null, 8), fromStart: false })).toBe(s);
    const fresh = reduce(s, { type: "previewed", preview: state(PREVIEW_ROWS, 451).preview! });
    expect(fresh.rowsCursor).toBeNull();
    expect(rowsRequest(fresh)).toEqual({ limit: 2 * PREVIEW_ROWS });
    // A page from the first row never drops rows already listed.
    expect(reduce(s, { type: "rows", page: page(0, 100, "c100"), fromStart: true })).toBe(s);
  });
});
