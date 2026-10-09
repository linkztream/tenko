import { describe, expect, it } from "vitest";
import type { ImportPreview, ImportView, Mapping, SheetAnalysis } from "./api";
import {
  INITIAL,
  blockersOf,
  canApply,
  checkFiles,
  columnIndex,
  decideProposal,
  mappingIssues,
  reduce,
  setColumnTarget,
  setHeaderRow,
  setSheetCidr,
  setSheetKind,
  targetOf,
  unacknowledged,
  type WizardState,
} from "./model";

const mapping: Mapping = {
  sheets: [
    { sheet: "192.0.2.0", kind: "network", cidr: "192.0.2.0/24", header_row: 1, columns: [{ column: "A", target: "address" }, { column: "B", target: "host" }] },
    { sheet: "Index", kind: "index", header_row: null, columns: [] },
  ],
  options: { conflict: "update", credentials: "skip" },
};

const view = (state: ImportView["state"] = "uploaded", job_id: string | null = null): ImportView => ({
  id: "imp-1",
  state,
  created: "2026-10-09T10:00:00Z",
  expires: "2026-10-10T10:00:00Z",
  files: [{ name: "ip-plan.xlsx", format: "xlsx", size: 12_345 }],
  sheets: [],
  mapping,
  mapped: false,
  targets: [],
  job_id,
});

const preview = (over: Partial<ImportPreview> = {}): ImportPreview => ({
  id: "imp-1",
  base_revision: 100,
  summary: { counts: [], lines: [], rows: { total: 0, free: 0, imported: 0, skipped: 0 }, loss: { info: 0, warning: 0, error: 0 }, chunks: 1 },
  sheets: [],
  rows: [],
  total_rows: 0,
  loss: [],
  proposals: [],
  credentials: { hosts: 0, new: 0, changed: 0, unchanged: 0, statement: "", allowed: true },
  warnings: [],
  can_apply: true,
  blockers: [],
  ...over,
});

describe("import wizard state machine", () => {
  it("walks from upload through mapping and preview to apply and done", () => {
    let s: WizardState = reduce(INITIAL, { type: "uploaded", view: view() });
    expect(s.step).toBe("mapping");
    expect(s.mapping).toEqual(mapping);
    expect(s.mapping).not.toBe(mapping);
    s = reduce(s, { type: "edit", mapping: setSheetKind(s.mapping as Mapping, "Index", "skip") });
    expect(s.dirty).toBe(true);
    s = reduce(s, { type: "saved", view: view("mapped") });
    expect(s.step).toBe("preview");
    expect(s.dirty).toBe(false);
    expect(canApply(s)).toBe(false);
    s = reduce(s, { type: "previewed", preview: preview() });
    expect(canApply(s)).toBe(true);
    s = reduce(s, { type: "applying", jobId: "job-1" });
    expect(s.step).toBe("apply");
    s = reduce(s, { type: "finished", succeeded: true });
    expect(s).toMatchObject({ step: "done", succeeded: true, jobId: "job-1" });
  });

  it("needs every blocking warning acknowledged before apply", () => {
    let s = reduce(reduce(INITIAL, { type: "uploaded", view: view() }), { type: "saved", view: view("mapped") });
    s = reduce(s, {
      type: "previewed",
      // As the server answers: the warning that needs an acknowledgement blocks apply.
      preview: preview({
        warnings: [
          { code: "ipam.prefix.nibble_boundary", message: "off nibble", requires_ack: true },
          { code: "ipam.address.in_supernet", message: "in supernet" },
        ],
        can_apply: false,
        blockers: ["ipam.plan.unacknowledged"],
      }),
    });
    expect(unacknowledged(s)).toEqual(["ipam.prefix.nibble_boundary"]);
    expect(blockersOf(s)).toEqual(["ipam.plan.unacknowledged"]);
    expect(canApply(s)).toBe(false);
    s = reduce(s, { type: "acknowledge", code: "ipam.prefix.nibble_boundary", on: true });
    expect(blockersOf(s)).toEqual([]);
    expect(canApply(s)).toBe(true);
    // A new preview without the warning drops its acknowledgement.
    s = reduce(s, { type: "previewed", preview: preview() });
    expect(s.acknowledged).toEqual([]);
  });

  it("does not apply while the server refuses or the mapping has unsaved edits", () => {
    let s = reduce(reduce(INITIAL, { type: "uploaded", view: view() }), { type: "saved", view: view("mapped") });
    s = reduce(s, { type: "previewed", preview: preview({ can_apply: false, blockers: ["import.credentials.vault_required"] }) });
    expect(canApply(s)).toBe(false);
    // An acknowledgement clears only the unacknowledged warnings, never another blocker.
    s = reduce(s, {
      type: "previewed",
      preview: preview({ can_apply: false, blockers: ["ipam.plan.unacknowledged", "import.conflict.kept"] }),
    });
    expect(blockersOf(s)).toEqual(["import.conflict.kept"]);
    expect(canApply(s)).toBe(false);
    s = reduce(s, { type: "previewed", preview: preview() });
    s = reduce(s, { type: "edit", mapping: decideProposal(s.mapping as Mapping, "203.0.113.0/24", false) });
    expect(canApply(s)).toBe(false);
  });

  it("goes back one step at a time and resumes where the import stands", () => {
    let s = reduce(reduce(INITIAL, { type: "uploaded", view: view() }), { type: "saved", view: view("mapped") });
    s = reduce(s, { type: "back" });
    expect(s.step).toBe("mapping");
    expect(reduce(s, { type: "back" })).toEqual(INITIAL);
    expect(reduce(INITIAL, { type: "resumed", view: view("applying", "job-2") })).toMatchObject({ step: "apply", jobId: "job-2" });
    expect(reduce(INITIAL, { type: "resumed", view: view("applied", "job-2") })).toMatchObject({ step: "done", succeeded: true });
    expect(reduce(INITIAL, { type: "resumed", view: view("mapped") }).step).toBe("mapping");
  });

  it("ignores events that do not belong to the current step", () => {
    const s = reduce(INITIAL, { type: "previewed", preview: preview() });
    expect(s).toBe(INITIAL);
    expect(reduce(INITIAL, { type: "applying", jobId: "x" })).toBe(INITIAL);
  });
});

describe("mapping edits and checks", () => {
  const sheets = [{ sheet: "192.0.2.0", rows: 256 } as SheetAnalysis];

  it("sets column targets in column order and removes ignored ones", () => {
    let m = setColumnTarget(mapping, "192.0.2.0", "D", "password");
    m = setColumnTarget(m, "192.0.2.0", "C", "login");
    expect(m.sheets[0]?.columns?.map((c) => c.column)).toEqual(["A", "B", "C", "D"]);
    m = setColumnTarget(m, "192.0.2.0", "B", "ignore");
    expect(targetOf(m, "192.0.2.0", "B")).toBe("ignore");
    expect(targetOf(m, "192.0.2.0", "C")).toBe("login");
  });

  it("reports a network sheet without a network and a header row outside the sheet", () => {
    let m = setSheetCidr(mapping, "192.0.2.0", "");
    m = setHeaderRow(m, "192.0.2.0", 300);
    // A network sheet without mapped columns still creates its network.
    m = setColumnTarget(m, "192.0.2.0", "A", "ignore");
    m = setColumnTarget(m, "192.0.2.0", "B", "ignore");
    expect(mappingIssues(m, sheets).map((i) => i.code)).toEqual(["import.issue.network_cidr", "import.issue.header_row"]);
    expect(mappingIssues(mapping, sheets)).toEqual([]);
  });

  it("needs a list sheet to name its rows by address, network or host", () => {
    let m = setSheetKind(mapping, "192.0.2.0", "list");
    expect(mappingIssues(m, sheets)).toEqual([]);
    m = setColumnTarget(m, "192.0.2.0", "A", "ignore");
    // The host column alone makes it a list of hosts.
    expect(mappingIssues(m, sheets)).toEqual([]);
    m = setColumnTarget(m, "192.0.2.0", "B", "description");
    expect(mappingIssues(m, sheets)).toEqual([{ sheet: "192.0.2.0", code: "import.issue.no_address" }]);
  });

  it("counts spreadsheet columns", () => {
    expect([columnIndex("A"), columnIndex("Z"), columnIndex("AA"), columnIndex("AB")]).toEqual([0, 25, 26, 27]);
  });

  it("checks files before upload", () => {
    const file = (name: string, size: number) => new File([new Uint8Array(size)], name);
    const r = checkFiles([file("ip-plan.xlsx", 10), file("notes.docx", 10)], 100, [".xlsx", ".csv"]);
    expect(r.ok.map((f) => f.name)).toEqual(["ip-plan.xlsx"]);
    expect(r.unsupported).toEqual(["notes.docx"]);
    expect(checkFiles([file("big.csv", 200)], 100, [".csv"]).tooLarge).toBe(true);
  });
});
