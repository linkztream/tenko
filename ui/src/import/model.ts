// The import wizard as a state machine (IPAM-11): upload, mapping, preview, apply, done.
// Pure functions over plain data, so every transition and every guard is testable without
// a DOM; the views only dispatch events and render the state.
//
//   upload --uploaded--> mapping --saved--> preview --applying--> apply --finished--> done
//      ^                   ^  |                |  ^                  |
//      +------back---------+  +----edit--------+  +---failed---------+
//
// Editing the mapping on the preview page (proposals) saves it and previews again; the
// preview is only applied when the server says it can be (`can_apply`) and every warning
// that needs an acknowledgement has one.
import { MAX_ROWS_PAGE, PREVIEW_ROWS, type ImportRowsPage, type RowsRequest } from "./api";
import type {
  ColumnMapping,
  ImportOptions,
  ImportPreview,
  ImportView,
  Mapping,
  SheetAnalysis,
  SheetKind,
  SheetMapping,
} from "./api";

export type Step = "upload" | "mapping" | "preview" | "apply" | "done";
export const STEPS: readonly Step[] = ["upload", "mapping", "preview", "apply", "done"];

export interface WizardState {
  step: Step;
  view: ImportView | null;
  /** The mapping being edited; saved with `saved`. */
  mapping: Mapping | null;
  /** The mapping differs from the one the server has. */
  dirty: boolean;
  preview: ImportPreview | null;
  /**
   * The cursor of the next page of the row list (GET /imports/{id}/rows); null before the
   * first page past the preview, and after the last.
   */
  rowsCursor: string | null;
  acknowledged: readonly string[];
  jobId: string | null;
  /** The apply job ended: true when it succeeded. */
  succeeded: boolean | null;
}

export type WizardEvent =
  | { type: "uploaded"; view: ImportView }
  | { type: "resumed"; view: ImportView }
  | { type: "edit"; mapping: Mapping }
  | { type: "saved"; view: ImportView }
  | { type: "previewed"; preview: ImportPreview }
  /** A page of the rows of the same preview, read from the first row or at the cursor. */
  | { type: "rows"; page: ImportRowsPage; fromStart: boolean }
  | { type: "acknowledge"; code: string; on: boolean }
  | { type: "applying"; jobId: string }
  | { type: "finished"; succeeded: boolean }
  | { type: "back" }
  | { type: "reset" };

export const INITIAL: WizardState = {
  step: "upload",
  view: null,
  mapping: null,
  dirty: false,
  preview: null,
  rowsCursor: null,
  acknowledged: [],
  jobId: null,
  succeeded: null,
};

/** Where a resumed import continues. */
function stepOf(view: ImportView): Step {
  switch (view.state) {
    case "applying":
      return "apply";
    case "applied":
      return "done";
    case "failed":
      return view.job_id ? "done" : "mapping";
    default:
      return "mapping";
  }
}

export function reduce(state: WizardState, event: WizardEvent): WizardState {
  switch (event.type) {
    case "uploaded":
      return { ...INITIAL, step: "mapping", view: event.view, mapping: clone(event.view.mapping) };
    case "resumed": {
      const step = stepOf(event.view);
      return {
        ...INITIAL,
        step,
        view: event.view,
        mapping: clone(event.view.mapping),
        jobId: event.view.job_id ?? null,
        succeeded: event.view.state === "applied" ? true : event.view.state === "failed" ? false : null,
      };
    }
    case "edit":
      if (state.step !== "mapping" && state.step !== "preview") return state;
      return { ...state, mapping: event.mapping, dirty: true };
    case "saved":
      return {
        ...state,
        step: "preview",
        view: event.view,
        mapping: clone(event.view.mapping),
        dirty: false,
        preview: null,
        rowsCursor: null,
      };
    case "previewed":
      if (state.step !== "preview") return state;
      return {
        ...state,
        preview: event.preview,
        rowsCursor: null,
        // Acknowledgements of warnings the new preview no longer has are dropped.
        acknowledged: state.acknowledged.filter((c) => event.preview.warnings.some((w) => w.code === c)),
      };
    case "rows": {
      // A page of another preview (the store changed since) is not merged: the wizard
      // previews again instead (see isCurrentPage).
      if (state.step !== "preview" || !state.preview || !isCurrentPage(state, event.page)) return state;
      const rows = event.fromStart ? event.page.items : [...state.preview.rows, ...event.page.items];
      if (rows.length < state.preview.rows.length) return state;
      return {
        ...state,
        rowsCursor: event.page.next_cursor ?? null,
        preview: { ...state.preview, rows, total_rows: event.page.total_rows },
      };
    }
    case "acknowledge": {
      const set = new Set(state.acknowledged);
      if (event.on) set.add(event.code);
      else set.delete(event.code);
      return { ...state, acknowledged: [...set] };
    }
    case "applying":
      if (state.step !== "preview") return state;
      return { ...state, step: "apply", jobId: event.jobId, succeeded: null };
    case "finished":
      if (state.step !== "apply") return state;
      return { ...state, step: "done", succeeded: event.succeeded };
    case "back":
      if (state.step === "preview") return { ...state, step: "mapping", preview: null, rowsCursor: null };
      if (state.step === "mapping") return INITIAL;
      if (state.step === "done" && state.succeeded === false) return { ...state, step: "preview", preview: null };
      return state;
    case "reset":
      return INITIAL;
  }
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

// ---------------------------------------------------------------------------------
// Guards

/** Warning codes of the preview that still need an acknowledgement. */
export function unacknowledged(state: WizardState): string[] {
  const preview = state.preview;
  if (!preview) return [];
  const given = new Set([...state.acknowledged, ...(state.mapping?.options?.acknowledge ?? [])]);
  return [...new Set(preview.warnings.filter((w) => w.requires_ack && !w.acknowledged && !given.has(w.code)).map((w) => w.code))];
}

/** Whether a page of rows belongs to the preview on show (the same store revision). */
export function isCurrentPage(state: WizardState, page: ImportRowsPage): boolean {
  return !!state.preview && page.base_revision === state.preview.base_revision;
}

/**
 * The request for the next page of the row list, `size` rows more; null when every row is
 * listed. The preview carries no cursor, so the first page past it reads from the first row
 * (the rows the preview listed come again, once); later pages follow the cursor.
 */
export function rowsRequest(state: WizardState, size: number = PREVIEW_ROWS): RowsRequest | null {
  const preview = state.preview;
  if (!preview || allRowsListed(state)) return null;
  const listed = preview.rows.length;
  if (state.rowsCursor) return { limit: Math.min(MAX_ROWS_PAGE, size), cursor: state.rowsCursor };
  return { limit: Math.min(MAX_ROWS_PAGE, listed + size) };
}

/** How many rows are listed once the next page arrived; 0 when every row is listed. */
export function nextRows(state: WizardState): number {
  const request = rowsRequest(state);
  const preview = state.preview;
  if (!request || !preview) return 0;
  const after = request.cursor ? preview.rows.length + request.limit : request.limit;
  return Math.min(preview.total_rows, after);
}

/** Every source row of the preview is listed. */
export function allRowsListed(state: WizardState): boolean {
  return !state.preview || state.preview.rows.length >= state.preview.total_rows;
}

/** The plan blocker that the acknowledgements sent with apply can clear. */
export const UNACKNOWLEDGED_BLOCKER = "ipam.plan.unacknowledged";

/**
 * What stops apply now: the server's blockers, except the unacknowledged warnings once the
 * person has acknowledged every one of them here (apply sends those acknowledgements).
 */
export function blockersOf(state: WizardState): string[] {
  const preview = state.preview;
  if (!preview) return [];
  const all = preview.blockers ?? [];
  return unacknowledged(state).length === 0 ? all.filter((b) => b !== UNACKNOWLEDGED_BLOCKER) : all;
}

export function canApply(state: WizardState): boolean {
  return state.step === "preview" && !state.dirty && !!state.preview && blockersOf(state).length === 0 && unacknowledged(state).length === 0;
}

export interface MappingIssue {
  sheet: string;
  /** Message key of the problem. */
  code: "import.issue.network_cidr" | "import.issue.header_row" | "import.issue.no_address";
}

const CIDR = /^[0-9a-f:.]+\/\d{1,3}$/i;
/** Targets that make a row of a list sheet an object. */
const LIST_SUBJECTS: readonly string[] = ["address", "prefix", "host", "interfaces"];

/** What stops the mapping from being saved, per sheet. */
export function mappingIssues(mapping: Mapping | null, sheets: readonly SheetAnalysis[]): MappingIssue[] {
  if (!mapping) return [];
  const issues: MappingIssue[] = [];
  for (const sm of mapping.sheets) {
    if (sm.kind === "skip") continue;
    const analysis = sheets.find((s) => s.sheet === sm.sheet);
    if (sm.kind === "network" && !(sm.cidr && CIDR.test(sm.cidr.trim()))) {
      issues.push({ sheet: sm.sheet, code: "import.issue.network_cidr" });
    }
    if (sm.header_row != null && (sm.header_row < 1 || (analysis && sm.header_row > analysis.rows))) {
      issues.push({ sheet: sm.sheet, code: "import.issue.header_row" });
    }
    // A network sheet without columns still creates its network; a list needs at least one
    // column that names something: an address, a network or a host (a host list).
    const targets = (sm.columns ?? []).map((c) => c.target);
    if (sm.kind === "list" && !LIST_SUBJECTS.some((t) => targets.includes(t))) {
      issues.push({ sheet: sm.sheet, code: "import.issue.no_address" });
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------------
// Mapping edits (pure, return a new mapping)

function updateSheet(mapping: Mapping, sheet: string, change: (sm: SheetMapping) => SheetMapping): Mapping {
  return { ...mapping, sheets: mapping.sheets.map((sm) => (sm.sheet === sheet ? change(sm) : sm)) };
}

export function setSheetKind(mapping: Mapping, sheet: string, kind: SheetKind): Mapping {
  return updateSheet(mapping, sheet, (sm) => ({ ...sm, kind }));
}

export function setSheetCidr(mapping: Mapping, sheet: string, cidr: string): Mapping {
  return updateSheet(mapping, sheet, (sm) => ({ ...sm, cidr: cidr.trim() === "" ? null : cidr.trim() }));
}

export function setHeaderRow(mapping: Mapping, sheet: string, row: number | null): Mapping {
  return updateSheet(mapping, sheet, (sm) => ({ ...sm, header_row: row }));
}

/** Sets the target of a column; `ignore` removes it from the mapping. */
export function setColumnTarget(mapping: Mapping, sheet: string, column: string, target: string): Mapping {
  return updateSheet(mapping, sheet, (sm) => {
    const rest = (sm.columns ?? []).filter((c) => c.column !== column);
    if (target === "ignore") return { ...sm, columns: rest };
    const old = (sm.columns ?? []).find((c) => c.column === column);
    const next: ColumnMapping = { column, target, interface: old?.interface ?? null };
    return { ...sm, columns: [...rest, next].sort((a, b) => columnIndex(a.column) - columnIndex(b.column)) };
  });
}

export function setColumnInterface(mapping: Mapping, sheet: string, column: string, name: string): Mapping {
  return updateSheet(mapping, sheet, (sm) => ({
    ...sm,
    columns: (sm.columns ?? []).map((c) => (c.column === column ? { ...c, interface: name.trim() || null } : c)),
  }));
}

export function setOption<K extends keyof ImportOptions>(mapping: Mapping, key: K, value: ImportOptions[K]): Mapping {
  return { ...mapping, options: { ...mapping.options, [key]: value } };
}

/** Accepts or rejects a proposed prefix. */
export function decideProposal(mapping: Mapping, cidr: string, accept: boolean): Mapping {
  const rest = (mapping.options?.proposals ?? []).filter((p) => p.cidr !== cidr);
  return setOption(mapping, "proposals", [...rest, { cidr, accept }]);
}

/** The target of a column in a sheet mapping (`ignore` when not mapped). */
export function targetOf(mapping: Mapping | null, sheet: string, column: string): string {
  const sm = mapping?.sheets.find((s) => s.sheet === sheet);
  return sm?.columns?.find((c) => c.column === column)?.target ?? "ignore";
}

/** "A" -> 0, "Z" -> 25, "AA" -> 26. */
export function columnIndex(letter: string): number {
  let n = 0;
  for (const ch of letter.toUpperCase()) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n - 1;
}

/** Files a person picked, checked before upload: size and extension. */
export function checkFiles(files: readonly File[], maxBytes: number, accepted: readonly string[]): {
  ok: File[];
  tooLarge: boolean;
  unsupported: string[];
} {
  const unsupported = files.filter((f) => !accepted.some((ext) => f.name.toLowerCase().endsWith(ext))).map((f) => f.name);
  const ok = files.filter((f) => !unsupported.includes(f.name));
  const total = ok.reduce((n, f) => n + f.size, 0);
  return { ok, tooLarge: total > maxBytes, unsupported };
}
