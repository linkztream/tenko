// Step 3: the preview as a full page (API-09): what the import creates, updates and leaves,
// grouped by kind as a checklist; the loss report by sheet, row and column; proposed
// prefixes to accept or reject; what happens to credentials, in plain words; the warnings
// with their acknowledgements; and why apply is blocked, when it is. The outcome of every
// sheet comes first; the source rows are listed page by page in a data grid.
import { createMemo, For, Show } from "solid-js";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { DataGrid } from "../../grid/DataGrid";
import type { Column } from "../../grid/types";
import { t, tDynamic } from "../../i18n";
import { toCsv } from "../../ipam/address/csv";
import { warningText } from "../../ipam/plan/describe";
import { kindWord } from "../../ipam/words";
import { saveTextFile } from "../../hosts/handoff";
import { MAX_PREVIEW_ROWS, type ItemAction, type ItemKey, type LossItem, type Mapping, type PreviewRow, type Severity } from "../api";
import { blockersOf, canApply, decideProposal, nextRows, UNACKNOWLEDGED_BLOCKER, unacknowledged, type WizardState } from "../model";

const ACTIONS: readonly ItemAction[] = ["create", "update", "unchanged", "kept"];

/** The natural key of an item as a person reads it. */
export function itemLabel(key: ItemKey): string {
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

/** A source row of the row list, with its place in the list. */
interface ListedRow {
  index: number;
  row: PreviewRow;
}

/** "Sheet!Row" as spreadsheet programs write a place (or only the sheet). */
export function rowPlace(row: PreviewRow): string {
  const sheet = row.location.sheet ?? "";
  return row.location.row != null ? `${sheet}!${row.location.row}` : sheet;
}

/** Loss report entries of one sheet by severity. */
export function lossCounts(
  loss: readonly { sheet?: string | null; entries: readonly { severity: Severity }[] }[],
  sheet: string,
): Record<Severity, number> {
  const out: Record<Severity, number> = { error: 0, warning: 0, info: 0 };
  for (const group of loss) {
    if ((group.sheet ?? "") !== sheet) continue;
    for (const e of group.entries) out[e.severity] += 1;
  }
  return out;
}

const ROW_COLUMNS: Column<ListedRow>[] = [
  {
    id: "where",
    header: () => t("import.rows.where"),
    width: 200,
    fixed: true,
    text: (r) => rowPlace(r.row),
    render: (r) => <span class="mono">{rowPlace(r.row)}</span>,
  },
  { id: "status", header: () => t("import.rows.status"), width: 150, render: (r) => t(`import.rows.status_${r.row.status}`) },
  {
    id: "items",
    header: () => t("import.rows.items"),
    render: (r) => (
      <For each={r.row.items} fallback={<span class="muted">{t("import.rows.nothing")}</span>}>
        {(item) => (
          <span class="import-row-item" data-action={item.action}>
            {t(`import.action.${item.action}`)} {kindWord(item.key.kind, 1)} <span class="mono">{itemLabel(item.key)}</span>
          </span>
        )}
      </For>
    ),
  },
];

function lossText(entry: LossItem): string {
  return tDynamic(`import.loss.${entry.code.replace(/^import\./, "")}`) ?? entry.code;
}

export function PreviewStep(props: {
  state: WizardState;
  busy: boolean;
  onAcknowledge: (code: string, on: boolean) => void;
  onMappingChange: (mapping: Mapping) => void;
  onBack: () => void;
  onApply: () => void;
  /** A page more of the row list is on its way. */
  rowsLoading?: boolean;
  rowsError?: unknown;
  onMoreRows?: () => void;
}) {
  const p = () => props.state.preview;
  const blocking = () => new Set(unacknowledged(props.state));
  const listed = createMemo<ListedRow[]>(() => (p()?.rows ?? []).map((row, index) => ({ index, row })));
  /** How many rows the next page adds. */
  const more = () => Math.max(0, nextRows(props.state) - (p()?.rows.length ?? 0));

  /** Every planned item, grouped by kind and action, once. */
  const groups = createMemo(() => {
    const out = new Map<string, { kind: string; action: ItemAction; items: Map<string, ItemKey> }>();
    for (const row of p()?.rows ?? []) {
      for (const item of row.items) {
        const id = `${item.key.kind}:${item.action}`;
        let g = out.get(id);
        if (!g) out.set(id, (g = { kind: item.key.kind, action: item.action, items: new Map() }));
        g.items.set(itemLabel(item.key), item.key);
      }
    }
    return [...out.values()].sort((a, b) => a.kind.localeCompare(b.kind) || ACTIONS.indexOf(a.action) - ACTIONS.indexOf(b.action));
  });

  const downloadLoss = () => {
    const rows = (p()?.loss ?? []).flatMap((sheet) =>
      sheet.entries.map((e) => [sheet.sheet ?? "", e.row != null ? String(e.row) : "", e.column ?? "", e.severity, e.code, e.detail]),
    );
    saveTextFile("import-loss-report.csv", toCsv(["sheet", "row", "column", "severity", "code", "detail"], rows), "text/csv;charset=utf-8");
  };

  return (
    <div class="import-preview" data-testid="import-preview-page">
      <Show when={p()} fallback={<p class="muted" role="status">{t("ipam.plan.previewing")}</p>}>
        {(preview) => (
          <>
            <section class="import-card" aria-labelledby="import-summary-title" data-testid="import-summary">
              <h2 id="import-summary-title">{t("import.preview.summary")}</h2>
              <div class="import-facts">
                <div>
                  <span class="big" data-testid="import-rows-total">{preview().summary.rows.total}</span> {t("import.preview.rows_total")}
                </div>
                <div>
                  <span class="big" data-testid="import-rows-imported">{preview().summary.rows.imported}</span> {t("import.preview.rows_imported")}
                </div>
                <div>
                  <span class="big" data-testid="import-rows-free">{preview().summary.rows.free}</span> {t("import.preview.rows_free")}
                </div>
                <div>
                  <span class="big" data-testid="import-rows-skipped">{preview().summary.rows.skipped}</span> {t("import.preview.rows_skipped")}
                </div>
              </div>
              <table class="plain import-counts" aria-label={t("import.preview.counts")}>
                <thead>
                  <tr>
                    <th scope="col">{t("import.preview.kind")}</th>
                    <For each={ACTIONS}>{(a) => <th scope="col" class="r">{t(`import.action.${a}`)}</th>}</For>
                  </tr>
                </thead>
                <tbody>
                  <For each={[...new Set(preview().summary.counts.map((c) => c.kind))]}>
                    {(kind) => (
                      <tr data-testid="import-count" data-key={kind} data-kind={kind}>
                        <td>{kind === "credential" ? t("import.preview.credentials_kind") : kindWord(kind, 2)}</td>
                        <For each={ACTIONS}>
                          {(a) => (
                            <td class="r num" data-col={a}>
                              {preview().summary.counts.find((c) => c.kind === kind && c.action === a)?.count ?? 0}
                            </td>
                          )}
                        </For>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </section>

            <Show when={preview().plan_error}>
              {(e) => (
                <Notice kind="bad" role="alert">
                  {tDynamic(`errors.${e().code}`, e().params ?? {}) ?? e().detail}
                </Notice>
              )}
            </Show>
            <Show when={blockersOf(props.state).length > 0}>
              <Notice kind="bad" title={t("import.preview.blocked")}>
                <ul class="plain-list" data-testid="import-blockers">
                  <For each={blockersOf(props.state)}>
                    {(code) => (
                      <li data-testid="import-blocker" data-key={code} data-code={code}>
                        {tDynamic(`errors.${code}`, code === UNACKNOWLEDGED_BLOCKER ? { codes: unacknowledged(props.state).join(", ") } : {}) ?? code}
                      </li>
                    )}
                  </For>
                </ul>
              </Notice>
            </Show>

            <Show when={preview().warnings.length > 0}>
              <section class="import-card" aria-labelledby="import-warnings-title">
                <h2 id="import-warnings-title">{t("import.preview.warnings")}</h2>
                <For each={preview().warnings}>
                  {(w) => (
                    <Notice kind={w.requires_ack ? "warn" : "info"}>
                      <p>{warningText(w)}</p>
                      <Show when={w.requires_ack && !w.acknowledged}>
                        <label class="ackrow">
                          <input
                            type="checkbox"
                            class="cb"
                            checked={!blocking().has(w.code)}
                            data-testid="import-ack"
                            data-code={w.code}
                            onChange={(e) => props.onAcknowledge(w.code, e.currentTarget.checked)}
                          />
                          {t("ipam.plan.ack")}
                        </label>
                      </Show>
                    </Notice>
                  )}
                </For>
              </section>
            </Show>

            <Show when={preview().credentials.hosts > 0}>
              <section class="import-card" aria-labelledby="import-cred-title" data-testid="import-credentials">
                <h2 id="import-cred-title">
                  <Icon name="key" /> {t("import.credentials.title")}
                </h2>
                <p>
                  {t("import.credentials.statement", {
                    hosts: preview().credentials.hosts,
                    created: preview().credentials.new,
                    changed: preview().credentials.changed,
                    unchanged: preview().credentials.unchanged,
                  })}
                </p>
                <Show when={!preview().credentials.allowed}>
                  <Notice kind="warn">
                    {/* The reason is translated when it is a known code; an English explanation is not shown. */}
                    {tDynamic(`import.credentials.reason.${preview().credentials.reason ?? ""}`) ?? t("import.credentials.not_allowed")}
                  </Notice>
                </Show>
              </section>
            </Show>

            <Show when={preview().proposals.length > 0}>
              <section class="import-card" aria-labelledby="import-proposals-title" data-testid="import-proposals">
                <h2 id="import-proposals-title">{t("import.proposals.title")}</h2>
                <p class="muted">{t("import.proposals.body")}</p>
                <ul class="plain-list">
                  <For each={preview().proposals}>
                    {(proposal) => (
                      <li data-testid="import-proposal" data-key={proposal.cidr}>
                        <label class="ackrow">
                          <input
                            type="checkbox"
                            class="cb"
                            data-testid="import-proposal-accept"
                            checked={proposal.accepted}
                            disabled={props.busy}
                            onChange={(e) =>
                              props.state.mapping &&
                              props.onMappingChange(decideProposal(props.state.mapping, proposal.cidr, e.currentTarget.checked))
                            }
                          />
                          <span class="mono">{proposal.cidr}</span>
                        </label>
                        <span class="muted">
                          {t("import.proposals.holds", { count: proposal.addresses.length, sheet: proposal.origin.sheet ?? "", row: proposal.origin.row ?? 0 })}
                        </span>
                      </li>
                    )}
                  </For>
                </ul>
              </section>
            </Show>

            <Show when={preview().sheets.length > 0}>
              <section class="import-card" aria-labelledby="import-sheets-title" data-testid="import-outcomes">
                <h2 id="import-sheets-title">{t("import.sheets.title")}</h2>
                <div class="table-wrap">
                  <table class="plain import-outcomes" aria-labelledby="import-sheets-title">
                    <thead>
                      <tr>
                        <th scope="col">{t("import.sheets.sheet")}</th>
                        <th scope="col">{t("import.sheets.kind")}</th>
                        <th scope="col">{t("import.sheet.cidr")}</th>
                        <th scope="col" class="r">{t("import.sheets.rows")}</th>
                        <th scope="col" class="r">{t("import.sheets.imported")}</th>
                        <th scope="col" class="r">{t("import.sheets.free")}</th>
                        <th scope="col" class="r">{t("import.sheets.skipped")}</th>
                        <th scope="col" class="r">{t("import.sheets.errors")}</th>
                        <th scope="col" class="r">{t("import.sheets.warnings")}</th>
                        <th scope="col" class="r">{t("import.sheets.notes")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={preview().sheets}>
                        {(o) => {
                          const loss = () => lossCounts(preview().loss, o.sheet);
                          return (
                            <tr data-testid="import-outcome" data-key={o.sheet} data-kind={o.kind}>
                              <th scope="row" class="mono">
                                {o.sheet}
                              </th>
                              <td data-col="kind">{t(`import.kind.${o.kind}`)}</td>
                              <td data-col="cidr" class="mono">
                                {o.cidr ?? ""}
                              </td>
                              <td data-col="rows" class="r num">
                                {o.rows}
                              </td>
                              <td data-col="imported" class="r num">
                                {o.imported}
                              </td>
                              <td data-col="free" class="r num">
                                {o.free}
                              </td>
                              <td data-col="skipped" class="r num">
                                {o.skipped}
                              </td>
                              <td data-col="error" class="r num">
                                {loss().error}
                              </td>
                              <td data-col="warning" class="r num">
                                {loss().warning}
                              </td>
                              <td data-col="info" class="r num">
                                {loss().info}
                              </td>
                            </tr>
                          );
                        }}
                      </For>
                    </tbody>
                  </table>
                </div>
              </section>
            </Show>

            <section class="import-card" aria-labelledby="import-changes-title" data-testid="import-changes">
              <h2 id="import-changes-title">{t("import.changes.title")}</h2>
              <Show when={preview().total_rows > preview().rows.length}>
                <p class="muted">{t("import.changes.first_rows", { shown: preview().rows.length, total: preview().total_rows })}</p>
              </Show>
              <For each={groups()}>
                {(g) => (
                  <details class="import-group" data-testid="import-group" data-key={`${g.kind}:${g.action}`} data-kind={g.kind} data-action={g.action} open={g.action === "create" || g.action === "update"}>
                    <summary>
                      {t("import.changes.group", { kind: kindWord(g.kind, g.items.size), action: t(`import.action.${g.action}`), count: g.items.size })}
                    </summary>
                    <ul class="plain-list mono">
                      <For each={[...g.items.keys()]}>{(label) => <li data-testid="import-change" data-key={label}>{label}</li>}</For>
                    </ul>
                  </details>
                )}
              </For>
            </section>

            <section class="import-card" aria-labelledby="import-rows-title" data-testid="import-rows">
              <h2 id="import-rows-title">
                {t("import.rows.title")}
                <span class="aside" data-testid="import-rows-count" role="status">
                  {t("import.rows.count", { shown: preview().rows.length, total: preview().total_rows })}
                </span>
              </h2>
              <div class="import-rows-grid">
                <DataGrid
                  id="import-rows"
                  label={t("import.rows.title")}
                  noSelection
                  columns={ROW_COLUMNS}
                  rows={listed()}
                  rowId={(r) => String(r.index)}
                  rowKey={(r) => rowPlace(r.row)}
                  loading={props.rowsLoading ?? false}
                  hasMore={more() > 0}
                  onLoadMore={() => props.onMoreRows?.()}
                  error={props.rowsError ?? null}
                  onRetry={() => props.onMoreRows?.()}
                  empty={<p class="muted">{t("import.rows.none")}</p>}
                />
              </div>
              <Show when={more() > 0}>
                <div>
                  <button
                    type="button"
                    class="btn sm"
                    data-testid="import-rows-more"
                    disabled={props.rowsLoading}
                    onClick={() => props.onMoreRows?.()}
                  >
                    {t("import.rows.more", { count: more() })}
                  </button>
                </div>
              </Show>
              <Show when={preview().total_rows > MAX_PREVIEW_ROWS}>
                <p class="muted" data-testid="import-rows-limit">
                  {t("import.rows.limit", { limit: MAX_PREVIEW_ROWS, total: preview().total_rows })}
                </p>
              </Show>
            </section>

            <section class="import-card" aria-labelledby="import-loss-title" data-testid="import-loss">
              <h2 id="import-loss-title">
                {t("import.loss.title")}
                <span class="aside">
                  {t("import.loss.counts", {
                    error: preview().summary.loss.error,
                    warning: preview().summary.loss.warning,
                    info: preview().summary.loss.info,
                  })}
                </span>
              </h2>
              <Show when={preview().loss.some((s) => s.entries.length > 0)} fallback={<p class="muted">{t("import.loss.none")}</p>}>
                <button type="button" class="btn sm" onClick={downloadLoss} data-testid="import-loss-csv">
                  <Icon name="download" size="sm" />
                  {t("import.loss.download")}
                </button>
                <For each={preview().loss.filter((s) => s.entries.length > 0)}>
                  {(sheet) => (
                    <div class="table-wrap">
                      <table class="plain" aria-label={sheet.sheet ?? t("import.loss.whole")}>
                        <caption>{sheet.sheet ?? t("import.loss.whole")}</caption>
                        <thead>
                          <tr>
                            <th scope="col">{t("import.loss.severity")}</th>
                            <th scope="col">{t("import.loss.where")}</th>
                            <th scope="col">{t("import.loss.what")}</th>
                            <th scope="col">{t("import.loss.detail")}</th>
                          </tr>
                        </thead>
                        <tbody>
                          <For each={sheet.entries}>
                            {(e) => (
                              <tr data-testid="import-loss-entry" data-code={e.code} data-severity={e.severity}>
                                <td>
                                  <span class={`sev ${e.severity}`}>
                                    <Icon name={e.severity === "info" ? "info" : "alert"} size="xs" />
                                    {t(`import.severity.${e.severity}`)}
                                  </span>
                                </td>
                                <td class="mono">
                                  {[e.column, e.row != null ? String(e.row) : null].filter(Boolean).join("")}
                                </td>
                                <td>{lossText(e)}</td>
                                <td class="muted">{e.detail}</td>
                              </tr>
                            )}
                          </For>
                        </tbody>
                      </table>
                    </div>
                  )}
                </For>
              </Show>
            </section>
          </>
        )}
      </Show>
      <div class="import-actions sticky">
        <button type="button" class="btn ghost" onClick={() => props.onBack()} data-testid="import-back">
          {t("import.preview.back")}
        </button>
        <Show when={p() && blocking().size > 0}>
          <span class="muted">{t("ipam.plan.ack_needed")}</span>
        </Show>
        <button
          type="button"
          class="btn primary"
          disabled={props.busy || !canApply(props.state)}
          data-testid="import-apply"
          onClick={() => props.onApply()}
        >
          {t("import.preview.apply", { count: p()?.summary.rows.imported ?? 0 })}
        </button>
      </div>
    </div>
  );
}
