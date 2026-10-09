// Step 3: the preview as a full page (API-09): what the import creates, updates and leaves,
// grouped by kind as a checklist; the loss report by sheet, row and column; proposed
// prefixes to accept or reject; what happens to credentials, in plain words; the warnings
// with their acknowledgements; and why apply is blocked, when it is.
import { createMemo, For, Show } from "solid-js";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { t, tDynamic } from "../../i18n";
import { toCsv } from "../../ipam/address/csv";
import { warningText } from "../../ipam/plan/describe";
import { kindWord } from "../../ipam/words";
import { saveTextFile } from "../../hosts/handoff";
import type { ItemAction, ItemKey, LossItem, Mapping } from "../api";
import { blockersOf, canApply, decideProposal, UNACKNOWLEDGED_BLOCKER, unacknowledged, type WizardState } from "../model";

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
}) {
  const p = () => props.state.preview;
  const blocking = () => new Set(unacknowledged(props.state));

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
                  <span class="big">{preview().summary.rows.total}</span> {t("import.preview.rows_total")}
                </div>
                <div>
                  <span class="big">{preview().summary.rows.imported}</span> {t("import.preview.rows_imported")}
                </div>
                <div>
                  <span class="big">{preview().summary.rows.free}</span> {t("import.preview.rows_free")}
                </div>
                <div>
                  <span class="big">{preview().summary.rows.skipped}</span> {t("import.preview.rows_skipped")}
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
                      <tr data-kind={kind}>
                        <td>{kind === "credential" ? t("import.preview.credentials_kind") : kindWord(kind, 2)}</td>
                        <For each={ACTIONS}>
                          {(a) => (
                            <td class="r num">
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
                      <li data-code={code}>
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
                      <li data-key={proposal.cidr}>
                        <label class="ackrow">
                          <input
                            type="checkbox"
                            class="cb"
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

            <section class="import-card" aria-labelledby="import-changes-title" data-testid="import-changes">
              <h2 id="import-changes-title">{t("import.changes.title")}</h2>
              <Show when={preview().total_rows > preview().rows.length}>
                <p class="muted">{t("import.changes.first_rows", { shown: preview().rows.length, total: preview().total_rows })}</p>
              </Show>
              <For each={groups()}>
                {(g) => (
                  <details class="import-group" data-kind={g.kind} data-action={g.action} open={g.action === "create" || g.action === "update"}>
                    <summary>
                      {t("import.changes.group", { kind: kindWord(g.kind, g.items.size), action: t(`import.action.${g.action}`), count: g.items.size })}
                    </summary>
                    <ul class="plain-list mono">
                      <For each={[...g.items.keys()]}>{(label) => <li>{label}</li>}</For>
                    </ul>
                  </details>
                )}
              </For>
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
