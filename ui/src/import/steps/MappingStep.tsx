// Step 2: how each sheet and column is read (docs/plans/import-fixtures.md, mapping rules):
// what a sheet is (network list, host list, index, ...), its network and header row, and
// the target of every column, prefilled with the server's suggestion. Credential columns
// are marked: their values go to the vault, never into IPAM fields.
import { For, Show } from "solid-js";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { tDynamic, t } from "../../i18n";
import type { ColumnAnalysis, ConflictPolicy, ImportView, Mapping, SheetAnalysis, SheetKind, ShapeCounts, TargetInfo } from "../api";
import {
  mappingIssues,
  setColumnInterface,
  setColumnTarget,
  setHeaderRow,
  setOption,
  setSheetCidr,
  setSheetKind,
  targetOf,
} from "../model";

const KINDS: readonly SheetKind[] = ["network", "list", "host", "index", "skip"];
const CONFLICTS: readonly ConflictPolicy[] = ["update", "skip", "fail"];
const SHAPES: readonly (keyof ShapeCounts)[] = ["address", "cidr", "range", "mac", "duid", "number", "text", "empty"];

/** The words of an import target; custom fields use the server's label. */
export function targetLabel(target: string, infos: readonly TargetInfo[]): string {
  return tDynamic(`import.target.${target}`) ?? infos.find((i) => i.target === target)?.label ?? target;
}

function shapesText(shapes: ShapeCounts): string {
  return SHAPES.filter((s) => (shapes[s] ?? 0) > 0)
    .map((s) => t("import.shape.count", { shape: t(`import.shape.${s}`), count: shapes[s] ?? 0 }))
    .join(", ");
}

export function MappingStep(props: {
  view: ImportView;
  mapping: Mapping;
  busy: boolean;
  onChange: (mapping: Mapping) => void;
  onSave: () => void;
  onDiscard: () => void;
}) {
  const issues = () => mappingIssues(props.mapping, props.view.sheets);
  const sheetMapping = (sheet: string) => props.mapping.sheets.find((s) => s.sheet === sheet);
  const addressColumns = (sheet: string) =>
    (sheetMapping(sheet)?.columns ?? []).filter((c) => c.target === "address").length;

  const options = () => props.mapping.options ?? {};

  return (
    <div class="import-mapping" data-testid="import-mapping">
      <section class="import-card" aria-labelledby="import-files-title">
        <h2 id="import-files-title">{t("import.mapping.files")}</h2>
        <ul class="list">
          <For each={props.view.files}>
            {(file) => (
              <li>
                <span class="mono">{file.name}</span>{" "}
                <span class="muted">
                  {file.format.toUpperCase()}
                  <Show when={file.text}>
                    {(text) => <> · {t("import.mapping.text", { encoding: text().encoding, delimiter: text().delimiter === "\t" ? t("import.mapping.tab") : text().delimiter })}</>}
                  </Show>
                </span>
              </li>
            )}
          </For>
        </ul>
      </section>

      <section class="import-card" aria-labelledby="import-options-title">
        <h2 id="import-options-title">{t("import.options.title")}</h2>
        <div class="import-options">
          <div class="field">
            <label for="import-vrf">{t("import.options.vrf")}</label>
            <input
              id="import-vrf"
              class="input"
              value={options().vrf ?? ""}
              placeholder={t("import.options.vrf_default")}
              data-testid="import-option-vrf"
              onChange={(e) => props.onChange(setOption(props.mapping, "vrf", e.currentTarget.value.trim() || null))}
            />
          </div>
          <div class="field">
            <label for="import-tenant">{t("import.options.tenant")}</label>
            <input
              id="import-tenant"
              class="input"
              value={options().tenant ?? ""}
              placeholder={t("import.options.tenant_default")}
              onChange={(e) => props.onChange(setOption(props.mapping, "tenant", e.currentTarget.value.trim() || null))}
            />
          </div>
          <div class="field">
            <label for="import-conflict">{t("import.options.conflict")}</label>
            <select
              id="import-conflict"
              class="select"
              value={options().conflict ?? "update"}
              data-testid="import-option-conflict"
              onChange={(e) => props.onChange(setOption(props.mapping, "conflict", e.currentTarget.value as ConflictPolicy))}
            >
              <For each={CONFLICTS}>{(c) => <option value={c}>{t(`import.conflict.${c}`)}</option>}</For>
            </select>
          </div>
          <div class="field">
            <span class="label">{t("import.options.credentials")}</span>
            <label class="ackrow">
              <input
                type="checkbox"
                class="cb"
                checked={(options().credentials ?? "skip") === "import"}
                data-testid="import-option-credentials"
                onChange={(e) =>
                  props.onChange(setOption(props.mapping, "credentials", e.currentTarget.checked ? "import" : "skip"))
                }
              />
              {t("import.options.credentials_import")}
            </label>
            <span class="help">{t("import.options.credentials_help")}</span>
          </div>
        </div>
      </section>

      <For each={props.view.sheets}>
        {(sheet: SheetAnalysis) => {
          const sm = () => sheetMapping(sheet.sheet);
          const sheetIssues = () => issues().filter((i) => i.sheet === sheet.sheet);
          return (
            <section class="import-card sheet-map" data-testid="import-sheet" data-key={sheet.sheet} data-sheet={sheet.sheet} aria-label={sheet.sheet}>
              <h3>
                <span class="mono">{sheet.sheet}</span>
                <span class="muted">
                  {t("import.sheet.summary", { file: sheet.file, rows: sheet.data_rows, width: sheet.width })}
                </span>
              </h3>
              <div class="sheet-head">
                <div class="field">
                  <label for={`kind-${sheet.sheet}`}>{t("import.sheet.kind")}</label>
                  <select
                    id={`kind-${sheet.sheet}`}
                    class="select"
                    value={sm()?.kind ?? "skip"}
                    data-testid="import-sheet-kind"
                    onChange={(e) => props.onChange(setSheetKind(props.mapping, sheet.sheet, e.currentTarget.value as SheetKind))}
                  >
                    <For each={KINDS}>{(k) => <option value={k}>{t(`import.kind.${k}`)}</option>}</For>
                  </select>
                </div>
                <Show when={sm()?.kind === "network"}>
                  <div class="field">
                    <label for={`cidr-${sheet.sheet}`}>{t("import.sheet.cidr")}</label>
                    <input
                      id={`cidr-${sheet.sheet}`}
                      class="input mono"
                      value={sm()?.cidr ?? ""}
                      spellcheck={false}
                      data-testid="import-sheet-cidr"
                      onChange={(e) => props.onChange(setSheetCidr(props.mapping, sheet.sheet, e.currentTarget.value))}
                    />
                    <Show when={sheet.mask_source}>
                      {(source) => <span class="help">{t(`import.mask.${source()}`)}</span>}
                    </Show>
                  </div>
                </Show>
                <div class="field">
                  <label for={`header-${sheet.sheet}`}>{t("import.sheet.header_row")}</label>
                  <input
                    id={`header-${sheet.sheet}`}
                    class="input num"
                    data-testid="import-sheet-header-row"
                    type="number"
                    min="1"
                    max={sheet.rows}
                    value={sm()?.header_row ?? ""}
                    placeholder={t("import.sheet.no_header")}
                    onChange={(e) =>
                      props.onChange(
                        setHeaderRow(props.mapping, sheet.sheet, e.currentTarget.value === "" ? null : Number(e.currentTarget.value)),
                      )
                    }
                  />
                </div>
                <div class="sheet-notes">
                  <Show when={sheet.listed_in_index}>
                    <span class="tag ok">{t("import.sheet.listed")}</span>
                  </Show>
                  <Show when={sheet.roles_from}>
                    {(from) => <span class="muted">{t("import.sheet.roles_from", { sheet: from() })}</span>}
                  </Show>
                </div>
              </div>
              <For each={sheetIssues()}>
                {(issue) => (
                  <Notice kind="warn" role="status">
                    {t(issue.code)}
                  </Notice>
                )}
              </For>
              <Show when={sm()?.kind !== "skip" && sheet.columns.length > 0}>
                <div class="table-wrap">
                  <table class="plain import-columns" aria-label={t("import.columns.label", { sheet: sheet.sheet })}>
                    <thead>
                      <tr>
                        <th scope="col">{t("import.columns.column")}</th>
                        <th scope="col">{t("import.columns.header")}</th>
                        <th scope="col">{t("import.columns.samples")}</th>
                        <th scope="col">{t("import.columns.shapes")}</th>
                        <th scope="col">{t("import.columns.target")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={sheet.columns}>
                        {(col: ColumnAnalysis) => {
                          const target = () => targetOf(props.mapping, sheet.sheet, col.column);
                          const credential = () => props.view.targets.find((i) => i.target === target())?.credential ?? false;
                          return (
                            <tr data-testid="import-column" data-key={col.column} data-column={col.column} data-target={target()}>
                              <td class="mono">{col.column}</td>
                              <td>{col.header ?? <span class="muted">–</span>}</td>
                              <td class="samples mono">{col.samples.join(" · ")}</td>
                              <td class="muted">{shapesText(col.shapes)}</td>
                              <td>
                                <div class="target-cell">
                                  <select
                                    class="select"
                                    aria-label={t("import.columns.target_of", { column: col.column, sheet: sheet.sheet })}
                                    value={target()}
                                    data-testid="import-column-target"
                                    onChange={(e) =>
                                      props.onChange(setColumnTarget(props.mapping, sheet.sheet, col.column, e.currentTarget.value))
                                    }
                                  >
                                    <option value="ignore">{targetLabel("ignore", props.view.targets)}</option>
                                    <For each={props.view.targets.filter((i) => i.target !== "ignore")}>
                                      {(info) => (
                                        <option value={info.target}>
                                          {info.credential
                                            ? t("import.columns.credential_option", { target: targetLabel(info.target, props.view.targets) })
                                            : targetLabel(info.target, props.view.targets)}
                                        </option>
                                      )}
                                    </For>
                                  </select>
                                  <Show when={target() !== col.suggested}>
                                    <span class="muted" title={t("import.columns.suggested", { target: targetLabel(col.suggested, props.view.targets) })}>
                                      <Icon name="info" size="xs" />
                                    </span>
                                  </Show>
                                  <Show when={credential()}>
                                    <span class="flag locked">
                                      <Icon name="key" size="xs" />
                                      {t("import.columns.vault")}
                                    </span>
                                  </Show>
                                  <Show when={target() === "address" && addressColumns(sheet.sheet) > 1}>
                                    <input
                                      class="input mono iface"
                                      data-testid="import-column-interface"
                                      aria-label={t("import.columns.interface", { column: col.column })}
                                      placeholder={t("import.columns.interface_placeholder")}
                                      value={sm()?.columns?.find((c) => c.column === col.column)?.interface ?? ""}
                                      onChange={(e) =>
                                        props.onChange(setColumnInterface(props.mapping, sheet.sheet, col.column, e.currentTarget.value))
                                      }
                                    />
                                  </Show>
                                </div>
                              </td>
                            </tr>
                          );
                        }}
                      </For>
                    </tbody>
                  </table>
                </div>
              </Show>
            </section>
          );
        }}
      </For>

      <div class="import-actions">
        <button type="button" class="btn ghost" onClick={() => props.onDiscard()} data-testid="import-discard">
          {t("import.discard")}
        </button>
        <button
          type="button"
          class="btn primary"
          disabled={props.busy || issues().length > 0}
          data-testid="import-preview"
          onClick={() => props.onSave()}
        >
          {t("import.mapping.preview")}
        </button>
      </div>
    </div>
  );
}
