// The editor of one option set (the options of the server, of a scope, and of any other owner the
// later packages add): one row per option with its code, its name and a value input by the type
// of the option. Codes come from the catalog and the custom definitions (the codes the server sets
// itself are not offered); a code without a known type is edited as hexadecimal. The whole set is
// saved with `PUT /dhcp/option-sets/{owner}` and the revision read. The errors of the server show
// under the row they name (`params.code`) or at the top.
import { createEffect, createMemo, createResource, createSignal, For, Match, on, Show, Switch, untrack } from "solid-js";
import { createLiveQuery } from "../../api/live";
import { ApiError, errorMessage } from "../../api/problem";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { getOptionSet, listCatalog, listOptionDefs, putOptionSet } from "../api";
import { dataText, parseHex, parseOptionText, type OptionShape, type ValueProblem } from "../model";
import type { OptionKind, OptionValueInput, OptionValueItem } from "../types";
import { kindWords } from "../words";

interface Row {
  /** `space:code`. */
  key: string;
  space: string;
  code: number;
  /** The value as typed; a signal of its own, so typing does not rebuild the row. */
  text: () => string;
  setText: (text: string) => void;
}

function makeRow(space: string, code: number, text: string): Row {
  const [get, set] = createSignal(text);
  return { key: keyOf(space, code), space, code, text: get, setText: set };
}

interface Known extends OptionShape {
  name: string;
}

const keyOf = (space: string, code: number) => `${space}:${code}`;

/** The shape of every option the editor can type: the catalog and the custom definitions. */
function createShapes() {
  const [catalog] = createResource(() => listCatalog());
  // The definitions follow the configuration: a code defined meanwhile is offered at once.
  const defsQuery = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const page = await listOptionDefs(signal);
      return { value: page.items, revision: page.revision };
    },
  });
  const defs = () => defsQuery.latest() ?? [];
  const known = createMemo(() => {
    const map = new Map<string, Known>();
    for (const c of catalog.latest ?? []) map.set(keyOf(c.space, c.code), { kind: c.kind, array: c.array, name: c.name });
    for (const d of defs()) map.set(keyOf(d.space, d.code), { kind: d.kind, array: d.array ?? false, name: d.name });
    return map;
  });
  const managed = createMemo(() => new Set((catalog.latest ?? []).filter((c) => c.server_managed).map((c) => keyOf(c.space, c.code))));
  const choices = createMemo(() => {
    const out: { space: string; code: number; name: string }[] = [];
    for (const c of catalog.latest ?? []) if (!c.server_managed) out.push({ space: c.space, code: c.code, name: c.name });
    for (const d of defs()) out.push({ space: d.space, code: d.code, name: d.name });
    return out.sort((a, b) => (a.space === b.space ? a.code - b.code : a.space < b.space ? -1 : 1));
  });
  return {
    known,
    managed,
    choices,
    ready: () => catalog.state === "ready" && defsQuery.latest() !== undefined,
    error: () => catalog.error ?? defsQuery.value.error,
    reload: () => defsQuery.refetch(),
  };
}

function rowOf(item: OptionValueItem, known: ReadonlyMap<string, Known>): Row {
  const shape = known.get(keyOf(item.space, item.code));
  const text = shape && item.typed !== undefined && item.typed !== null ? dataText(item.typed) : item.data;
  return makeRow(item.space, item.code, text);
}

/** The word for a problem with the value of an option. */
function valueMessage(problem: ValueProblem | "raw_hex"): string {
  return t(`dhcp.optset.check.${problem}`);
}

const LISTED: ReadonlySet<OptionKind> = new Set(["ipv4_address", "ipv6_address", "ipv6_prefix", "fqdn"]);

/** Whether the value of an option is typed in a text area: routes, octets and lists of addresses or names. */
function multiline(shape: Known | undefined): boolean {
  return !!shape && (shape.kind === "classless_routes" || shape.kind === "binary" || (shape.array && LISTED.has(shape.kind)));
}

export function OptionSetEditor(props: {
  /** The owner in its path form: `server`, `scope:<prefix>`. */
  owner: string;
  /** Names the editor for assistive technology. */
  label: string;
  canWrite: boolean;
  /** A value that changes when the definitions changed on the page around the editor: they are read again. */
  refresh?: unknown;
  /** Called after a save, with the saved set. */
  onSaved?: () => void;
  testid?: string;
}) {
  const shapes = createShapes();
  createEffect(on(() => props.refresh, () => shapes.reload(), { defer: true }));
  const [set, { refetch }] = createResource(
    () => props.owner,
    (owner) => getOptionSet(owner),
  );
  const [rows, setRows] = createSignal<Row[]>([]);
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [top, setTop] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const [codeText, setCodeText] = createSignal("");
  const [codeError, setCodeError] = createSignal<string | undefined>();

  // The rows follow the set the server holds, once the types are known.
  createEffect(() => {
    const current = set.latest;
    if (!current || !shapes.ready()) return;
    // The types are read without a dependency: a definition that arrives later does not discard what is being typed.
    const known = untrack(shapes.known);
    setRows(current.values.map((v) => rowOf(v, known)));
    setErrors({});
    setTop(undefined);
  });

  const available = createMemo(() => shapes.choices().filter((c) => !rows().some((r) => r.key === keyOf(c.space, c.code))));
  const editable = () => props.canWrite && !busy();

  const remove = (key: string) => setRows((list) => list.filter((r) => r.key !== key));
  const add = (space: string, code: number) => {
    const key = keyOf(space, code);
    if (rows().some((r) => r.key === key)) return;
    const shape = shapes.known().get(key);
    setRows((list) => [...list, makeRow(space, code, shape?.kind === "bool" && !shape.array ? "true" : "")]);
  };
  const addCode = () => {
    const text = codeText().trim();
    const code = Number(text);
    if (!/^\d+$/.test(text) || code < 1 || code > 254) {
      setCodeError(t("dhcp.optset.check.code"));
      return;
    }
    if (shapes.managed().has(keyOf("dhcp4", code))) {
      setCodeError(t("dhcp.optset.check.managed"));
      return;
    }
    setCodeError(undefined);
    add("dhcp4", code);
    setCodeText("");
  };

  const save = async () => {
    const current = set.latest;
    if (!current || busy()) return;
    const problems: Record<string, string> = {};
    const values: OptionValueInput[] = [];
    for (const row of rows()) {
      const shape = shapes.known().get(row.key);
      const space = row.space === "dhcp4" ? {} : { space: row.space };
      if (shape) {
        const parsed = parseOptionText(shape, row.text());
        if (parsed.ok) values.push({ ...space, code: row.code, typed: parsed.data });
        else problems[row.key] = valueMessage(parsed.problem);
      } else {
        const hex = parseHex(row.text(), 4096);
        if (hex === null) problems[row.key] = valueMessage("raw_hex");
        else values.push({ ...space, code: row.code, data: hex });
      }
    }
    setErrors(problems);
    setTop(undefined);
    if (Object.keys(problems).length > 0) return;
    setBusy(true);
    try {
      await putOptionSet(current, values);
      toast({ kind: "ok", title: t("dhcp.optset.saved") });
      await refetch();
      props.onSaved?.();
    } catch (err) {
      const code = err instanceof ApiError ? err.params.code : undefined;
      const space = err instanceof ApiError ? (err.params.space ?? "dhcp4") : "dhcp4";
      if (code && rows().some((r) => r.key === keyOf(space, Number(code)))) setErrors({ [keyOf(space, Number(code))]: errorMessage(err) });
      else setTop(err);
    } finally {
      setBusy(false);
    }
  };

  const label = (row: Row) => {
    const shape = shapes.known().get(row.key);
    return shape?.name ?? t("dhcp.optset.unknown", { code: row.code });
  };

  return (
    <div class="dhcp-optset" data-testid={props.testid ?? "optset-editor"} data-owner={props.owner}>
      <ErrorNotice error={set.error ?? shapes.error()} />
      <Show when={set.latest && shapes.ready()} fallback={<p class="muted">{t("common.loading")}</p>}>
        <Show when={rows().length > 0} fallback={<p class="muted" data-testid="optset-empty">{t("dhcp.optset.empty")}</p>}>
          <div class="table-wrap">
            <table class="plain">
              <caption class="sr-only">{props.label}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("dhcp.optset.col.code")}</th>
                  <th scope="col">{t("dhcp.optset.col.name")}</th>
                  <th scope="col">{t("dhcp.optset.col.value")}</th>
                  <th scope="col">
                    <span class="sr-only">{t("dhcp.optset.col.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                <For each={rows()}>
                  {(row) => {
                    const shape = () => shapes.known().get(row.key);
                    const error = () => errors()[row.key];
                    const common = () => ({
                      id: `dhcp-f-optset-${row.key}`,
                      "aria-label": t("dhcp.optset.value_of", { name: label(row) }),
                      "aria-invalid": error() ? ("true" as const) : undefined,
                      "aria-describedby": error() ? `dhcp-f-optset-${row.key}-error` : undefined,
                    });
                    return (
                      <>
                        <tr data-testid="optset-row" data-key={row.key} data-code={row.code}>
                          <td class="mono">{row.code}</td>
                          <td>
                            <span class="mono">{label(row)}</span>
                            <Show when={shape()}>{(s) => <span class="muted"> {kindWords(s().kind, s().array)}</span>}</Show>
                            <Show when={!shape()}>
                              <span class="muted"> {t("dhcp.optset.raw")}</span>
                            </Show>
                          </td>
                          <td class="dhcp-optset-value">
                            <Switch
                              fallback={
                                <input
                                  {...common()}
                                  class="input mono"
                                  value={row.text()}
                                  readOnly={!editable()}
                                  spellcheck={false}
                                  data-testid="optset-value"
                                  onInput={(e) => row.setText(e.currentTarget.value)}
                                />
                              }
                            >
                              <Match when={shape()?.kind === "empty"}>
                                <span class="muted" data-testid="optset-flag">{t("dhcp.optset.flag")}</span>
                              </Match>
                              <Match when={shape()?.kind === "bool" && !shape()?.array}>
                                <select
                                  {...common()}
                                  class="select"
                                  value={row.text()}
                                  disabled={!editable()}
                                  data-testid="optset-value"
                                  onChange={(e) => row.setText(e.currentTarget.value)}
                                >
                                  <option value="true">{t("common.yes")}</option>
                                  <option value="false">{t("common.no")}</option>
                                </select>
                              </Match>
                              <Match when={multiline(shape())}>
                                <textarea
                                  {...common()}
                                  class="input mono"
                                  rows={shape()?.kind === "classless_routes" ? 3 : 2}
                                  value={row.text()}
                                  readOnly={!editable()}
                                  spellcheck={false}
                                  data-testid="optset-value"
                                  onInput={(e) => row.setText(e.currentTarget.value)}
                                />
                              </Match>
                            </Switch>
                            <Show when={shape()?.kind === "classless_routes"}>
                              <span class="help">{t("dhcp.optset.routes_help")}</span>
                            </Show>
                          </td>
                          <td class="r">
                            <Show when={props.canWrite}>
                              <button
                                type="button"
                                class="icon-btn"
                                aria-label={t("dhcp.optset.remove", { name: label(row) })}
                                disabled={busy()}
                                data-testid="optset-remove"
                                onClick={() => remove(row.key)}
                              >
                                <Icon name="trash" />
                              </button>
                            </Show>
                          </td>
                        </tr>
                        <Show when={error()}>
                          <tr data-testid="optset-row-error-line">
                            <td colSpan={4}>
                              <span class="help bad" id={`dhcp-f-optset-${row.key}-error`} data-testid="optset-row-error" data-key={row.key}>
                                {error()}
                              </span>
                            </td>
                          </tr>
                        </Show>
                      </>
                    );
                  }}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
        <ErrorNotice error={top()} />
        <Show when={props.canWrite}>
          <div class="dhcp-optset-add">
            <select
              class="select"
              aria-label={t("dhcp.optset.add")}
              value=""
              disabled={busy() || available().length === 0}
              data-testid="optset-add"
              onChange={(e) => {
                const [space, code] = e.currentTarget.value.split("|");
                if (space && code) add(space, Number(code));
                e.currentTarget.value = "";
              }}
            >
              <option value="">{t("dhcp.optset.add")}</option>
              <For each={available()}>{(c) => <option value={`${c.space}|${c.code}`}>{`${c.code} ${c.name}`}</option>}</For>
            </select>
            <span class="dhcp-optset-code">
              <input
                class="input"
                inputmode="numeric"
                aria-label={t("dhcp.optset.add_code")}
                placeholder={t("dhcp.optset.add_code")}
                value={codeText()}
                aria-invalid={codeError() ? "true" : undefined}
                data-testid="optset-add-code"
                onInput={(e) => setCodeText(e.currentTarget.value)}
              />
              <button type="button" class="btn" disabled={busy()} data-testid="optset-add-code-go" onClick={addCode}>
                {t("common.action.add")}
              </button>
            </span>
            <Show when={codeError()}>
              <span class="help bad" data-testid="optset-code-error">{codeError()}</span>
            </Show>
          </div>
          <div class="dhcp-actions">
            <button type="button" class="btn primary" disabled={busy()} data-testid="optset-save" onClick={() => void save()}>
              {t("dhcp.optset.save")}
            </button>
            <button
              type="button"
              class="btn ghost"
              disabled={busy()}
              data-testid="optset-revert"
              onClick={() => {
                void refetch();
              }}
            >
              {t("dhcp.optset.revert")}
            </button>
          </div>
        </Show>
      </Show>
    </div>
  );
}
