// The settings page for the guardrails (WP3.11d, WP3.12a; docs/connectors-unifi.md, section 6):
// the most layer 2 writes through one controller and the list of protected ports, networks,
// VLANs and clients that connector writes and moves never touch. Paths are added in a dialog
// and removed in the list; nothing is sent until Save, which carries the ETag of the read as
// `If-Match`. A changed revision (409) reloads the page with a notice. Administrators only.
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { latest } from "../../api/live";
import { ApiError, isApiError } from "../../api/problem";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";
import {
  DEFAULT_PARALLEL,
  EMPTY_DRAFT,
  KINDS,
  kindText,
  MAX_PARALLEL,
  MAX_PATHS,
  MIN_PARALLEL,
  parallelOf,
  pathKey,
  pathOfDraft,
  pathText,
  saveErrorText,
  type Guardrails,
  type PathDraft,
  type PathErrors,
  type PathKind,
  type ProtectedPath,
} from "./model";
import "../settings.css";
import "./guardrails.css";

interface Loaded {
  guardrails: Guardrails;
  etag: string | number | null;
}

async function load(): Promise<Loaded> {
  const read = await api.getWithEtag("/api/v1/settings/guardrails");
  return { guardrails: read.value, etag: read.etag };
}

export default function GuardrailsPage() {
  const [loaded, { refetch }] = createResource(load);
  const [conflict, setConflict] = createSignal(false);

  return (
    <div class="page" data-testid="page-guardrails">
      <PageHead title={t("guardrails.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("guardrails.lede")}</p>
        <ErrorNotice error={loaded.error} />
        <Show when={latest(loaded)} fallback={<Show when={!loaded.error}><p class="muted" role="status">{t("common.loading")}</p></Show>} keyed>
          {(current) => (
            <>
              <Show when={conflict()}>
                <div class="gr-notices">
                  <Notice kind="warn" role="status" testid="guardrails-reloaded">
                    {t("guardrails.reloaded")}
                  </Notice>
                </div>
              </Show>
              <GuardrailsForm
                loaded={current}
                onSaved={() => {
                  setConflict(false);
                  void refetch();
                }}
                onConflict={() => {
                  setConflict(true);
                  void refetch();
                }}
              />
            </>
          )}
        </Show>
      </div>
    </div>
  );
}

function GuardrailsForm(props: { loaded: Loaded; onSaved: () => void; onConflict: () => void }) {
  const stored = untrack(() => props.loaded.guardrails);
  const [parallel, setParallel] = createSignal(String(stored.max_parallel));
  const [paths, setPaths] = createSignal<ProtectedPath[]>([...stored.protected]);
  const [adding, setAdding] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  let addButton: HTMLButtonElement | undefined;
  const parallelValue = () => parallelOf(parallel());
  const parallelError = () => (parallelValue() === null ? t("guardrails.error.parallel", { min: MIN_PARALLEL, max: MAX_PARALLEL }) : undefined);

  const remove = (key: string) => {
    setPaths((list) => list.filter((p) => pathKey(p) !== key));
    // The row that had focus is gone; keep the keyboard where it was working.
    addButton?.focus();
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    const value = parallelValue();
    if (value === null || busy()) return;
    setBusy(true);
    setError(null);
    try {
      await api.put("/api/v1/settings/guardrails", {
        body: { max_parallel: value, protected: paths() },
        ifMatch: props.loaded.etag ?? undefined,
      });
      toast({ kind: "ok", title: t("guardrails.saved") });
      props.onSaved();
    } catch (err) {
      if (isApiError(err, "sys.store.precondition_failed")) {
        props.onConflict();
        return;
      }
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form class="card gr-form" data-testid="guardrails-form" onSubmit={(e) => void submit(e)} novalidate>
      <Show when={error()}>
        {(err) => (
          <Notice kind="bad" role="alert" testid="error-notice" code={err() instanceof ApiError ? (err() as ApiError).code : undefined}>
            {saveErrorText(err())}
          </Notice>
        )}
      </Show>
      <div class="field">
        <label for="gr-parallel">{t("guardrails.parallel.label")}</label>
        <input
          id="gr-parallel"
          class="input num"
          type="number"
          min={MIN_PARALLEL}
          max={MAX_PARALLEL}
          data-testid="field-max_parallel"
          aria-invalid={parallelError() ? "true" : undefined}
          aria-describedby="gr-parallel-help gr-parallel-limits"
          value={parallel()}
          onInput={(e) => setParallel(e.currentTarget.value)}
        />
        <span class="help" id="gr-parallel-help">{t("guardrails.parallel.help")}</span>
        <span
          class={parallelError() ? "help bad field-error" : "help"}
          id="gr-parallel-limits"
          data-testid={parallelError() ? "field-error" : undefined}
          data-field={parallelError() ? "max_parallel" : undefined}
        >
          {parallelError() ?? t("guardrails.parallel.limits", { min: MIN_PARALLEL, max: MAX_PARALLEL, default: DEFAULT_PARALLEL })}
        </span>
      </div>

      <section class="page-section" aria-labelledby="gr-paths" data-testid="guardrails-paths">
        <div class="gr-head">
          <h2 id="gr-paths">{t("guardrails.paths.heading")}</h2>
          <button
            type="button"
            class="btn"
            data-testid="guardrails-add"
            ref={addButton}
            disabled={paths().length >= MAX_PATHS}
            onClick={() => setAdding(true)}
          >
            <Icon name="plus" size="sm" />
            {t("guardrails.add")}
          </button>
        </div>
        <Notice kind="info" testid="guardrails-note">
          {t("guardrails.note")}
        </Notice>
        <Show when={paths().length > 0} fallback={<p class="muted" data-testid="guardrails-empty">{t("guardrails.paths.none")}</p>}>
          <div class="table-wrap">
            <table class="plain">
              <caption class="sr-only">{t("guardrails.paths.heading")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("guardrails.col.kind")}</th>
                  <th scope="col">{t("guardrails.col.path")}</th>
                  <th scope="col" class="r">
                    <span class="sr-only">{t("guardrails.col.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                <For each={paths()}>
                  {(path) => (
                    <tr data-testid="guardrail-path" data-kind={path.type} data-key={pathKey(path)}>
                      <td>{kindText(path.type)}</td>
                      <td class="mono gr-path">{pathText(path)}</td>
                      <td class="r">
                        <button
                          type="button"
                          class="btn sm ghost"
                          data-testid="guardrail-remove"
                          aria-label={t("guardrails.remove_label", { path: pathText(path) })}
                          onClick={() => remove(pathKey(path))}
                        >
                          <Icon name="trash" size="sm" />
                          {t("guardrails.remove")}
                        </button>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </section>

      <div class="form-row">
        <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
          {t("common.action.save")}
        </button>
      </div>

      <Show when={adding()}>
        <AddDialog
          existing={paths()}
          onAdd={(path) => {
            setPaths((list) => [...list, path]);
            setAdding(false);
          }}
          onClose={() => setAdding(false)}
        />
      </Show>
    </form>
  );
}

/** The kind of path and the fields of that kind; the path is added to the list, not saved. */
function AddDialog(props: { existing: readonly ProtectedPath[]; onAdd: (path: ProtectedPath) => void; onClose: () => void }) {
  const [draft, setDraft] = createSignal<PathDraft>({ ...EMPTY_DRAFT });
  const [errors, setErrors] = createSignal<PathErrors>({});
  const [duplicate, setDuplicate] = createSignal(false);
  const set = (change: Partial<PathDraft>) => {
    setDraft((d) => ({ ...d, ...change }));
    setErrors({});
    setDuplicate(false);
  };

  const submit = (e: Event) => {
    e.preventDefault();
    const result = pathOfDraft(draft());
    if ("errors" in result) {
      setErrors(result.errors);
      return;
    }
    if (props.existing.some((p) => pathKey(p) === pathKey(result.path))) {
      setDuplicate(true);
      return;
    }
    props.onAdd(result.path);
  };

  return (
    <Dialog label={t("guardrails.dialog.title")} onClose={props.onClose} class="dialog" testid="dialog-guardrail-path">
      <form class="dialog-form" onSubmit={submit} novalidate>
        <h2 class="dialog-title">{t("guardrails.dialog.title")}</h2>
        <div class="dialog-body">
          <p class="muted">{t("guardrails.dialog.body")}</p>
          <Show when={duplicate()}>
            <Notice kind="bad" role="alert" testid="guardrails-duplicate">
              {t("guardrails.error.duplicate")}
            </Notice>
          </Show>
          <div class="field">
            <label for="gr-kind">{t("guardrails.field.kind")}</label>
            <select
              id="gr-kind"
              class="select"
              data-testid="field-kind"
              value={draft().kind}
              onChange={(e) => set({ kind: e.currentTarget.value as PathKind })}
            >
              <For each={KINDS}>{(kind) => <option value={kind} selected={draft().kind === kind}>{kindText(kind)}</option>}</For>
            </select>
          </div>
          <Show when={draft().kind === "port"}>
            <div class="field">
              <label for="gr-device">{t("guardrails.field.device")}</label>
              <input
                id="gr-device"
                class="input mono"
                type="text"
                autocomplete="off"
                spellcheck={false}
                data-testid="field-device"
                aria-invalid={errors().device ? "true" : undefined}
                aria-describedby="gr-device-help"
                value={draft().device}
                onInput={(e) => set({ device: e.currentTarget.value })}
              />
              <span class={errors().device ? "help bad field-error" : "help"} id="gr-device-help" data-testid={errors().device ? "field-error" : undefined} data-field={errors().device ? "device" : undefined}>
                {errors().device ?? t("guardrails.help.device")}
              </span>
            </div>
            <div class="field">
              <label for="gr-port">{t("guardrails.field.port")}</label>
              <input
                id="gr-port"
                class="input num"
                type="text"
                inputmode="numeric"
                autocomplete="off"
                data-testid="field-port"
                aria-invalid={errors().port ? "true" : undefined}
                aria-describedby="gr-port-help"
                value={draft().port}
                onInput={(e) => set({ port: e.currentTarget.value })}
              />
              <span class={errors().port ? "help bad field-error" : "help"} id="gr-port-help" data-testid={errors().port ? "field-error" : undefined} data-field={errors().port ? "port" : undefined}>
                {errors().port ?? t("guardrails.help.port")}
              </span>
            </div>
          </Show>
          <Show when={draft().kind === "network"}>
            <div class="field">
              <label for="gr-network">{t("guardrails.field.network")}</label>
              <input
                id="gr-network"
                class="input mono"
                type="text"
                autocomplete="off"
                spellcheck={false}
                data-testid="field-network"
                aria-invalid={errors().network ? "true" : undefined}
                aria-describedby="gr-network-help"
                value={draft().network}
                onInput={(e) => set({ network: e.currentTarget.value })}
              />
              <span class={errors().network ? "help bad field-error" : "help"} id="gr-network-help" data-testid={errors().network ? "field-error" : undefined} data-field={errors().network ? "network" : undefined}>
                {errors().network ?? t("guardrails.help.network")}
              </span>
            </div>
          </Show>
          <Show when={draft().kind === "vlan"}>
            <div class="field">
              <label for="gr-vid">{t("guardrails.field.vid")}</label>
              <input
                id="gr-vid"
                class="input num"
                type="text"
                inputmode="numeric"
                autocomplete="off"
                data-testid="field-vid"
                aria-invalid={errors().vid ? "true" : undefined}
                aria-describedby="gr-vid-help"
                value={draft().vid}
                onInput={(e) => set({ vid: e.currentTarget.value })}
              />
              <span class={errors().vid ? "help bad field-error" : "help"} id="gr-vid-help" data-testid={errors().vid ? "field-error" : undefined} data-field={errors().vid ? "vid" : undefined}>
                {errors().vid ?? t("guardrails.help.vid")}
              </span>
            </div>
          </Show>
          <Show when={draft().kind === "client"}>
            <div class="field">
              <label for="gr-mac">{t("guardrails.field.mac")}</label>
              <input
                id="gr-mac"
                class="input mono"
                type="text"
                autocomplete="off"
                spellcheck={false}
                data-testid="field-mac"
                aria-invalid={errors().mac ? "true" : undefined}
                aria-describedby="gr-mac-help"
                value={draft().mac}
                onInput={(e) => set({ mac: e.currentTarget.value })}
              />
              <span class={errors().mac ? "help bad field-error" : "help"} id="gr-mac-help" data-testid={errors().mac ? "field-error" : undefined} data-field={errors().mac ? "mac" : undefined}>
                {errors().mac ?? t("guardrails.help.mac")}
              </span>
            </div>
          </Show>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit">
            {t("guardrails.dialog.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
