// The settings page for the reconciler (WP3.11d, WP3.12a; docs/reconciliation.md, section 3.1.1):
// how often it runs, how long facts and unseen addresses live, and whether adoption policies are
// applied. The seven settings are shown in human units and sent as seconds. The save carries the
// ETag of the read as `If-Match`; a changed revision (409) reloads the form with a notice.
// Administrators only.
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { latest } from "../../api/live";
import { ApiError, isApiError } from "../../api/problem";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { tDynamic, t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";
import { NameAuthority } from "./NameAuthority";
import { body, draftErrors, draftOf, FIELDS, limitsText, saveErrorText, unitText, type Draft, type FieldId, type ReconcilerSettings } from "./model";
import "../settings.css";
import "./reconciler.css";

interface Loaded {
  settings: ReconcilerSettings;
  etag: string | number | null;
}

async function load(): Promise<Loaded> {
  const read = await api.getWithEtag("/api/v1/settings/reconciler");
  return { settings: read.value, etag: read.etag };
}

export default function ReconcilerPage() {
  const [loaded, { refetch }] = createResource(load);
  const [conflict, setConflict] = createSignal(false);

  return (
    <div class="page" data-testid="page-reconciler">
      <PageHead title={t("reconciler.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("reconciler.lede")}</p>
        <ErrorNotice error={loaded.error} />
        <Show when={latest(loaded)} fallback={<Show when={!loaded.error}><p class="muted" role="status">{t("common.loading")}</p></Show>} keyed>
          {(current) => (
            <>
              <Show when={conflict()}>
                <div class="rc-notices">
                  <Notice kind="warn" role="status" testid="reconciler-reloaded">
                    {t("reconciler.reloaded")}
                  </Notice>
                </div>
              </Show>
              <SettingsForm
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
        <NameAuthority />
      </div>
    </div>
  );
}

function SettingsForm(props: { loaded: Loaded; onSaved: () => void; onConflict: () => void }) {
  const stored = untrack(() => props.loaded.settings);
  const [draft, setDraft] = createSignal<Draft>(draftOf(stored));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const errors = () => draftErrors(draft(), stored);
  const setText = (id: FieldId, value: string) => setDraft((d) => ({ ...d, text: { ...d.text, [id]: value } }));

  const submit = async (e: Event) => {
    e.preventDefault();
    if (Object.keys(errors()).length > 0 || busy()) return;
    setBusy(true);
    setError(null);
    try {
      await api.put("/api/v1/settings/reconciler", {
        body: body(draft(), stored),
        ifMatch: props.loaded.etag ?? undefined,
      });
      toast({ kind: "ok", title: t("reconciler.saved") });
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
    <form class="card rc-form" data-testid="reconciler-form" onSubmit={(e) => void submit(e)} novalidate>
      <Show when={error()}>
        {(err) => (
          <Notice kind="bad" role="alert" testid="error-notice" code={err() instanceof ApiError ? (err() as ApiError).code : undefined}>
            {saveErrorText(err())}
          </Notice>
        )}
      </Show>
      <div class="field">
        <label class="choice">
          <input
            type="checkbox"
            checked={draft().adopt}
            data-testid="field-adopt"
            aria-describedby="rc-adopt-help"
            onChange={(e) => setDraft((d) => ({ ...d, adopt: e.currentTarget.checked }))}
          />
          <span>{t("reconciler.field.adopt")}</span>
        </label>
        <span class="help" id="rc-adopt-help">{t("reconciler.help.adopt")}</span>
      </div>
      <For each={FIELDS}>
        {(spec) => {
          const id = `rc-${spec.id}`;
          const message = () => errors()[spec.id];
          return (
            <div class="field">
              <label for={id}>{tDynamic(`reconciler.field.${spec.id}`) ?? spec.id}</label>
              <div class="form-row">
                <input
                  id={id}
                  class="input num"
                  type="number"
                  step="any"
                  inputmode="decimal"
                  data-testid={`field-${spec.id}`}
                  aria-invalid={message() ? "true" : undefined}
                  aria-describedby={`${id}-help ${id}-limits`}
                  value={draft().text[spec.id]}
                  onInput={(e) => setText(spec.id, e.currentTarget.value)}
                />
                <span class="rc-unit">{unitText(spec.unit)}</span>
              </div>
              <span class="help" id={`${id}-help`}>{tDynamic(`reconciler.help.${spec.id}`) ?? ""}</span>
              <span class={message() ? "help bad field-error" : "help"} id={`${id}-limits`} data-testid={message() ? "field-error" : undefined} data-field={message() ? spec.id : undefined}>
                {message() ?? limitsText(spec)}
              </span>
            </div>
          );
        }}
      </For>
      <div class="form-row">
        <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
          {t("common.action.save")}
        </button>
      </div>
    </form>
  );
}
