// The settings page for the audit export (WP3.11b, IAM-18, TGL-21; slice-3 plan WP3.3): the sinks
// that receive every audit record, each with its transport, format, delivery state and how far it
// lags behind the chain; a dialog to add or change a sink that can send a test record first; and
// the warning of TGL-21 when the profile requires a sink and none delivers. The sinks are saved as
// one list with the revision they were read at. Administrators only.
import { createEffect, createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { isApiError } from "../../api/problem";
import { api } from "../../api/client";
import { asWorkingModel } from "../../api/pending";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { formatNumber, formatRelative, t } from "../../i18n";
import { RunDialog } from "../UserDialogs";
import { SettingsNav } from "../SettingsNav";
import {
  defaultPort,
  FORMATS,
  formatText,
  lag,
  newSink,
  sinkProblems,
  sinkTarget,
  stateText,
  TRANSPORTS,
  transportText,
  type AuditExportTestResult,
  type AuditExportView,
  type AuditSink,
  type AuditSinkView,
  type SinkFormat,
  type SinkTransport,
} from "./model";
import "../settings.css";
import "./audit-export.css";

/** The command that checks the chain of a JSON export offline (a command, not a word). */
const VERIFY_COMMAND = "tenko audit verify --file export.jsonl";

/** The configuration of a sink without its status, as the update takes it. */
function plain(sink: AuditSinkView | AuditSink): AuditSink {
  const { status: _status, ...rest } = sink as AuditSinkView;
  return rest;
}

export default function AuditExportPage() {
  const view = createLiveQuery<AuditExportView>({
    topics: ["system"],
    fetch: async (signal) => {
      const value = await asWorkingModel<AuditExportView>(api.get("/api/v1/settings/audit-export", { signal }));
      return { value, revision: value.revision };
    },
  });
  const [editing, setEditing] = createSignal<AuditSink | null>(null);
  const [removing, setRemoving] = createSignal<AuditSinkView | null>(null);
  const [error, setError] = createSignal<unknown>(null);
  const current = () => latest(view);
  const delivering = () => (current()?.sinks ?? []).some((s) => s.enabled && s.status.state !== "failing");

  /** Saves the list with one sink replaced, added or removed. */
  const save = async (change: (sinks: AuditSink[]) => AuditSink[]) => {
    const now = current();
    if (!now) return;
    try {
      await api.put("/api/v1/settings/audit-export", {
        body: { sinks: change(now.sinks.map(plain)) } as never,
        ifMatch: now.revision,
      });
      setError(null);
      view.refetch();
    } catch (err) {
      if (isApiError(err, "sys.store.precondition_failed")) view.refetch();
      throw err;
    }
  };

  const saveSink = async (next: AuditSink) => {
    const known = (current()?.sinks ?? []).some((s) => s.id === next.id);
    await save((sinks) => (known ? sinks.map((s) => (s.id === next.id ? next : s)) : [...sinks, next]));
    toast({ kind: "ok", title: t("audit_export.saved", { name: next.name }) });
  };

  const removeSink = async (sink: AuditSinkView) => {
    await save((sinks) => sinks.filter((s) => s.id !== sink.id));
    toast({ kind: "ok", title: t("audit_export.removed", { name: sink.name }) });
  };

  const toggle = async (sink: AuditSinkView) => {
    try {
      await save((sinks) => sinks.map((s) => (s.id === sink.id ? { ...s, enabled: !s.enabled } : s)));
      toast({ kind: "ok", title: sink.enabled ? t("audit_export.paused", { name: sink.name }) : t("audit_export.resumed", { name: sink.name }) });
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div class="page" data-testid="page-audit-export">
      <PageHead title={t("audit_export.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("audit_export.lede")}</p>
        <ErrorNotice error={view.value.error} />
        <ErrorNotice error={error()} />
        <Show when={current()?.required && !delivering()}>
          <Notice kind="bad" role="alert" title={t("audit_export.required.title")}>
            <span data-testid="audit-export-required">{t("audit_export.required.body")}</span>
          </Notice>
        </Show>
        <section class="page-section" aria-labelledby="ae-sinks" data-testid="audit-export-sinks">
          <div class="ae-head">
            <h2 id="ae-sinks">{t("audit_export.sinks.heading")}</h2>
            <button
              type="button"
              class="btn"
              data-testid="audit-export-add"
              disabled={!current()}
              onClick={() => setEditing(newSink(crypto.randomUUID()))}
            >
              <Icon name="plus" size="sm" />
              {t("audit_export.add")}
            </button>
          </div>
          <Show
            when={current()}
            fallback={
              <Show when={!view.value.error}>
                <p class="muted" role="status">
                  {t("common.loading")}
                </p>
              </Show>
            }
          >
            {(data) => (
              <Show when={data().sinks.length > 0} fallback={<p class="muted" data-testid="audit-export-empty">{t("audit_export.none")}</p>}>
                <div class="table-wrap">
                  <table class="plain">
                    <caption class="sr-only">{t("audit_export.sinks.heading")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("audit_export.col.name")}</th>
                        <th scope="col">{t("audit_export.col.target")}</th>
                        <th scope="col">{t("audit_export.col.format")}</th>
                        <th scope="col">{t("audit_export.col.state")}</th>
                        <th scope="col" class="num">{t("audit_export.col.lag")}</th>
                        <th scope="col" class="r">
                          <span class="sr-only">{t("audit_export.col.actions")}</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={data().sinks}>
                        {(sink) => (
                          <tr data-testid="audit-export-sink" data-key={sink.name} data-state={sink.status.state}>
                            <td>{sink.name}</td>
                            <td>
                              {transportText(sink.transport)} <span class="mono">{sinkTarget(sink)}</span>
                            </td>
                            <td>{formatText(sink.format)}</td>
                            <td>
                              <span
                                class={`tag ${sink.status.state === "failing" ? "conflict" : sink.status.state === "ok" ? "ok" : ""}`}
                                data-testid="audit-export-state"
                              >
                                {stateText(sink.status.state)}
                              </span>
                              <Show when={sink.status.state === "failing" && sink.status.failing_since}>
                                {(since) => (
                                  <small class="muted ae-help">
                                    {t("audit_export.failing_since", { when: formatRelative(since()) })}
                                    <Show when={sink.status.last_error}>{(e) => <>: {e()}</>}</Show>
                                  </small>
                                )}
                              </Show>
                              <Show when={sink.status.state === "ok" && sink.status.last_delivery_at}>
                                {(at) => <small class="muted ae-help">{t("audit_export.delivered", { when: formatRelative(at()) })}</small>}
                              </Show>
                            </td>
                            <td class="num" data-testid="audit-export-lag">
                              {formatNumber(lag(sink.status))}
                            </td>
                            <td class="r ae-actions">
                              <button type="button" class="btn sm" data-testid="audit-export-edit" onClick={() => setEditing(plain(sink))}>
                                {t("common.action.edit")}
                              </button>
                              <button type="button" class="btn sm" data-testid="audit-export-toggle" onClick={() => void toggle(sink)}>
                                {sink.enabled ? t("audit_export.pause") : t("audit_export.resume")}
                              </button>
                              <button
                                type="button"
                                class="btn sm"
                                data-testid="audit-export-remove"
                                aria-label={t("audit_export.remove_named", { name: sink.name })}
                                onClick={() => setRemoving(sink)}
                              >
                                {t("common.action.remove")}
                              </button>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
              </Show>
            )}
          </Show>
        </section>
        <section class="page-section" aria-labelledby="ae-verify">
          <h2 id="ae-verify">{t("audit_export.verify.heading")}</h2>
          <p class="muted">{t("audit_export.verify.body")}</p>
          <pre class="ae-command mono">{VERIFY_COMMAND}</pre>
        </section>
      </div>

      <Show when={editing()}>
        {(sink) => (
          <SinkDialog
            sink={sink()}
            isNew={!(current()?.sinks ?? []).some((s) => s.id === sink().id)}
            save={saveSink}
            onClose={() => setEditing(null)}
          />
        )}
      </Show>
      <Show when={removing()}>
        {(sink) => (
          <RunDialog
            title={t("audit_export.remove_title", { name: sink().name })}
            body={<p>{current()?.required && (current()?.sinks.length ?? 0) <= 1 ? t("audit_export.remove_last") : t("audit_export.remove_body")}</p>}
            confirmLabel={t("common.action.remove")}
            danger
            run={() => removeSink(sink())}
            onClose={() => setRemoving(null)}
          />
        )}
      </Show>
    </div>
  );
}

/** Adds or changes one sink; "Send test record" tries the sink as it stands in the form. */
function SinkDialog(props: { sink: AuditSink; isNew: boolean; save: (sink: AuditSink) => Promise<void>; onClose: () => void }) {
  const [sink, setSink] = createSignal<AuditSink>(untrack(() => ({ ...props.sink })));
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [test, setTest] = createSignal<AuditExportTestResult | null>(null);
  const [testing, setTesting] = createSignal(false);
  const problems = () => (submitted() ? sinkProblems(sink()) : {});
  const set = (change: Partial<AuditSink>) => setSink((s) => ({ ...s, ...change }));

  // A changed form makes an earlier test result stale.
  createEffect(() => {
    sink();
    setTest(null);
  });

  const setTransport = (transport: SinkTransport) => {
    const s = sink();
    const fileChange = (transport === "file") !== (s.transport === "file");
    set({
      transport,
      port: transport === "file" ? null : fileChange || s.port === defaultPort(s.transport) ? defaultPort(transport) : s.port,
      format: transport === "file" && fileChange ? "json" : s.format,
    });
  };

  const runTest = async () => {
    setSubmitted(true);
    if (Object.keys(sinkProblems(sink())).length > 0) return;
    setTesting(true);
    setError(null);
    try {
      const result = await asWorkingModel<AuditExportTestResult>(
        api.post("/api/v1/settings/audit-export/test", { body: { sink: sink() } as never }),
      );
      setTest(result);
    } catch (err) {
      setError(err);
    } finally {
      setTesting(false);
    }
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (Object.keys(sinkProblems(sink())).length > 0 || busy()) return;
    setBusy(true);
    setError(null);
    try {
      await props.save({ ...sink(), name: sink().name.trim() });
      props.onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };


  return (
    <Dialog
      label={props.isNew ? t("audit_export.add_title") : t("audit_export.edit_title")}
      onClose={props.onClose}
      class="dialog wide"
      testid="dialog-audit-sink"
    >
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{props.isNew ? t("audit_export.add_title") : t("audit_export.edit_title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <div class="field">
            <label for="ae-name">{t("audit_export.field.name")}</label>
            <input
              id="ae-name"
              class="input"
              data-testid="field-name"
              autocomplete="off"
              aria-invalid={problems().name ? "true" : undefined}
              aria-describedby={problems().name ? "ae-name-error" : undefined}
              value={sink().name}
              onInput={(e) => set({ name: e.currentTarget.value })}
            />
            <Show when={problems().name}>
              <span class="help bad field-error" id="ae-name-error">
                {problems().name}
              </span>
            </Show>
          </div>
          <fieldset class="field">
            <legend class="label">{t("audit_export.field.transport")}</legend>
            <div class="choices" role="radiogroup" aria-label={t("audit_export.field.transport")}>
              <For each={TRANSPORTS}>
                {(transport) => (
                  <label class="choice">
                    <input
                      type="radio"
                      name="ae-transport"
                      checked={sink().transport === transport}
                      data-testid={`field-transport-${transport}`}
                      onChange={() => setTransport(transport)}
                    />
                    <span>
                      <strong>{transportText(transport)}</strong>
                      <small class="muted">{t(`audit_export.transport.${transport}_help`)}</small>
                    </span>
                  </label>
                )}
              </For>
            </div>
          </fieldset>
          <div class="field">
            <label for="ae-format">{t("audit_export.field.format")}</label>
            <select id="ae-format" class="select" data-testid="field-format" onChange={(e) => set({ format: e.currentTarget.value as SinkFormat })}>
              <For each={FORMATS}>
                {(format) => (
                  <option value={format} selected={sink().format === format}>
                    {formatText(format)}
                  </option>
                )}
              </For>
            </select>
          </div>
          <Show
            when={sink().transport !== "file"}
            fallback={
              <>
                <div class="field">
                  <label for="ae-path">{t("audit_export.field.path")}</label>
                  <input
                    id="ae-path"
                    class="input mono"
                    data-testid="field-path"
                    autocomplete="off"
                    spellcheck={false}
                    aria-invalid={problems().path ? "true" : undefined}
                    aria-describedby="ae-path-help"
                    value={sink().path ?? ""}
                    onInput={(e) => set({ path: e.currentTarget.value })}
                  />
                  <span class={problems().path ? "help bad field-error" : "help"} id="ae-path-help">
                    {problems().path ?? t("audit_export.field.path_help")}
                  </span>
                </div>
                <div class="field">
                  <label for="ae-keep">{t("audit_export.field.keep_files")}</label>
                  <input
                    id="ae-keep"
                    class="input num"
                    type="number"
                    min={1}
                    data-testid="field-keep_files"
                    value={sink().keep_files ?? 10}
                    onInput={(e) => set({ keep_files: Number(e.currentTarget.value) || null })}
                  />
                </div>
              </>
            }
          >
            <div class="ae-host">
              <div class="field">
                <label for="ae-host">{t("audit_export.field.host")}</label>
                <input
                  id="ae-host"
                  class="input mono"
                  data-testid="field-host"
                  autocomplete="off"
                  spellcheck={false}
                  aria-invalid={problems().host ? "true" : undefined}
                  aria-describedby={problems().host ? "ae-host-error" : undefined}
                  value={sink().host ?? ""}
                  onInput={(e) => set({ host: e.currentTarget.value })}
                />
                <Show when={problems().host}>
                  <span class="help bad field-error" id="ae-host-error">
                    {problems().host}
                  </span>
                </Show>
              </div>
              <div class="field">
                <label for="ae-port">{t("audit_export.field.port")}</label>
                <input
                  id="ae-port"
                  class="input num"
                  type="number"
                  min={1}
                  max={65535}
                  data-testid="field-port"
                  aria-invalid={problems().port ? "true" : undefined}
                  aria-describedby={problems().port ? "ae-port-error" : undefined}
                  value={sink().port ?? ""}
                  onInput={(e) => set({ port: Number(e.currentTarget.value) })}
                />
                <Show when={problems().port}>
                  <span class="help bad field-error" id="ae-port-error">
                    {problems().port}
                  </span>
                </Show>
              </div>
            </div>
            <Show when={sink().transport === "tls"}>
              <div class="field">
                <label for="ae-ca">{t("audit_export.field.ca_pem")}</label>
                <textarea
                  id="ae-ca"
                  class="input mono"
                  rows={5}
                  spellcheck={false}
                  data-testid="field-ca_pem"
                  aria-describedby="ae-ca-help"
                  value={sink().ca_pem ?? ""}
                  onInput={(e) => set({ ca_pem: e.currentTarget.value.trim() ? e.currentTarget.value : null })}
                />
                <span class="help" id="ae-ca-help">
                  {t("audit_export.field.ca_pem_help")}
                </span>
              </div>
              <label class="ackrow">
                <input
                  type="checkbox"
                  class="cb"
                  checked={!!sink().client_certificate}
                  data-testid="field-client_certificate"
                  onChange={(e) => set({ client_certificate: e.currentTarget.checked })}
                />
                {t("audit_export.field.client_certificate")}
              </label>
            </Show>
            <Show when={sink().transport === "udp"}>
              <p class="note" role="status">
                {t("audit_export.udp_warning")}
              </p>
            </Show>
          </Show>
          <div class="form-row">
            <button type="button" class="btn" data-testid="audit-export-test" disabled={testing()} onClick={() => void runTest()}>
              {t("audit_export.test")}
            </button>
            <Show when={test()}>
              {(result) => (
                <span
                  class={`ae-test ${result().delivered ? "ok" : "bad"}`}
                  role="status"
                  data-testid="audit-export-test-result"
                  data-delivered={result().delivered ? "true" : "false"}
                >
                  <Icon name={result().delivered ? "check" : "alert"} size="sm" />
                  {result().delivered ? t("audit_export.test_ok") : t("audit_export.test_failed", { detail: result().detail ?? "" })}
                </span>
              )}
            </Show>
          </div>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("common.action.save")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
