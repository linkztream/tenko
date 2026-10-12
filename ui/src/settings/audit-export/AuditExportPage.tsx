// The settings page for the audit export (WP3.11b, IAM-18, TGL-21; slice-3 plan WP3.3): the sinks
// that receive every audit record, each with its transport, format, delivery state and how far it
// lags behind the chain; a dialog to add or change a sink that can send a test record first; and
// the warning of TGL-21 when the profile requires a sink and none delivers. The sinks are saved as
// one list with the revision they were read at. Administrators only.
import { createEffect, createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { isApiError } from "../../api/problem";
import { api } from "../../api/client";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { formatNumber, formatRelative, t } from "../../i18n";
import { RunDialog } from "../UserDialogs";
import { SettingsNav } from "../SettingsNav";
import {
  ALERT_AFTER_RANGE,
  CHOICES,
  choiceOf,
  choiceText,
  FACILITIES,
  failureText,
  FORMATS,
  formatText,
  formOf,
  formProblems,
  lag,
  MAX_SINKS,
  newForm,
  policyText,
  sameAsStored,
  serverProblems,
  sinkTarget,
  specOf,
  specOfSink,
  stateTag,
  stateText,
  warningText,
  withChoice,
  type AuditExportTest,
  type AuditExportTestResult,
  type AuditExportView,
  type FormProblems,
  type Sink,
  type SinkChoice,
  type SinkForm,
  type SinkSpec,
  type SinkView,
} from "./model";
import "../settings.css";
import "./audit-export.css";

/** The command that checks the chain of a JSON export offline (a command, not a word). */
const VERIFY_COMMAND = "tenko audit verify --file export.jsonl";

export default function AuditExportPage() {
  const view = createLiveQuery<AuditExportView>({
    topics: ["system"],
    fetch: async (signal) => ({ value: await api.get("/api/v1/settings/audit-export", { signal }) }),
  });
  const [editing, setEditing] = createSignal<SinkForm | null>(null);
  const [removing, setRemoving] = createSignal<SinkView | null>(null);
  const [error, setError] = createSignal<unknown>(null);
  const current = () => latest(view);

  /** Saves the complete list with one sink replaced, added or removed, at the revision it was read at. */
  const save = async (change: (sinks: SinkSpec[]) => SinkSpec[], alertAfter?: number) => {
    const now = current();
    if (!now) return;
    try {
      await api.put("/api/v1/settings/audit-export", {
        body: { sinks: change(now.sinks.map((s) => specOfSink(s))), alert_after_secs: alertAfter ?? now.alert_after_secs },
        ifMatch: now.revision,
      });
      setError(null);
      view.refetch();
    } catch (err) {
      if (isApiError(err, "audit.export.conflict") || isApiError(err, "sys.store.precondition_failed")) view.refetch();
      throw err;
    }
  };

  const saveSink = async (form: SinkForm) => {
    const spec = specOf(form);
    const known = form.id !== null && (current()?.sinks ?? []).some((s) => s.id === form.id);
    await save((sinks) => (known ? sinks.map((s) => (s.id === form.id ? spec : s)) : [...sinks, spec]));
    toast({ kind: "ok", title: t("audit_export.saved", { name: spec.name }) });
  };

  const removeSink = async (sink: SinkView) => {
    await save((sinks) => sinks.filter((s) => s.id !== sink.id));
    toast({ kind: "ok", title: t("audit_export.removed", { name: sink.name }) });
  };

  const toggle = async (sink: SinkView) => {
    try {
      await save((sinks) => sinks.map((s) => (s.id === sink.id ? { ...s, enabled: !s.enabled } : s)));
      toast({ kind: "ok", title: sink.enabled ? t("audit_export.paused", { name: sink.name }) : t("audit_export.resumed", { name: sink.name }) });
    } catch (err) {
      setError(err);
    }
  };

  const isLast = (sink: SinkView) => !!current()?.policy.required && !(current()?.sinks ?? []).some((s) => s.id !== sink.id && s.enabled);

  return (
    <div class="page" data-testid="page-audit-export">
      <PageHead title={t("audit_export.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("audit_export.lede")}</p>
        <ErrorNotice error={view.value.error} />
        <ErrorNotice error={error()} />
        <For each={current()?.warnings ?? []}>
          {(warning) => (
            <Notice
              kind="bad"
              role="alert"
              title={warning.code === "audit.export.required" ? t("audit_export.required.title") : t("audit_export.failing.title")}
              testid="audit-export-warning"
              code={warning.code}
            >
              <span data-testid={warning.code === "audit.export.required" ? "audit-export-required" : undefined}>{warningText(warning)}</span>
            </Notice>
          )}
        </For>
        <section class="page-section" aria-labelledby="ae-sinks" data-testid="audit-export-sinks">
          <div class="ae-head">
            <h2 id="ae-sinks">{t("audit_export.sinks.heading")}</h2>
            <button
              type="button"
              class="btn"
              data-testid="audit-export-add"
              disabled={!current() || (current()?.sinks.length ?? 0) >= MAX_SINKS}
              onClick={() => setEditing(newForm())}
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
                        <th scope="col" class="num">{t("audit_export.col.delivered")}</th>
                        <th scope="col" class="num">{t("audit_export.col.lag")}</th>
                        <th scope="col" class="r">
                          <span class="sr-only">{t("audit_export.col.actions")}</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={data().sinks}>
                        {(sink) => (
                          <tr data-testid="audit-export-sink" data-key={sink.name} data-id={sink.id} data-state={sink.status.state}>
                            <td>{sink.name}</td>
                            <td>
                              {choiceText(choiceOf(sink))} <span class="mono">{sinkTarget(sink)}</span>
                            </td>
                            <td>{formatText(sink.format)}</td>
                            <td>
                              <span class={`tag ${stateTag(sink.status.state)}`} data-testid="audit-export-state" data-state={sink.status.state}>
                                {stateText(sink.status.state)}
                              </span>
                              <Show when={sink.status.last_error}>
                                {(failure) => (
                                  <small class="muted ae-help" data-testid="audit-export-error" data-code={failure().code}>
                                    <Show when={sink.status.failing_since}>
                                      {(since) => <>{t("audit_export.failing_since", { when: formatRelative(since()) })}: </>}
                                    </Show>
                                    {failureText(failure())}
                                  </small>
                                )}
                              </Show>
                              <Show when={sink.status.last_success_at}>
                                {(at) => (
                                  <small class="muted ae-help" data-testid="audit-export-last-success">
                                    {t("audit_export.delivered", { when: formatRelative(at()) })}
                                  </small>
                                )}
                              </Show>
                              <Show when={sink.status.checkpoint}>
                                {(mark) => (
                                  <small class="muted ae-help" data-testid="audit-export-checkpoint">
                                    {t("audit_export.checkpoint", { seq: formatNumber(mark().head.seq), when: formatRelative(mark().at) })}
                                  </small>
                                )}
                              </Show>
                            </td>
                            <td class="num mono" data-testid="audit-export-delivered">
                              {formatNumber(sink.status.delivered.seq)}
                            </td>
                            <td class="num" data-testid="audit-export-lag">
                              {formatNumber(lag(sink.status))}
                            </td>
                            <td class="r ae-actions">
                              <button type="button" class="btn sm" data-testid="audit-export-edit" onClick={() => setEditing(formOf(sink))}>
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
        <Show when={current()}>
          {(data) => (
            <section class="page-section" aria-labelledby="ae-policy" data-testid="audit-export-policy" data-required={String(data().policy.required)} data-satisfied={String(data().policy.satisfied)}>
              <h2 id="ae-policy">{t("audit_export.policy.heading")}</h2>
              <p>{t("audit_export.policy.value", { value: policyText(data().policy) })}</p>
              <Show when={data().policy.required}>
                <p class="muted">{data().policy.satisfied ? t("audit_export.policy.met") : t("audit_export.policy.unmet")}</p>
              </Show>
              <AlertAfter seconds={data().alert_after_secs} save={(seconds) => save((sinks) => sinks, seconds)} />
            </section>
          )}
        </Show>
        <section class="page-section" aria-labelledby="ae-verify">
          <h2 id="ae-verify">{t("audit_export.verify.heading")}</h2>
          <p class="muted">{t("audit_export.verify.body")}</p>
          <pre class="ae-command mono">{VERIFY_COMMAND}</pre>
        </section>
      </div>

      <Show when={editing()}>
        {(form) => (
          <SinkDialog
            form={form()}
            stored={(current()?.sinks ?? []).find((s) => s.id === form().id)}
            save={saveSink}
            onClose={() => setEditing(null)}
          />
        )}
      </Show>
      <Show when={removing()}>
        {(sink) => (
          <RunDialog
            title={t("audit_export.remove_title", { name: sink().name })}
            body={<p>{isLast(sink()) ? t("audit_export.remove_last") : t("audit_export.remove_body")}</p>}
            confirmLabel={t("common.action.remove")}
            danger
            run={() => removeSink(sink())}
            onStale={() => view.refetch()}
            onClose={() => setRemoving(null)}
          />
        )}
      </Show>
    </div>
  );
}

/** The seconds a sink may fail before the alarm `audit.export.failing`. */
function AlertAfter(props: { seconds: number; save: (seconds: number) => Promise<void> }) {
  const [draft, setDraft] = createSignal<string | null>(null);
  const [problem, setProblem] = createSignal<string | null>(null);
  const [error, setError] = createSignal<unknown>(null);
  const value = () => draft() ?? String(props.seconds);
  const submit = async (e: Event) => {
    e.preventDefault();
    const seconds = Number(value());
    if (!Number.isInteger(seconds) || seconds < ALERT_AFTER_RANGE.min || seconds > ALERT_AFTER_RANGE.max) {
      setProblem(t("audit_export.error.alert_after"));
      return;
    }
    setProblem(null);
    setError(null);
    try {
      await props.save(seconds);
      setDraft(null);
      toast({ kind: "ok", title: t("audit_export.alert_after_saved") });
    } catch (err) {
      setError(err);
    }
  };
  return (
    <form class="ae-alert" onSubmit={(e) => void submit(e)} novalidate>
      <ErrorNotice error={error()} />
      <div class="field">
        <label for="ae-alert-after">{t("audit_export.field.alert_after")}</label>
        <div class="ae-inline">
          <input
            id="ae-alert-after"
            class="input num"
            type="number"
            min={ALERT_AFTER_RANGE.min}
            max={ALERT_AFTER_RANGE.max}
            data-testid="field-alert_after_secs"
            aria-invalid={problem() ? "true" : undefined}
            aria-describedby="ae-alert-after-help"
            value={value()}
            onInput={(e) => setDraft(e.currentTarget.value)}
          />
          <button type="submit" class="btn" data-testid="audit-export-alert-save" disabled={draft() === null || draft() === String(props.seconds)}>
            {t("common.action.save")}
          </button>
        </div>
        <span class={problem() ? "help bad field-error" : "help"} id="ae-alert-after-help">
          {problem() ?? t("audit_export.field.alert_after_help")}
        </span>
      </div>
    </form>
  );
}

/** A text input with its label, help and problem. */
function TextField(props: {
  id: string;
  label: string;
  value: string;
  onInput: (value: string) => void;
  testid: string;
  problem?: string | undefined;
  help?: string | undefined;
  mono?: boolean;
  type?: "text" | "number";
  min?: number;
  max?: number;
  step?: number | "any";
}) {
  const describedby = () => (props.problem ? `${props.id}-error` : props.help ? `${props.id}-help` : undefined);
  return (
    <div class="field">
      <label for={props.id}>{props.label}</label>
      <input
        id={props.id}
        class={`input${props.mono ? " mono" : ""}${props.type === "number" ? " num" : ""}`}
        type={props.type ?? "text"}
        min={props.min}
        max={props.max}
        step={props.step}
        data-testid={props.testid}
        autocomplete="off"
        spellcheck={false}
        aria-invalid={props.problem ? "true" : undefined}
        aria-describedby={describedby()}
        value={props.value}
        onInput={(e) => props.onInput(e.currentTarget.value)}
      />
      <Show when={props.problem}>
        <span class="help bad field-error" id={`${props.id}-error`}>
          {props.problem}
        </span>
      </Show>
      <Show when={!props.problem && props.help}>
        <span class="help" id={`${props.id}-help`}>
          {props.help}
        </span>
      </Show>
    </div>
  );
}

/** A PEM text area with its label, help and problem. */
function PemField(props: { id: string; label: string; value: string; onInput: (value: string) => void; testid: string; problem?: string | undefined; help?: string | undefined }) {
  const describedby = () => (props.problem ? `${props.id}-error` : props.help ? `${props.id}-help` : undefined);
  return (
    <div class="field">
      <label for={props.id}>{props.label}</label>
      <textarea
        id={props.id}
        class="input mono"
        rows={5}
        spellcheck={false}
        data-testid={props.testid}
        aria-invalid={props.problem ? "true" : undefined}
        aria-describedby={describedby()}
        value={props.value}
        onInput={(e) => props.onInput(e.currentTarget.value)}
      />
      <Show when={props.problem}>
        <span class="help bad field-error" id={`${props.id}-error`}>
          {props.problem}
        </span>
      </Show>
      <Show when={!props.problem && props.help}>
        <span class="help" id={`${props.id}-help`}>
          {props.help}
        </span>
      </Show>
    </div>
  );
}

/** Adds or changes one sink; "Send test record" tries the sink as it stands in the form. */
function SinkDialog(props: { form: SinkForm; stored: Sink | undefined; save: (form: SinkForm) => Promise<void>; onClose: () => void }) {
  const [form, setForm] = createSignal<SinkForm>(untrack(() => ({ ...props.form })));
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [fromServer, setFromServer] = createSignal<FormProblems>({});
  const [test, setTest] = createSignal<AuditExportTestResult | null>(null);
  const [testing, setTesting] = createSignal(false);
  const isNew = () => props.form.id === null;
  const problems = (): FormProblems => ({ ...(submitted() ? formProblems(form()) : {}), ...fromServer() });
  const set = (change: Partial<SinkForm>) => {
    setForm((f) => ({ ...f, ...change }));
    setFromServer({});
  };

  // A changed form makes an earlier test result stale.
  createEffect(() => {
    form();
    setTest(null);
  });

  const runTest = async () => {
    setSubmitted(true);
    if (Object.keys(formProblems(form())).length > 0) return;
    setTesting(true);
    setError(null);
    try {
      const id = form().id;
      const body: AuditExportTest = id !== null && sameAsStored(form(), props.stored) ? { sink: id } : { spec: specOf(form()) };
      setTest(await api.post("/api/v1/settings/audit-export/test", { body }));
    } catch (err) {
      setError(err);
      setFromServer(serverProblems(err));
    } finally {
      setTesting(false);
    }
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (Object.keys(formProblems(form())).length > 0 || busy()) return;
    setBusy(true);
    setError(null);
    try {
      await props.save(form());
      props.onClose();
    } catch (err) {
      setError(err);
      setFromServer(serverProblems(err));
    } finally {
      setBusy(false);
    }
  };

  const choice = () => form().choice;

  return (
    <Dialog
      label={isNew() ? t("audit_export.add_title") : t("audit_export.edit_title")}
      onClose={props.onClose}
      class="dialog wide"
      testid="dialog-audit-sink"
    >
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{isNew() ? t("audit_export.add_title") : t("audit_export.edit_title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <TextField id="ae-name" label={t("audit_export.field.name")} testid="field-name" value={form().name} problem={problems().name} onInput={(name) => set({ name })} />
          <fieldset class="field">
            <legend class="label">{t("audit_export.field.transport")}</legend>
            <div class="choices" role="radiogroup" aria-label={t("audit_export.field.transport")}>
              <For each={CHOICES}>
                {(option: SinkChoice) => (
                  <label class="choice">
                    <input
                      type="radio"
                      name="ae-transport"
                      checked={choice() === option}
                      data-testid={`field-transport-${option}`}
                      onChange={() => {
                        setForm((f) => withChoice(f, option));
                        setFromServer({});
                      }}
                    />
                    <span>
                      <strong>{choiceText(option)}</strong>
                      <small class="muted">{t(`audit_export.transport.${option}_help`)}</small>
                    </span>
                  </label>
                )}
              </For>
            </div>
          </fieldset>
          <div class="field">
            <label for="ae-format">{t("audit_export.field.format")}</label>
            <select id="ae-format" class="select" data-testid="field-format" onChange={(e) => set({ format: e.currentTarget.value as SinkForm["format"] })}>
              <For each={FORMATS}>
                {(format) => (
                  <option value={format} selected={form().format === format}>
                    {formatText(format)}
                  </option>
                )}
              </For>
            </select>
          </div>
          <Show
            when={choice() !== "file"}
            fallback={
              <>
                <TextField
                  id="ae-file"
                  label={t("audit_export.field.file")}
                  testid="field-file"
                  mono
                  value={form().file}
                  problem={problems().file}
                  help={t("audit_export.field.file_help")}
                  onInput={(file) => set({ file })}
                />
                <div class="ae-host">
                  <TextField
                    id="ae-max-mib"
                    label={t("audit_export.field.max_mib")}
                    testid="field-max_mib"
                    type="number"
                    min={0.0625}
                    step="any"
                    value={form().max_mib}
                    problem={problems().max_mib}
                    onInput={(max_mib) => set({ max_mib })}
                  />
                  <TextField
                    id="ae-keep"
                    label={t("audit_export.field.keep")}
                    testid="field-keep"
                    type="number"
                    min={0}
                    max={1000}
                    value={form().keep}
                    problem={problems().keep}
                    onInput={(keep) => set({ keep })}
                  />
                </div>
              </>
            }
          >
            <div class="ae-host">
              <TextField id="ae-host" label={t("audit_export.field.host")} testid="field-host" mono value={form().host} problem={problems().host} onInput={(host) => set({ host })} />
              <TextField
                id="ae-port"
                label={t("audit_export.field.port")}
                testid="field-port"
                type="number"
                min={1}
                max={65535}
                value={form().port}
                problem={problems().port}
                onInput={(port) => set({ port })}
              />
            </div>
            <div class="field">
              <label for="ae-facility">{t("audit_export.field.facility")}</label>
              <select id="ae-facility" class="select mono" data-testid="field-facility" onChange={(e) => set({ facility: e.currentTarget.value as SinkForm["facility"] })}>
                <For each={FACILITIES}>
                  {(facility) => (
                    <option value={facility} selected={form().facility === facility}>
                      {facility}
                    </option>
                  )}
                </For>
              </select>
            </div>
            <Show when={choice() === "tls"}>
              <TextField
                id="ae-server-name"
                label={t("audit_export.field.server_name")}
                testid="field-server_name"
                mono
                value={form().server_name}
                problem={problems().server_name}
                help={t("audit_export.field.server_name_help")}
                onInput={(server_name) => set({ server_name })}
              />
              <PemField
                id="ae-ca"
                label={t("audit_export.field.ca_pem")}
                testid="field-ca_pem"
                value={form().ca_pem}
                problem={problems().ca_pem}
                help={t("audit_export.field.ca_pem_help")}
                onInput={(ca_pem) => set({ ca_pem })}
              />
              <PemField
                id="ae-client-cert"
                label={t("audit_export.field.client_cert_pem")}
                testid="field-client_cert_pem"
                value={form().client_cert_pem}
                problem={problems().client_cert_pem}
                help={t("audit_export.field.client_cert_pem_help")}
                onInput={(client_cert_pem) => set({ client_cert_pem })}
              />
              <TextField
                id="ae-client-key"
                label={t("audit_export.field.client_key")}
                testid="field-client_key"
                mono
                value={form().client_key}
                problem={problems().client_key}
                help={t("audit_export.field.client_key_help")}
                onInput={(client_key) => set({ client_key })}
              />
            </Show>
            <Show when={choice() === "udp"}>
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
                  data-code={result().error?.code}
                >
                  <Icon name={result().delivered ? "check" : "alert"} size="sm" />
                  {result().delivered
                    ? t("audit_export.test_ok", { ms: formatNumber(result().elapsed_ms) })
                    : t("audit_export.test_failed", {
                        ms: formatNumber(result().elapsed_ms),
                        detail: result().error ? failureText(result().error!) : "",
                      })}
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
