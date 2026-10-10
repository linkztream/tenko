// Creating and changing a connector instance (CONN-19): the plugin (on create), the name, the
// settings in a form built from the plugin's settings schema, the secrets by purpose (chosen
// from the operator secrets, those tagged with the purpose first; never a value), the schedule,
// and the guardrail that allows writes (TGL-20, off by default). The form checks what the host
// checks; the host has the last word and its field errors land under the same fields. A change
// sends only what changed, with the revision the person saw.
import { createMemo, createResource, createSignal, For, Show, untrack } from "solid-js";
import { isApiError } from "../api/problem";
import { isAdmin } from "../auth/session";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { formatList, t } from "../i18n";
import { Field, FieldRow, SelectInput } from "../ipam/formKit";
import { listSecrets } from "../secrets/api";
import {
  createConnector,
  updateConnector,
  type ConnectorChange,
  type ConnectorView,
  type PluginInfo,
  type SecretChoice,
} from "./api";
import { capabilityWord, problemMessages, secretsForPurpose, serverMessages } from "./model";
import { checkSettings, initialSettings, settingsForm, settingsToSend, type JsonSchema, type Settings } from "./schema";
import { SchemaForm } from "./SchemaForm";

const MAX_NAME = 100;
const POLL = { min: 60, max: 86_400, fallback: 300 };
const TIMEOUT = { min: 1, max: 600, fallback: 30 };

/** The secret references of an instance as a choice by purpose. */
function choiceOf(c: ConnectorView | undefined): SecretChoice {
  const out: SecretChoice = {};
  for (const [purpose, ref] of Object.entries(c?.secrets ?? {})) out[purpose] = ref.secret;
  return out;
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** A whole number in bounds from a text field, `null` for empty, or an error message. */
function interval(text: string, bounds: { min: number; max: number }): { value: number | null; error?: string } {
  const s = text.trim();
  if (s === "") return { value: null };
  const n = Number(s);
  if (!Number.isInteger(n) || n < bounds.min || n > bounds.max) {
    return { value: null, error: t("connectors.form.interval_range", { min: bounds.min, max: bounds.max }) };
  }
  return { value: n };
}

export function ConnectorForm(props: {
  plugins: readonly PluginInfo[];
  /** Changing this instance; without it the form creates one. */
  connector?: ConnectorView | undefined;
  onDone: (view: ConnectorView) => void;
  onClose: () => void;
}) {
  const editing = () => !!props.connector;
  const usable = createMemo(() => props.plugins.filter((p) => p.usable && p.manifest));
  const [pluginName, setPluginName] = createSignal(untrack(() => props.connector?.plugin ?? usable()[0]?.name ?? ""));
  const plugin = () => props.plugins.find((p) => p.name === pluginName());
  const manifest = () => plugin()?.manifest ?? undefined;
  const form = createMemo(() => settingsForm(manifest()?.settings as JsonSchema | undefined));

  const [name, setName] = createSignal(untrack(() => props.connector?.name ?? ""));
  const [settings, setSettings] = createSignal<Settings>(untrack(() => initialSettings(form(), props.connector?.settings as Settings | undefined)));
  const [secrets, setSecrets] = createSignal<SecretChoice>(untrack(() => choiceOf(props.connector)));
  const [poll, setPoll] = createSignal(untrack(() => (props.connector?.poll_interval_secs ? String(props.connector.poll_interval_secs) : "")));
  const [timeout, setTimeoutText] = createSignal(untrack(() => (props.connector?.call_timeout_secs ? String(props.connector.call_timeout_secs) : "")));
  const [writes, setWrites] = createSignal(untrack(() => props.connector?.writes_enabled ?? false));
  const [enabled, setEnabled] = createSignal(true);
  const [tried, setTried] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  // The operator secrets to choose from (metadata only). Viewers see none.
  const [secretList] = createResource(async () => {
    try {
      return await listSecrets();
    } catch {
      return [];
    }
  });

  const pickPlugin = (next: string) => {
    setPluginName(next);
    const p = props.plugins.find((x) => x.name === next);
    setSettings(initialSettings(settingsForm(p?.manifest?.settings as JsonSchema | undefined)));
    setSecrets({});
    // The guardrail is a choice for the plugin at hand, off until the person turns it on.
    setWrites(false);
    setError(null);
  };

  const decls = () => manifest()?.secrets ?? [];
  const writable = () => (manifest()?.capabilities ?? []).some((c) => c === "network_controller" || c === "actuator");
  const defaults = () => manifest()?.defaults;

  // Local checks.
  const nameError = () => {
    const n = name().trim();
    if (n === "") return t("connectors.form.name_required");
    if ([...n].length > MAX_NAME) return t("connectors.form.name_long", { max: MAX_NAME });
    return undefined;
  };
  const pollCheck = () => interval(poll(), POLL);
  const timeoutCheck = () => interval(timeout(), TIMEOUT);
  const problems = createMemo(() => checkSettings(form(), settings()));
  const missingSecrets = () => decls().filter((d) => d.required && !secrets()[d.purpose]);
  const valid = () => !nameError() && !pollCheck().error && !timeoutCheck().error && problems().length === 0 && missingSecrets().length === 0 && !!manifest();

  const server = createMemo(() => serverMessages(error()));
  const settingErrors = createMemo(() => ({ ...(tried() ? problemMessages(problems()) : {}), ...Object.fromEntries(Object.entries(server()).filter(([k]) => k.startsWith("settings."))) }));
  const shown = (local: string | undefined, path: string) => (tried() ? local : undefined) ?? server()[path];
  const generalError = () => {
    const e = error();
    if (!e) return null;
    const placed = Object.keys(server()).some((k) => k.startsWith("settings.") || k.startsWith("secrets.") || ["name", "plugin", "poll_interval_secs", "call_timeout_secs"].includes(k));
    return placed ? null : e;
  };

  // Secret references need the rights to reveal and update the secrets: administrators only.
  const mayReference = () => isAdmin();

  const change = (): ConnectorChange => {
    const c = props.connector as ConnectorView;
    const out: ConnectorChange = {};
    if (name().trim() !== c.name) out.name = name().trim();
    const nextSettings = settingsToSend(form(), settings());
    if (!sameJson(nextSettings, settingsToSend(form(), c.settings as Settings))) out.settings = nextSettings;
    if (!sameJson(secrets(), choiceOf(c))) out.secrets = secrets();
    const p = pollCheck().value;
    if (p !== (c.poll_interval_secs ?? null)) out.poll_interval_secs = p ?? 0;
    const tm = timeoutCheck().value;
    if (tm !== (c.call_timeout_secs ?? null)) out.call_timeout_secs = tm ?? 0;
    if (writes() !== (c.writes_enabled ?? false)) out.writes_enabled = writes();
    return out;
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    setTried(true);
    if (!valid() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      if (editing()) {
        const c = props.connector as ConnectorView;
        const diff = change();
        props.onDone(Object.keys(diff).length === 0 ? c : await updateConnector(c.id, diff, c.revision));
      } else {
        props.onDone(
          await createConnector({
            name: name().trim(),
            plugin: pluginName(),
            settings: settingsToSend(form(), settings()),
            secrets: secrets(),
            poll_interval_secs: pollCheck().value,
            call_timeout_secs: timeoutCheck().value,
            writes_enabled: writes(),
            enabled: enabled(),
          }),
        );
      }
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };

  const title = () => (editing() ? t("connectors.form.title_edit", { name: props.connector?.name ?? "" }) : t("connectors.form.title_create"));

  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog connector-dialog">
      <form class="connector-form" data-testid="dialog-connector-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{title()}</h2>

        <Show
          when={!editing()}
          fallback={
            <p class="muted" data-testid="connector-form-plugin">
              {t("connectors.form.plugin_fixed", { plugin: pluginName(), version: manifest()?.version ?? "" })}
            </p>
          }
        >
          <Show when={usable().length > 0} fallback={<Notice kind="warn">{t("connectors.form.no_plugins")}</Notice>}>
            <Field name="plugin" label={t("connectors.form.plugin")} required error={server().plugin}>
              {(c) => (
                <SelectInput
                  {...c}
                  value={pluginName()}
                  options={usable().map((p) => ({ value: p.name, label: `${p.name} ${p.manifest?.version ?? ""}`.trim() }))}
                  onChange={pickPlugin}
                />
              )}
            </Field>
          </Show>
        </Show>
        <Show when={manifest()}>
          {(m) => (
            <p class="muted connector-form-about">
              {m().description} <span class="caps">{formatList(m().capabilities.map(capabilityWord))}</span>
            </p>
          )}
        </Show>

        <Field name="name" label={t("connectors.form.name")} required help={t("connectors.form.name_help")} error={shown(nameError(), "name")}>
          {(c) => <input {...c} class="input" autocomplete="off" value={name()} onInput={(e) => setName(e.currentTarget.value)} />}
        </Field>

        <fieldset class="connector-fieldset" data-testid="connector-settings">
          <legend>{t("connectors.form.settings")}</legend>
          <SchemaForm form={form()} values={settings()} onChange={setSettings} errors={settingErrors()} disabled={busy()} idPrefix="cf" />
        </fieldset>

        <Show when={decls().length > 0}>
          <fieldset class="connector-fieldset" data-testid="connector-secrets">
            <legend>{t("connectors.form.secrets")}</legend>
            <p class="muted">{t("connectors.form.secrets_help")}</p>
            <Show when={!mayReference()}>
              <Notice kind="info">{t("connectors.form.secrets_admin")}</Notice>
            </Show>
            <For each={decls()}>
              {(decl) => {
                const options = () => secretsForPurpose(decl, secretList() ?? []);
                const missing = () => tried() && decl.required && !secrets()[decl.purpose];
                return (
                  <Field
                    name={`secret-${decl.purpose}`}
                    label={t("connectors.form.secret_purpose", { purpose: decl.purpose })}
                    required={decl.required ?? false}
                    help={decl.description}
                    error={missing() ? t("connectors.form.secret_missing") : server()[`secrets.${decl.purpose}`]}
                  >
                    {(c) => (
                      <select
                        {...c}
                        class="select"
                        disabled={!mayReference() || busy()}
                        onChange={(e) => setSecrets({ ...secrets(), [decl.purpose]: e.currentTarget.value })}
                      >
                        <option value="" selected={!secrets()[decl.purpose]}>
                          {t("connectors.form.secret_none")}
                        </option>
                        <Show when={options().tagged.length > 0}>
                          <optgroup label={t("connectors.form.secret_tagged", { purpose: decl.purpose })}>
                            <For each={options().tagged}>
                              {(s) => (
                                <option value={s.id} selected={secrets()[decl.purpose] === s.id}>
                                  {s.name}
                                </option>
                              )}
                            </For>
                          </optgroup>
                        </Show>
                        <Show when={options().other.length > 0}>
                          <optgroup label={t("connectors.form.secret_other")}>
                            <For each={options().other}>
                              {(s) => (
                                <option value={s.id} selected={secrets()[decl.purpose] === s.id}>
                                  {s.name}
                                </option>
                              )}
                            </For>
                          </optgroup>
                        </Show>
                        {/* A referenced secret this account cannot list stays selectable as it is. */}
                        <Show when={secretList() && secrets()[decl.purpose] && !(secretList() ?? []).some((s) => s.id === secrets()[decl.purpose])}>
                          <option value={secrets()[decl.purpose]} selected>
                            {t("connectors.form.secret_unlisted")}
                          </option>
                        </Show>
                      </select>
                    )}
                  </Field>
                );
              }}
            </For>
          </fieldset>
        </Show>

        <FieldRow>
          <Field
            name="poll_interval"
            label={t("connectors.form.poll")}
            help={t("connectors.form.default_secs", { secs: defaults()?.poll_interval_secs ?? POLL.fallback })}
            error={shown(pollCheck().error, "poll_interval_secs")}
          >
            {(c) => (
              <input
                {...c}
                class="input num"
                type="number"
                min={POLL.min}
                max={POLL.max}
                step="1"
                placeholder={String(defaults()?.poll_interval_secs ?? POLL.fallback)}
                value={poll()}
                onInput={(e) => setPoll(e.currentTarget.value)}
              />
            )}
          </Field>
          <Field
            name="call_timeout"
            label={t("connectors.form.timeout")}
            help={t("connectors.form.default_secs", { secs: defaults()?.call_timeout_secs ?? TIMEOUT.fallback })}
            error={shown(timeoutCheck().error, "call_timeout_secs")}
          >
            {(c) => (
              <input
                {...c}
                class="input num"
                type="number"
                min={TIMEOUT.min}
                max={TIMEOUT.max}
                step="1"
                placeholder={String(defaults()?.call_timeout_secs ?? TIMEOUT.fallback)}
                value={timeout()}
                onInput={(e) => setTimeoutText(e.currentTarget.value)}
              />
            )}
          </Field>
        </FieldRow>

        <fieldset class="connector-fieldset" data-testid="connector-guardrails">
          <legend>{t("connectors.form.guardrails")}</legend>
          <label class="check-row">
            <input
              type="checkbox"
              class="cb"
              checked={writes()}
              disabled={!writable() || busy()}
              data-testid="field-writes_enabled"
              onChange={(e) => setWrites(e.currentTarget.checked)}
            />
            <span>
              {t("connectors.form.writes")}
              <small class="help">{writable() ? t("connectors.form.writes_help") : t("connectors.form.writes_read_only")}</small>
            </span>
          </label>
          <Show when={writes()}>
            <Notice kind="warn" testid="connector-writes-warning">
              {t("connectors.form.writes_warning")}
            </Notice>
          </Show>
          <Show when={!editing()}>
            <label class="check-row">
              <input type="checkbox" class="cb" checked={enabled()} data-testid="field-enabled" onChange={(e) => setEnabled(e.currentTarget.checked)} />
              <span>{t("connectors.form.enabled")}</span>
            </label>
          </Show>
        </fieldset>

        <Show when={(manifest()?.network ?? []).length > 0}>
          <section class="connector-targets" aria-labelledby="cf-targets">
            <h3 id="cf-targets">{t("connectors.form.targets")}</h3>
            <ul>
              <For each={manifest()?.network ?? []}>
                {(n) => (
                  <li>
                    <Icon name="globe" size="sm" />{" "}
                    <span class="mono">
                      {n.host ?? (n.setting ? String(settings()[n.setting.replace(/^\//, "")] ?? n.setting) : "")}
                      {(n.ports?.length ?? 0) > 0 ? ` (${(n.ports ?? []).join(", ")})` : ""}
                    </span>{" "}
                    <span class="muted">{n.description}</span>
                  </li>
                )}
              </For>
            </ul>
          </section>
        </Show>

        <Show when={isApiError(error(), "connect.instance.conflict")}>
          <Notice kind="warn">{t("connectors.form.stale")}</Notice>
        </Show>
        <Show when={!isApiError(error(), "connect.instance.conflict")}>
          <ErrorNotice error={generalError()} />
        </Show>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" disabled={busy() || !manifest()} data-testid="form-submit">
            {editing() ? t("connectors.form.save") : t("connectors.form.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
