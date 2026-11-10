// The editors of the toggle dialog, one for each shape of value. An editor starts from the
// current value, reports its draft through `onDraft` (undefined while the form is invalid)
// and says what is wrong next to the field.
import { createEffect, createMemo, createSignal, For, Show, untrack } from "solid-js";
import type { BreachMode, LockoutMode, MfaRequirement, PasswordPolicy, SessionLifetime } from "../api/types";
import { Switch as SwitchControl } from "../components/Switch";
import { formatDuration, t } from "../i18n";
import { FieldHelp, SelectField } from "./fields";
import {
  AUDIT_EXPORT,
  AUDIT_EXPORT_DEFAULT,
  LOCKOUT_MODES,
  lockoutValue,
  REVEAL_DEFAULT,
  REVEAL_STEP_UP,
  UPDATES_DEFAULT,
  UPDATES_INSTALL,
  type AuditExport,
  type LockoutValue,
  type RevealPolicy,
  type RevealStepUp,
  type UpdatesInstall,
  type UpdatesPolicy,
} from "./toggles";
import { customPolicy, DURATION_UNITS, lockPolicyOf, splitDuration, toDays, toSeconds, type DurationUnit } from "./toggleEdit";

export interface EditorProps<T> {
  initial: T;
  /** The value to save, or undefined while the form has a mistake in it. */
  onDraft: (value: T | undefined) => void;
}

// ---------------------------------------------------------------------------------
// TGL-01: password policy preset

type Preset = PasswordPolicy["preset"];

export function PolicyEditor(props: EditorProps<PasswordPolicy>) {
  const init = untrack(() => props.initial);
  const [preset, setPreset] = createSignal<Preset>(init.preset);
  const [min, setMin] = createSignal(init.preset === "custom" ? String(init.min_length) : "12");
  const [max, setMax] = createSignal(init.preset === "custom" && init.max_length ? String(init.max_length) : "");
  const [pattern, setPattern] = createSignal(init.preset === "custom" ? (init.pattern ?? "") : "");

  const custom = createMemo(() => customPolicy({ min: min(), max: max(), pattern: pattern() }));
  createEffect(() => {
    const p = preset();
    props.onDraft(p === "custom" ? custom().policy : { preset: p });
  });

  return (
    <>
      <SelectField
        id="tg-preset"
        testid="field-password_policy"
        label={t("settings.security.policy.preset")}
        value={preset()}
        onChange={setPreset}
        options={[
          { value: "pin", label: t("toggles.password_policy.pin") },
          { value: "standard", label: t("toggles.password_policy.standard") },
          { value: "hardened", label: t("toggles.password_policy.hardened") },
          { value: "custom", label: t("settings.security.policy.custom") },
        ]}
      />
      <Show when={preset() === "custom"}>
        <div class="field-pair">
          <div class="field">
            <label for="tg-min">{t("settings.security.policy.min")}</label>
            <input
              id="tg-min"
              class="input num"
              inputmode="numeric"
              autocomplete="off"
              value={min()}
              aria-invalid={custom().errors.min ? "true" : undefined}
              aria-describedby="tg-min-help"
              onInput={(e) => setMin(e.currentTarget.value)}
            />
            <FieldHelp
              id="tg-min-help"
              help={t("settings.security.policy.min_help")}
              error={custom().errors.min ? t("settings.security.policy.min_error") : undefined}
            />
          </div>
          <div class="field">
            <label for="tg-max">{t("settings.security.policy.max")}</label>
            <input
              id="tg-max"
              class="input num"
              inputmode="numeric"
              autocomplete="off"
              value={max()}
              aria-invalid={custom().errors.max ? "true" : undefined}
              aria-describedby="tg-max-help"
              onInput={(e) => setMax(e.currentTarget.value)}
            />
            <FieldHelp
              id="tg-max-help"
              help={t("settings.security.policy.max_help")}
              error={custom().errors.max ? t("settings.security.policy.max_error") : undefined}
            />
          </div>
        </div>
        <div class="field">
          <label for="tg-pattern">{t("settings.security.policy.pattern")}</label>
          <input
            id="tg-pattern"
            class="input mono"
            autocomplete="off"
            autocapitalize="off"
            spellcheck={false}
            value={pattern()}
            aria-invalid={custom().errors.pattern ? "true" : undefined}
            aria-describedby="tg-pattern-help"
            onInput={(e) => setPattern(e.currentTarget.value)}
          />
          <FieldHelp
            id="tg-pattern-help"
            help={t("settings.security.policy.pattern_help")}
            error={custom().errors.pattern ? t("settings.security.policy.pattern_error") : undefined}
          />
        </div>
      </Show>
    </>
  );
}

// ---------------------------------------------------------------------------------
// TGL-02, TGL-06, TGL-07: one choice of a few

export function MfaEditor(props: EditorProps<MfaRequirement>) {
  const [value, setValue] = createSignal<MfaRequirement>(untrack(() => props.initial));
  createEffect(() => props.onDraft(value()));
  const options: readonly MfaRequirement[] = ["optional", "administrators", "everyone"];
  return (
    <SelectField
      id="tg-mfa"
      testid="field-mfa"
      label={t("toggles.mfa.name")}
      value={value()}
      onChange={setValue}
      options={options.map((v) => ({ value: v, label: t(`toggles.mfa.${v}`) }))}
    />
  );
}

export function BreachEditor(props: EditorProps<BreachMode>) {
  const [value, setValue] = createSignal<BreachMode>(untrack(() => props.initial));
  createEffect(() => props.onDraft(value()));
  const options: readonly BreachMode[] = ["off", "online", "offline", "offline_preferred"];
  return (
    <SelectField
      id="tg-breach"
      testid="field-breach_check"
      label={t("toggles.breach_check.name")}
      value={value()}
      onChange={setValue}
      options={options.map((v) => ({ value: v, label: t(`toggles.breach_check.${v}`) }))}
    />
  );
}

/** The profile's value next to a field, for the help line under it. */
function withProfile(help: string, value: string): string {
  return `${help} ${t("settings.security.lockout.profile_value", { value })}`;
}

export function LockoutEditor(props: EditorProps<LockoutValue> & { profileDefault?: unknown }) {
  const init = untrack(() => lockoutValue(props.initial));
  const reference = untrack(() => lockoutValue(props.profileDefault ?? props.initial));
  const lock0 = splitDuration(init.lock_secs);
  const [mode, setMode] = createSignal<LockoutMode>(init.mode);
  const [attempts, setAttempts] = createSignal(String(init.attempts));
  const [waits, setWaits] = createSignal(init.waits_secs.join(", "));
  const [lock, setLock] = createSignal(String(lock0.amount));
  const [lockUnit, setLockUnit] = createSignal<DurationUnit>(lock0.unit);
  const [account, setAccount] = createSignal(String(init.account_max_delay_secs));
  const [passkey, setPasskey] = createSignal(init.passkey_holds_lock);

  const result = createMemo(() =>
    lockPolicyOf({ attempts: attempts(), waits: waits(), lock: lock(), lockUnit: lockUnit(), account: account() }, passkey()),
  );
  createEffect(() => {
    const policy = result().policy;
    props.onDraft(policy ? { mode: mode(), ...policy } : undefined);
  });

  const locks = () => mode() === "delay_then_temporary_lock" || mode() === "lock_until_unlock";
  const resetToProfile = () => {
    const lock1 = splitDuration(reference.lock_secs);
    setMode(reference.mode);
    setAttempts(String(reference.attempts));
    setWaits(reference.waits_secs.join(", "));
    setLock(String(lock1.amount));
    setLockUnit(lock1.unit);
    setAccount(String(reference.account_max_delay_secs));
    setPasskey(reference.passkey_holds_lock);
  };

  return (
    <>
      <SelectField
        id="tg-lockout"
        testid="field-lockout"
        label={t("toggles.lockout.name")}
        value={mode()}
        onChange={setMode}
        options={LOCKOUT_MODES.map((v) => ({ value: v, label: t(`toggles.lockout.${v}`) }))}
        help={withProfile(t(`settings.security.lockout.mode_help.${mode()}`), t(`toggles.lockout.${reference.mode}`))}
      />
      <Show when={mode() !== "off"}>
        <p class="muted" id="tg-lockout-explain">
          {t("settings.security.lockout.explain")}
        </p>
        <div class="field">
          <label for="tg-lock-attempts">{t("settings.security.lockout.attempts")}</label>
          <input
            id="tg-lock-attempts"
            data-testid="field-lock_attempts"
            class="input num"
            inputmode="numeric"
            autocomplete="off"
            value={attempts()}
            aria-invalid={result().errors.attempts ? "true" : undefined}
            aria-describedby="tg-lock-attempts-help"
            onInput={(e) => setAttempts(e.currentTarget.value)}
          />
          <FieldHelp
            id="tg-lock-attempts-help"
            help={withProfile(t("settings.security.lockout.attempts_help"), String(reference.attempts))}
            error={result().errors.attempts ? t("settings.security.lockout.attempts_error") : undefined}
          />
        </div>
        <div class="field">
          <label for="tg-lock-waits">{t("settings.security.lockout.waits")}</label>
          <input
            id="tg-lock-waits"
            data-testid="field-lock_waits"
            class="input"
            autocomplete="off"
            spellcheck={false}
            value={waits()}
            aria-invalid={result().errors.waits ? "true" : undefined}
            aria-describedby="tg-lock-waits-help"
            onInput={(e) => setWaits(e.currentTarget.value)}
          />
          <FieldHelp
            id="tg-lock-waits-help"
            help={withProfile(t("settings.security.lockout.waits_help"), reference.waits_secs.join(", "))}
            error={result().errors.waits ? t("settings.security.lockout.waits_error") : undefined}
          />
        </div>
        <Show when={locks()}>
          <DurationField
            id="tg-lock-secs"
            label={t("settings.security.lockout.lock")}
            amount={lock()}
            unit={lockUnit()}
            onAmount={setLock}
            onUnit={setLockUnit}
            error={result().errors.lock ? t("settings.security.lockout.lock_error") : undefined}
            help={withProfile(t("settings.security.lockout.lock_help"), formatDuration(reference.lock_secs))}
          />
        </Show>
        <div class="field">
          <label for="tg-lock-account">{t("settings.security.lockout.account")}</label>
          <input
            id="tg-lock-account"
            data-testid="field-lock_account"
            class="input num"
            inputmode="numeric"
            autocomplete="off"
            value={account()}
            aria-invalid={result().errors.account ? "true" : undefined}
            aria-describedby="tg-lock-account-help"
            onInput={(e) => setAccount(e.currentTarget.value)}
          />
          <FieldHelp
            id="tg-lock-account-help"
            help={withProfile(t("settings.security.lockout.account_help"), String(reference.account_max_delay_secs))}
            error={result().errors.account ? t("settings.security.lockout.account_error") : undefined}
          />
        </div>
        <Show when={locks()}>
          <div class="field">
            {/* The markup of components/Switch, which has no way to carry a test id on its input. */}
            <label class="pref switch">
              <span>{t("settings.security.lockout.passkey")}</span>
              <input
                id="tg-lock-passkey"
                type="checkbox"
                role="switch"
                data-testid="field-passkey_holds_lock"
                checked={passkey()}
                onChange={(e) => setPasskey(e.currentTarget.checked)}
              />
              <small>
                {withProfile(
                  t("settings.security.lockout.passkey_hint"),
                  reference.passkey_holds_lock ? t("common.yes") : t("common.no"),
                )}
              </small>
            </label>
          </div>
        </Show>
      </Show>
      <div class="field">
        <button type="button" class="btn sm ghost" data-testid="lockout-reset" onClick={resetToProfile}>
          {t("settings.security.lockout.reset")}
        </button>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------------
// TGL-03: passkey for administrators

export function PasskeyEditor(props: EditorProps<boolean>) {
  const [value, setValue] = createSignal(untrack(() => props.initial));
  createEffect(() => props.onDraft(value()));
  return (
    <div class="field">
      <SwitchControl
        id="tg-passkey"
        checked={value()}
        onChange={setValue}
        label={t("toggles.passkey_for_admins.name")}
        hint={t("settings.security.passkey.hint")}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------------
// TGL-04: session lifetimes

function unitLabel(unit: DurationUnit): string {
  return t(`settings.security.unit.${unit}`);
}

function DurationField(props: {
  id: string;
  label: string;
  amount: string;
  unit: DurationUnit;
  onAmount: (value: string) => void;
  onUnit: (value: DurationUnit) => void;
  error?: string | undefined;
  help?: string;
}) {
  const helpId = () => `${props.id}-help`;
  return (
    <div class="field">
      <label for={props.id}>{props.label}</label>
      <div class="form-row">
        <input
          id={props.id}
          class="input num duration"
          inputmode="numeric"
          autocomplete="off"
          value={props.amount}
          aria-invalid={props.error ? "true" : undefined}
          aria-describedby={helpId()}
          onInput={(e) => props.onAmount(e.currentTarget.value)}
        />
        <select
          class="select"
          aria-label={t("settings.security.unit.label", { field: props.label })}
          onChange={(e) => props.onUnit(e.currentTarget.value as DurationUnit)}
        >
          <For each={DURATION_UNITS}>
            {(u) => (
              <option value={u} selected={u === props.unit}>
                {unitLabel(u)}
              </option>
            )}
          </For>
        </select>
      </div>
      <FieldHelp id={helpId()} help={props.help} error={props.error} />
    </div>
  );
}

export function SessionEditor(props: EditorProps<SessionLifetime>) {
  const init = untrack(() => props.initial);
  const a0 = splitDuration(init.absolute_secs);
  const i0 = splitDuration(init.idle_secs);
  const [absAmount, setAbsAmount] = createSignal(String(a0.amount));
  const [absUnit, setAbsUnit] = createSignal<DurationUnit>(a0.unit);
  const [idleAmount, setIdleAmount] = createSignal(String(i0.amount));
  const [idleUnit, setIdleUnit] = createSignal<DurationUnit>(i0.unit);

  const absolute = createMemo(() => toSeconds(absAmount(), absUnit()));
  const idle = createMemo(() => toSeconds(idleAmount(), idleUnit()));
  const order = () => {
    const a = absolute();
    const i = idle();
    return a !== undefined && i !== undefined && i > a;
  };

  createEffect(() => {
    const a = absolute();
    const i = idle();
    props.onDraft(a !== undefined && i !== undefined && i <= a ? { absolute_secs: a, idle_secs: i } : undefined);
  });

  return (
    <>
      <DurationField
        id="tg-abs"
        label={t("settings.security.session.absolute")}
        amount={absAmount()}
        unit={absUnit()}
        onAmount={setAbsAmount}
        onUnit={setAbsUnit}
        error={absolute() === undefined ? t("settings.security.session.number_error") : undefined}
        help={t("settings.security.session.absolute_help")}
      />
      <DurationField
        id="tg-idle"
        label={t("settings.security.session.idle")}
        amount={idleAmount()}
        unit={idleUnit()}
        onAmount={setIdleAmount}
        onUnit={setIdleUnit}
        error={
          idle() === undefined
            ? t("settings.security.session.number_error")
            : order()
              ? t("settings.security.session.order_error")
              : undefined
        }
        help={t("settings.security.session.idle_help")}
      />
    </>
  );
}

// ---------------------------------------------------------------------------------
// TGL-05: API token maximum

export function TokenEditor(props: EditorProps<number | null>) {
  const init = untrack(() => props.initial);
  const [mode, setMode] = createSignal<"days" | "unlimited">(init === null || init === undefined ? "unlimited" : "days");
  const [days, setDays] = createSignal(init === null || init === undefined ? "90" : String(init));
  const parsed = createMemo(() => toDays(days()));

  createEffect(() => {
    if (mode() === "unlimited") props.onDraft(null);
    else props.onDraft(parsed());
  });

  return (
    <>
      <div class="field">
        <span class="label" id="tg-token-label">
          {t("toggles.token_max_days.name")}
        </span>
        <div class="choices" role="radiogroup" aria-labelledby="tg-token-label">
          <label class="choice">
            <input type="radio" name="tg-token" checked={mode() === "days"} onChange={() => setMode("days")} />
            <span>{t("settings.security.token.limited")}</span>
          </label>
          <label class="choice">
            <input type="radio" name="tg-token" checked={mode() === "unlimited"} onChange={() => setMode("unlimited")} />
            <span>
              {t("toggles.token_max_days.unlimited")}
              <small class="muted">{t("settings.security.token.unlimited_hint")}</small>
            </span>
          </label>
        </div>
      </div>
      <Show when={mode() === "days"}>
        <div class="field">
          <label for="tg-days">{t("settings.security.token.days")}</label>
          <input
            id="tg-days"
            class="input num duration"
            inputmode="numeric"
            autocomplete="off"
            value={days()}
            aria-invalid={parsed() === undefined ? "true" : undefined}
            aria-describedby="tg-days-help"
            onInput={(e) => setDays(e.currentTarget.value)}
          />
          <FieldHelp
            id="tg-days-help"
            help={t("settings.security.token.days_help")}
            error={parsed() === undefined ? t("settings.security.token.days_error") : undefined}
          />
        </div>
      </Show>
    </>
  );
}

// ---------------------------------------------------------------------------------
// TGL-21: whether the audit log leaves the installation

export function AuditExportEditor(props: EditorProps<AuditExport>) {
  const [value, setValue] = createSignal<AuditExport>(untrack(() => props.initial) ?? AUDIT_EXPORT_DEFAULT.home);
  createEffect(() => props.onDraft(value()));

  return (
    <div class="field">
      <span class="label" id="tg-audit-export-label">
        {t("settings.security.audit_export.mode")}
      </span>
      <div class="choices" role="radiogroup" aria-labelledby="tg-audit-export-label">
        <For each={AUDIT_EXPORT}>
          {(mode) => (
            <label class="choice">
              <input
                type="radio"
                name="tg-audit-export"
                value={mode}
                data-testid={`field-audit_export-${mode}`}
                checked={value() === mode}
                onChange={() => setValue(mode)}
              />
              <span>
                {t(`settings.security.audit_export.${mode}`)}
                <small class="muted">{t(`settings.security.audit_export.${mode}_help`)}</small>
              </span>
            </label>
          )}
        </For>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------
// TGL-23: the update check and who may install

export function UpdatesEditor(props: EditorProps<UpdatesPolicy>) {
  const init = untrack(() => props.initial) ?? UPDATES_DEFAULT.home;
  const [check, setCheck] = createSignal(init.check);
  const [install, setInstall] = createSignal<UpdatesInstall>(init.install);
  createEffect(() => props.onDraft({ check: check(), install: install() }));

  return (
    <>
      <div class="field">
        <SwitchControl
          id="tg-updates-check"
          checked={check()}
          onChange={setCheck}
          label={t("settings.security.updates.check")}
          hint={t("settings.security.updates.check_hint")}
        />
      </div>
      <div class="field">
        <span class="label" id="tg-updates-install-label">
          {t("settings.security.updates.install")}
        </span>
        <div class="choices" role="radiogroup" aria-labelledby="tg-updates-install-label">
          <For each={UPDATES_INSTALL}>
            {(mode) => (
              <label class="choice">
                <input
                  type="radio"
                  name="tg-updates-install"
                  value={mode}
                  data-testid="updates-install-mode"
                  data-key={mode}
                  checked={install() === mode}
                  onChange={() => setInstall(mode)}
                />
                <span>
                  {t(`settings.security.updates.install_${mode}`)}
                  <small class="muted">{t(`settings.security.updates.install_${mode}_help`)}</small>
                </span>
              </label>
            )}
          </For>
        </div>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------------
// TGL-24: what revealing an operator secret takes

export function RevealEditor(props: EditorProps<RevealPolicy>) {
  const init = untrack(() => props.initial) ?? REVEAL_DEFAULT.home;
  const [stepUp, setStepUp] = createSignal<RevealStepUp>(init.step_up);
  const [bound, setBound] = createSignal(init.bound_host_only);
  createEffect(() => props.onDraft({ step_up: stepUp(), bound_host_only: bound() }));

  return (
    <>
      <div class="field">
        <span class="label" id="tg-secret-reveal-step-up-label">
          {t("settings.security.secret_reveal.step_up")}
        </span>
        <div class="choices" role="radiogroup" aria-labelledby="tg-secret-reveal-step-up-label">
          <For each={REVEAL_STEP_UP}>
            {(mode) => (
              <label class="choice">
                <input
                  type="radio"
                  name="tg-secret-reveal-step-up"
                  value={mode}
                  data-testid={`field-step_up-${mode}`}
                  checked={stepUp() === mode}
                  onChange={() => setStepUp(mode)}
                />
                <span>
                  {t(`settings.security.secret_reveal.step_up_${mode}`)}
                  <small class="muted">{t(`settings.security.secret_reveal.step_up_${mode}_help`)}</small>
                </span>
              </label>
            )}
          </For>
        </div>
      </div>
      <div class="field">
        {/* The markup of components/Switch, which has no way to carry a test id on its input. */}
        <label class="pref switch">
          <span>{t("settings.security.secret_reveal.bound_host")}</span>
          <input
            id="tg-secret-reveal-bound"
            type="checkbox"
            role="switch"
            data-testid="field-bound_host_only"
            checked={bound()}
            onChange={(e) => setBound(e.currentTarget.checked)}
          />
          <small>{t("settings.security.secret_reveal.bound_host_hint")}</small>
        </label>
      </div>
      <p class="muted" id="tg-secret-reveal-pin-rule">
        {t("settings.security.secret_reveal.pin_rule")}
      </p>
    </>
  );
}
