import { createEffect, createSignal, For, on, onCleanup, Show } from "solid-js";
import { api } from "../../api/client";
import { fieldErrorMessage, isApiError } from "../../api/problem";
import type { PasswordCheckResult, PasswordPolicy, PolicyViolation } from "../../api/types";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t, tDynamic } from "../../i18n";
import { session } from "../session";
import { refreshSession } from "./shared";

type ItemState = "idle" | "pending" | "ok" | "bad" | "off";

interface CheckItem {
  id: string;
  text: string;
  state: ItemState;
}

/** Violations that belong to the preset's own rule: length, digits only, pattern. */
const RULE_KINDS: ReadonlySet<PolicyViolation["kind"]> = new Set([
  "too_short",
  "too_long",
  "pin_digits_only",
  "pattern_mismatch",
  "invalid_characters",
]);

/** Every violation the checklist has its own line for; others get a line of their own. */
const KNOWN_KINDS: ReadonlySet<PolicyViolation["kind"]> = new Set([...RULE_KINDS, "trivial", "context_specific", "breached"]);

const STATE_WORD = {
  idle: "account.password.state.idle",
  pending: "account.password.state.pending",
  ok: "account.password.state.ok",
  bad: "account.password.state.bad",
  off: "account.password.state.off",
} as const;

/** The translated sentence of one violation (the messages under errors.auth.password). */
function violationText(v: PolicyViolation): string | undefined {
  const args: Record<string, unknown> =
    v.kind === "too_short"
      ? { min: v.min }
      : v.kind === "too_long"
        ? { max: v.max }
        : v.kind === "context_specific"
          ? { context: v.context }
          : {};
  return tDynamic(`errors.auth.password.${v.kind}`, args);
}

function minLength(policy: PasswordPolicy): number {
  switch (policy.preset) {
    case "pin":
      return 4;
    case "standard":
      return 12;
    case "hardened":
      return 16;
    case "custom":
      return policy.min_length;
  }
}

function ruleText(policy: PasswordPolicy | undefined): string {
  if (!policy) return t("account.password.rule.profile", { profile: profileName() });
  const min = minLength(policy);
  switch (policy.preset) {
    case "pin":
      return t("account.password.rule.pin", { min });
    case "hardened":
      return t("account.password.rule.passphrase", { min });
    case "custom":
      return policy.pattern ? t("account.password.rule.pattern", { min }) : t("account.password.rule.length", { min });
    case "standard":
      return t("account.password.rule.length", { min });
  }
}

function profileName(): string {
  return t(`profile.${session()?.profile ?? "home"}.name`);
}

/** Change of the password or PIN, with the live checklist of the policy (IAM-03, IAM-04). */
export function PasswordSection() {
  const [current, setCurrent] = createSignal("");
  const [next, setNext] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [show, setShow] = createSignal(false);
  const [result, setResult] = createSignal<{ password: string; value: PasswordCheckResult } | null>(null);
  const [policy, setPolicy] = createSignal<PasswordPolicy | undefined>(undefined);
  const [checking, setChecking] = createSignal(false);
  const [checkFailed, setCheckFailed] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  let currentInput!: HTMLInputElement;
  let nextInput!: HTMLInputElement;
  let confirmInput!: HTMLInputElement;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let controller: AbortController | undefined;
  let sequence = 0;

  const runCheck = async (password: string, mine: number) => {
    controller?.abort();
    controller = new AbortController();
    try {
      const value = await api.post("/api/v1/auth/password/check", { body: { password }, signal: controller.signal });
      if (mine !== sequence) return;
      setPolicy(value.policy);
      if (password !== "") setResult({ password, value });
      setCheckFailed(false);
    } catch (err) {
      if (mine !== sequence || (err instanceof DOMException && err.name === "AbortError")) return;
      // The check is feedback only; the server decides when the password is submitted.
      if (password !== "") setCheckFailed(true);
    } finally {
      if (mine === sequence) setChecking(false);
    }
  };

  // The policy is known before the first keystroke: ask with an empty password once.
  void runCheck("", sequence);

  // Live feedback while typing, debounced by 300 ms.
  createEffect(
    on(
      next,
      (password) => {
        clearTimeout(timer);
        sequence += 1;
        const mine = sequence;
        setCheckFailed(false);
        if (password === "") {
          controller?.abort();
          setResult(null);
          setChecking(false);
          return;
        }
        setChecking(true);
        timer = setTimeout(() => void runCheck(password, mine), 300);
      },
      { defer: true },
    ),
  );
  onCleanup(() => {
    clearTimeout(timer);
    controller?.abort();
  });

  const fresh = () => {
    const r = result();
    return r && r.password === next() ? r.value : undefined;
  };

  const items = (): CheckItem[] => {
    const res = fresh();
    const base = (bad: boolean | undefined): ItemState =>
      next() === "" ? "idle" : !fresh() ? (checkFailed() ? "idle" : "pending") : bad ? "bad" : "ok";
    const violations = res?.violations ?? [];
    const hasRule = violations.some((v) => RULE_KINDS.has(v.kind));
    const out: CheckItem[] = [
      { id: "rule", text: ruleText(res?.policy ?? policy()), state: base(hasRule) },
      { id: "trivial", text: t("account.password.check.trivial"), state: base(violations.some((v) => v.kind === "trivial")) },
      {
        id: "context",
        text: t("account.password.check.context"),
        state: base(violations.some((v) => v.kind === "context_specific")),
      },
    ];
    const breach = res?.breach_check;
    if (breach === "off") {
      out.push({ id: "breach", text: t("account.password.check.breach_off"), state: "off" });
    } else if (breach === "unavailable") {
      out.push({ id: "breach", text: t("account.password.check.breach_unavailable"), state: "off" });
    } else if (breach === "breached") {
      out.push({ id: "breach", text: t("errors.auth.password.breached"), state: "bad" });
    } else {
      out.push({ id: "breach", text: t("account.password.check.breach_clean"), state: base(false) });
    }
    for (const v of violations.filter((x) => !KNOWN_KINDS.has(x.kind))) {
      out.push({ id: `other-${v.kind}`, text: violationText(v) ?? t("errors.auth.password.policy"), state: "bad" });
    }
    return out;
  };

  const mismatch = () => confirm() !== "" && confirm() !== next();
  const unacceptable = () => fresh()?.acceptable === false;

  const submit = async (e: Event) => {
    e.preventDefault();
    if (!next()) {
      nextInput.focus();
      return;
    }
    if (next() !== confirm()) {
      confirmInput.focus();
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const res = await api.post("/api/v1/auth/password", {
        body: { new_password: next(), ...(current() ? { current_password: current() } : {}) },
      });
      setCurrent("");
      setNext("");
      setConfirm("");
      setShow(false);
      toast({
        title: t("account.password.changed"),
        body: t("account.password.changed_others", { count: res.sessions_revoked }),
        kind: "ok",
      });
      void refreshSession();
    } catch (err) {
      setError(err);
      if (isApiError(err, "auth.password.incorrect")) currentInput.focus();
    } finally {
      setBusy(false);
    }
  };

  const wrongCurrent = () => isApiError(error(), "auth.password.incorrect");
  const policyErrors = () => {
    const err = error();
    return isApiError(err, "auth.password.policy") ? err.fieldErrors.map(fieldErrorMessage) : [];
  };

  return (
    <section class="page-section" aria-labelledby="acct-password">
      <h2 id="acct-password">{t("account.password.title")}</h2>
      <Show
        when={!session()?.flags.break_glass}
        fallback={<Notice kind="info">{t("errors.auth.break_glass.hardware_key_only")}</Notice>}
      >
        <p>{t("account.password.lede")}</p>
        <form class="form" onSubmit={(e) => void submit(e)} novalidate>
          <div class="field">
            <label for="acct-pw-current">{t("account.password.current")}</label>
            <input
              ref={currentInput}
              id="acct-pw-current"
              class="input"
              type="password"
              autocomplete="current-password"
              aria-describedby="acct-pw-current-help"
              aria-invalid={wrongCurrent() ? "true" : undefined}
              value={current()}
              onInput={(e) => setCurrent(e.currentTarget.value)}
            />
            <span class={wrongCurrent() ? "help bad" : "help"} id="acct-pw-current-help">
              {wrongCurrent() ? t("errors.auth.password.incorrect") : t("account.password.current_help")}
            </span>
          </div>

          <div class="field">
            <label for="acct-pw-new">{t("account.password.new")}</label>
            <div class="acct-pwrow">
              <input
                ref={nextInput}
                id="acct-pw-new"
                class="input"
                type={show() ? "text" : "password"}
                autocomplete="new-password"
                autocapitalize="off"
                spellcheck={false}
                aria-describedby="acct-pw-checks"
                value={next()}
                onInput={(e) => setNext(e.currentTarget.value)}
              />
              <button
                type="button"
                class="icon-btn"
                aria-pressed={show()}
                aria-label={t("account.password.show")}
                title={t("account.password.show")}
                onClick={() => setShow(!show())}
              >
                <Icon name="eye" />
              </button>
            </div>
            <ul class="pw-checks" id="acct-pw-checks" aria-live="polite" aria-label={t("account.password.checks")}>
              <For each={items()}>
                {(item) => (
                  <li classList={{ [item.state]: true }}>
                    <span class="pw-ck" aria-hidden="true">
                      <Show when={item.state === "ok"}>
                        <Icon name="check" size="xs" />
                      </Show>
                      <Show when={item.state === "bad"}>
                        <Icon name="x" size="xs" />
                      </Show>
                      <Show when={item.state === "off"}>
                        <Icon name="alert" size="xs" />
                      </Show>
                    </span>
                    <span>
                      <span class="sr-only">{t(STATE_WORD[item.state])}: </span>
                      {item.text}
                    </span>
                  </li>
                )}
              </For>
            </ul>
          </div>

          <div class="field">
            <label for="acct-pw-confirm">{t("account.password.confirm")}</label>
            <input
              ref={confirmInput}
              id="acct-pw-confirm"
              class="input"
              type={show() ? "text" : "password"}
              autocomplete="new-password"
              autocapitalize="off"
              spellcheck={false}
              aria-invalid={mismatch() ? "true" : undefined}
              aria-describedby={mismatch() ? "acct-pw-confirm-help" : undefined}
              value={confirm()}
              onInput={(e) => setConfirm(e.currentTarget.value)}
            />
            <Show when={mismatch()}>
              <span class="help bad" id="acct-pw-confirm-help">
                {t("account.password.mismatch")}
              </span>
            </Show>
          </div>

          <Show when={error() && !wrongCurrent()}>
            <div>
              <ErrorNotice error={error()} />
              <Show when={policyErrors().length}>
                <ul class="acct-errlist">
                  <For each={policyErrors()}>{(message) => <li>{message}</li>}</For>
                </ul>
              </Show>
            </div>
          </Show>

          <div class="form-row">
            <button
              type="submit"
              class="btn primary"
              disabled={busy() || !next() || !confirm() || mismatch() || unacceptable() || checking()}
            >
              {t("account.password.submit")}
            </button>
          </div>
        </form>
      </Show>
    </section>
  );
}
