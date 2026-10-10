// The reveal of an operator secret (IAM-16, API-11, TGL-24): one click asks the server for
// the value, which is copied to the clipboard and cleared again after the time the server
// names (30 s), with a visible countdown and the audit line of the reveal. The value is not
// rendered unless the person presses "Show value", and the dialog drops it when it closes.
//
// When the reveal policy asks for a fresh or stronger sign-in (`auth.step_up_required`), the
// dialog signs the person in again in place, with the password (and a second factor when the
// server asks) or a passkey, ends the previous session and reveals again.
import { createSignal, Match, onCleanup, onMount, Show, Switch } from "solid-js";
import { api } from "../api/client";
import { errorMessage, isApiError } from "../api/problem";
import type { SecondFactorMethod } from "../api/types";
import { acceptLogin, session } from "../auth/session";
import { CeremonyError, signInWithPasskey, webauthnAvailable } from "../auth/webauthn";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { formatDateTime, t } from "../i18n";
import { revealSecret } from "./api";
import { copyValue, scheduleClear, type ClearOutcome, type CopyOutcome } from "./clipboard";
import "./secrets.css";

export interface RevealTarget {
  /** The secret. */
  id: string;
  /** Its name, for the title. */
  name: string;
  /** The host the person looks at; the secret must be bound to it. */
  host?: string | undefined;
}

type Phase = "working" | "stepup" | "done" | "failed";

interface Outcome {
  username: string | null;
  revealedAt: string;
  clearAfter: number;
  copy: CopyOutcome;
}

export function RevealDialog(props: { target: RevealTarget; reason?: string; onClose: () => void }) {
  const [phase, setPhase] = createSignal<Phase>("working");
  const [required, setRequired] = createSignal("fresh");
  const [error, setError] = createSignal<unknown>(null);
  const [outcome, setOutcome] = createSignal<Outcome | null>(null);
  // The value lives only while the dialog is open; it is rendered only after "Show value".
  const [value, setValue] = createSignal<string | null>(null);
  const [shown, setShown] = createSignal(false);
  const [remaining, setRemaining] = createSignal(0);
  const [cleared, setCleared] = createSignal<ClearOutcome | null>(null);
  let countdown: ReturnType<typeof setInterval> | undefined;
  let open = true;

  const startCountdown = (seconds: number) => {
    clearInterval(countdown);
    setRemaining(seconds);
    countdown = setInterval(() => {
      setRemaining((s) => {
        if (s <= 1) {
          clearInterval(countdown);
          return 0;
        }
        return s - 1;
      });
    }, 1000);
  };

  const copied = (text: string, seconds: number) => {
    setCleared(null);
    scheduleClear(text, seconds, (result) => {
      if (!open) return;
      setCleared(result);
      // Once the clipboard is clear, the dialog forgets the value too.
      setValue(null);
      setShown(false);
    });
    startCountdown(seconds);
  };

  const reveal = async () => {
    setPhase("working");
    setError(null);
    try {
      const answer = await revealSecret(props.target.id, {
        ...(props.target.host ? { host: props.target.host } : {}),
        ...(props.reason ? { reason: props.reason } : {}),
      });
      if (!open) return;
      const text = answer.value;
      const copy = await copyValue(text);
      if (!open) return;
      setValue(text);
      setOutcome({
        username: answer.username ?? null,
        revealedAt: answer.revealed_at,
        clearAfter: answer.clear_after_secs,
        copy,
      });
      if (copy === "copied") copied(text, answer.clear_after_secs);
      setPhase("done");
    } catch (err) {
      if (!open) return;
      if (isApiError(err, "auth.step_up_required")) {
        setRequired(err.params.required ?? "fresh");
        setPhase("stepup");
        return;
      }
      setError(err);
      setPhase("failed");
    }
  };

  /** The second click when the browser refused the first copy. */
  const copyAgain = async () => {
    const text = value();
    const o = outcome();
    if (text === null || !o) return;
    const copy = await copyValue(text);
    setOutcome({ ...o, copy });
    if (copy === "copied") copied(text, o.clearAfter);
  };

  onMount(() => void reveal());
  onCleanup(() => {
    open = false;
    clearInterval(countdown);
    setValue(null);
    setShown(false);
  });

  const who = () => session()?.user.name ?? "";

  return (
    <Dialog label={t("secrets.reveal.title", { name: props.target.name })} onClose={props.onClose} testid="dialog-reveal" class="dialog">
      <div class="dialog-form">
        <h2 class="dialog-title">
          <Icon name="key" /> {t("secrets.reveal.title", { name: props.target.name })}
        </h2>
        <div class="dialog-body">
          <Switch>
            <Match when={phase() === "working"}>
              <p class="muted" role="status" data-testid="reveal-status" data-state="working">
                {t("secrets.reveal.working")}
              </p>
            </Match>
            <Match when={phase() === "stepup"}>
              <StepUp required={required()} onDone={() => void reveal()} />
            </Match>
            <Match when={phase() === "failed"}>
              <div data-testid="reveal-status" data-state="failed">
                <ErrorNotice error={error()} />
              </div>
            </Match>
            <Match when={phase() === "done" && outcome()}>
              {(o) => (
                <div class="reveal-done" data-testid="reveal-status" data-state={cleared() ?? o().copy}>
                  <Switch>
                    <Match when={cleared() === "cleared"}>
                      <Notice kind="ok" role="status">
                        {t("secrets.reveal.cleared")}
                      </Notice>
                    </Match>
                    <Match when={cleared() === "left"}>
                      <Notice kind="info" role="status">
                        {t("secrets.reveal.left")}
                      </Notice>
                    </Match>
                    <Match when={cleared() === "failed"}>
                      <Notice kind="warn" role="status">
                        {t("secrets.reveal.clear_failed")}
                      </Notice>
                    </Match>
                    <Match when={o().copy === "copied"}>
                      <Notice kind="ok" role="status">
                        <span data-testid="reveal-countdown" data-seconds={remaining()}>
                          {t("secrets.reveal.copied", { seconds: remaining() })}
                        </span>
                      </Notice>
                    </Match>
                    <Match when={o().copy === "blocked"}>
                      <Notice kind="warn" role="status">
                        {t("secrets.reveal.copy_blocked")}
                      </Notice>
                      <p>
                        <button type="button" class="btn" data-testid="reveal-copy" onClick={() => void copyAgain()}>
                          <Icon name="copy" /> {t("secrets.reveal.copy")}
                        </button>
                      </p>
                    </Match>
                  </Switch>
                  <dl class="kv">
                    <Show when={o().username}>
                      {(name) => (
                        <>
                          <dt>{t("secrets.reveal.username")}</dt>
                          <dd class="mono" data-testid="reveal-username">
                            {name()}
                          </dd>
                        </>
                      )}
                    </Show>
                    <Show when={value() !== null}>
                      <dt>{t("secrets.reveal.value")}</dt>
                      <dd>
                        <Show when={shown()} fallback={<span class="muted">{t("secrets.reveal.hidden")}</span>}>
                          <code class="mono reveal-value" data-testid="reveal-value">
                            {value()}
                          </code>
                        </Show>{" "}
                        <button
                          type="button"
                          class="btn sm ghost"
                          data-testid="reveal-show"
                          aria-pressed={shown() ? "true" : "false"}
                          onClick={() => setShown(!shown())}
                        >
                          <Icon name="eye" size="sm" /> {shown() ? t("secrets.reveal.hide") : t("secrets.reveal.show")}
                        </button>
                      </dd>
                    </Show>
                  </dl>
                  <p class="help" data-testid="reveal-audit">
                    <Icon name="audit" size="xs" />{" "}
                    {t("secrets.reveal.audit", { user: who(), time: formatDateTime(o().revealedAt) })}
                  </p>
                </div>
              )}
            </Match>
          </Switch>
        </div>
        <div class="dialog-actions">
          <Show when={phase() === "failed"}>
            <button type="button" class="btn" data-testid="reveal-retry" onClick={() => void reveal()}>
              {t("common.action.retry")}
            </button>
          </Show>
          <button type="button" class="btn primary" data-testid="reveal-close" onClick={() => props.onClose()}>
            {t("common.action.close")}
          </button>
        </div>
      </div>
    </Dialog>
  );
}

/**
 * A fresh sign-in inside the dialog. `required` is the `required` parameter of the step-up:
 * `passkey` (a passkey or security key), `fresh` or `password` (any method stronger than a
 * PIN). The previous session ends once the new one exists.
 */
function StepUp(props: { required: string; onDone: () => void }) {
  const [password, setPassword] = createSignal("");
  const [code, setCode] = createSignal("");
  const [challenge, setChallenge] = createSignal<{ id: string; methods: SecondFactorMethod[] } | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const previous = session()?.session_id;
  const userName = () => session()?.user.name ?? "";
  const passkeyOnly = () => props.required === "passkey";
  let codeInput: HTMLInputElement | undefined;

  const describe = (err: unknown): string =>
    err instanceof CeremonyError ? t(`auth.signin.ceremony.${err.reason}`) : errorMessage(err);

  const finish = async () => {
    // The new session carries the fresh sign-in; the one it replaces ends.
    const current = session()?.session_id;
    if (previous && previous !== current) {
      try {
        await api.delete("/api/v1/auth/sessions/{id}", { path: { id: previous } });
      } catch {
        // It ends on its own; the new session works either way.
      }
    }
    props.onDone();
  };

  const run = async (step: () => Promise<boolean>) => {
    setBusy(true);
    setError(null);
    try {
      if (await step()) await finish();
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  };

  const withPassword = (e: Event) => {
    e.preventDefault();
    const ch = challenge();
    const typedCode = code().trim();
    const name = userName();
    const typedPassword = password();
    void run(async () => {
      if (ch) {
        const res = await acceptLogin(await api.post("/api/v1/auth/login/totp", { body: { challenge_id: ch.id, code: typedCode } }));
        return res.status === "authenticated";
      }
      const res = await acceptLogin(await api.post("/api/v1/auth/login/password", { body: { user_name: name, password: typedPassword } }));
      setPassword("");
      if (res.status === "second_factor") {
        setChallenge({ id: res.challenge_id, methods: res.methods });
        queueMicrotask(() => codeInput?.focus());
        return false;
      }
      return true;
    });
  };

  const withPasskey = () => {
    const ch = challenge();
    void run(async () => {
      const res = await acceptLogin(await signInWithPasskey(ch ? { challenge_id: ch.id } : {}));
      return res.status === "authenticated";
    });
  };

  const reasonKey = () =>
    props.required === "passkey"
      ? "secrets.reveal.stepup.passkey"
      : props.required === "password"
        ? "secrets.reveal.stepup.password"
        : "secrets.reveal.stepup.fresh";

  return (
    <div data-testid="reveal-stepup" data-required={props.required}>
      <Notice kind="warn" role="alert" title={t("secrets.reveal.stepup.title")}>
        {t(reasonKey())}
      </Notice>
      <Show when={error()}>
        {(message) => (
          <Notice kind="bad" role="alert">
            {message()}
          </Notice>
        )}
      </Show>
      <Show when={!passkeyOnly()}>
        <form class="stepup-form" onSubmit={withPassword} novalidate>
          <Show
            when={challenge()}
            fallback={
              <div class="field">
                <label for="reveal-stepup-password">{t("secrets.reveal.stepup.password_label", { user: userName() })}</label>
                <input
                  id="reveal-stepup-password"
                  class="input"
                  type="password"
                  autocomplete="current-password"
                  data-testid="field-stepup-password"
                  value={password()}
                  onInput={(e) => setPassword(e.currentTarget.value)}
                />
              </div>
            }
          >
            <div class="field">
              <label for="reveal-stepup-code">{t("secrets.reveal.stepup.code_label")}</label>
              <input
                ref={(el) => (codeInput = el)}
                id="reveal-stepup-code"
                class="input mono"
                inputmode="numeric"
                autocomplete="one-time-code"
                data-testid="field-stepup-code"
                value={code()}
                onInput={(e) => setCode(e.currentTarget.value)}
              />
            </div>
          </Show>
          <p>
            <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
              {t("secrets.reveal.stepup.continue")}
            </button>
          </p>
        </form>
      </Show>
      <Show when={webauthnAvailable() && (passkeyOnly() || !challenge() || challenge()?.methods.includes("webauthn"))}>
        <p>
          <button type="button" class="btn" data-testid="reveal-stepup-passkey" disabled={busy()} onClick={withPasskey}>
            <Icon name="key" /> {t("secrets.reveal.stepup.with_passkey")}
          </button>
        </p>
      </Show>
      <Show when={passkeyOnly() && !webauthnAvailable()}>
        <Notice kind="bad" role="alert">
          {t("auth.signin.ceremony.unsupported")}
        </Notice>
      </Show>
    </div>
  );
}
