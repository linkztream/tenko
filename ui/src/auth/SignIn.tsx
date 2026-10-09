import { useSearchParams } from "@solidjs/router";
import { createSignal, For, Match, onCleanup, Show, Switch } from "solid-js";
import { api } from "../api/client";
import { errorMessage, isApiError } from "../api/problem";
import type { SecondFactorMethod } from "../api/types";
import { cycleTheme, theme } from "../app/prefs";
import { Icon } from "../components/Icon";
import { Mark, Wordmark } from "../components/Mark";
import { availableLocales, locale, setLocale, storeLocale, t } from "../i18n";
import { themeLabel } from "../shell/TopBar";
import { acceptLogin } from "./session";
import { CeremonyError, signInWithPasskey, webauthnAvailable } from "./webauthn";
import "./auth.css";

type Stage = "passkey" | "password" | "second" | "break-glass";
type SecondMethod = "totp" | "recovery";

/**
 * Sign-in, passkey first (design/mockups/signin.html). A password sign-in continues with
 * the second factor the server asks for: an authenticator code, a recovery code or a
 * passkey. Break-glass access (IAM-09) sits behind a link at the bottom.
 */
export default function SignIn() {
  const [params] = useSearchParams();
  const [stage, setStage] = createSignal<Stage>("passkey");
  const [busy, setBusy] = createSignal(false);
  const [waiting, setWaiting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [userName, setUserName] = createSignal(typeof params.user === "string" ? params.user : "");
  const [password, setPassword] = createSignal("");
  const [code, setCode] = createSignal("");
  const [challenge, setChallenge] = createSignal<{ id: string; methods: SecondFactorMethod[] } | null>(null);
  const [method, setMethod] = createSignal<SecondMethod>("totp");
  const [retryIn, setRetryIn] = createSignal(0);
  let passwordInput!: HTMLInputElement;
  let userInput!: HTMLInputElement;
  let codeInput!: HTMLInputElement;
  let controller: AbortController | undefined;
  let countdown: ReturnType<typeof setInterval> | undefined;

  onCleanup(() => {
    controller?.abort();
    clearInterval(countdown);
  });

  const describe = (err: unknown): string => {
    if (err instanceof CeremonyError) return t(`auth.signin.ceremony.${err.reason}`);
    return errorMessage(err);
  };

  const startCountdown = (seconds: number) => {
    clearInterval(countdown);
    setRetryIn(Math.max(1, Math.ceil(seconds)));
    countdown = setInterval(() => {
      setRetryIn((s) => {
        if (s <= 1) {
          clearInterval(countdown);
          return 0;
        }
        return s - 1;
      });
    }, 1000);
  };

  const fail = (err: unknown) => {
    if (isApiError(err, "auth.throttled")) {
      const fromParams = Number(err.params.retry_after);
      startCountdown(err.retryAfter ?? (Number.isFinite(fromParams) ? fromParams : 20));
      setError(null);
      return;
    }
    if (isApiError(err, "auth.challenge_invalid")) {
      setChallenge(null);
      setStage("password");
    }
    setError(describe(err));
  };

  const passkey = async (breakGlass = false) => {
    setError(null);
    setBusy(true);
    setWaiting(true);
    controller = new AbortController();
    try {
      const ch = challenge();
      await acceptLogin(
        await signInWithPasskey({
          signal: controller.signal,
          ...(breakGlass ? { break_glass: true } : {}),
          ...(ch ? { challenge_id: ch.id } : {}),
        }),
      );
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
      setWaiting(false);
    }
  };

  const submitPassword = async (e: Event) => {
    e.preventDefault();
    if (!userName().trim()) {
      userInput.focus();
      return;
    }
    if (!password()) {
      passwordInput.focus();
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const res = await acceptLogin(
        await api.post("/api/v1/auth/login/password", { body: { user_name: userName().trim(), password: password() } }),
      );
      if (res.status === "second_factor") {
        setChallenge({ id: res.challenge_id, methods: res.methods });
        setMethod(res.methods.includes("totp") ? "totp" : "recovery");
        setPassword("");
        setStage("second");
        queueMicrotask(() => codeInput?.focus());
      }
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  const submitCode = async (e: Event) => {
    e.preventDefault();
    const ch = challenge();
    if (!ch) return;
    if (!code().trim()) {
      codeInput.focus();
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const path = method() === "totp" ? "/api/v1/auth/login/totp" : "/api/v1/auth/login/recovery";
      await acceptLogin(await api.post(path, { body: { challenge_id: ch.id, code: code().trim() } }));
    } catch (err) {
      setCode("");
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  const go = (next: Stage) => {
    controller?.abort();
    setError(null);
    setStage(next);
    if (next !== "second") setChallenge(null);
    if (next === "password") {
      const target = userName() ? passwordInput : userInput;
      queueMicrotask(() => target?.focus());
    }
  };

  const pickLanguage = async (code: string) => {
    storeLocale(code);
    await setLocale(code);
  };

  const secure = () => typeof location === "undefined" || location.protocol === "https:" || location.hostname === "localhost";
  const icon = () => (theme() === "system" ? "system" : theme() === "light" ? "sun" : "moon");

  return (
    <div class="focus-page" data-testid="page-signin">
      <div class="focus-top">
        <button type="button" class="icon-btn" onClick={() => cycleTheme()} aria-label={themeLabel()} title={themeLabel()}>
          <Icon name={icon()} />
        </button>
      </div>
      <main class="focus-center">
        <div class="signin-box">
          <div class="lockup">
            <Mark duo class="mark" label={t("auth.signin.product")} />
            <Wordmark />
          </div>

          <section class="card signin-card" aria-labelledby="signin-title">
            <div>
              <h1 id="signin-title">
                {stage() === "second"
                  ? t("auth.signin.second_title")
                  : stage() === "break-glass"
                    ? t("auth.signin.break_glass_title")
                    : t("auth.signin.title")}
              </h1>
              <p class="lead">
                {stage() === "second"
                  ? method() === "totp"
                    ? t("auth.signin.second_lead_totp")
                    : t("auth.signin.second_lead_recovery")
                  : stage() === "break-glass"
                    ? t("auth.signin.break_glass_lead")
                    : t("auth.signin.lead")}
              </p>
            </div>

            <Show when={error()}>
              <div class="note bad" role="alert" data-testid="signin-error">
                <Icon name="alert" size="sm" />
                <span class="grow">{error()}</span>
              </div>
            </Show>

            <Switch>
              <Match when={stage() === "passkey"}>
                <div class="fields">
                  <button
                    type="button"
                    class="btn primary wide"
                    disabled={busy()}
                    onClick={() => void passkey()}
                    data-testid="signin-passkey"
                  >
                    <Icon name="key" />
                    {t("auth.signin.passkey")}
                  </button>
                  <Show when={waiting()}>
                    <div class="wait" role="status">
                      <span class="jstate waiting">{t("auth.signin.waiting")}</span>
                    </div>
                  </Show>
                  <Show when={!webauthnAvailable()}>
                    <p class="help">{secure() ? t("auth.signin.passkey_unsupported") : t("auth.signin.passkey_insecure")}</p>
                  </Show>
                  <div class="or">{t("auth.signin.or")}</div>
                  <button type="button" class="btn wide" onClick={() => go("password")} data-testid="signin-use-password">
                    {t("auth.signin.use_password")}
                  </button>
                </div>
              </Match>

              <Match when={stage() === "password"}>
                <form class="fields" onSubmit={(e) => void submitPassword(e)} novalidate data-testid="signin-password-form">
                  <div class="field">
                    <label for="signin-user">{t("auth.signin.user_name")}</label>
                    <input
                      ref={userInput}
                      id="signin-user"
                      data-testid="field-user-name"
                      class="input"
                      autocomplete="username"
                      autocapitalize="off"
                      spellcheck={false}
                      value={userName()}
                      onInput={(e) => setUserName(e.currentTarget.value)}
                    />
                  </div>
                  <div class="field">
                    <label for="signin-password">{t("auth.signin.password")}</label>
                    <input
                      ref={passwordInput}
                      id="signin-password"
                      data-testid="field-password"
                      class="input"
                      type="password"
                      autocomplete="current-password"
                      value={password()}
                      onInput={(e) => setPassword(e.currentTarget.value)}
                    />
                  </div>
                  <Show when={retryIn() > 0}>
                    <div class="note warn" role="status">
                      <Icon name="clock" size="sm" />
                      <span class="grow">
                        <strong>{t("auth.signin.retry_in", { seconds: retryIn() })}</strong>{" "}
                        {t("auth.signin.throttle_explain")}
                      </span>
                    </div>
                  </Show>
                  <button type="submit" class="btn primary wide" disabled={busy() || retryIn() > 0} data-testid="form-submit">
                    {t("auth.signin.submit")}
                  </button>
                  <div class="links">
                    <button type="button" class="linkbtn" onClick={() => go("passkey")}>
                      {t("auth.signin.use_passkey")}
                    </button>
                  </div>
                </form>
              </Match>

              <Match when={stage() === "second"}>
                <form class="fields" onSubmit={(e) => void submitCode(e)} novalidate data-testid="signin-code-form">
                  <div class="field">
                    <label for="signin-code">
                      {method() === "totp" ? t("auth.signin.totp_code") : t("auth.signin.recovery_code")}
                    </label>
                    <input
                      ref={codeInput}
                      id="signin-code"
                      data-testid="field-code"
                      class="input mono"
                      autocomplete="one-time-code"
                      inputmode={method() === "totp" ? "numeric" : "text"}
                      autocapitalize="characters"
                      spellcheck={false}
                      value={code()}
                      onInput={(e) => setCode(e.currentTarget.value)}
                    />
                  </div>
                  <Show when={retryIn() > 0}>
                    <div class="note warn" role="status">
                      <Icon name="clock" size="sm" />
                      <span class="grow">
                        <strong>{t("auth.signin.retry_in", { seconds: retryIn() })}</strong>
                      </span>
                    </div>
                  </Show>
                  <button type="submit" class="btn primary wide" disabled={busy() || retryIn() > 0} data-testid="form-submit">
                    {t("auth.signin.verify")}
                  </button>
                  <div class="links">
                    <For each={challenge()?.methods ?? []}>
                      {(m) => (
                        <Show when={m !== method()}>
                          <button
                            type="button"
                            class="linkbtn"
                            data-testid="signin-method"
                            data-key={m}
                            onClick={() => {
                              if (m === "webauthn") void passkey();
                              else {
                                setMethod(m);
                                setCode("");
                                setError(null);
                                queueMicrotask(() => codeInput?.focus());
                              }
                            }}
                          >
                            {m === "totp"
                              ? t("auth.signin.use_totp")
                              : m === "recovery"
                                ? t("auth.signin.use_recovery")
                                : t("auth.signin.use_passkey")}
                          </button>
                        </Show>
                      )}
                    </For>
                    <button type="button" class="linkbtn" onClick={() => go("password")}>
                      {t("auth.signin.start_over")}
                    </button>
                  </div>
                  <Show when={waiting()}>
                    <div class="wait" role="status">
                      <span class="jstate waiting">{t("auth.signin.waiting")}</span>
                    </div>
                  </Show>
                </form>
              </Match>

              <Match when={stage() === "break-glass"}>
                <div class="fields">
                  <div class="note warn">
                    <Icon name="alert" size="sm" />
                    <span class="grow">{t("auth.signin.break_glass_warning")}</span>
                  </div>
                  <button type="button" class="btn danger wide" disabled={busy()} onClick={() => void passkey(true)}>
                    <Icon name="key" />
                    {t("auth.signin.break_glass_button")}
                  </button>
                  <Show when={waiting()}>
                    <div class="wait" role="status">
                      <span class="jstate waiting">{t("auth.signin.waiting_key")}</span>
                    </div>
                  </Show>
                  <div class="links">
                    <button type="button" class="linkbtn" onClick={() => go("passkey")}>
                      {t("auth.signin.back_to_sign_in")}
                    </button>
                  </div>
                </div>
              </Match>
            </Switch>
          </section>

          <Show when={stage() !== "break-glass"}>
            <p class="break-glass-link">
              <button type="button" class="linkbtn subtle" onClick={() => go("break-glass")}>
                {t("auth.signin.break_glass_link")}
              </button>
            </p>
          </Show>
        </div>
      </main>
      <footer class="focus-foot">
        <span class={secure() ? undefined : "insecure"}>
          <Icon name={secure() ? "shield" : "alert"} size="sm" />
          {secure() ? t("auth.signin.secure") : t("auth.signin.insecure")}
        </span>
        <label class="lang">
          <Icon name="globe" size="sm" />
          <span class="sr-only">{t("shell.account.language")}</span>
          <select
            class="select"
            value={locale()}
            onChange={(e) => void pickLanguage(e.currentTarget.value)}
            data-testid="field-language"
          >
            <For each={availableLocales()}>{(l) => <option value={l.code}>{l.name}</option>}</For>
          </select>
        </label>
      </footer>
    </div>
  );
}
