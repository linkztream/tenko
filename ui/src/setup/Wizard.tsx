import { useNavigate } from "@solidjs/router";
import { createEffect, For, Match, on, onCleanup, onMount, Show, Switch } from "solid-js";
import { paths } from "../app/paths";
import { cycleTheme, theme } from "../app/prefs";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { Mark, Wordmark } from "../components/Mark";
import { ErrorNotice } from "../components/Notice";
import { availableLocales, locale, setLocale, storeLocale, t } from "../i18n";
import { themeLabel } from "../shell/TopBar";
import { firstBlockedStep, FOCUS, gateFor, LAST_STEP, STEP_COUNT, STEP_IDS, type Gate, type StepId } from "./gates";
import { Admin } from "./steps/Admin";
import { DataDir } from "./steps/DataDir";
import { Host } from "./steps/Host";
import { ProfileStep } from "./steps/Profile";
import { Result } from "./steps/Result";
import { Review } from "./steps/Review";
import { Roles } from "./steps/Roles";
import { Welcome } from "./steps/Welcome";
import { isValidUserName, validateHostName } from "./validate";
import { createWizard, WizardProvider } from "./controller";
import "./wizard.css";

const STEP_NAME = {
  welcome: "setup.step.welcome.name",
  profile: "setup.step.profile.name",
  admin: "setup.step.admin.name",
  host: "setup.step.host.name",
  disk: "setup.step.disk.name",
  roles: "setup.step.roles.name",
  done: "setup.step.done.name",
} as const satisfies Record<StepId, string>;

const STEP_TITLE = {
  welcome: "setup.step.welcome.title",
  profile: "setup.step.profile.title",
  admin: "setup.step.admin.title",
  host: "setup.step.host.title",
  disk: "setup.step.disk.title",
  roles: "setup.step.roles.title",
  done: "setup.step.done.title",
} as const satisfies Record<StepId, string>;

interface Meta {
  text: string;
  danger?: boolean;
}

/**
 * First-run setup (API-10, design/mockups/wizard.html): seven steps and one request at the
 * end. The page is a focused page without the shell; it stays mounted after the request
 * signs the new administrator in, to show the recovery codes and what to do next.
 */
export default function Wizard() {
  const navigate = useNavigate();
  const w = createWizard({
    onClosed: () => navigate(paths.dashboard(), { replace: true }),
    onOpen: () => navigate(paths.dashboard()),
  });
  let blocker: HTMLElement | undefined;

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.altKey && e.key === "ArrowLeft") {
      e.preventDefault();
      w.back();
      return;
    }
    if (e.key !== "Enter" || e.repeat || e.ctrlKey || e.altKey || e.metaKey || e.shiftKey) return;
    const target = e.target instanceof HTMLElement ? e.target : null;
    const tag = target?.tagName;
    if (tag === "BUTTON" || tag === "A" || tag === "SELECT" || tag === "TEXTAREA") return;
    if (target?.closest("[role='dialog']")) return;
    if (!w.loaded()) return;
    e.preventDefault();
    if (w.finished()) w.open();
    else w.next();
  };

  onMount(() => {
    void w.load();
    document.addEventListener("keydown", onKeyDown);
    onCleanup(() => document.removeEventListener("keydown", onKeyDown));
  });

  // A refused Continue flashes the message again.
  createEffect(
    on(
      w.nudge,
      () => {
        if (!blocker) return;
        blocker.classList.remove("nudge");
        void blocker.offsetWidth;
        blocker.classList.add("nudge");
      },
      { defer: true },
    ),
  );

  /** Why the primary button is blocked right now, or null. */
  const current = (): Gate | null => {
    if (w.finished()) return w.openGate();
    if (w.state.step === LAST_STEP) {
      const input = w.gateInput();
      const blockedAt = firstBlockedStep(input);
      return blockedAt === null ? null : gateFor(blockedAt, input);
    }
    return w.gate();
  };

  const meta = (i: number): Meta | null => {
    if (!w.state.visited[i]) return null;
    switch (STEP_IDS[i]) {
      case "profile":
        return { text: t(`profile.${w.state.profile}.name`), danger: w.state.profile === "lab" };
      case "admin":
        return isValidUserName(w.state.userName) ? { text: w.state.userName.trim() } : null;
      case "host": {
        const host = validateHostName(w.state.hostName);
        return host.ok ? { text: host.name } : null;
      }
      case "disk": {
        const path = w.dataDir()?.path;
        return path ? { text: path } : null;
      }
      case "roles":
        return { text: t("setup.steps.roles_meta", { count: Object.values(w.state.roles).filter(Boolean).length }) };
      default:
        return null;
    }
  };

  const stepName = (i: number): string => {
    const id = STEP_IDS[i];
    return id ? t(STEP_NAME[id]) : "";
  };

  const stepLabel = (i: number): string =>
    [
      t("setup.steps.item", { number: i + 1, name: stepName(i) }),
      meta(i)?.text,
      w.isDone(i) ? t("setup.steps.completed") : undefined,
    ]
      .filter((part): part is string => !!part)
      .join(", ");

  const title = (): string => {
    if (w.finished()) return t("setup.result.title");
    const id = STEP_IDS[w.state.step];
    return id ? t(STEP_TITLE[id]) : "";
  };

  const reviewLab = () => {
    if (w.finished()) return;
    w.review(1);
    document.getElementById(FOCUS.labAck)?.focus();
  };

  const pickLanguage = async (code: string) => {
    storeLocale(code);
    await setLocale(code);
  };

  const themeIcon = () => (theme() === "system" ? "system" : theme() === "light" ? "sun" : "moon");

  return (
    <WizardProvider value={w}>
      <div class="wz-page" data-testid="page-setup">
        <div class="wz-top">
          <Show when={w.state.profile === "lab"}>
            <div class="banner danger" role="alert">
              <Icon name="alert" size="sm" />
              <strong>{t("setup.banner.title")}</strong>
              <span class="grow">{t("setup.banner.body")}</span>
              <Show when={!w.finished()}>
                <button type="button" class="btn sm danger" onClick={reviewLab}>
                  {t("setup.banner.review")}
                </button>
              </Show>
            </div>
          </Show>
          <header class="wz-head">
            <div class="brand">
              <span class="mark-cell">
                <Mark duo label={t("auth.signin.product")} />
              </span>
              <Wordmark />
            </div>
            <span class="spacer" />
            <div class="group">
              <label class="sr-only" for="wz-language">
                {t("shell.account.language")}
              </label>
              <select
                id="wz-language"
                class="select"
                data-testid="field-language"
                value={locale()}
                onChange={(e) => void pickLanguage(e.currentTarget.value)}
              >
                <For each={availableLocales()}>{(l) => <option value={l.code}>{l.name}</option>}</For>
              </select>
              <button
                type="button"
                class="icon-btn"
                onClick={() => cycleTheme()}
                aria-label={themeLabel()}
                title={themeLabel()}
              >
                <Icon name={themeIcon()} />
              </button>
            </div>
          </header>
        </div>

        <div class="wz-layout">
          <nav aria-label={t("setup.steps.label")}>
            <ol class="wz-steps">
              <For each={STEP_IDS}>
                {(id, i) => (
                  <li>
                    <button
                      type="button"
                      class="wz-step"
                      data-testid="setup-step"
                      data-key={id}
                      classList={{ done: w.isDone(i()) }}
                      aria-current={w.state.step === i() ? "step" : undefined}
                      aria-label={stepLabel(i())}
                      disabled={w.finished()}
                      onClick={() => w.goTo(i())}
                    >
                      <span class="n">{w.isDone(i()) ? <Icon name="check" /> : i() + 1}</span>
                      <span class="lbl">
                        <span class="lbl-text">{t(STEP_NAME[id])}</span>
                        <Show when={meta(i())}>
                          {(m) => (
                            <span class="meta" classList={{ danger: m().danger === true }}>
                              {m().text}
                            </span>
                          )}
                        </Show>
                      </span>
                    </button>
                  </li>
                )}
              </For>
            </ol>
          </nav>

          <main
            class="card wz-card"
            aria-labelledby="wz-title"
            data-testid="setup-card"
            data-key={w.finished() ? "result" : STEP_IDS[w.state.step]}
          >
            <div class="wz-body">
              <div class="wz-stepno">{t("setup.stepno", { step: w.state.step + 1, total: STEP_COUNT })}</div>
              <h1 id="wz-title" tabindex="-1">
                {title()}
              </h1>
              <Show
                when={w.loaded()}
                fallback={
                  <Show
                    when={w.loadError()}
                    fallback={
                      <p class="wz-help gap" role="status">
                        {t("common.loading")}
                      </p>
                    }
                  >
                    <div class="wz-problem">
                      <ErrorNotice error={w.loadError()} />
                      <p class="wz-help gap">
                        <button type="button" class="btn sm" onClick={() => void w.load()}>
                          {t("common.action.retry")}
                        </button>
                      </p>
                    </div>
                  </Show>
                }
              >
                <Show when={!w.finished()} fallback={<Result />}>
                  <Switch>
                    <Match when={w.state.step === 0}>
                      <Welcome />
                    </Match>
                    <Match when={w.state.step === 1}>
                      <ProfileStep />
                    </Match>
                    <Match when={w.state.step === 2}>
                      <Admin />
                    </Match>
                    <Match when={w.state.step === 3}>
                      <Host />
                    </Match>
                    <Match when={w.state.step === 4}>
                      <DataDir />
                    </Match>
                    <Match when={w.state.step === 5}>
                      <Roles />
                    </Match>
                    <Match when={w.state.step === 6}>
                      <Review />
                    </Match>
                  </Switch>
                </Show>
              </Show>
            </div>

            <footer class="wz-foot">
              <Show when={!w.finished() && w.state.step > 0}>
                <button
                  type="button"
                  class="btn ghost"
                  onClick={() => w.back()}
                  aria-keyshortcuts="Alt+ArrowLeft"
                  data-testid="setup-back"
                >
                  {t("common.action.back")}{" "}
                  <span aria-hidden="true">
                    <Kbd keys={["Alt", "←"]} />
                  </span>
                </button>
              </Show>
              <span class="spacer" />
              <div class="wz-blocker-slot" role="status">
                <Show when={current()}>
                  {(g) => (
                    <span
                      class="wz-blocker"
                      data-testid="setup-blocker"
                      classList={{ pending: g().soft === true }}
                      ref={(el) => {
                        blocker = el;
                      }}
                    >
                      <Icon name="alert" size="sm" />
                      <span>{t(g().message)}</span>
                    </span>
                  )}
                </Show>
              </div>
              <Show
                when={!w.finished()}
                fallback={
                  <button
                    type="button"
                    id="wz-open"
                    data-testid="setup-open"
                    class="btn primary"
                    aria-disabled={current() ? "true" : "false"}
                    aria-keyshortcuts="Enter"
                    onClick={() => w.open()}
                  >
                    {t("setup.footer.open")}{" "}
                    <span aria-hidden="true">
                      <Kbd keys={["Enter"]} />
                    </span>
                  </button>
                }
              >
                <button
                  type="button"
                  id="wz-next"
                  data-testid="setup-next"
                  class="btn primary"
                  aria-disabled={current() || w.state.submitting ? "true" : "false"}
                  aria-keyshortcuts="Enter"
                  onClick={() => w.next()}
                >
                  {w.state.step === LAST_STEP
                    ? w.state.submitting
                      ? t("setup.footer.finishing")
                      : t("setup.footer.finish")
                    : t("common.action.continue")}{" "}
                  <span aria-hidden="true">
                    <Kbd keys={["Enter"]} />
                  </span>
                </button>
              </Show>
            </footer>
          </main>
        </div>
      </div>
    </WizardProvider>
  );
}
