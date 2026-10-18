// The updates page (/updates, administrators): the running version, the newer releases with
// their notes and marks, the check of the release source, and how to install. An install
// that has started replaces the install panel with its live progress.
import { A } from "@solidjs/router";
import { createEffect, createSignal, For, on, onCleanup, onMount, Show } from "solid-js";
import { events } from "../api/events";
import { isApiError } from "../api/problem";
import { paths } from "../app/paths";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";
import { SettingsNav } from "../settings/SettingsNav";
import { readUpdates, type InstallStarted, type UpdateStatus } from "./api";
import { CheckPanel } from "./CheckPanel";
import { InstallPanel } from "./InstallPanel";
import { InstallProgress } from "./InstallProgress";
import { ReleaseCard } from "./ReleaseCard";
import { refreshUpdateStatus } from "./status";
import { codeText, whenText } from "./words";
import "./marks.css";
import "./updates.css";

interface Active {
  jobId: string;
  version: string;
  restarting: boolean;
}

export default function UpdatesPage() {
  const [status, setStatus] = createSignal<UpdateStatus | null>(null);
  const [state, setState] = createSignal<"loading" | "ready" | "unavailable" | "error">("loading");
  const [error, setError] = createSignal<unknown>(null);
  const [running, setRunning] = createSignal<Active | null>(null);

  const load = async () => {
    try {
      setStatus(await readUpdates());
      setState("ready");
    } catch (err) {
      if (isApiError(err) && (err.status === 503 || err.code === "update.unavailable")) {
        setState("unavailable");
      } else if (status() === null) {
        setError(err);
        setState("error");
      }
    }
  };

  /** A newer answer of the server (after a check or an uploaded release list). */
  const accept = (next: UpdateStatus) => {
    setStatus(next);
    setState("ready");
    refreshUpdateStatus();
  };

  onMount(() => {
    void load();
    let debounce: ReturnType<typeof setTimeout> | undefined;
    const off = events.subscribe("admin", () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => void load(), 250);
    });
    onCleanup(() => {
      clearTimeout(debounce);
      off();
    });
  });

  // An install that is under way when the page opens (or reloads) is followed from here.
  createEffect(
    on(status, (s) => {
      const attempt = s?.attempt;
      if (!s || !attempt || running()) return;
      if ((attempt.state === "installing" || attempt.state === "restarting") && attempt.job_id) {
        setRunning({ jobId: attempt.job_id, version: attempt.to, restarting: attempt.state === "restarting" });
      }
    }),
  );

  const started = (s: InstallStarted) => {
    setRunning({ jobId: s.job_id, version: s.version, restarting: false });
    refreshUpdateStatus();
  };

  return (
    <div class="page" data-testid="page-updates">
      <PageHead title={t("updates.title")} sub={status() ? t("updates.sub", { version: status()?.running ?? "" }) : undefined} />
      <SettingsNav />
      <div class="page-body">
        <Show when={state() === "loading"}>
          <p class="muted" role="status">
            {t("common.loading")}
          </p>
        </Show>
        <Show when={state() === "unavailable"}>
          <Notice kind="info" testid="updates-unavailable">
            {t("updates.unavailable")}
          </Notice>
        </Show>
        <Show when={state() === "error"}>
          <ErrorNotice error={error()} />
          <div>
            <button type="button" class="btn" onClick={() => void load()}>
              {t("common.action.retry")}
            </button>
          </div>
        </Show>
        <Show when={state() === "ready" ? status() : null}>
          {(s) => (
            <>
              <Running status={s()} />
              <AttemptNotice status={s()} />
              <Show
                when={running()}
                fallback={
                  <InstallPanel status={s()} onStatus={accept} onStarted={started} onReload={() => void load()} />
                }
              >
                {(r) => (
                  <InstallProgress
                    jobId={r().jobId}
                    version={r().version}
                    readyTimeoutSecs={s().install.ready_timeout_secs}
                    restarting={r().restarting}
                  />
                )}
              </Show>
              <Releases status={s()} />
              <CheckPanel status={s()} onStatus={accept} onReload={() => void load()} />
            </>
          )}
        </Show>
      </div>
    </div>
  );
}

/** The running version, its data format and what is newest. */
function Running(props: { status: UpdateStatus }) {
  const s = () => props.status;
  return (
    <section class="page-section" aria-labelledby="upd-running" data-testid="updates-running">
      <h2 id="upd-running">{t("updates.running.heading")}</h2>
      <div class="card upd-card">
        <dl class="kv upd-kv">
          <dt>{t("updates.running.version")}</dt>
          <dd class="mono" data-testid="updates-running-version">
            {s().running}
          </dd>
          <dt>{t("updates.running.format")}</dt>
          <dd>{s().format}</dd>
          <dt>{t("updates.running.platform")}</dt>
          <dd class="mono">{s().platform}</dd>
          <dt>{t("updates.running.newest")}</dt>
          <dd data-testid="updates-newest">
            <Show when={s().update_available && (s().latest ?? s().releases[0]?.version)} fallback={t("updates.running.up_to_date")}>
              {(version) => <span class="mono">{version()}</span>}
            </Show>
          </dd>
        </dl>
      </div>
    </section>
  );
}

/** The last install attempt, when it did not go through (a switch back or a failure). */
function AttemptNotice(props: { status: UpdateStatus }) {
  const attempt = () => props.status.attempt;
  return (
    <Show when={attempt()?.state === "rolled_back" || attempt()?.state === "failed" ? attempt() : null}>
      {(a) => (
        <Notice
          kind="bad"
          role="alert"
          testid="updates-attempt"
          title={
            a().state === "rolled_back"
              ? t("updates.attempt.rolled_back", { from: a().from, to: a().to })
              : t("updates.attempt.failed", { to: a().to })
          }
        >
          <Show when={a().reason}>{(reason) => <span data-code={reason()}>{t("updates.restart.reason", { reason: codeText(reason()) })}</span>}</Show>{" "}
          <span class="muted">{whenText(a().at)}</span>
          <Show when={a().job_id}>
            {(id) => (
              <>
                {" "}
                <A href={paths.job(id())}>{t("updates.progress.job_link")}</A>
              </>
            )}
          </Show>
        </Notice>
      )}
    </Show>
  );
}

/** Every newer release, newest first. */
function Releases(props: { status: UpdateStatus }) {
  return (
    <section class="page-section" aria-labelledby="upd-releases" data-testid="updates-releases">
      <h2 id="upd-releases">
        {t("updates.releases.heading")}
        <span class="aside">{t("updates.releases.count", { count: props.status.releases.length })}</span>
      </h2>
      <Show when={props.status.releases.length > 0} fallback={<p class="muted">{t("updates.releases.none")}</p>}>
        <For each={props.status.releases}>{(release, i) => <ReleaseCard release={release} newest={i() === 0} />}</For>
      </Show>
    </section>
  );
}
