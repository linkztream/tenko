// An install in progress: first the steps of its job, live (fetch, verify, check, switch),
// then "Restarting into <version>" while the public health probe is asked every two seconds
// for the new version. The page reloads when it answers; when it does not within the time the
// server allows plus a minute, the last attempt says what happened.
import { A } from "@solidjs/router";
import { createEffect, createSignal, For, on, onCleanup, onMount, Show, untrack } from "solid-js";
import { events } from "../api/events";
import { ApiError, CLIENT_CODES } from "../api/problem";
import type { JobDetail } from "../api/types";
import { paths } from "../app/paths";
import { Notice } from "../components/Notice";
import { t } from "../i18n";
import { isFinal } from "../jobs/model";
import { JobStateChip, StepStateChip } from "../jobs/StateChip";
import { codedErrorText, stepSummary } from "../jobs/words";
import { readHealthVersion, readJob, readUpdates, type UpdateAttempt } from "./api";
import { pageActions, restartTimeoutMs, watchRestart } from "./restart";
import { codeText, whenText } from "./words";

type Phase = "job" | "restarting" | "timeout" | "failed";

/** The safety poll of the job while no event arrives. */
const JOB_POLL_MS = 3000;

function isNetworkError(err: unknown): boolean {
  return err instanceof ApiError && err.code === CLIENT_CODES.network;
}

export function InstallProgress(props: {
  jobId: string;
  version: string;
  /** Seconds the server gives the new version to become ready. */
  readyTimeoutSecs: number;
  /** Start in the restart phase (the page was opened while the server restarted). */
  restarting?: boolean;
}) {
  // The job and the first phase are fixed for the life of the component.
  const jobId = untrack(() => props.jobId);
  const [job, setJob] = createSignal<JobDetail | null>(null);
  const [phase, setPhase] = createSignal<Phase>(untrack(() => (props.restarting ? "restarting" : "job")));
  const [attempt, setAttempt] = createSignal<UpdateAttempt | null>(null);
  const [attemptKnown, setAttemptKnown] = createSignal(false);

  // ---- The job

  let controller: AbortController | undefined;
  const loadJob = async () => {
    controller?.abort();
    controller = new AbortController();
    try {
      const detail = await readJob(jobId, controller.signal);
      setJob(detail);
      if (untrack(phase) !== "job") return;
      if (detail.job.state === "succeeded") setPhase("restarting");
      else if (isFinal(detail.job.state)) setPhase("failed");
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      // The server went away while the job ran: it is switching to the new version.
      if (untrack(phase) === "job" && isNetworkError(err) && untrack(job) !== null) setPhase("restarting");
    }
  };

  onMount(() => {
    void loadJob();
    const poll = setInterval(() => {
      if (untrack(phase) === "job") void loadJob();
    }, JOB_POLL_MS);
    let debounce: ReturnType<typeof setTimeout> | undefined;
    const offJobs = events.subscribe("jobs", (event) => {
      if (untrack(phase) !== "job") return;
      if (event.objects.length > 0 && !event.objects.some((o) => o.id === jobId)) return;
      clearTimeout(debounce);
      debounce = setTimeout(() => void loadJob(), 150);
    });
    const offReset = events.onReset("jobs", () => void loadJob());
    onCleanup(() => {
      clearInterval(poll);
      clearTimeout(debounce);
      controller?.abort();
      offJobs();
      offReset();
    });
  });

  // ---- The restart

  createEffect(
    on(phase, (p) => {
      if (p !== "restarting") return;
      const stop = watchRestart({
        target: props.version,
        probe: () => readHealthVersion(),
        timeoutMs: restartTimeoutMs(props.readyTimeoutSecs),
        onReady: () => pageActions.reload(),
        onTimeout: () => setPhase("timeout"),
      });
      onCleanup(stop);
    }),
  );

  // What the server recorded, once the wait is over (or the job failed).
  createEffect(
    on(phase, (p) => {
      if (p !== "timeout" && p !== "failed") return;
      void (async () => {
        try {
          setAttempt((await readUpdates()).attempt ?? null);
        } catch {
          setAttempt(null);
        }
        setAttemptKnown(true);
      })();
    }),
  );

  const failure = () => job()?.job.error;
  const stateKey = () => {
    const p = phase();
    if (p === "timeout") {
      const a = attempt();
      if (attemptKnown() && a?.state === "rolled_back") return "rolled_back";
      if (attemptKnown() && a?.state === "failed") return "failed";
      if (attemptKnown() && a?.state === "confirmed") return "confirmed";
    }
    return p;
  };

  return (
    <section class="page-section" aria-labelledby="upd-progress" data-testid="updates-progress" data-state={stateKey()}>
      <h2 id="upd-progress">
        <Show when={phase() === "restarting"} fallback={t("updates.progress.heading", { version: props.version })}>
          {t("updates.restart.title", { version: props.version })}
        </Show>
      </h2>
      <div class="card upd-card" aria-live="polite">
        <Show when={job()}>
          {(detail) => (
            <>
              <div class="upd-job">
                <JobStateChip state={detail().job.state} done={doneCount(detail())} total={detail().job.steps.length} />
                <A href={paths.job(jobId)} data-testid="updates-job-link">
                  {t("updates.progress.job_link")}
                </A>
              </div>
              <ol class="upd-steps" data-testid="updates-steps">
                <For each={detail().job.steps}>
                  {(step) => (
                    <li data-testid="updates-step" data-key={step.kind} data-state={step.state.state}>
                      <StepStateChip state={step.state.state} />
                      <span>{stepSummary(step.kind)}</span>
                    </li>
                  )}
                </For>
              </ol>
            </>
          )}
        </Show>

        <Show when={phase() === "restarting"}>
          <p data-testid="updates-restarting">{t("updates.restart.body", { version: props.version })}</p>
        </Show>

        <Show when={phase() === "failed"}>
          <Notice kind="bad" title={t("updates.progress.failed", { version: props.version })} role="alert" testid="updates-failed">
            <Show when={failure()} fallback={t("updates.progress.failed_unknown")}>
              {(error) => <>{codedErrorText(error())}</>}
            </Show>
          </Notice>
        </Show>

        <Show when={phase() === "timeout"}>
          <Outcome attempt={attempt()} known={attemptKnown()} version={props.version} seconds={restartTimeoutMs(props.readyTimeoutSecs) / 1000} />
        </Show>
      </div>
    </section>
  );
}

/** Steps that are finished, for the progress pie of the job chip. */
function doneCount(detail: JobDetail): number {
  return detail.job.steps.filter((s) => s.state.state === "done" || s.state.state === "skipped").length;
}

/** What the server recorded about the attempt after the wait ran out. */
function Outcome(props: { attempt: UpdateAttempt | null; known: boolean; version: string; seconds: number }) {
  return (
    <Show when={props.known} fallback={<p class="muted">{t("common.loading")}</p>}>
      <Show
        when={props.attempt?.state === "rolled_back" || props.attempt?.state === "failed" || props.attempt?.state === "confirmed"}
        fallback={
          <Notice kind="bad" title={t("updates.restart.timeout_title")} role="alert" testid="updates-timeout">
            {t("updates.restart.timeout_body", { version: props.version, seconds: props.seconds })}
            <ul>
              <li>{t("updates.restart.check_service")}</li>
              <li>{t("updates.restart.check_log")}</li>
              <li>{t("updates.restart.check_previous")}</li>
            </ul>
            <p>
              <button type="button" class="btn" onClick={() => pageActions.reload()} data-testid="updates-reload">
                {t("updates.restart.reload")}
              </button>
            </p>
          </Notice>
        }
      >
        <Show
          when={props.attempt?.state === "confirmed"}
          fallback={
            <Notice
              kind="bad"
              title={
                props.attempt?.state === "rolled_back"
                  ? t("updates.restart.rolled_back", { from: props.attempt.from, to: props.attempt.to })
                  : t("updates.progress.failed", { version: props.version })
              }
              role="alert"
              testid="updates-outcome"
            >
              <Show when={props.attempt?.reason}>
                {(reason) => <span data-code={reason()}>{t("updates.restart.reason", { reason: codeText(reason()) })}</span>}
              </Show>
              <Show when={props.attempt}>{(a) => <span class="muted"> {whenText(a().at)}</span>}</Show>
            </Notice>
          }
        >
          <Notice kind="ok" title={t("updates.restart.confirmed", { version: props.version })} testid="updates-outcome">
            <button type="button" class="btn" onClick={() => pageActions.reload()} data-testid="updates-reload">
              {t("updates.restart.reload")}
            </button>
          </Notice>
        </Show>
      </Show>
    </Show>
  );
}
