// One job (/jobs/<id>): who started it and when, how it ends if nobody acts, its steps with the
// manual tasks that wait for a person, and the log of every transition. Nothing happens
// silently (design principle 4): a step that waits shows what it waits for and until when, and
// a deadline that passes rolls the job back, which the page says before it happens.
//
// The detail follows the `jobs` topic, filtered to events that name this job, so a step that
// finishes elsewhere shows up here without a reload.
import { A, useParams } from "@solidjs/router";
import { createEffect, createSignal, For, Show, type JSX } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import type { JobDetail as JobDetailData } from "../api/types";
import { decodeSegment, paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { ConfirmDialog } from "../components/Dialog";
import { Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { PrincipalLabel, shortId } from "../components/Principal";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { formatDuration, t, tx } from "../i18n";
import { canExecuteJobs } from "./access";
import { cancelJob } from "./data";
import { canCancel, groupLabel, isFinal } from "./model";
import { TransitionLog } from "./Log";
import { JobStateChip } from "./StateChip";
import { StepList } from "./Steps";
import { TargetLabel } from "./Target";
import { codedErrorDetail, codedErrorText, jobTitle, problemText } from "./words";
import "./jobs.css";

function Fact(props: { label: string; children: JSX.Element; testid?: string }) {
  return (
    <div data-testid={props.testid}>
      <dt>{props.label}</dt>
      <dd>{props.children}</dd>
    </div>
  );
}

function Crumbs(props: { id: string }) {
  return (
    <nav class="job-crumbs" aria-label={t("jobs.crumbs")}>
      <A href={paths.jobs()}>{t("jobs.title")}</A>
      <Icon name="chev-r" size="xs" />
      <span class="mono">{shortId(props.id)}</span>
    </nav>
  );
}

function CancelDialog(props: { detail: JobDetailData; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(undefined);
  const queued = () => props.detail.job.state === "queued";

  const confirm = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const summary = await cancelJob(props.detail.job.id);
      toast({
        kind: "ok",
        title: summary.state === "cancelled" ? t("jobs.cancel.done") : t("jobs.cancel.requested"),
      });
      props.onDone();
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };

  return (
    <ConfirmDialog
      title={t("jobs.cancel.title")}
      body={
        <>
          <p data-testid="job-cancel-text">{queued() ? t("jobs.cancel.body_queued") : t("jobs.cancel.body_active")}</p>
          <Show when={error()}>
            {(err) => (
              <p class="help bad field-error" role="alert" data-testid="job-cancel-error">
                <Icon name="alert" size="sm" />
                <span>{problemText(err())}</span>
              </p>
            )}
          </Show>
        </>
      }
      confirmLabel={t("jobs.cancel.confirm")}
      cancelLabel={t("jobs.cancel.keep")}
      danger
      busy={busy()}
      onConfirm={() => void confirm()}
      onClose={props.onClose}
    />
  );
}

function JobBody(props: { detail: JobDetailData; onChanged: () => void }) {
  const [cancelling, setCancelling] = createSignal(false);
  const job = () => props.detail.job;
  const spec = () => job().spec;
  const done = () => job().steps.filter((s) => s.state.state === "done" || s.state.state === "skipped").length;

  return (
    <>
      <PageHead
        crumbs={<Crumbs id={job().id} />}
        title={jobTitle(spec())}
        sub={
          <>
            <span class="mono">{spec().kind}</span>
            <JobStateChip state={job().state} done={done()} total={job().steps.length} />
          </>
        }
        actions={
          <Show when={canCancel(job().state, !!job().cancel_requested)}>
            <button
              type="button"
              class="btn danger"
              data-testid="job-cancel"
              disabled={!canExecuteJobs()}
              title={canExecuteJobs() ? undefined : t("jobs.no_right")}
              onClick={() => setCancelling(true)}
            >
              {t("jobs.cancel.button")}
            </button>
          </Show>
        }
      />
      <div class="page-body">
        <Show when={job().cancel_requested && !isFinal(job().state) ? job().cancel_requested : undefined}>
          {(stamp) => (
            <Notice kind="info" role="status">
              <span data-testid="job-cancel-requested">
                {tx("jobs.cancel.note", {
                  when: <TimeAgo at={stamp().at} />,
                  who: <PrincipalLabel principal={stamp().by} />,
                })}
              </span>
            </Notice>
          )}
        </Show>
        <Show when={job().error}>
          {(error) => (
            <Notice
              kind={error().code === "jobs.cancelled" ? "info" : "bad"}
              title={error().code === "jobs.cancelled" ? undefined : t("jobs.problem.title")}
            >
              <span data-testid="job-error">
                {codedErrorText(error())}
                <Show when={codedErrorDetail(error())}>
                  {(detail) => (
                    <>
                      {" "}
                      <span class="muted">{t("jobs.problem.detail", { detail: detail() })}</span>
                    </>
                  )}
                </Show>
              </span>
            </Notice>
          )}
        </Show>

        <dl class="job-facts" data-testid="job-facts">
          <Fact label={t("jobs.fact.id")}>
            <span class="mono">{job().id}</span>
          </Fact>
          <Fact label={t("jobs.fact.created")}>
            {tx("jobs.fact.when_by", {
              when: <TimeAgo at={job().created.at} />,
              who: <PrincipalLabel principal={job().created.by} />,
            })}
          </Fact>
          <Fact label={t("jobs.fact.started")}>
            <Show when={job().started} fallback={<span class="muted">{t("jobs.fact.not_yet")}</span>}>
              <TimeAgo at={job().started} />
            </Show>
          </Fact>
          <Fact label={t("jobs.fact.finished")}>
            <Show when={job().finished} fallback={<span class="muted">{t("jobs.fact.not_yet")}</span>}>
              <TimeAgo at={job().finished} />
            </Show>
          </Fact>
          <Fact label={t("jobs.fact.timeout")}>
            <span title={t("jobs.fact.timeout_hint")} class="num">
              {formatDuration(spec().timeout)}
            </span>
          </Fact>
          <Show when={spec().group}>
            {(group) => (
              <Fact label={t("jobs.fact.group")} testid="job-group-fact">
                <A href={paths.jobs({ group: group() })} title={group()} data-testid="job-group-link">
                  {t("jobs.fact.group_link")}
                </A>{" "}
                <span class="mono muted">{groupLabel(group())}</span>
                <Show when={spec().group_limit}>
                  {(limit) => (
                    <>
                      {" "}
                      <span class="muted">{t("jobs.fact.group_limit", { limit: limit() })}</span>
                    </>
                  )}
                </Show>
              </Fact>
            )}
          </Show>
          <Show when={spec().targets.length > 0}>
            <Fact label={t("jobs.fact.targets")} testid="job-targets">
              <ul class="job-targets">
                <For each={spec().targets}>
                  {(target) => (
                    <li>
                      <TargetLabel target={target} />
                    </li>
                  )}
                </For>
              </ul>
            </Fact>
          </Show>
        </dl>

        <section class="page-section" aria-labelledby="job-steps-title">
          <h2 id="job-steps-title">
            {t("jobs.steps.heading")}
            <span class="aside">{t("jobs.progress", { done: done(), total: job().steps.length })}</span>
          </h2>
          <StepList detail={props.detail} canExecute={canExecuteJobs()} onChanged={props.onChanged} />
        </section>

        <section class="page-section" aria-labelledby="job-log-title">
          <h2 id="job-log-title">{t("jobs.log.heading")}</h2>
          <TransitionLog detail={props.detail} />
        </section>
      </div>
      <Show when={cancelling()}>
        <CancelDialog
          detail={props.detail}
          onClose={() => setCancelling(false)}
          onDone={() => {
            setCancelling(false);
            props.onChanged();
          }}
        />
      </Show>
    </>
  );
}

function JobPage(props: { id: string }) {
  const live = createLiveQuery<JobDetailData>({
    topics: ["jobs"],
    relevant: (event) => [...event.objects, ...event.deleted].some((o) => o.kind === "job" && o.id === props.id),
    fetch: async (signal) => {
      const detail = await api.get("/api/v1/jobs/{id}", { path: { id: props.id }, signal });
      return { value: detail, revision: detail.revision };
    },
  });

  // The job on screen: the last answer of the server. A failed refresh keeps showing it.
  const [current, setCurrent] = createSignal<JobDetailData>();
  createEffect(() => {
    const state = live.value.state;
    if (state === "ready" || state === "refreshing") setCurrent(live.value());
  });

  return (
    <div class="page job-page" data-testid="page-job">
      <Show
        when={current()}
        fallback={
          <div class="page-body">
            <Crumbs id={props.id} />
            <Show
              when={live.value.error}
              fallback={
                <p class="muted" role="status">
                  {t("common.loading")}
                </p>
              }
            >
              <Notice kind="bad" role="alert">
                <span data-testid="job-load-error">{problemText(live.value.error)}</span>
              </Notice>
              <div>
                <button type="button" class="btn" onClick={() => live.refetch()}>
                  {t("common.action.retry")}
                </button>
              </div>
            </Show>
          </div>
        }
      >
        {(detail) => <JobBody detail={detail()} onChanged={() => live.refetch()} />}
      </Show>
    </div>
  );
}

export default function JobDetail() {
  const params = useParams();
  // A different job in the URL is a different page: its own live query, its own notes.
  return (
    <Show when={decodeSegment(params.id)} keyed>
      {(id) => <JobPage id={id} />}
    </Show>
  );
}
