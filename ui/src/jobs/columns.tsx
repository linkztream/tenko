// Columns of the jobs grid (docs/plans/ui-plan.md section 5.4): State in glyph and word, the Job
// by its title from the label catalog with its object count in muted ink, the Kind code in the
// data font, the Steps (for a job that is done, how long it took), the Current step while a job
// runs or waits, Started by and Finished. State, title and progress come from the list itself;
// what the current step does is only on the job's detail, which the cell reads once per revision
// of the job and only for rows in view (the grid renders no others).
import { A } from "@solidjs/router";
import { createResource, Show } from "solid-js";
import type { JobSummary, StepStateKind } from "../api/types";
import { paths } from "../app/paths";
import { PrincipalLabel } from "../components/Principal";
import { TimeAgo } from "../grid/cells";
import type { Column } from "../grid/types";
import { t } from "../i18n";
import { readJobDetail } from "./data";
import { durationSeconds } from "./layout";
import { isFinal, needsPerson } from "./model";
import { JobStateChip } from "./StateChip";
import { firstHost, TargetLabel } from "./Target";
import { cancelRolledBack, describeStep, durationText, jobStateText, jobTitle, stepStateWord, titleSaysCount } from "./words";

/** The state of a job in words; a job that waits for a person says so instead of "Waiting". */
export function stateText(job: JobSummary): string {
  if (needsPerson(job) && !isFinal(job.state)) return t("jobs.state.waiting_you");
  return jobStateText(job.state, cancelRolledBack(job) ? "cancel" : undefined);
}

/** The state in glyph and word: "Waiting for you" for a job with a task open for a person. */
function StateCell(props: { job: JobSummary }) {
  const you = () => needsPerson(props.job) && !isFinal(props.job.state);
  return (
    <span class="job-state-cell">
      <Show
        when={you()}
        fallback={
          <JobStateChip
            state={props.job.state}
            done={props.job.steps_done}
            total={props.job.step_count}
            rollback={cancelRolledBack(props.job) ? "cancel" : undefined}
          />
        }
      >
        <span class="jstate waiting you" data-state={props.job.state} data-testid="job-state" data-needs="true">
          {t("jobs.state.waiting_you")}
        </span>
      </Show>
      <Show when={props.job.cancel_requested && !isFinal(props.job.state)}>
        <span class="flag job-cancel-flag">{t("jobs.flag.cancel_requested")}</span>
      </Show>
    </span>
  );
}

/** The title, the host the job is about when it has one, and how many objects it changes, muted. */
function TitleCell(props: { job: JobSummary }) {
  return (
    <span class="job-title-cell">
      <A class="job-link" href={paths.job(props.job.id)} tabIndex={-1}>
        {jobTitle(props.job)}
      </A>
      <Show when={firstHost(props.job.targets)}>{(host) => <TargetLabel target={host()} />}</Show>
      <Show when={!titleSaysCount(props.job) && props.job.targets.length > 0}>
        <span class="job-count" data-testid="job-count">
          {t("jobs.targets", { count: props.job.targets.length })}
        </span>
      </Show>
    </span>
  );
}

/** "3 of 4" while a job runs or after it stopped; for a job that is done, how long it took. */
export function stepsText(job: JobSummary): string {
  const took = job.state === "succeeded" ? durationSeconds(job) : undefined;
  return took === undefined ? t("jobs.steps_of", { done: job.steps_done, total: job.step_count }) : durationText(took);
}

function StepsCell(props: { job: JobSummary }) {
  const took = () => (props.job.state === "succeeded" ? durationSeconds(props.job) : undefined);
  return (
    <Show when={took() !== undefined ? { seconds: took() ?? 0 } : undefined} fallback={<span class="num">{stepsText(props.job)}</span>}>
      {(took) => (
        <span class="num" data-testid="job-duration" title={t("jobs.duration.took", { duration: durationText(took().seconds) })}>
          {durationText(took().seconds)}
        </span>
      )}
    </Show>
  );
}

/**
 * What the current step does and its state, for a job that runs or waits only; a job that is over
 * has no current step. The words arrive with the job detail, read once per revision; until then
 * the cell shows the position.
 */
function CurrentStepCell(props: { job: JobSummary }) {
  const wanted = () => !isFinal(props.job.state) && props.job.current_step != null;
  const [detail] = createResource(
    () => (wanted() ? `${props.job.id}@${props.job.revision}:${props.job.state}:${props.job.steps_done}` : false),
    () => readJobDetail(props.job),
  );
  const shown = (): { text: string; state: StepStateKind | undefined } | null => {
    if (!wanted()) return null;
    const i = props.job.current_step;
    if (i === null || i === undefined) return null;
    const d = detail();
    const step = d?.job.steps[i];
    return {
      text: step ? describeStep(step, d?.preview?.steps[i]) : t("jobs.step_position", { n: i + 1, total: props.job.step_count }),
      state: props.job.current_step_state ?? step?.state.state,
    };
  };
  return (
    <Show when={shown()}>
      {(step) => (
        <span class="job-step-cell" title={step().text}>
          <span>{step().text}</span>
          <Show when={step().state}>{(state) => <span class="muted"> · {stepStateWord(state())}</span>}</Show>
        </span>
      )}
    </Show>
  );
}

export function jobColumns(): Column<JobSummary>[] {
  return [
    {
      id: "state",
      header: () => t("jobs.col.state"),
      width: 150,
      fixed: true,
      text: stateText,
      render: (j) => <StateCell job={j} />,
    },
    {
      id: "title",
      header: () => t("jobs.col.job"),
      fixed: true,
      text: (j) => jobTitle(j),
      render: (j) => <TitleCell job={j} />,
    },
    {
      id: "kind",
      header: () => t("jobs.col.kind"),
      width: 150,
      text: (j) => j.kind,
      render: (j) => <span class="mono job-kind">{j.kind}</span>,
    },
    {
      id: "steps",
      header: () => t("jobs.col.steps"),
      width: 100,
      text: stepsText,
      render: (j) => <StepsCell job={j} />,
    },
    {
      id: "step",
      header: () => t("jobs.col.step"),
      width: 300,
      render: (j) => <CurrentStepCell job={j} />,
    },
    {
      id: "by",
      header: () => t("jobs.col.by"),
      width: 140,
      render: (j) => <PrincipalLabel principal={j.created.by} />,
    },
    {
      id: "created",
      header: () => t("jobs.col.created"),
      width: 120,
      hidden: true,
      render: (j) => <TimeAgo at={j.created.at} />,
    },
    {
      id: "finished",
      header: () => t("jobs.col.finished"),
      width: 120,
      align: "right",
      render: (j) => <TimeAgo at={j.finished} />,
    },
  ];
}
