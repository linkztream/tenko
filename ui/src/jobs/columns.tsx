// Columns of the jobs grid. State, title and progress come from the list itself; what the
// current step does is only on the job's detail, which the cell reads once per revision of the
// job and only for rows in view (the grid renders no others).
import { A } from "@solidjs/router";
import { createResource, Show } from "solid-js";
import type { JobSummary, StepStateKind } from "../api/types";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { PrincipalLabel } from "../components/Principal";
import { TimeAgo } from "../grid/cells";
import type { Column } from "../grid/types";
import { t } from "../i18n";
import { readJobDetail } from "./data";
import { isFinal, needsPerson } from "./model";
import { JobStateChip } from "./StateChip";
import { firstHost, TargetLabel } from "./Target";
import { describeStep, jobStateWord, jobTitle, stepStateWord } from "./words";

/** The state in glyph and word, with a marker when the job waits for a person. */
function StateCell(props: { job: JobSummary }) {
  return (
    <span class="job-state-cell">
      <JobStateChip state={props.job.state} done={props.job.steps_done} total={props.job.step_count} />
      <Show when={needsPerson(props.job)}>
        <span class="flag discrepancy job-needs" data-testid="job-needs">
          <Icon name="alert" size="xs" />
          {t("jobs.needs_you")}
        </span>
      </Show>
      <Show when={props.job.cancel_requested && !isFinal(props.job.state)}>
        <span class="flag job-cancel-flag">{t("jobs.flag.cancel_requested")}</span>
      </Show>
    </span>
  );
}

/** The title, the host the job is about when it has one, and how many objects it changes. */
function TitleCell(props: { job: JobSummary }) {
  return (
    <>
      <A class="job-link" href={paths.job(props.job.id)} tabIndex={-1}>
        {jobTitle(props.job)}
      </A>{" "}
      <Show when={firstHost(props.job.targets)}>
        {(host) => (
          <>
            <TargetLabel target={host()} />{" "}
          </>
        )}
      </Show>
      <span class="muted">{t("jobs.targets", { count: props.job.targets.length })}</span>
    </>
  );
}

/**
 * What the current step does and its state. A job that is over has no current step: one that
 * failed points at the step that failed, any other shows a dash. The words arrive with the
 * job detail, read once per revision; until then a running job shows the position.
 */
function CurrentStepCell(props: { job: JobSummary }) {
  const over = () => isFinal(props.job.state);
  const wanted = () =>
    over() ? props.job.state === "failed" || props.job.state === "rolled_back" : props.job.current_step != null;
  const [detail] = createResource(
    () => (wanted() ? `${props.job.id}@${props.job.revision}:${props.job.state}:${props.job.steps_done}` : false),
    () => readJobDetail(props.job),
  );
  const shown = (): { text: string; state: StepStateKind | undefined } | null => {
    const d = detail();
    if (over()) {
      const step = d?.job.steps.find((s) => s.state.state === "failed" || s.state.state === "compensation_failed");
      return step ? { text: describeStep(step, d?.preview?.steps[step.index]), state: step.state.state } : null;
    }
    const i = props.job.current_step;
    if (i === null || i === undefined) return null;
    const step = d?.job.steps[i];
    return {
      text: step ? describeStep(step, d?.preview?.steps[i]) : t("jobs.step_position", { n: i + 1, total: props.job.step_count }),
      state: props.job.current_step_state ?? step?.state.state,
    };
  };
  return (
    <Show when={shown()} fallback={<span class="muted">–</span>}>
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
      width: 250,
      fixed: true,
      text: (j) => jobStateWord(j.state),
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
      width: 130,
      text: (j) => j.kind,
      render: (j) => <span class="mono">{j.kind}</span>,
    },
    {
      id: "progress",
      header: () => t("jobs.col.progress"),
      width: 130,
      text: (j) => t("jobs.progress", { done: j.steps_done, total: j.step_count }),
      render: (j) => <span class="num">{t("jobs.progress", { done: j.steps_done, total: j.step_count })}</span>,
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
      width: 130,
      render: (j) => <PrincipalLabel principal={j.created.by} />,
    },
    {
      id: "created",
      header: () => t("jobs.col.created"),
      width: 120,
      render: (j) => <TimeAgo at={j.created.at} />,
    },
    {
      id: "finished",
      header: () => t("jobs.col.finished"),
      width: 120,
      render: (j) => <TimeAgo at={j.finished} />,
    },
  ];
}
