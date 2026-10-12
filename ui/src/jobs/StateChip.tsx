// The glyph and the word of a job state or a step state (design.css `.jstate`): a filling pie
// for running work, a dashed ring for waiting, a ring and a dot for done, a diamond for failed,
// an open ring for rolled back. The glyph never stands alone, so color is never the only cue.
import type { JobState, StepStateKind } from "../api/types";
import { progressPercent } from "./model";
import { jobStateClass, jobStateText, stepStateClass, stepStateWord } from "./words";
import "./jobs.css";

/**
 * The state of a job. A running job shows its progress in the pie when the step counts are given.
 * A cancelled job that its cancellation rolled back (`rollback="cancel"`, see `cancelRolledBack`)
 * looks like a rolled back one and says so, with `data-rollback="cancel"`.
 */
export function JobStateChip(props: {
  state: JobState;
  done?: number | undefined;
  total?: number | undefined;
  rollback?: "cancel" | undefined;
}) {
  const style = () =>
    props.state === "running" && props.total !== undefined
      ? { "--p": `${progressPercent(props.done ?? 0, props.total)}%` }
      : undefined;
  const byCancel = () => props.rollback === "cancel" && props.state === "cancelled";
  return (
    <span
      class={`jstate ${byCancel() ? "rolledback" : jobStateClass(props.state)}`}
      style={style()}
      data-state={props.state}
      data-rollback={byCancel() ? "cancel" : undefined}
      data-testid="job-state"
    >
      {jobStateText(props.state, props.rollback)}
    </span>
  );
}

/** The state of one step of a job. */
export function StepStateChip(props: { state: StepStateKind }) {
  return (
    <span class={`jstate ${stepStateClass(props.state)}`} data-state={props.state} data-testid="job-step-state">
      {stepStateWord(props.state)}
    </span>
  );
}
