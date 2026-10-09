// The glyph and the word of a job state or a step state (design.css `.jstate`): a filling pie
// for running work, a dashed ring for waiting, a ring and a dot for done, a diamond for failed,
// an open ring for rolled back. The glyph never stands alone, so color is never the only cue.
import type { JobState, StepStateKind } from "../api/types";
import { progressPercent } from "./model";
import { jobStateClass, jobStateWord, stepStateClass, stepStateWord } from "./words";
import "./jobs.css";

/** The state of a job. A running job shows its progress in the pie when the step counts are given. */
export function JobStateChip(props: { state: JobState; done?: number | undefined; total?: number | undefined }) {
  const style = () =>
    props.state === "running" && props.total !== undefined
      ? { "--p": `${progressPercent(props.done ?? 0, props.total)}%` }
      : undefined;
  return (
    <span class={`jstate ${jobStateClass(props.state)}`} style={style()} data-state={props.state}>
      {jobStateWord(props.state)}
    </span>
  );
}

/** The state of one step of a job. */
export function StepStateChip(props: { state: StepStateKind }) {
  return (
    <span class={`jstate ${stepStateClass(props.state)}`} data-state={props.state}>
      {stepStateWord(props.state)}
    </span>
  );
}
