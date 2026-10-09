// The transition log of a job (IPAM-17): every change of the job and of its steps, oldest
// first, with who caused it and the note of a manual task. Every transition is also in the
// audit log; this is the job's own view of it.
import { For, Show } from "solid-js";
import type { JobDetail, Transition } from "../api/types";
import { PrincipalLabel } from "../components/Principal";
import { formatDateTime, t, tDynamic } from "../i18n";
import { describeStep, jobStateWord, stepStateWord } from "./words";

function eventText(row: Transition): string {
  switch (row.event) {
    case "submitted":
      return t("jobs.event.submitted");
    case "claimed":
      return t("jobs.event.claimed");
    case "cancel_requested":
      return t("jobs.event.cancel_requested");
    case "step":
      return t("jobs.event.step");
    case "job":
      return (row.action ? tDynamic(`jobs.action.${row.action}`) : undefined) ?? row.action ?? row.event;
  }
}

/** What changed: the job from one state to the next, a step to its new state, or the state a job began in. */
function changeText(row: Transition): string {
  if (row.event === "step" && row.step_state) return stepStateWord(row.step_state.state);
  if (row.event === "job" && row.from && row.from !== row.state) {
    return t("jobs.log.change", { from: jobStateWord(row.from), to: jobStateWord(row.state) });
  }
  return jobStateWord(row.state);
}

export function TransitionLog(props: { detail: JobDetail }) {
  const stepText = (index: number) => {
    const step = props.detail.job.steps[index];
    return step ? describeStep(step, props.detail.preview?.steps[index]) : "";
  };
  return (
    <div class="table-wrap">
      <table class="plain job-log" aria-label={t("jobs.log.label")} data-testid="job-log">
        <thead>
          <tr>
            <th scope="col">{t("jobs.log.col.time")}</th>
            <th scope="col">{t("jobs.log.col.event")}</th>
            <th scope="col">{t("jobs.log.col.by")}</th>
            <th scope="col">{t("jobs.log.col.change")}</th>
            <th scope="col">{t("jobs.log.col.step")}</th>
            <th scope="col">{t("jobs.log.col.note")}</th>
          </tr>
        </thead>
        <tbody>
          <For each={props.detail.transitions}>
            {(row) => (
              <tr data-testid="job-log-row" data-seq={row.seq}>
                <td class="num">
                  <time datetime={row.at}>{formatDateTime(row.at, { dateStyle: "medium", timeStyle: "medium" })}</time>
                </td>
                <td>{eventText(row)}</td>
                <td>
                  <PrincipalLabel principal={row.by} />
                </td>
                <td>{changeText(row)}</td>
                <td class="log-step">
                  <Show when={row.step !== null && row.step !== undefined}>
                    <span class="num">{(row.step ?? 0) + 1}</span> <span class="muted">{stepText(row.step ?? 0)}</span>
                  </Show>
                </td>
                <td class="log-note" data-testid="job-log-note">
                  {row.note}
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}
