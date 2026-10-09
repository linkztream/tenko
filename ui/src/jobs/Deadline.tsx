// The deadline of a step that waits: a countdown that ticks with the one-second clock of the
// shell, with the exact time as the tooltip. After the deadline it says so and that the job
// rolls back by itself. The countdown sits in no live region, so a screen reader does not
// read it out every second; it reads the text when the reader gets there.
import { Show } from "solid-js";
import { formatDateTime, t, tx } from "../i18n";
import { now } from "../shell/status";
import { countdownParts } from "./model";

/** "10 h 59 min", "4 min 12 s", "45 s". */
export function countdownText(seconds: number): string {
  return countdownParts(seconds)
    .map((part) => t(`jobs.duration.${part.unit}`, { value: part.value }))
    .join(" ");
}

/** The deadline sentence for a point in time, counting down while it lies ahead. */
export function Deadline(props: { at: string }) {
  const remaining = () => (Date.parse(props.at) - now()) / 1000;
  return (
    <Show when={remaining() > 0} fallback={<span data-testid="job-deadline-passed">{t("jobs.deadline.passed")}</span>}>
      <span data-testid="job-deadline">
        {tx("jobs.deadline.line", {
          when: (
            <time datetime={props.at} title={formatDateTime(props.at, { dateStyle: "medium", timeStyle: "medium" })}>
              {t("jobs.deadline.in", { time: countdownText(remaining()) })}
            </time>
          ),
        })}
      </span>
    </Show>
  );
}
