// What the nudge step of a move job (`ipam.move.nudge`, ADR 0028) shows under its head: the client
// came back by itself (when, and whether its DHCP exchange or its lease showed it), or the switch
// port went down and up again, or the client was disconnected from its access point, or why
// nothing was done; a step that ran again after an interruption says it did not nudge twice.
//
// The step keeps its output as hex-encoded JSON (`MoveNudgeOutput`); output that is absent or
// cannot be read shows nothing, and the head of the step says the rest. The port that did not come
// up again fails the step: its error (`connect.port_stuck`) is shown with the step's other errors.
import { Show } from "solid-js";
import { decodeMoveNudgeOutput } from "../api/moves";
import type { StepPreview, StepRecord } from "../api/types";
import { TimeAgo } from "../grid/cells";
import { t, tDynamic, tx } from "../i18n";
import { Line } from "./L2Step";

/** The words for a code of a refused or failed nudge: its translation, else the English detail, else the code. */
function reasonText(code: string, detail: string | undefined, params: Record<string, string | number>): string {
  return tDynamic(`errors.${code}`, params) ?? (detail || code);
}

/** A time as "5 minutes ago"; a dash when the report has none. */
const ago = (at: string | null | undefined) => (at ? <TimeAgo at={at} /> : "–");

/** The details of the nudge step of a move job; `preview` names the switch or access point. */
export function NudgeStep(props: { step: StepRecord; preview?: StepPreview | undefined }) {
  const output = () => decodeMoveNudgeOutput(props.step.output);
  // Output of a step that has not run is not an outcome yet.
  const ran = () => props.step.state.state !== "pending" && props.step.state.state !== "running";
  const port = () => {
    const change = output()?.change;
    return change?.type === "bounce_port" ? change.data.port : undefined;
  };
  const device = () => {
    const change = output()?.change;
    return props.preview?.args?.device ?? (change?.type === "bounce_port" ? change.data.device : "?");
  };
  const failure = (code: string, detail: string | undefined, connector: string) =>
    reasonText(code, detail, { connector, device: device(), port: port() ?? "?", cause: detail ?? "" });

  return (
    <Show when={ran() ? output() : undefined}>
      {(out) => (
        <div class="step-l2" role="group" aria-label={t("jobs.nudge.title")} data-testid="job-nudge">
          <Show when={out().reappeared_at}>
            {(at) => (
              <Line testid="job-nudge-reappeared" icon="check" kind="ok">
                {tx(out().reappeared_by === "lease" ? "jobs.nudge.reappeared_lease" : "jobs.nudge.reappeared_dhcp", {
                  when: ago(at()),
                })}
              </Line>
            )}
          </Show>
          <Show when={out().report}>
            {(report) => (
              <Show
                when={report().outcome === "done"}
                fallback={
                  <Line testid="job-nudge-failed" icon="alert" kind="warn">
                    {t("jobs.nudge.failed", {
                      reason: failure(report().code ?? "", report().detail, report().connector),
                    })}
                  </Line>
                }
              >
                <Show
                  when={report().change.type === "bounce_port"}
                  fallback={
                    <Line testid="job-nudge-kicked" icon="check" kind="ok">
                      {tx("jobs.nudge.kicked", { when: ago(report().at ?? props.step.finished) })}
                    </Line>
                  }
                >
                  <Line testid="job-nudge-bounced" icon="check" kind="ok">
                    {report().up_at
                      ? tx("jobs.nudge.bounced", {
                          port: port() ?? "?",
                          device: device(),
                          down: ago(report().at),
                          up: ago(report().up_at),
                        })
                      : tx("jobs.nudge.bounced_down", { port: port() ?? "?", device: device(), down: ago(report().at) })}
                  </Line>
                </Show>
              </Show>
            )}
          </Show>
          <Show when={!out().report ? out().problem : undefined}>
            {(problem) => (
              <Line testid="job-nudge-failed" icon="alert" kind="warn">
                {t("jobs.nudge.failed", { reason: reasonText(problem().code, problem().detail, {}) })}
              </Line>
            )}
          </Show>
          <Show when={out().interrupted}>
            <Line testid="job-nudge-interrupted" icon="info">
              {t("jobs.nudge.interrupted")}
            </Line>
          </Show>
        </div>
      )}
    </Show>
  );
}
