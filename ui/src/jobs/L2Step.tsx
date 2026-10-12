// What the L2 step of a move job (`ipam.move.controller`, the change through the network
// controller) shows under its head: the planned change while the step has not run; once it has
// run, what it changed (the controller's read-back diff), the receipt of the write and the
// controller's warnings; during a rollback, whether the controller has the previous setting again
// or a person has to put it back, and which setting that is.
//
// The step keeps its output as hex-encoded JSON (`MoveL2Output`); output that is absent or cannot
// be read shows no diff, and the head of the step says the rest.
import { createMemo, createUniqueId, For, Show, type JSX } from "solid-js";
import { decodeMoveL2Output, type DiffEntry, type MoveL2Output } from "../api/moves";
import type { JobState, StepPreview, StepRecord } from "../api/types";
import { Icon, type IconName } from "../components/Icon";
import { TimeAgo } from "../grid/cells";
import { t, tx } from "../i18n";
import { manualOf } from "./model";

/**
 * The planned change from the arguments of the step in the job preview: the first line of the
 * diff the server found when the move was previewed. Without a path there is nothing to show.
 */
export function plannedLine(preview: StepPreview | undefined): DiffEntry | undefined {
  const args = preview?.args;
  if (!args?.path) return undefined;
  return { path: args.path, before: args.before ?? null, after: args.after ?? null };
}

/**
 * The setting a person puts back when the rollback of the L2 step asks for it: the first line of
 * the controller's diff, or the planned line when an interrupted attempt left an empty diff. The
 * step's page and the group checklist show it as the undo hint.
 */
export function undoLine(step: StepRecord, preview: StepPreview | undefined): DiffEntry | undefined {
  return decodeMoveL2Output(step.output)?.diff?.[0] ?? plannedLine(preview);
}

/** Whether the controller was written to (or may have been): only then a rollback has anything to undo. */
function wrote(output: MoveL2Output): boolean {
  if (output.unchanged) return false;
  return !!output.unknown_write || (!!output.receipt && !output.receipt.dry_run);
}

function Absent() {
  return <span class="muted">{t("jobs.l2.absent")}</span>;
}

/** A path of the controller; a long one may break after a slash. */
function Path(props: { path: string }) {
  return (
    <For each={props.path.split("/")}>
      {(part, i) => (
        <>
          {i() > 0 ? "/" : ""}
          {i() > 0 ? <wbr /> : null}
          {part}
        </>
      )}
    </For>
  );
}

function Value(props: { value: string | null | undefined }) {
  return (
    <Show when={props.value != null && props.value !== ""} fallback={<Absent />}>
      <span class="mono">{props.value}</span>
    </Show>
  );
}

/** Setting, before and after of the lines of a diff. */
function DiffTable(props: { lines: readonly DiffEntry[]; label: string; testid: string }) {
  return (
    <div class="l2-diff-wrap">
      <table class="plain l2-diff" data-testid={props.testid}>
        <caption class="l2-label">{props.label}</caption>
        <thead>
          <tr>
            <th scope="col">{t("jobs.l2.col.path")}</th>
            <th scope="col">{t("jobs.l2.col.before")}</th>
            <th scope="col">{t("jobs.l2.col.after")}</th>
          </tr>
        </thead>
        <tbody>
          <For each={props.lines}>
            {(line) => (
              <tr data-testid="job-l2-diff-line" data-path={line.path}>
                <th scope="row" class="mono l2-path">
                  <Path path={line.path} />
                </th>
                <td class="l2-before">
                  <Value value={line.before} />
                </td>
                <td class="l2-after">
                  <Value value={line.after} />
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

function Line(props: { testid: string; icon: IconName; kind?: "ok" | "warn"; children: JSX.Element }) {
  return (
    <p class="l2-line" classList={{ ok: props.kind === "ok", warn: props.kind === "warn" }} data-testid={props.testid}>
      <Icon name={props.icon} size="sm" />
      <span>{props.children}</span>
    </p>
  );
}

/**
 * The details of the L2 step of a move job. `preview` is the step's entry in the job preview
 * (its arguments name the planned change) and `jobState` tells a rollback from a run.
 */
export function L2Step(props: { step: StepRecord; preview?: StepPreview | undefined; jobState: JobState }) {
  const uid = createUniqueId();
  const output = createMemo(() => decodeMoveL2Output(props.step.output));
  const state = () => props.step.state.state;
  const planned = createMemo(() => plannedLine(props.preview));

  // The planned change is shown while the step has not run; after that the output is the truth.
  const plan = () => (!output() && (state() === "pending" || state() === "running") ? planned() : undefined);
  const lines = () => output()?.diff ?? [];
  const receipt = () => {
    const r = output()?.receipt;
    return r && !r.dry_run ? r : undefined;
  };
  const warnings = () => (output()?.warnings ?? []).filter((w) => typeof w === "string" && w !== "");
  const reverted = () => {
    const out = output();
    return state() === "compensated" && out !== undefined && wrote(out);
  };
  // A manual undo task of this step: the rollback could not put the setting back by itself.
  const asksPerson = () => props.jobState === "rolling_back" && manualOf(props.step) !== undefined;
  // The first line of the diff; an interrupted attempt leaves an empty diff, then the planned line stands in.
  const hint = () => (asksPerson() ? (lines()[0] ?? planned()) : undefined);

  const any = () => plan() || output() || hint();

  return (
    <Show when={any()}>
      <div class="step-l2" role="group" aria-label={t("jobs.l2.title")} data-testid="job-l2">
        <Show when={plan()}>
          {(line) => <DiffTable lines={[line()]} label={t("jobs.l2.planned")} testid="job-l2-planned" />}
        </Show>
        <Show when={output()}>
          {(out) => (
            <>
              <Show when={lines().length > 0}>
                <DiffTable lines={lines()} label={t("jobs.l2.diff")} testid="job-l2-diff" />
              </Show>
              <Show when={out().unchanged}>
                <Line testid="job-l2-unchanged" icon="info">
                  {t("jobs.l2.unchanged")}
                </Line>
              </Show>
              <Show when={receipt()}>
                {(r) => (
                  <>
                    <Line testid="job-l2-receipt" icon="check" kind="ok">
                      {tx("jobs.l2.receipt", { when: <TimeAgo at={r().applied_at} />, count: r().undo_steps })}
                    </Line>
                    <Show when={r().undo_steps === 0}>
                      <Line testid="job-l2-no-undo" icon="alert" kind="warn">
                        {t("jobs.l2.no_undo")}
                      </Line>
                    </Show>
                  </>
                )}
              </Show>
              <Show when={out().unknown_write}>
                <Line testid="job-l2-unknown-write" icon="alert" kind="warn">
                  {t("jobs.l2.unknown_write")}
                </Line>
              </Show>
              <Show when={reverted()}>
                <Line testid="job-l2-reverted" icon="undo" kind="ok">
                  {t("jobs.l2.reverted")}
                </Line>
              </Show>
              <Show when={warnings().length > 0}>
                <div class="l2-warnings" data-testid="job-l2-warnings">
                  <p class="l2-label" id={`l2-warnings-${uid}`}>
                    {t("jobs.l2.warnings")}
                  </p>
                  <ul aria-labelledby={`l2-warnings-${uid}`}>
                    <For each={warnings()}>{(warning) => <li>{warning}</li>}</For>
                  </ul>
                </div>
              </Show>
            </>
          )}
        </Show>
        {/* Last, so it sits right above the task and the form of the undo step. */}
        <Show when={hint()}>
          {(line) => (
            <p class="l2-hint" data-testid="job-l2-undo-hint">
              {t("jobs.l2.undo_hint", { path: line().path, before: line().before || t("jobs.l2.absent") })}
            </p>
          )}
        </Show>
      </div>
    </Show>
  );
}
