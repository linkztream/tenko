// One job group on the jobs list (/jobs?group=<key>): a line with the jobs of the group by state
// and the parallelism, and above all the grouped checklist of every manual task that waits in
// the group, so a whole move batch can be worked through from one page (design decision 7).
// Tasks are grouped by step kind in the order of a move (intent, DHCP, device, DNS, layer 2,
// observation, cleanup); "Mark done" completes that step without a note, like on the job's page.
//
// The group's jobs come from the list (the API has no group filter, so the list filters on the
// client). The manual tasks are not on the list, so the detail of each job that waits is read
// once per revision (data.ts); a job that changes brings a new revision and is read again.
import { A } from "@solidjs/router";
import { createMemo, createResource, For, Show } from "solid-js";
import { latest } from "../api/live";
import { createStore } from "solid-js/store";
import type { JobState, JobSummary, ObjectRef } from "../api/types";
import { JOB_STATES } from "../api/types";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { shortId } from "../components/Principal";
import { toast } from "../components/toast";
import { formatNumber, t } from "../i18n";
import { canExecuteJob } from "./access";
import { completeStep, mapLimit, readJobDetail } from "./data";
import { groupLabel, kindRank, manualOf, needsPerson } from "./model";
import { undoLine } from "./L2Step";
import { JobStateChip } from "./StateChip";
import { firstHost, TargetLabel } from "./Target";
import { cancelRolledBack, codedErrorText, jobStateClass, jobStateWord, problemText, stepName, taskText } from "./words";
import "./jobs.css";

/** Jobs read at the same time while the tasks of a group load. */
const PARALLEL_READS = 6;

interface ChecklistTask {
  key: string;
  jobId: string;
  /** The targets of the job: whether the account may complete the task depends on them. */
  targets: readonly ObjectRef[];
  index: number;
  kind: string;
  text: string;
  undo: boolean;
  /** The host the job is about, shown next to the task. */
  host: ObjectRef | undefined;
  /** For the undo of a layer 2 change: the setting to put back on the network controller. */
  hint: string | undefined;
}

/** The tag a rolled back move leaves on its object (docs/moves.md): a value, never translated. */
const MOVE_FAILED_TAG = "move-failed";

/** The step kind of a move's layer 2 change through the network controller. */
const CONTROLLER_STEP = "ipam.move.controller";

/**
 * Whether a job of the group ended without its change: rolled back, failed, or rolled back by
 * its cancellation. For a move the object keeps its old address and carries the tag `move-failed`.
 */
export function notMoved(job: JobSummary): boolean {
  return job.state === "rolled_back" || job.state === "failed" || cancelRolledBack(job);
}

interface ItemState {
  status: "idle" | "busy" | "done";
  error?: string | undefined;
}

export function GroupPanel(props: {
  group: string;
  /** Every loaded job of the group, newest first. */
  jobs: readonly JobSummary[];
  /** More pages of the list are still on their way, so the group may not be complete. */
  loading: boolean;
  /** A task was completed: the list reads again. */
  onChanged: () => void;
}) {
  const [items, setItems] = createStore<Record<string, ItemState>>({});

  // The jobs that wait for a person, read again when one of them gets a new revision.
  const waiting = createMemo(() => props.jobs.filter(needsPerson));
  const signature = createMemo(() => waiting().map((j) => `${j.id}@${j.revision}:${j.state}:${j.steps_done}`).join(","));
  const [details] = createResource(signature, async () => {
    const read = await mapLimit(waiting(), PARALLEL_READS, readJobDetail);
    return read.flatMap((d) => (d ? [d] : []));
  });

  // The limit is on the spec of the jobs, not on the list; any job of the group has it.
  const sample = createMemo(() => props.jobs[0]);
  const [limit] = createResource(
    () => {
      const job = sample();
      return job ? `${job.id}@${job.revision}` : false;
    },
    async () => {
      const job = sample();
      return job ? ((await readJobDetail(job))?.job.spec.group_limit ?? null) : null;
    },
  );

  const counts = createMemo(() => {
    const byState = new Map<JobState, number>();
    for (const job of props.jobs) byState.set(job.state, (byState.get(job.state) ?? 0) + 1);
    return JOB_STATES.flatMap((state) => {
      const count = byState.get(state);
      return count ? [[state, count] as const] : [];
    });
  });

  const tasks = createMemo<ChecklistTask[]>(() =>
    (latest(details) ?? []).flatMap((detail) =>
      detail.job.steps.flatMap((step) => {
        const manual = manualOf(step);
        if (!manual) return [];
        const undo = detail.job.state === "rolling_back";
        const line = undo && step.kind === CONTROLLER_STEP ? undoLine(step, detail.preview?.steps[step.index]) : undefined;
        return [
          {
            key: `${detail.job.id}:${step.index}`,
            jobId: detail.job.id,
            targets: detail.job.spec.targets,
            index: step.index,
            kind: step.kind,
            text: taskText(manual.task),
            undo,
            host: firstHost(detail.job.spec.targets),
            hint: line
              ? t("jobs.l2.undo_hint", { path: line.path, before: line.before || t("jobs.l2.absent") })
              : undefined,
          },
        ];
      }),
    ),
  );

  const groups = createMemo(() => {
    const byKind = new Map<string, ChecklistTask[]>();
    for (const task of tasks()) byKind.set(task.kind, [...(byKind.get(task.kind) ?? []), task]);
    return [...byKind.entries()]
      .sort(([a], [b]) => kindRank(a) - kindRank(b) || a.localeCompare(b))
      .map(([kind, list]) => ({ kind, tasks: list }));
  });

  // The jobs that ended without their change, with the reason the job recorded.
  const failed = createMemo(() => props.jobs.filter(notMoved));

  const complete = async (task: ChecklistTask) => {
    setItems(task.key, { status: "busy", error: undefined });
    try {
      await completeStep(task.jobId, task.index, "");
      setItems(task.key, { status: "done" });
      toast({ kind: "ok", title: t("jobs.complete.done", { n: task.index + 1 }) });
      props.onChanged();
    } catch (err) {
      setItems(task.key, { status: "idle", error: problemText(err) });
    }
  };

  return (
    <section class="job-group" aria-labelledby="job-group-title" data-testid="job-group">
      <div class="job-group-head">
        <h2 id="job-group-title">{t("jobs.group.heading", { group: groupLabel(props.group) })}</h2>
        <p class="job-group-summary" data-testid="job-group-summary">
          <span>{t("jobs.group.summary", { count: props.jobs.length })}</span>
          <For each={counts()}>
            {([state, count]) => (
              <span class={`jstate ${jobStateClass(state)}`} data-state={state} data-testid="job-group-state" data-key={state}>
                {formatNumber(count)} {jobStateWord(state)}
              </span>
            )}
          </For>
          <Show when={limit()}>
            {(max) => <span class="muted">{t("jobs.group.limit", { limit: max() })}</span>}
          </Show>
        </p>
      </div>

      <div class="job-group-tasks" data-testid="job-group-checklist" aria-busy={details.loading || props.loading}>
        <div class="job-group-tasks-head">
          <h3>{t("jobs.checklist.heading")}</h3>
          <span class="muted">{t("jobs.checklist.open", { count: tasks().length })}</span>
        </div>
        <p class="muted">{t("jobs.checklist.hint")}</p>
        <Show
          when={groups().length > 0}
          fallback={
            <p class="muted" role="status">
              {details.loading || props.loading ? t("jobs.checklist.loading") : t("jobs.checklist.empty")}
            </p>
          }
        >
          <For each={groups()}>
            {(group) => (
              <section class="check-group" data-kind={group.kind} data-testid="job-group-kind" data-key={group.kind}>
                <h4>{t("jobs.checklist.group", { name: stepName(group.kind), count: group.tasks.length })}</h4>
                <ul class="check-list">
                  <For each={group.tasks}>
                    {(task) => (
                      <li class="check-item" data-testid="job-group-task" data-job={task.jobId} data-index={task.index}>
                        <div class="check-text">
                          <Show when={task.undo}>
                            <span class="tag">{t("jobs.tag.undo")}</span>{" "}
                          </Show>
                          <Show when={task.host}>
                            {(host) => (
                              <>
                                <strong class="check-host">
                                  <TargetLabel target={host()} />
                                </strong>{" "}
                              </>
                            )}
                          </Show>
                          <span>{task.text}</span>
                          <Show when={task.hint}>
                            {(hint) => (
                              <p class="l2-hint" data-testid="job-group-l2-hint">
                                {hint()}
                              </p>
                            )}
                          </Show>
                          <Show when={items[task.key]?.error}>
                            {(message) => (
                              <p class="help bad field-error" role="alert">
                                <Icon name="alert" size="sm" />
                                <span>{message()}</span>
                              </p>
                            )}
                          </Show>
                        </div>
                        <A class="mono check-job" href={paths.job(task.jobId)} data-testid="job-group-task-link">
                          {shortId(task.jobId)}
                        </A>
                        <button
                          type="button"
                          class="btn sm"
                          data-testid="job-group-task-complete"
                          aria-label={t("jobs.checklist.mark_done", { task: task.text })}
                          disabled={!canExecuteJob({ id: task.jobId, targets: task.targets }) || (items[task.key]?.status ?? "idle") !== "idle"}
                          title={canExecuteJob({ id: task.jobId, targets: task.targets }) ? undefined : t("jobs.no_right")}
                          onClick={() => void complete(task)}
                        >
                          {t("jobs.complete.button")}
                        </button>
                      </li>
                    )}
                  </For>
                </ul>
              </section>
            )}
          </For>
        </Show>
      </div>

      <Show when={failed().length > 0}>
        <div class="job-group-failed" data-testid="job-group-not-moved">
          <div class="job-group-tasks-head">
            <h3>{t("jobs.group.not_moved.heading")}</h3>
            <span class="muted">{t("jobs.group.not_moved.count", { count: failed().length })}</span>
          </div>
          <p class="muted">{t("jobs.group.not_moved.hint")}</p>
          <ul class="check-list">
            <For each={failed()}>
              {(job) => (
                <li class="check-item" data-testid="job-group-not-moved-item" data-job={job.id} data-state={job.state}>
                  <div class="check-text">
                    <Show when={firstHost(job.targets)}>
                      {(host) => (
                        <>
                          <strong class="check-host">
                            <TargetLabel target={host()} />
                          </strong>{" "}
                        </>
                      )}
                    </Show>
                    <JobStateChip state={job.state} rollback={cancelRolledBack(job) ? "cancel" : undefined} />{" "}
                    <Show when={job.kind === "ipam.move"}>
                      <span class="tag mono" data-testid="job-group-move-failed">
                        {MOVE_FAILED_TAG}
                      </span>
                    </Show>
                    <p class="help" data-testid="job-group-not-moved-reason">
                      {job.error ? codedErrorText(job.error) : t("jobs.group.not_moved.no_reason")}
                    </p>
                  </div>
                  <A class="mono check-job" href={paths.job(job.id)} data-testid="job-group-not-moved-link">
                    {shortId(job.id)}
                  </A>
                </li>
              )}
            </For>
          </ul>
        </div>
      </Show>
    </section>
  );
}
