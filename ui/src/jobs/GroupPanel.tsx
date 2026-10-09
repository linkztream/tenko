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
import { createStore } from "solid-js/store";
import type { JobState, JobSummary, ObjectRef } from "../api/types";
import { JOB_STATES } from "../api/types";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { shortId } from "../components/Principal";
import { toast } from "../components/toast";
import { formatNumber, t } from "../i18n";
import { completeStep, mapLimit, readJobDetail } from "./data";
import { groupLabel, kindRank, manualOf, needsPerson } from "./model";
import { firstHost, TargetLabel } from "./Target";
import { jobStateClass, jobStateWord, problemText, stepName, taskText } from "./words";
import "./jobs.css";

/** Jobs read at the same time while the tasks of a group load. */
const PARALLEL_READS = 6;

interface ChecklistTask {
  key: string;
  jobId: string;
  index: number;
  kind: string;
  text: string;
  undo: boolean;
  /** The host the job is about, shown next to the task. */
  host: ObjectRef | undefined;
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
  canExecute: boolean;
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
    (details.latest ?? []).flatMap((detail) =>
      detail.job.steps.flatMap((step) => {
        const manual = manualOf(step);
        if (!manual) return [];
        return [
          {
            key: `${detail.job.id}:${step.index}`,
            jobId: detail.job.id,
            index: step.index,
            kind: step.kind,
            text: taskText(manual.task),
            undo: detail.job.state === "rolling_back",
            host: firstHost(detail.job.spec.targets),
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
              <span class={`jstate ${jobStateClass(state)}`} data-state={state}>
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
              <section class="check-group" data-kind={group.kind}>
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
                          <Show when={items[task.key]?.error}>
                            {(message) => (
                              <p class="help bad field-error" role="alert">
                                <Icon name="alert" size="sm" />
                                <span>{message()}</span>
                              </p>
                            )}
                          </Show>
                        </div>
                        <A class="mono check-job" href={paths.job(task.jobId)}>
                          {shortId(task.jobId)}
                        </A>
                        <button
                          type="button"
                          class="btn sm"
                          data-testid="job-group-task-complete"
                          aria-label={t("jobs.checklist.mark_done", { task: task.text })}
                          disabled={!props.canExecute || (items[task.key]?.status ?? "idle") !== "idle"}
                          title={props.canExecute ? undefined : t("jobs.no_right")}
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
    </section>
  );
}
