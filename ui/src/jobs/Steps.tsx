// The steps of a job, in order: what each does, its state in glyph and word, when it ran, and for
// a step that waits for a person the task, a note and "Mark done". The list keeps one element
// per step across refreshes (`Index`), so a note that is being typed survives a live update.
import { createSignal, createUniqueId, Index, Match, Show, Switch } from "solid-js";
import type { JobDetail, ManualTask, StepRecord } from "../api/types";
import { Icon } from "../components/Icon";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { formatList, t, tx } from "../i18n";
import { completeStep } from "./data";
import { Deadline } from "./Deadline";
import { MAX_NOTE_BYTES, manualOf, noteBytes, observationOf, stepErrorOf } from "./model";
import { StepStateChip } from "./StateChip";
import { codedErrorDetail, codedErrorText, describeStep, problemText, stepName, taskText } from "./words";

/** What a step that waits for an observation waits for, as one sentence. */
function observationText(step: StepRecord): string {
  const data = observationOf(step);
  if (!data) return "";
  const parts = data.condition.any_of.map((predicate) => {
    if (predicate.type === "address_seen") {
      const { ip, mac } = predicate.data;
      return mac ? t("jobs.observe.address_seen_mac", { ip, mac }) : t("jobs.observe.address_seen", { ip });
    }
    if (predicate.type === "lease_in_prefix") return t("jobs.observe.lease", { mac: predicate.data.mac });
    return t("jobs.observe.other");
  });
  return t("jobs.observe.waiting", { what: formatList(parts, "disjunction") });
}

/**
 * The task of a step that waits for a person: its text, the deadline, an optional note and the
 * button that tells the job the task is done. The note is limited in bytes, like on the server,
 * and a note that is too long is refused here, before anything is sent.
 */
export function ManualStep(props: {
  jobId: string;
  index: number;
  task: ManualTask;
  deadline: string | null;
  /** The job rolls back: this is a task that undoes a step. */
  undo: boolean;
  canExecute: boolean;
  onDone: () => void;
}) {
  const uid = createUniqueId();
  let area!: HTMLTextAreaElement;
  const [note, setNote] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(undefined);
  const used = () => noteBytes(note());
  const over = () => Math.max(0, used() - MAX_NOTE_BYTES);

  const submit = async () => {
    if (over() > 0) {
      area.focus();
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      await completeStep(props.jobId, props.index, note());
      toast({ kind: "ok", title: t("jobs.complete.done", { n: props.index + 1 }) });
      setNote("");
      props.onDone();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="step-task" data-testid="job-step-task">
      <p class="task-text">
        <Show when={props.undo}>
          <span class="tag">{t("jobs.tag.undo")}</span>{" "}
        </Show>
        {taskText(props.task)}
      </p>
      <Show when={props.deadline}>{(at) => <p class="step-deadline"><Deadline at={at()} /></p>}</Show>
      <div class="field">
        <label for={`note-${uid}`}>{t("jobs.note.label")}</label>
        <textarea
          ref={area}
          id={`note-${uid}`}
          class="input"
          rows={2}
          value={note()}
          disabled={!props.canExecute}
          aria-invalid={over() > 0 ? "true" : undefined}
          aria-describedby={`note-help-${uid} note-count-${uid}`}
          data-testid="job-step-note"
          onInput={(e) => setNote(e.currentTarget.value)}
        />
        <div class="note-meta">
          <span class="help" id={`note-help-${uid}`}>
            {t("jobs.note.help")}
          </span>
          <span class="help num" classList={{ bad: over() > 0 }} id={`note-count-${uid}`} data-testid="job-step-note-count">
            {t("jobs.note.counter", { used: used(), max: MAX_NOTE_BYTES })}
          </span>
        </div>
        <Show when={over() > 0}>
          <p class="help bad field-error" role="alert" data-testid="job-step-note-over">
            <Icon name="alert" size="sm" />
            <span>{t("jobs.note.over", { over: over() })}</span>
          </p>
        </Show>
      </div>
      <div class="form-row">
        <button
          type="button"
          class="btn primary"
          data-testid="job-step-complete"
          data-index={props.index}
          disabled={busy() || !props.canExecute}
          onClick={() => void submit()}
        >
          {t("jobs.complete.button")}
        </button>
        <Show when={!props.canExecute}>
          <span class="help">{t("jobs.no_right")}</span>
        </Show>
      </div>
      <Show when={error()}>
        {(err) => (
          <p class="help bad field-error" role="alert" data-testid="job-step-error">
            <Icon name="alert" size="sm" />
            <span>{problemText(err())}</span>
          </p>
        )}
      </Show>
    </div>
  );
}

function StepItem(props: {
  step: StepRecord;
  detail: JobDetail;
  canExecute: boolean;
  onChanged: () => void;
}) {
  const state = () => props.step.state.state;
  const manual = () => manualOf(props.step);
  // The summary of a manual step is the text of its task, which is shown below: the head then
  // names the step in a few words, so the sentence is not there twice.
  const summary = () => {
    const text = describeStep(props.step, props.detail.preview?.steps[props.step.index]);
    const task = manual();
    return task && taskText(task.task) === text ? stepName(props.step.kind) : text;
  };
  const error = () => stepErrorOf(props.step);
  const rollingBack = () => props.detail.job.state === "rolling_back";

  return (
    <li class="job-step" data-testid="job-step" data-index={props.step.index} data-state={state()}>
      <span class="step-no num" aria-hidden="true">
        {props.step.index + 1}
      </span>
      <div class="step-body">
        <div class="step-head">
          <span class="step-summary">{summary()}</span>
          <StepStateChip state={state()} />
        </div>
        <Show when={props.step.started || props.step.finished || (props.step.attempts ?? 0) > 0}>
          <p class="step-meta muted">
            <Show when={props.step.started}>
              {(at) => <span>{tx("jobs.stepmeta.started", { when: <TimeAgo at={at()} /> })}</span>}
            </Show>
            <Show when={props.step.finished}>
              {(at) => <span>{tx("jobs.stepmeta.finished", { when: <TimeAgo at={at()} /> })}</span>}
            </Show>
            <Show when={(props.step.attempts ?? 0) > 0}>
              <span>{t("jobs.stepmeta.attempts", { count: props.step.attempts ?? 0 })}</span>
            </Show>
          </p>
        </Show>
        <Switch>
          <Match when={manual()}>
            {(m) => (
              <ManualStep
                jobId={props.detail.job.id}
                index={props.step.index}
                task={m().task}
                deadline={m().deadline}
                undo={rollingBack()}
                canExecute={props.canExecute}
                onDone={props.onChanged}
              />
            )}
          </Match>
          <Match when={observationOf(props.step)}>
            {(o) => (
              <div class="step-task">
                <p class="task-text">{observationText(props.step)}</p>
                <p class="step-deadline">
                  <Deadline at={o().deadline} />
                </p>
              </div>
            )}
          </Match>
          <Match when={error()}>
            {(e) => (
              <p class="step-error" data-testid="job-step-failure">
                <Icon name="alert" size="sm" />
                <span>
                  {codedErrorText(e())}
                  <Show when={codedErrorDetail(e())}>
                    {(detail) => (
                      <>
                        {" "}
                        <span class="muted">{t("jobs.problem.detail", { detail: detail() })}</span>
                      </>
                    )}
                  </Show>
                </span>
              </p>
            )}
          </Match>
        </Switch>
      </div>
    </li>
  );
}

/** The ordered list of steps of a job. */
export function StepList(props: { detail: JobDetail; canExecute: boolean; onChanged: () => void }) {
  return (
    <ol class="job-steps" aria-label={t("jobs.steps.label")} data-testid="job-steps">
      <Index each={props.detail.job.steps}>
        {(step) => <StepItem step={step()} detail={props.detail} canExecute={props.canExecute} onChanged={props.onChanged} />}
      </Index>
    </ol>
  );
}
