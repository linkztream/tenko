// The settings page for backups (WP3.11b, OPS-07; docs/backup.md): the state of the backups with
// the conditions to look at (stale, failed, restored), "Back up now" with an optional passphrase,
// the interval schedule with how many backups are kept, the newest backups of every controller
// and the command that restores one of them on a new host. Restoring and downloading are not
// offered in the UI in Phase 1. Administrators only; a change needs a sign-in within the last
// five minutes (`auth.step_up_required`).
import { A, useNavigate } from "@solidjs/router";
import { createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery, latest } from "../../api/live";
import { isApiError } from "../../api/problem";
import { paths } from "../../app/paths";
import { copyText } from "../../auth/account/shared";
import { signOut } from "../../auth/session";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { formatDateTime, formatRelative, t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";
import {
  ageText,
  draftErrors,
  draftOf,
  intervalText,
  MAX_INTERVAL_HOURS,
  MAX_KEEP,
  MIN_INTERVAL_HOURS,
  MIN_KEEP,
  MIN_PASSPHRASE,
  needsRecipient,
  outcomeText,
  reasonText,
  restoreCommand,
  scheduleText,
  settingsBody,
  sizeText,
  slotsText,
  warningText,
  type BackupRun,
  type BackupSettings,
  type BackupStatus,
  type RestoreNotice,
  type ScheduleDraft,
} from "./model";
import "../settings.css";
import "./backup.css";

export default function BackupPage() {
  const status = createLiveQuery<BackupStatus>({
    topics: ["system"],
    fetch: async (signal) => {
      const value = await api.get("/api/v1/system/backups", { signal });
      return { value };
    },
  });
  const [creating, setCreating] = createSignal(false);
  const [restoring, setRestoring] = createSignal<BackupRun | null>(null);
  const [stepUp, setStepUp] = createSignal(false);
  const [job, setJob] = createSignal<string | null>(null);

  return (
    <div class="page" data-testid="page-backup">
      <PageHead title={t("backup.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("backup.lede")}</p>
        <ErrorNotice error={status.value.error} />
        <Show when={stepUp()}>
          <StepUp />
        </Show>
        <Show when={latest(status)} fallback={<Show when={!status.value.error}><p class="muted" role="status">{t("common.loading")}</p></Show>}>
          {(s) => (
            <>
              <Show when={s().warnings.length > 0}>
                <div class="bk-warnings" data-testid="backup-warnings">
                  <For each={s().warnings}>
                    {(warning) => (
                      <Notice kind="warn" role="status" testid="backup-warning" code={warning.code}>
                        {warningText(warning)}
                      </Notice>
                    )}
                  </For>
                </div>
              </Show>
              <Show when={s().restored}>{(notice) => <RestoredNotice notice={notice()} />}</Show>

              <section class="page-section" aria-labelledby="backup-state" data-testid="backup-status">
                <div class="bk-head">
                  <h2 id="backup-state">{t("backup.state.heading")}</h2>
                  <button
                    type="button"
                    class="btn primary"
                    data-testid="backup-now"
                    disabled={s().running}
                    onClick={() => {
                      setStepUp(false);
                      setCreating(true);
                    }}
                  >
                    <Icon name="disk" size="sm" />
                    {s().running ? t("backup.running") : t("backup.now")}
                  </button>
                </div>
                <StateFacts status={s()} />
                <Show when={job()}>
                  {(id) => (
                    <p class="muted" data-testid="backup-job">
                      <A href={paths.job(id())}>{t("backup.job_link")}</A>
                    </p>
                  )}
                </Show>
              </section>

              <section class="page-section" aria-labelledby="backup-schedule" data-testid="backup-schedule">
                <h2 id="backup-schedule">{t("backup.schedule.heading")}</h2>
                {/* The form starts again from the stored settings when their revision changes. */}
                <Show when={`${s().settings.revision ?? "none"}`} keyed>
                  {(_revision) => <ScheduleForm settings={s().settings} onSaved={() => status.refetch()} onStepUp={() => setStepUp(true)} />}
                </Show>
              </section>

              <section class="page-section" aria-labelledby="backup-runs" data-testid="backup-runs">
                <h2 id="backup-runs">{t("backup.runs.heading")}</h2>
                <Show when={s().recent.length > 0} fallback={<p class="muted" data-testid="backup-runs-empty">{t("backup.runs.none")}</p>}>
                  <div class="table-wrap">
                    <table class="plain">
                      <caption class="sr-only">{t("backup.runs.heading")}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{t("backup.runs.col.finished")}</th>
                          <th scope="col">{t("backup.runs.col.outcome")}</th>
                          <th scope="col">{t("backup.runs.col.reason")}</th>
                          <th scope="col">{t("backup.runs.col.file")}</th>
                          <th scope="col" class="num">{t("backup.runs.col.size")}</th>
                          <th scope="col" class="num">{t("backup.runs.col.node")}</th>
                          <th scope="col" class="r">
                            <span class="sr-only">{t("backup.runs.col.actions")}</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={s().recent}>
                          {(run) => (
                            <tr data-testid="backup-run" data-key={run.id} data-outcome={run.outcome} data-reason={run.reason}>
                              <td>{formatDateTime(run.finished_at)}</td>
                              <td>
                                <span class={run.outcome === "succeeded" ? "tag ok" : "tag conflict"} data-testid="backup-run-outcome">
                                  {outcomeText(run.outcome)}
                                </span>
                                <Show when={run.error}>
                                  {(error) => (
                                    <div class="muted bk-break" data-testid="backup-run-error" data-code={error().code}>
                                      {error().code}: {error().detail}
                                    </div>
                                  )}
                                </Show>
                              </td>
                              <td>{reasonText(run)}</td>
                              <td class="mono bk-break" data-testid="backup-run-file">{run.file ?? ""}</td>
                              <td class="num">{run.bytes == null ? "" : sizeText(run.bytes)}</td>
                              <td class="num">{run.node}</td>
                              <td class="r">
                                <Show when={run.outcome === "succeeded" && run.file}>
                                  <button
                                    type="button"
                                    class="btn sm"
                                    data-testid="backup-restore-open"
                                    aria-label={t("backup.restore.open_named", { file: run.file ?? "" })}
                                    onClick={() => setRestoring(run)}
                                  >
                                    {t("backup.restore.open")}
                                  </button>
                                </Show>
                              </td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </div>
                </Show>
              </section>

              <Show when={creating()}>
                <CreateDialog
                  recipient={Boolean(s().settings.recipient)}
                  onDone={(run) => {
                    setJob(run.job ?? null);
                    status.refetch();
                  }}
                  onStepUp={() => {
                    setCreating(false);
                    setStepUp(true);
                  }}
                  onClose={() => setCreating(false)}
                />
              </Show>
              <Show when={restoring()}>{(run) => <RestoreDialog run={run()} onClose={() => setRestoring(null)} />}</Show>
            </>
          )}
        </Show>
      </div>
    </div>
  );
}

/** The answer to `auth.step_up_required`: sign in again and come back to this page. */
function StepUp() {
  const navigate = useNavigate();
  const signInAgain = async () => {
    await signOut();
    navigate(paths.signIn(paths.settings("backup")), { replace: true });
  };
  return (
    <div data-testid="backup-step-up">
      <Notice kind="warn" role="alert" title={t("backup.step_up.title")}>
        <p>{t("backup.step_up.body")}</p>
        <button type="button" class="btn sm" data-testid="backup-sign-in-again" onClick={() => void signInAgain()}>
          {t("backup.step_up.sign_in")}
        </button>
      </Notice>
    </div>
  );
}

/** The installation was started from a restore and no good backup has been made since. */
function RestoredNotice(props: { notice: RestoreNotice }) {
  return (
    <div data-testid="backup-restored">
      <Notice kind="info" role="status" title={t("backup.restored.title")}>
        <p>
          {t("backup.restored.body", {
            file: props.notice.file,
            at: formatDateTime(props.notice.restored_at),
            created: formatDateTime(props.notice.backup_created_at),
          })}
        </p>
        <p class="muted">{t("backup.restored.nodes", { source: props.notice.source_node, node: props.notice.node, revision: props.notice.revision })}</p>
      </Notice>
    </div>
  );
}

function StateFacts(props: { status: BackupStatus }) {
  const s = () => props.status;
  return (
    <div class="card facts">
      <dl class="kv">
        <dt>{t("backup.state.target")}</dt>
        <dd class="mono" data-testid="backup-target">
          {s().settings.effective_target_dir}
        </dd>
        <dt>{t("backup.state.last_good")}</dt>
        <dd data-testid="backup-last-good">
          <Show when={s().last_good} fallback={t("backup.state.never")}>
            {(run) => (
              <>
                {formatRelative(run().finished_at)} <span class="muted">({formatDateTime(run().finished_at)})</span>
              </>
            )}
          </Show>
        </dd>
        <Show when={s().age_seconds != null}>
          <dt>{t("backup.state.age_label")}</dt>
          <dd data-testid="backup-age">{ageText(s().age_seconds ?? 0)}</dd>
        </Show>
        <Show when={s().last_failed}>
          {(run) => (
            <>
              <dt>{t("backup.state.last_failed")}</dt>
              <dd data-testid="backup-last-failed">
                {formatRelative(run().finished_at)}
                <Show when={run().error}>{(error) => <>: {error().code}</>}</Show>
              </dd>
            </>
          )}
        </Show>
        <dt>{t("backup.state.next")}</dt>
        <dd data-testid="backup-next">
          <Show when={s().settings.enabled && s().next_due_at} fallback={t("backup.state.not_scheduled")}>
            {(at) => formatDateTime(at())}
          </Show>
        </dd>
        <dt>{t("backup.state.running")}</dt>
        <dd data-testid="backup-running">{s().running ? t("backup.state.running_yes") : t("backup.state.running_no")}</dd>
        <dt>{t("backup.state.recipient")}</dt>
        <dd>{s().settings.recipient ? t("backup.state.recipient_yes") : t("backup.state.recipient_no")}</dd>
      </dl>
    </div>
  );
}

/** The interval schedule, how many backups are kept, the recipient and the target directory. */
function ScheduleForm(props: { settings: BackupSettings; onSaved: () => void; onStepUp: () => void }) {
  const [draft, setDraft] = createSignal<ScheduleDraft>(untrack(() => draftOf(props.settings)));
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const set = (change: Partial<ScheduleDraft>) => setDraft((d) => ({ ...d, ...change }));
  const errors = () => draftErrors(draft());
  const missingRecipient = () => needsRecipient(draft());
  const blocked = () => Object.keys(errors()).length > 0 || missingRecipient();

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (blocked() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await api.put("/api/v1/system/backups/settings", {
        body: settingsBody(draft()),
        ifMatch: props.settings.revision ?? undefined,
      });
      toast({ kind: "ok", title: t("backup.schedule.saved", { schedule: scheduleText(saved) }) });
      props.onSaved();
    } catch (err) {
      if (isApiError(err, "auth.step_up_required")) {
        props.onStepUp();
        return;
      }
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form class="card bk-form" onSubmit={(e) => void submit(e)} novalidate>
      <ErrorNotice error={error()} />
      <div class="field">
        <label class="choice">
          <input
            type="checkbox"
            checked={draft().enabled}
            data-testid="field-enabled"
            onChange={(e) => set({ enabled: e.currentTarget.checked })}
          />
          <span>{t("backup.schedule.enabled")}</span>
        </label>
        <span class="help">{t("backup.schedule.enabled_help")}</span>
      </div>
      <Show when={missingRecipient()}>
        <p class="note warn" role="status" data-testid="backup-needs-recipient">
          {t("backup.schedule.needs_recipient")}
        </p>
      </Show>
      <div class="bk-row">
        <div class="field">
          <label for="bk-interval">{t("backup.schedule.interval")}</label>
          <input
            id="bk-interval"
            class="input num"
            type="number"
            min={MIN_INTERVAL_HOURS}
            max={MAX_INTERVAL_HOURS}
            data-testid="field-interval"
            aria-invalid={errors().interval ? "true" : undefined}
            aria-describedby="bk-interval-help"
            value={draft().intervalHours}
            onInput={(e) => set({ intervalHours: e.currentTarget.valueAsNumber })}
          />
          <span class={errors().interval ? "help bad field-error" : "help"} id="bk-interval-help">
            {errors().interval ?? t("backup.schedule.interval_help", { every: intervalText(draft().intervalHours) })}
          </span>
        </div>
        <div class="field">
          <label for="bk-keep">{t("backup.schedule.keep")}</label>
          <input
            id="bk-keep"
            class="input num"
            type="number"
            min={MIN_KEEP}
            max={MAX_KEEP}
            data-testid="field-keep"
            aria-invalid={errors().keep ? "true" : undefined}
            aria-describedby="bk-keep-help"
            value={draft().keep}
            onInput={(e) => set({ keep: e.currentTarget.valueAsNumber })}
          />
          <span class={errors().keep ? "help bad field-error" : "help"} id="bk-keep-help">
            {errors().keep ?? t("backup.schedule.keep_help")}
          </span>
        </div>
      </div>
      <div class="field">
        <label for="bk-recipient">{t("backup.schedule.recipient")}</label>
        <input
          id="bk-recipient"
          class="input mono"
          type="text"
          autocomplete="off"
          spellcheck={false}
          data-testid="field-recipient"
          aria-invalid={errors().recipient || (submitted() && missingRecipient()) ? "true" : undefined}
          aria-describedby="bk-recipient-help"
          value={draft().recipient}
          onInput={(e) => set({ recipient: e.currentTarget.value })}
        />
        <span class={errors().recipient ? "help bad field-error" : "help"} id="bk-recipient-help">
          {errors().recipient ?? t("backup.schedule.recipient_help")}
        </span>
      </div>
      <div class="field">
        <label for="bk-target">{t("backup.schedule.target_dir")}</label>
        <input
          id="bk-target"
          class="input mono"
          type="text"
          autocomplete="off"
          spellcheck={false}
          data-testid="field-target-dir"
          aria-invalid={errors().targetDir ? "true" : undefined}
          aria-describedby="bk-target-help"
          value={draft().targetDir}
          onInput={(e) => set({ targetDir: e.currentTarget.value })}
        />
        <span class={errors().targetDir ? "help bad field-error" : "help"} id="bk-target-help">
          {errors().targetDir ?? t("backup.schedule.target_dir_help", { dir: props.settings.effective_target_dir })}
        </span>
      </div>
      <div class="field">
        <label class="choice">
          <input
            type="checkbox"
            checked={draft().includeConfig}
            data-testid="field-include-config"
            onChange={(e) => set({ includeConfig: e.currentTarget.checked })}
          />
          <span>{t("backup.schedule.include_config")}</span>
        </label>
      </div>
      <div class="form-row">
        <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
          {t("common.action.save")}
        </button>
      </div>
    </form>
  );
}

/** "Back up now": to the configured recipient, with a passphrase typed twice as an addition. */
function CreateDialog(props: { recipient: boolean; onDone: (run: BackupRun) => void; onStepUp: () => void; onClose: () => void }) {
  const [passphrase, setPassphrase] = createSignal("");
  const [again, setAgain] = createSignal("");
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  // With a recipient the passphrase is optional; without one it is the only way to open the backup.
  const wanted = () => !props.recipient || passphrase() !== "" || again() !== "";
  const phraseError = () => {
    if (!submitted() || !wanted()) return undefined;
    if ([...passphrase()].length < MIN_PASSPHRASE) return t("backup.create.error.short", { min: MIN_PASSPHRASE });
    if (passphrase() !== again()) return t("backup.create.error.mismatch");
    return undefined;
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (busy()) return;
    if (wanted() && ([...passphrase()].length < MIN_PASSPHRASE || passphrase() !== again())) return;
    setBusy(true);
    setError(null);
    try {
      const run = await api.post("/api/v1/system/backups", { body: wanted() ? { passphrase: passphrase() } : {} });
      setPassphrase("");
      setAgain("");
      toast({ kind: "ok", title: t("backup.create.done", { file: run.file ?? "" }) });
      props.onDone(run);
      props.onClose();
    } catch (err) {
      if (isApiError(err, "auth.step_up_required")) {
        props.onStepUp();
        return;
      }
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("backup.create.title")} onClose={props.onClose} class="dialog" testid="dialog-backup">
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("backup.create.title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <p class="muted">{t("backup.create.body")}</p>
          <p data-testid="backup-create-key">{props.recipient ? t("backup.create.with_recipient") : t("backup.create.passphrase_only")}</p>
          <div class="field">
            <label for="bk-pass">{props.recipient ? t("backup.create.passphrase_optional") : t("backup.create.passphrase")}</label>
            <input
              id="bk-pass"
              class="input"
              type="password"
              autocomplete="new-password"
              data-testid="field-passphrase"
              aria-invalid={phraseError() ? "true" : undefined}
              aria-describedby="bk-pass-help"
              value={passphrase()}
              onInput={(e) => setPassphrase(e.currentTarget.value)}
            />
            <span class={phraseError() ? "help bad field-error" : "help"} id="bk-pass-help">
              {phraseError() ?? t("backup.create.passphrase_help", { min: MIN_PASSPHRASE })}
            </span>
          </div>
          <div class="field">
            <label for="bk-again">{t("backup.create.again")}</label>
            <input
              id="bk-again"
              class="input"
              type="password"
              autocomplete="new-password"
              data-testid="field-passphrase-again"
              value={again()}
              onInput={(e) => setAgain(e.currentTarget.value)}
            />
          </div>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("backup.now")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/** The command that restores a backup on a new host. */
function RestoreDialog(props: { run: BackupRun; onClose: () => void }) {
  const command = () => restoreCommand(props.run);
  return (
    <Dialog label={t("backup.restore.title", { file: props.run.file ?? "" })} onClose={props.onClose} class="dialog wide" testid="dialog-backup-restore">
      <h2 class="dialog-title">{t("backup.restore.title", { file: props.run.file ?? "" })}</h2>
      <div class="dialog-body">
        <p>{t("backup.restore.body")}</p>
        <div class="form-row">
          <code class="bk-command" data-testid="backup-restore-command">
            {command()}
          </code>
          <button type="button" class="btn sm" onClick={() => void copyText(command())}>
            <Icon name="copy" size="sm" />
            {t("common.action.copy")}
          </button>
        </div>
        <p class="muted">{t("backup.restore.slots", { slots: slotsText(props.run.slots) })}</p>
        <p class="muted">{t("backup.restore.note")}</p>
      </div>
      <div class="dialog-actions">
        <button type="button" class="btn primary" data-testid="form-cancel" onClick={() => props.onClose()}>
          {t("common.action.close")}
        </button>
      </div>
    </Dialog>
  );
}
