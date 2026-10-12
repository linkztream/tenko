// The settings page for backups (WP3.11b, OPS-07; slice-3 plan WP3.4b, S3-Q11): the state of the
// backups in the target directory with the warning after 7 days without one, "Back up now" with a
// passphrase or the recipient key file, the schedule and how many backups are kept, and the
// restore preview of a backup: its manifest and the command that restores it on a new host.
// Restoring and downloading are not offered in the UI in Phase 1. Administrators only.
import { A } from "@solidjs/router";
import { createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { isApiError } from "../../api/problem";
import { api } from "../../api/client";
import { asWorkingModel, pendingApi } from "../../api/pending";
import { paths } from "../../app/paths";
import { copyText } from "../../auth/account/shared";
import { signOut } from "../../auth/session";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { formatDateTime, formatNumber, formatRelative, t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";
import {
  MIN_PASSPHRASE,
  restoreCommand,
  scheduleText,
  sizeText,
  validTime,
  weekdayName,
  type BackupFile,
  type BackupSchedule,
  type BackupSettings,
  type BackupStarted,
  type BackupStatus,
} from "./model";
import "../settings.css";
import "./backup.css";

export default function BackupPage() {
  const status = createLiveQuery<BackupStatus>({
    topics: ["system"],
    fetch: async (signal) => ({ value: await asWorkingModel<BackupStatus>(api.get("/api/v1/system/backups", { signal })) }),
  });
  const settings = createLiveQuery<BackupSettings>({
    topics: ["system"],
    fetch: async (signal) => {
      const value = await pendingApi.get("/api/v1/settings/backup", { signal });
      return { value, revision: value.revision };
    },
  });
  const [creating, setCreating] = createSignal(false);
  const [preview, setPreview] = createSignal<BackupFile | null>(null);
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
          <div data-testid="backup-step-up">
            <Notice kind="warn" role="alert" title={t("backup.step_up.title")}>
              <p>{t("backup.step_up.body")}</p>
              <button type="button" class="btn sm" data-testid="backup-sign-in-again" onClick={() => void signOut()}>
                {t("backup.step_up.sign_in")}
              </button>
            </Notice>
          </div>
        </Show>
        <Show when={latest(status)} fallback={<Show when={!status.value.error}><p class="muted" role="status">{t("common.loading")}</p></Show>}>
          {(s) => (
            <>
              <Show when={s().stale}>
                <Notice kind="warn" role="status" title={t("backup.stale.title")}>
                  <span data-testid="backup-stale">{t("backup.stale.body")}</span>
                </Notice>
              </Show>
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
                <div class="card facts">
                  <dl class="kv">
                    <dt>{t("backup.state.target")}</dt>
                    <dd class="mono" data-testid="backup-target">
                      {s().target}
                    </dd>
                    <dt>{t("backup.state.last_good")}</dt>
                    <dd data-testid="backup-last-good">
                      <Show when={s().last_good_at} fallback={t("backup.state.never")}>
                        {(at) => (
                          <>
                            {formatRelative(at())} <span class="muted">({formatDateTime(at())})</span>
                          </>
                        )}
                      </Show>
                    </dd>
                    <Show when={s().last_attempt && !s().last_attempt?.ok ? s().last_attempt : undefined}>
                      {(attempt) => (
                        <>
                          <dt>{t("backup.state.last_failed")}</dt>
                          <dd data-testid="backup-last-failed">
                            {formatRelative(attempt().at)}: {attempt().error ?? ""}
                          </dd>
                        </>
                      )}
                    </Show>
                    <dt>{t("backup.state.next")}</dt>
                    <dd>
                      <Show when={s().next_at} fallback={t("backup.state.not_scheduled")}>
                        {(at) => formatDateTime(at())}
                      </Show>
                    </dd>
                    <dt>{t("backup.state.recipient")}</dt>
                    <dd>{s().recipient ? t("backup.state.recipient_yes") : t("backup.state.recipient_no")}</dd>
                  </dl>
                </div>
                <Show when={job()}>
                  {(id) => (
                    <p class="muted" data-testid="backup-job">
                      <A href={paths.job(id())}>{t("backup.job_link")}</A>
                    </p>
                  )}
                </Show>
              </section>

              <ScheduleSection settings={latest(settings)} recipient={s().recipient} onSaved={() => settings.refetch()} error={settings.value.error} />

              <section class="page-section" aria-labelledby="backup-files" data-testid="backup-files">
                <h2 id="backup-files">{t("backup.files.heading")}</h2>
                <Show when={s().backups.length > 0} fallback={<p class="muted" data-testid="backup-files-empty">{t("backup.files.none")}</p>}>
                  <div class="table-wrap">
                    <table class="plain">
                      <caption class="sr-only">{t("backup.files.heading")}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{t("backup.files.col.file")}</th>
                          <th scope="col">{t("backup.files.col.created")}</th>
                          <th scope="col" class="num">{t("backup.files.col.size")}</th>
                          <th scope="col">{t("backup.files.col.made")}</th>
                          <th scope="col" class="r">
                            <span class="sr-only">{t("backup.files.col.actions")}</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={s().backups}>
                          {(file) => (
                            <tr data-testid="backup-file" data-key={file.file}>
                              <td class="mono">{file.file}</td>
                              <td>{formatDateTime(file.created_at)}</td>
                              <td class="num">{sizeText(file.size_bytes)}</td>
                              <td>{file.trigger === "schedule" ? t("backup.files.scheduled") : t("backup.files.manual")}</td>
                              <td class="r">
                                <button
                                  type="button"
                                  class="btn sm"
                                  data-testid="backup-preview"
                                  aria-label={t("backup.preview.open_named", { file: file.file })}
                                  onClick={() => setPreview(file)}
                                >
                                  {t("backup.preview.open")}
                                </button>
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
                  recipient={s().recipient}
                  onStarted={(id) => {
                    setJob(id);
                    status.refetch();
                  }}
                  onStepUp={() => {
                    setCreating(false);
                    setStepUp(true);
                  }}
                  onClose={() => setCreating(false)}
                />
              </Show>
              <Show when={preview()}>
                {(file) => <PreviewDialog file={file()} target={s().target} onClose={() => setPreview(null)} />}
              </Show>
            </>
          )}
        </Show>
      </div>
    </div>
  );
}

/** The schedule, the time, the weekday and how many backups are kept. */
function ScheduleSection(props: { settings: BackupSettings | undefined; recipient: boolean; error: unknown; onSaved: () => void }) {
  return (
    <section class="page-section" aria-labelledby="backup-schedule" data-testid="backup-schedule">
      <h2 id="backup-schedule">{t("backup.schedule.heading")}</h2>
      <ErrorNotice error={props.error} />
      <Show when={props.settings} keyed fallback={<p class="muted">{t("common.loading")}</p>}>
        {(settings) => <ScheduleForm settings={settings} recipient={props.recipient} onSaved={props.onSaved} />}
      </Show>
    </section>
  );
}

function ScheduleForm(props: { settings: BackupSettings; recipient: boolean; onSaved: () => void }) {
  const start = untrack(() => props.settings);
  const [schedule, setSchedule] = createSignal<BackupSchedule>({ ...start.schedule });
  const [keep, setKeep] = createSignal(start.keep);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const timeError = () => (schedule().kind !== "off" && !validTime(schedule().time) ? t("backup.schedule.error.time") : undefined);
  const keepError = () => (!Number.isInteger(keep()) || keep() < 1 || keep() > 365 ? t("backup.schedule.error.keep") : undefined);
  const set = (change: Partial<BackupSchedule>) => setSchedule((s) => ({ ...s, ...change }));

  const submit = async (e: Event) => {
    e.preventDefault();
    if (timeError() || keepError() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const s = schedule();
      await pendingApi.put("/api/v1/settings/backup", {
        body: { schedule: { kind: s.kind, time: s.time, weekday: s.kind === "weekly" ? (s.weekday ?? 6) : null }, keep: keep() },
        ifMatch: props.settings.revision,
      });
      toast({ kind: "ok", title: t("backup.schedule.saved", { schedule: scheduleText(s) }) });
      props.onSaved();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form class="card bk-form" onSubmit={(e) => void submit(e)} novalidate>
      <ErrorNotice error={error()} />
      <fieldset class="field">
        <legend class="label">{t("backup.schedule.when")}</legend>
        <div class="choices bk-kinds" role="radiogroup" aria-label={t("backup.schedule.when")}>
          <For each={["off", "daily", "weekly"] as const}>
            {(kind) => (
              <label class="choice">
                <input
                  type="radio"
                  name="bk-kind"
                  checked={schedule().kind === kind}
                  data-testid={`field-schedule-${kind}`}
                  onChange={() => set({ kind })}
                />
                <span>{t(`backup.schedule.${kind}`)}</span>
              </label>
            )}
          </For>
        </div>
      </fieldset>
      <Show when={schedule().kind !== "off"}>
        <div class="bk-row">
          <Show when={schedule().kind === "weekly"}>
            <div class="field">
              <label for="bk-weekday">{t("backup.schedule.weekday")}</label>
              <select id="bk-weekday" class="select" data-testid="field-weekday" onChange={(e) => set({ weekday: Number(e.currentTarget.value) })}>
                <For each={[0, 1, 2, 3, 4, 5, 6]}>
                  {(day) => (
                    <option value={day} selected={(schedule().weekday ?? 6) === day}>
                      {weekdayName(day)}
                    </option>
                  )}
                </For>
              </select>
            </div>
          </Show>
          <div class="field">
            <label for="bk-time">{t("backup.schedule.time")}</label>
            <input
              id="bk-time"
              class="input mono"
              type="time"
              data-testid="field-time"
              aria-invalid={timeError() ? "true" : undefined}
              aria-describedby="bk-time-help"
              value={schedule().time}
              onInput={(e) => set({ time: e.currentTarget.value })}
            />
            <span class={timeError() ? "help bad field-error" : "help"} id="bk-time-help">
              {timeError() ?? t("backup.schedule.time_help")}
            </span>
          </div>
        </div>
        <Show when={!props.recipient}>
          <p class="note" role="status" data-testid="backup-needs-recipient">
            {t("backup.schedule.needs_recipient")}
          </p>
        </Show>
      </Show>
      <div class="field">
        <label for="bk-keep">{t("backup.schedule.keep")}</label>
        <input
          id="bk-keep"
          class="input num"
          type="number"
          min={1}
          max={365}
          data-testid="field-keep"
          aria-invalid={keepError() ? "true" : undefined}
          aria-describedby="bk-keep-help"
          value={keep()}
          onInput={(e) => setKeep(Number(e.currentTarget.value))}
        />
        <span class={keepError() ? "help bad field-error" : "help"} id="bk-keep-help">
          {keepError() ?? t("backup.schedule.keep_help")}
        </span>
      </div>
      <div class="form-row">
        <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
          {t("common.action.save")}
        </button>
      </div>
    </form>
  );
}

/** "Back up now": with the recipient key file, or with a passphrase typed twice. */
function CreateDialog(props: { recipient: boolean; onStarted: (job: string) => void; onStepUp: () => void; onClose: () => void }) {
  const [useRecipient, setUseRecipient] = createSignal(untrack(() => props.recipient));
  const [passphrase, setPassphrase] = createSignal("");
  const [again, setAgain] = createSignal("");
  const [submitted, setSubmitted] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const phraseError = () => {
    if (!submitted() || useRecipient()) return undefined;
    if ([...passphrase()].length < MIN_PASSPHRASE) return t("backup.create.error.short", { min: MIN_PASSPHRASE });
    if (passphrase() !== again()) return t("backup.create.error.mismatch");
    return undefined;
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    setSubmitted(true);
    if (phraseError() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const started = await asWorkingModel<BackupStarted>(
        api.post("/api/v1/system/backups", { body: (useRecipient() ? {} : { passphrase: passphrase() }) as never }),
      );
      setPassphrase("");
      setAgain("");
      toast({ kind: "ok", title: t("backup.create.started") });
      props.onStarted(started.job);
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
          <Show when={props.recipient}>
            <fieldset class="field">
              <legend class="label">{t("backup.create.key")}</legend>
              <div class="choices" role="radiogroup" aria-label={t("backup.create.key")}>
                <label class="choice">
                  <input type="radio" name="bk-key" checked={useRecipient()} data-testid="field-key-recipient" onChange={() => setUseRecipient(true)} />
                  <span>{t("backup.create.key_recipient")}</span>
                </label>
                <label class="choice">
                  <input type="radio" name="bk-key" checked={!useRecipient()} data-testid="field-key-passphrase" onChange={() => setUseRecipient(false)} />
                  <span>{t("backup.create.key_passphrase")}</span>
                </label>
              </div>
            </fieldset>
          </Show>
          <Show when={!useRecipient()}>
            <div class="field">
              <label for="bk-pass">{t("backup.create.passphrase")}</label>
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
          </Show>
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

/** The manifest of a backup and the command that restores it on a new host. */
function PreviewDialog(props: { file: BackupFile; target: string; onClose: () => void }) {
  const command = () => restoreCommand(props.file, props.target);
  return (
    <Dialog label={t("backup.preview.title", { file: props.file.file })} onClose={props.onClose} class="dialog wide" testid="dialog-backup-preview">
      <h2 class="dialog-title">{t("backup.preview.title", { file: props.file.file })}</h2>
      <div class="dialog-body">
        <dl class="kv">
          <dt>{t("backup.preview.created")}</dt>
          <dd>{formatDateTime(props.file.created_at)}</dd>
          <dt>{t("backup.preview.version")}</dt>
          <dd class="mono" data-testid="backup-preview-version">
            {props.file.tenko_version}
          </dd>
          <dt>{t("backup.preview.format")}</dt>
          <dd class="num">{props.file.data_format}</dd>
          <dt>{t("backup.preview.revision")}</dt>
          <dd class="num">{formatNumber(props.file.revision)}</dd>
          <dt>{t("backup.preview.audit_head")}</dt>
          <dd class="num">{formatNumber(props.file.audit_head)}</dd>
          <dt>{t("backup.preview.ca")}</dt>
          <dd class="mono bk-break" data-testid="backup-preview-ca">
            {props.file.ca_fingerprint}
          </dd>
          <dt>{t("backup.preview.key")}</dt>
          <dd>{props.file.key === "recipient" ? t("backup.create.key_recipient") : t("backup.create.key_passphrase")}</dd>
        </dl>
        <div class="table-wrap">
          <table class="plain" data-testid="backup-preview-parts">
            <caption>{t("backup.preview.parts")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("backup.preview.col.part")}</th>
                <th scope="col" class="num">{t("backup.files.col.size")}</th>
                <th scope="col">{t("backup.preview.col.sha256")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={props.file.parts}>
                {(part) => (
                  <tr>
                    <td class="mono">{part.name}</td>
                    <td class="num">{sizeText(part.size_bytes)}</td>
                    <td class="mono bk-break">{part.sha256}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
        <p>{t("backup.preview.restore_body")}</p>
        <div class="form-row">
          <code class="bk-command" data-testid="backup-restore-command">
            {command()}
          </code>
          <button type="button" class="btn sm" onClick={() => void copyText(command())}>
            <Icon name="copy" size="sm" />
            {t("common.action.copy")}
          </button>
        </div>
        <p class="muted">{t("backup.preview.restore_note")}</p>
      </div>
      <div class="dialog-actions">
        <button type="button" class="btn primary" data-testid="form-cancel" onClick={() => props.onClose()}>
          {t("common.action.close")}
        </button>
      </div>
    </Dialog>
  );
}
