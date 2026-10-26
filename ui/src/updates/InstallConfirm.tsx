// The confirmation before an install or an upload, with the backup before it (ADR 0023). It
// names the version and, for a release that needs an action from the operator, repeats the
// action text of every release on the way (an upgrade across several releases needs all of
// their actions).
//
// The backup: when the newest good backup is younger than the server's limit
// (`install.backup.max_age_seconds`, one hour) the dialog says how old it is and installs.
// Otherwise it asks "Are you sure you do not want a backup first?" with "Backup now" (the
// default) and "No, don't back up" (not offered when the profile requires a backup). "Backup
// now" writes the backup (with a passphrase when no recipient is set up) and installs only
// once it is recorded good; a failed backup shows its error and offers the choices again.
import { createSignal, createUniqueId, For, Show, untrack } from "solid-js";
import { ApiError, isApiError } from "../api/problem";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { ErrorNotice, Notice } from "../components/Notice";
import { t } from "../i18n";
import { ageText, MIN_PASSPHRASE } from "../settings/backup/model";
import { backupBeforeUpdate, type BackupAnswer, type UpdateStatus } from "./api";
import { Markdown } from "./markdown";

/** The releases that will be installed over when `version` is installed: it and everything older. */
export function releasesOnTheWay(status: UpdateStatus, version: string) {
  const at = status.releases.findIndex((r) => r.version === version);
  return at < 0 ? [] : status.releases.slice(at);
}

/**
 * The age of the newest good backup now: the status's age plus the time since the status
 * arrived; `null` without a backup.
 */
export function backupAgeNow(status: UpdateStatus, receivedAt: number, now = Date.now()): number | null {
  const age = status.install.backup.age_seconds;
  if (age === null || age === undefined) return null;
  return age + Math.max(0, Math.floor((now - receivedAt) / 1000));
}

/** Whether an install may go ahead without the question: a good backup younger than the limit. */
export function backupIsRecent(status: UpdateStatus, receivedAt: number, now = Date.now()): boolean {
  const age = backupAgeNow(status, receivedAt, now);
  return age !== null && age < status.install.backup.max_age_seconds;
}

function OnTheWay(props: { status: UpdateStatus; version: string; kind: "download" | "upload" }) {
  const onTheWay = () => releasesOnTheWay(props.status, props.version);
  const actions = () => onTheWay().filter((r) => r.requires_action);
  const security = () => onTheWay().some((r) => r.security);
  return (
    <>
      <p>
        {props.kind === "upload"
          ? t("updates.install.confirm_upload", { version: props.version, seconds: props.status.install.ready_timeout_secs })
          : t("updates.install.confirm_body", { version: props.version, seconds: props.status.install.ready_timeout_secs })}
      </p>
      <Show when={security()}>
        <p>{t("updates.install.confirm_security")}</p>
      </Show>
      <Show when={actions().length > 0}>
        <Notice kind="warn" title={t("updates.install.confirm_action")} testid="update-confirm-action">
          <For each={actions()}>
            {(release) => (
              <div class="upd-confirm-action" data-key={release.version}>
                <strong>{t("updates.release.title", { version: release.version })}</strong>
                <Show when={release.action} fallback={<p>{t("updates.release.action_unspecified")}</p>}>
                  {(action) => <Markdown source={action()} />}
                </Show>
              </div>
            )}
          </For>
        </Notice>
      </Show>
    </>
  );
}

interface ConfirmProps {
  status: UpdateStatus;
  version: string;
  /** `download`: the server fetches the release; `upload`: the chosen file is sent. */
  kind: "download" | "upload";
  /** The install request is under way. */
  busy: boolean;
  /** When the status arrived (`Date.now()`), to age the backup it reports. */
  receivedAt: number;
  /** Start the install: `skip` when the administrator declined a backup, else nothing. */
  onConfirm: (backup: BackupAnswer) => void;
  /** A failure the panel shows instead of the dialog: the backup needs a fresh sign-in. */
  onFailure: (err: unknown) => void;
  onClose: () => void;
}

export function InstallConfirm(props: ConfirmProps) {
  // Decided once, when the dialog opens: the question does not change under the cursor, also
  // not when the status is read again while the backup runs.
  const age = untrack(() => backupAgeNow(props.status, props.receivedAt));
  const recent = untrack(() => backupIsRecent(props.status, props.receivedAt));
  return (
    <Show when={recent} fallback={<BackupQuestion {...props} age={age} />}>
      <ConfirmDialog
        testid="dialog-update-install"
        title={t("updates.install.confirm_title", { version: props.version })}
        confirmLabel={t("updates.install.confirm_ok", { version: props.version })}
        cancelLabel={t("common.action.cancel")}
        busy={props.busy}
        onConfirm={() => props.onConfirm(undefined)}
        onClose={props.onClose}
        body={
          <>
            <p class="muted" data-testid="update-backup-recent">
              {t("updates.backup.recent", { age: ageText(age ?? 0) })}
            </p>
            <OnTheWay status={props.status} version={props.version} kind={props.kind} />
          </>
        }
      />
    </Show>
  );
}

/** The question when no good backup is recent, with "Backup now" as the default. */
function BackupQuestion(props: ConfirmProps & { age: number | null }) {
  const gate = () => props.status.install.backup;
  const ids = { pass: createUniqueId(), again: createUniqueId() };
  const [backingUp, setBackingUp] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [passphrase, setPassphrase] = createSignal("");
  const [again, setAgain] = createSignal("");
  const [submitted, setSubmitted] = createSignal(false);
  let backupButton!: HTMLButtonElement;
  let closed = false;

  const needsPassphrase = () => !gate().recipient;
  const phraseError = () => {
    if (!submitted() || !needsPassphrase()) return undefined;
    if ([...passphrase()].length < MIN_PASSPHRASE) return t("backup.create.error.short", { min: MIN_PASSPHRASE });
    if (passphrase() !== again()) return t("backup.create.error.mismatch");
    return undefined;
  };
  const working = () => backingUp() || props.busy;
  const close = () => {
    // A backup that runs cannot be called back; the dialog stays until it is done.
    if (backingUp()) return;
    closed = true;
    props.onClose();
  };

  const backupNow = async (e?: Event) => {
    e?.preventDefault();
    setSubmitted(true);
    if (working() || phraseError() !== undefined) return;
    setBackingUp(true);
    setError(null);
    try {
      await backupBeforeUpdate(props.version, needsPassphrase() ? passphrase() : undefined);
      setPassphrase("");
      setAgain("");
      setBackingUp(false);
      if (!closed) props.onConfirm(undefined);
    } catch (err) {
      setBackingUp(false);
      if (isApiError(err, "auth.step_up_required")) {
        props.onFailure(err);
        return;
      }
      setError(err);
    }
  };

  const detail = () => {
    const err = error();
    return err instanceof ApiError && err.detail ? err.detail : null;
  };

  return (
    <Dialog
      label={t("updates.install.confirm_title", { version: props.version })}
      onClose={close}
      class="dialog"
      initialFocus={() => backupButton}
      testid="dialog-update-install"
    >
      <form class="dialog-form" onSubmit={(e) => void backupNow(e)} novalidate>
        <h2 class="dialog-title">{t("updates.install.confirm_title", { version: props.version })}</h2>
        <div class="dialog-body">
          <p data-testid="update-backup-question">
            <strong>{t("updates.backup.question")}</strong>
          </p>
          <p class="muted" data-testid="update-backup-age">
            {props.age === null ? t("updates.backup.never") : t("updates.backup.stale", { age: ageText(props.age) })}
          </p>
          <Show when={!gate().skip_allowed}>
            <p data-testid="update-backup-required">{t("updates.backup.required")}</p>
          </Show>
          <Show when={needsPassphrase()}>
            <p data-testid="update-backup-passphrase-lead">{t("updates.backup.passphrase_lead")}</p>
            <div class="field">
              <label for={ids.pass}>{t("backup.create.passphrase")}</label>
              <input
                id={ids.pass}
                class="input"
                type="password"
                autocomplete="new-password"
                data-testid="update-backup-passphrase"
                aria-invalid={phraseError() ? "true" : undefined}
                aria-describedby={`${ids.pass}-help`}
                value={passphrase()}
                disabled={working()}
                onInput={(e) => setPassphrase(e.currentTarget.value)}
              />
              <span class={phraseError() ? "help bad field-error" : "help"} id={`${ids.pass}-help`}>
                {phraseError() ?? t("backup.create.passphrase_help", { min: MIN_PASSPHRASE })}
              </span>
            </div>
            <div class="field">
              <label for={ids.again}>{t("backup.create.again")}</label>
              <input
                id={ids.again}
                class="input"
                type="password"
                autocomplete="new-password"
                data-testid="update-backup-passphrase-again"
                value={again()}
                disabled={working()}
                onInput={(e) => setAgain(e.currentTarget.value)}
              />
            </div>
          </Show>
          <Show when={backingUp()}>
            <p role="status" data-testid="update-backup-running">
              {t("updates.backup.running")}
            </p>
          </Show>
          <Show when={error()}>
            <div data-testid="update-backup-failed">
              <p>{t("updates.backup.failed")}</p>
              <ErrorNotice error={error()} />
              <Show when={detail()}>{(text) => <p class="muted">{text()}</p>}</Show>
            </div>
          </Show>
          <OnTheWay status={props.status} version={props.version} kind={props.kind} />
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" disabled={backingUp()} onClick={close} data-testid="confirm-cancel">
            {t("common.action.cancel")}
          </button>
          <Show when={gate().skip_allowed}>
            <button
              type="button"
              class="btn"
              disabled={working()}
              onClick={() => props.onConfirm("skip")}
              data-testid="update-backup-skip"
            >
              {t("updates.backup.skip")}
            </button>
          </Show>
          <button ref={backupButton} type="submit" class="btn primary" disabled={working()} data-testid="update-backup-now">
            {t("updates.backup.now")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
