// How to install the newest release on this installation. By what the server reports:
// "Install <version>" when it can fetch and switch by itself (after a confirmation that names
// the version and repeats any action the release asks for), the reason when it cannot, the
// pull command for a container, and the upload from files when that is possible. A step-up
// answer explains the fresh sign-in; the rest of the failures are shown as they are.
import { A } from "@solidjs/router";
import { createSignal, Show } from "solid-js";
import { isApiError } from "../api/problem";
import { newIdempotencyKey } from "../api/client";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { installVersion, type InstallStarted, type UpdateStatus } from "./api";
import { InstallConfirm } from "./InstallConfirm";
import { StepUpNotice } from "./StepUpNotice";
import { UploadPanel } from "./UploadPanel";
import { blockedText } from "./words";

export function InstallPanel(props: {
  status: UpdateStatus;
  onStatus: (status: UpdateStatus) => void;
  onStarted: (started: InstallStarted) => void;
  /** Reads the status again (after the server said the install is blocked). */
  onReload: () => void;
}) {
  const [confirming, setConfirming] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [stepUp, setStepUp] = createSignal(false);
  const [copied, setCopied] = createSignal(false);
  let key = newIdempotencyKey();

  const install = () => props.status.install;
  const newest = () => props.status.latest ?? props.status.releases[0]?.version ?? "";
  const blocked = () => install().from_source_blocked ?? null;
  const showUpload = () => install().upload || !props.status.check.enabled;

  /** Step-up, a blocked install and the other failures of an install or an upload. */
  const fail = (err: unknown) => {
    if (isApiError(err, "auth.step_up_required")) {
      setStepUp(true);
      setError(null);
      return;
    }
    setStepUp(false);
    setError(err);
    // The server knows better than the status on screen why it is blocked now.
    if (isApiError(err, "update.install_blocked")) props.onReload();
  };

  const start = async () => {
    if (busy()) return;
    setBusy(true);
    setError(null);
    setStepUp(false);
    try {
      const started = await installVersion(newest(), key);
      setConfirming(false);
      key = newIdempotencyKey();
      props.onStarted(started);
    } catch (err) {
      setConfirming(false);
      key = newIdempotencyKey();
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    const command = install().pull_command;
    if (!command) return;
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({ kind: "bad", title: t("updates.install.copy_failed") });
    }
  };

  return (
    <>
      <section class="page-section" aria-labelledby="upd-install" data-testid="updates-install-panel">
        <h2 id="upd-install">{t("updates.install.heading")}</h2>
        <div class="card upd-card">
          <Show
            when={props.status.update_available}
            fallback={<p data-testid="updates-uptodate">{t("updates.install.up_to_date", { version: props.status.running })}</p>}
          >
            <Show when={install().from_source}>
              <p>{t("updates.install.lead", { version: newest() })}</p>
              <Show when={install().step_up}>
                <p class="muted" data-testid="updates-stepup-hint">
                  <Icon name="lock" size="xs" /> {t("updates.install.step_up_hint")}
                </p>
              </Show>
              <div class="upd-actions">
                <button
                  type="button"
                  class="btn primary"
                  onClick={() => {
                    key = newIdempotencyKey();
                    setConfirming(true);
                  }}
                  data-testid="updates-install"
                >
                  <Icon name="download" size="sm" />
                  {t("updates.install.button", { version: newest() })}
                </button>
              </div>
            </Show>
            <Show when={!install().from_source && blocked()}>
              {(reason) => (
                <Notice kind="info" title={t("updates.install.blocked_title")} testid="updates-blocked">
                  <span data-testid="updates-blocked-reason" data-key={reason()}>
                    {blockedText(reason(), props.status.platform)}
                  </span>
                  <Show when={reason() === "upload_only"}>
                    {" "}
                    <A href={paths.settings("security")}>{t("updates.blocked.settings_link")}</A>
                  </Show>
                </Notice>
              )}
            </Show>
            <Show when={install().pull_command}>
              {(command) => (
                <div class="upd-pull" data-testid="updates-pull">
                  <p>{t("updates.install.pull_lead")}</p>
                  <div class="upd-code">
                    <pre>
                      <code data-testid="updates-pull-command">{command()}</code>
                    </pre>
                    <button type="button" class="btn sm" onClick={() => void copy()} data-testid="updates-copy">
                      <Icon name={copied() ? "check" : "copy"} size="sm" />
                      {copied() ? t("common.action.copied") : t("common.action.copy")}
                    </button>
                  </div>
                </div>
              )}
            </Show>
          </Show>
          <Show when={stepUp()}>
            <StepUpNotice />
          </Show>
          <ErrorNotice error={error()} />
        </div>
      </section>

      <Show when={showUpload()}>
        <UploadPanel
          status={props.status}
          canInstall={install().upload}
          onStatus={props.onStatus}
          onStarted={props.onStarted}
          onFailure={fail}
        />
      </Show>

      <Show when={confirming()}>
        <InstallConfirm
          status={props.status}
          version={newest()}
          kind="download"
          busy={busy()}
          onConfirm={() => void start()}
          onClose={() => setConfirming(false)}
        />
      </Show>
    </>
  );
}
