// The confirmation before an install or an upload. It names the version and, for a release
// that needs an action from the operator, repeats the action text of every release on the
// way (an upgrade across several releases needs all of their actions).
import { For, Show } from "solid-js";
import { ConfirmDialog } from "../components/Dialog";
import { Notice } from "../components/Notice";
import { t } from "../i18n";
import type { UpdateStatus } from "./api";
import { Markdown } from "./markdown";

/** The releases that will be installed over when `version` is installed: it and everything older. */
export function releasesOnTheWay(status: UpdateStatus, version: string) {
  const at = status.releases.findIndex((r) => r.version === version);
  return at < 0 ? [] : status.releases.slice(at);
}

export function InstallConfirm(props: {
  status: UpdateStatus;
  version: string;
  /** `download`: the server fetches the release; `upload`: the chosen file is sent. */
  kind: "download" | "upload";
  busy: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const onTheWay = () => releasesOnTheWay(props.status, props.version);
  const actions = () => onTheWay().filter((r) => r.requires_action);
  const security = () => onTheWay().some((r) => r.security);
  return (
    <ConfirmDialog
      testid="dialog-update-install"
      title={t("updates.install.confirm_title", { version: props.version })}
      confirmLabel={t("updates.install.confirm_ok", { version: props.version })}
      cancelLabel={t("common.action.cancel")}
      busy={props.busy}
      onConfirm={props.onConfirm}
      onClose={props.onClose}
      body={
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
      }
    />
  );
}
