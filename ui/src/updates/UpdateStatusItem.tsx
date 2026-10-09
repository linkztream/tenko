// "Update available: <version>" in the status bar, for administrators when a newer release
// exists; loaded lazily after the shell, like the utilization alarms. Nothing shows for an
// account that may not read the status, a server without an update service, or an
// installation that is up to date.
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import { UPDATES_PATH } from "./paths";
import { useUpdateStatus } from "./status";
import "./marks.css";

export default function UpdateStatusItem() {
  const status = useUpdateStatus();
  const newest = () => {
    const s = status();
    return s?.update_available ? (s.latest ?? s.releases[0]?.version ?? null) : null;
  };
  return (
    <Show when={newest()}>
      {(version) => (
        <A
          class="status-update"
          classList={{ security: status()?.security === true }}
          href={UPDATES_PATH}
          title={t("shell.status.update_title")}
          data-testid="status-update"
        >
          <Icon name={status()?.security ? "shield" : "download"} size="sm" />
          {t("shell.status.update", { version: version() })}
          <Show when={status()?.security}>
            <strong>{t("shell.status.update_security")}</strong>
          </Show>
        </A>
      )}
    </Show>
  );
}
