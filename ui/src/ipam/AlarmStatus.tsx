// The utilization alarms in the status bar: loaded lazily after the shell, so the first
// page load stays small. Nothing shows while every prefix is below its thresholds.
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import { createAlarms } from "./alarms";

export default function AlarmStatus() {
  const alarms = createAlarms();
  return (
    <Show when={alarms.list().length > 0}>
      <A
        class="status-alarms"
        classList={{ crit: alarms.critical() > 0 }}
        href={`${paths.dashboard()}#alarms`}
        title={t("shell.status.alarms_title")}
        data-testid="status-alarms"
      >
        <Icon name="alert" size="sm" />
        {t("shell.status.alarms", { count: alarms.list().length })}
        <Show when={alarms.critical() > 0}>
          <strong>{t("shell.status.critical", { count: alarms.critical() })}</strong>
        </Show>
      </A>
    </Show>
  );
}
