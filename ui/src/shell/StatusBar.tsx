import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { events, type ConnectionState } from "../api/events";
import { paths } from "../app/paths";
import { formatRelative, t, type MessageKey } from "../i18n";
import { now, selection, type JobCounts } from "./status";

const STATE: Record<ConnectionState, { key: MessageKey; dot: string }> = {
  live: { key: "shell.status.live", dot: "dot live" },
  connecting: { key: "shell.status.connecting", dot: "dot warn" },
  reconnecting: { key: "shell.status.reconnecting", dot: "dot warn" },
  offline: { key: "shell.status.offline", dot: "dot bad" },
  idle: { key: "shell.status.idle", dot: "dot idle" },
};

/** The status bar (decision 14): live connection, last event, jobs, selection, version. */
export function StatusBar(props: { jobs: JobCounts | null; version: string | undefined }) {
  const state = () => STATE[events.state()];
  const lastEvent = () => {
    const at = events.lastEventAt();
    if (at === null) return t("shell.status.no_events");
    return t("shell.status.last_event", { ago: formatRelative(Math.min(at, now()), now()) });
  };
  return (
    <footer class="statusbar">
      <span title={t("shell.status.live_title")}>
        <span class={state().dot} />
        {t(state().key)}
      </span>
      <span>{lastEvent()}</span>
      <Show when={props.jobs}>
        {(jobs) => (
          <A class="status-jobs" href={paths.jobs()} title={t("shell.status.jobs_title")}>
            <span class="jstate running">{t("shell.status.running", { count: jobs().running })}</span>
            <span class="jstate waiting">{t("shell.status.waiting", { count: jobs().waiting })}</span>
          </A>
        )}
      </Show>
      <Show when={selection()}>
        {(sel) => <span>{t("shell.status.selection", { selected: sel().selected, total: sel().total })}</span>}
      </Show>
      <span class="grow" />
      <Show when={props.version}>
        <span>{t("shell.status.version", { version: props.version ?? "" })}</span>
      </Show>
    </footer>
  );
}
