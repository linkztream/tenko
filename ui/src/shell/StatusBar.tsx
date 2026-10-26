import { A } from "@solidjs/router";
import { lazy, Show } from "solid-js";
import { events, type ConnectionState } from "../api/events";
import { paths } from "../app/paths";
import { isAdmin } from "../auth/session";
import { partition } from "../cluster/partition";
import { Icon } from "../components/Icon";
import { formatRelative, t, type MessageKey } from "../i18n";
import { moduleRestart, moduleRunning } from "../updates/modules";
import { UPDATES_PATH } from "../updates/paths";
import { PartitionStatus } from "./ClusterBanner";
import { now, selection, type JobCounts } from "./status";

const STATE: Record<ConnectionState, { key: MessageKey; dot: string }> = {
  live: { key: "shell.status.live", dot: "dot live" },
  connecting: { key: "shell.status.connecting", dot: "dot warn" },
  reconnecting: { key: "shell.status.reconnecting", dot: "dot warn" },
  offline: { key: "shell.status.offline", dot: "dot bad" },
  idle: { key: "shell.status.idle", dot: "dot idle" },
};

// The utilization alarms come from the IPAM area; loaded after the shell is up.
const AlarmStatus = lazy(() => import("../ipam/AlarmStatus"));
// The notice of a newer release comes from the updates area, for administrators only.
const UpdateStatusItem = lazy(() => import("../updates/UpdateStatusItem"));
// The open proposals come from the discovery area; loaded after the shell is up.
const ProposalsStatusItem = lazy(() => import("../discovery/ProposalsStatusItem"));

/**
 * The status bar (decision 14): live connection, last event, the age of a stale local copy, jobs,
 * alarms, open proposals, selection, version.
 */
export function StatusBar(props: { jobs: JobCounts | null; version: string | undefined }) {
  const state = () => STATE[events.state()];
  const lastEvent = () => {
    const at = events.lastEventAt();
    if (at === null) return t("shell.status.no_events");
    return t("shell.status.last_event", {
      ago: formatRelative(Math.min(at, now()), now()),
    });
  };
  return (
    <footer class="statusbar">
      <span title={t("shell.status.live_title")}>
        <span class={state().dot} />
        {t(state().key)}
      </span>
      <span>{lastEvent()}</span>
      <Show when={partition.active()}>
        <PartitionStatus status />
      </Show>
      <Show when={props.jobs}>
        {(jobs) => (
          <A class="status-jobs" href={paths.jobs()} title={t("shell.status.jobs_title")}>
            <span class="jstate running">{t("shell.status.running", { count: jobs().running })}</span>
            <span class="jstate waiting">{t("shell.status.waiting", { count: jobs().waiting })}</span>
          </A>
        )}
      </Show>
      <Show when={moduleRunning("ipam")}>
        <AlarmStatus />
      </Show>
      <Show when={moduleRunning("discovery")}>
        <ProposalsStatusItem />
      </Show>
      <Show when={isAdmin()}>
        <UpdateStatusItem />
        <Show when={moduleRestart() !== "none"}>
          <span class="status-modules" title={t("shell.status.modules_restart_title")} data-testid="status-modules">
            <Icon name="refresh" size="sm" />
            {t("shell.status.modules_restart")}
          </span>
        </Show>
      </Show>
      <Show when={selection()}>
        {(sel) => (
          <span>
            {t("shell.status.selection", {
              selected: sel().selected,
              total: sel().total,
            })}
          </span>
        )}
      </Show>
      <span class="grow" />
      <Show when={props.version}>
        <Show when={isAdmin()} fallback={<span>{t("shell.status.version", { version: props.version ?? "" })}</span>}>
          <A
            class="status-version"
            href={UPDATES_PATH}
            aria-label={t("shell.status.version_link", { version: props.version ?? "" })}
            data-testid="status-version"
          >
            {t("shell.status.version", { version: props.version ?? "" })}
          </A>
        </Show>
      </Show>
    </footer>
  );
}
