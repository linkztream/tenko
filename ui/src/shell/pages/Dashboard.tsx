import { For, Show } from "solid-js";
import { PageHead } from "../../components/PageHead";
import { Si } from "../../components/Si";
import { formatDuration, t, type MessageKey } from "../../i18n";
import { createShellStatus } from "../status";
import { storeRoleLabel } from "../TopBar";

const ROLE: Record<string, MessageKey> = {
  controller: "node.role.controller",
  dns: "node.role.dns",
  dhcp: "node.role.dhcp",
  probe: "node.role.probe",
};

/**
 * The start page (decision 13). Slice 1 shows the node and store at a glance; the health
 * charts of the dashboard mockup arrive with the DNS and DHCP roles.
 */
export default function Dashboard() {
  const status = createShellStatus();
  const s = () => status.system();
  return (
    <div class="page">
      <PageHead title={t("shell.nav.dashboard")} sub={t("shell.dashboard.sub")} />
      <div class="page-body">
        <div class="tiles">
          <section class="card tile">
            <h2>{t("shell.dashboard.node")}</h2>
            <div class="tile-value">{s() ? storeRoleLabel(s()?.store.role) : "–"}</div>
            <p class="muted">
              <For each={s()?.node.roles ?? []} fallback={t("shell.dashboard.no_roles")}>
                {(r, i) => (
                  <>
                    {i() > 0 ? ", " : ""}
                    {ROLE[r] ? t(ROLE[r]!) : r}
                  </>
                )}
              </For>
            </p>
          </section>
          <section class="card tile">
            <h2>{t("shell.dashboard.revision")}</h2>
            <div class="tile-value">
              <Si value={s()?.store.revision} />
            </div>
            <p class="muted">{t("shell.dashboard.revision_hint")}</p>
          </section>
          <section class="card tile">
            <h2>{t("shell.dashboard.jobs")}</h2>
            <div class="tile-value">
              <Si value={status.jobs() ? status.jobs()!.running + status.jobs()!.waiting : null} />
            </div>
            <p class="muted">{t("shell.dashboard.jobs_hint")}</p>
          </section>
          <section class="card tile">
            <h2>{t("shell.dashboard.uptime")}</h2>
            <div class="tile-value">{s() ? formatDuration(Math.floor((s()?.uptime_seconds ?? 0) / 60) * 60) : "–"}</div>
            <p class="muted">{s() ? t("shell.status.version", { version: s()!.version }) : ""}</p>
          </section>
        </div>
        <Show when={status.systemError()}>
          <p class="muted">{t("shell.top.node_unreachable")}</p>
        </Show>
        <p class="muted">{t("shell.dashboard.note")}</p>
      </div>
    </div>
  );
}
