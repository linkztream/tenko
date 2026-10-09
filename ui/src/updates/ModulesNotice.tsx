// The notice for administrators while a change of the modules waits for a restart: what
// runs now and what will run after it. The server reports it as the status warning
// `sys.modules.restart_required` (parameters `configured` and `running`), which the
// dashboard already reads for its node tile.
import { Show } from "solid-js";
import type { SystemStatus } from "../api/types";
import { isAdmin } from "../auth/session";
import { Notice } from "../components/Notice";
import { formatList, t } from "../i18n";
import { parseModuleList, RESTART_WARNING, type ModuleName } from "./modules";

const NAME = {
  ipam: "dashboard.modules.name.ipam",
  dns: "dashboard.modules.name.dns",
  dhcp: "dashboard.modules.name.dhcp",
  discovery: "dashboard.modules.name.discovery",
} as const satisfies Record<ModuleName, string>;

function names(list: readonly ModuleName[]): string {
  return list.length === 0 ? t("dashboard.modules.none") : formatList(list.map((m) => t(NAME[m])));
}

export default function ModulesNotice(props: { warnings: SystemStatus["warnings"] | undefined }) {
  const warning = () => (props.warnings ?? []).find((w) => w.code === RESTART_WARNING);
  return (
    <Show when={isAdmin() ? warning() : undefined}>
      {(w) => (
        <Notice kind="warn" role="status" title={t("dashboard.modules.restart_title")} testid="dashboard-modules-restart">
          {t("dashboard.modules.restart_body", {
            running: names(parseModuleList(w().params?.running)),
            configured: names(parseModuleList(w().params?.configured)),
          })}
        </Notice>
      )}
    </Show>
  );
}
