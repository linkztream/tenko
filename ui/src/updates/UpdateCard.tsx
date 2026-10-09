// The dashboard card "Update available": the newest version, its marks and a link to the
// updates page. Nothing shows when nothing is newer or this account may not read updates.
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { t } from "../i18n";
import { Marks } from "./Marks";
import { UPDATES_PATH } from "./paths";
import { useUpdateStatus } from "./status";

export default function UpdateCard() {
  const status = useUpdateStatus();
  const newest = () => {
    const s = status();
    return s?.update_available ? (s.latest ?? s.releases[0]?.version ?? null) : null;
  };
  return (
    <Show when={newest()}>
      {(version) => (
        <section class="card dash-card update-card" aria-labelledby="dash-update" data-testid="dashboard-update">
          <h2 id="dash-update">{t("dashboard.update.title")}</h2>
          <p>{t("dashboard.update.body", { version: version(), running: status()?.running ?? "" })}</p>
          <Marks
            security={status()?.security}
            action={status()?.requires_action}
            securityLabel={t("dashboard.update.security")}
            actionLabel={t("dashboard.update.action")}
          />
          <p>
            <A class="btn" href={UPDATES_PATH} data-testid="dashboard-update-open">
              {t("dashboard.update.open")}
            </A>
          </p>
        </section>
      )}
    </Show>
  );
}
