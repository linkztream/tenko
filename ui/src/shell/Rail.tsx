import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import { AREAS } from "./areas";

/** The navigation rail: icons with labels, 72 px (decision 13). */
export function Rail(props: { activeJobs: number }) {
  return (
    <nav class="rail" aria-label={t("shell.nav.label")}>
      <For each={AREAS}>
        {(area) => (
          <A
            href={area.path}
            end={area.path === "/"}
            class={area.id === "settings" ? "bottom" : undefined}
            title={t("shell.nav.tooltip", { area: t(area.label), key: area.chord })}
          >
            <Icon name={area.icon} />
            {t(area.label)}
            <Show when={area.id === "jobs" && props.activeJobs > 0}>
              <span class="badge-count" aria-label={t("shell.nav.jobs_badge", { count: props.activeJobs })}>
                {props.activeJobs}
              </span>
            </Show>
          </A>
        )}
      </For>
    </nav>
  );
}
