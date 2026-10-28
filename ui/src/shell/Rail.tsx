import { A } from "@solidjs/router";
import { createMemo, For, Show } from "solid-js";
import { session } from "../auth/session";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import { areaEnabled } from "../updates/modules";
import { AREAS, type Area } from "./areas";
import type { FindingCounts } from "./findings";
import type * as Badges from "./railBadge";

/**
 * The navigation rail: icons with labels, 72 px (decision 13), the twelve areas in three groups
 * separated by hairlines with Settings at the bottom (decision 17), each with its badge
 * (railBadge.tsx, which the shell hands in once it has loaded).
 */
export function Rail(props: { counts: FindingCounts | null; badges?: Pick<typeof Badges, "railBadge" | "RailBadgeView"> | undefined }) {
  const weakened = () => {
    const banner = session()?.banner;
    return !!banner && !banner.lab && banner.weaker_than_home;
  };
  const shown = createMemo(() => AREAS.filter((a) => areaEnabled(a.id)));
  // A hairline before the first item of every group but the first; Settings is pushed down.
  const startsGroup = (area: Area, index: number) => index > 0 && area.group !== "bottom" && shown()[index - 1]?.group !== area.group;
  return (
    <nav class="rail" aria-label={t("shell.nav.label")} data-testid="rail">
      <For each={shown()}>
        {(area, index) => {
          const badge = createMemo(() => props.badges?.railBadge(area, props.counts, weakened()) ?? null);
          return (
            <>
              <Show when={startsGroup(area, index())}>
                <span class="sep" aria-hidden="true" data-testid="rail-sep" />
              </Show>
              <A
                href={area.path}
                end={area.path === "/"}
                class={area.id === "settings" ? "bottom" : undefined}
                title={t("shell.nav.tooltip", { area: t(area.label), key: area.chord })}
                aria-label={badge()?.label}
                data-area={area.id}
                data-group={area.group}
              >
                <Icon name={area.icon} />
                {t(area.label)}
                <Show when={badge()}>
                  {(b) => {
                    const View = props.badges?.RailBadgeView;
                    return View ? <View badge={b()} /> : null;
                  }}
                </Show>
              </A>
            </>
          );
        }}
      </For>
    </nav>
  );
}
