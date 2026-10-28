// What the active security profile changes, behind the profile chip of the top bar
// (docs/SECURITY-PROFILES.md, ui-plan section 6): every toggle of the UI with the value the
// profile sets, the ones this installation changed marked "Changed" (the session's banner names
// them), and for an administrator the way to the security settings. The values come from the
// profile table the settings page previews with (settings/profileMatrix.ts); no read.
import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import type { Profile } from "../api/types";
import { paths } from "../app/paths";
import { isAdmin, session } from "../auth/session";
import { Popover } from "../components/Popover";
import { t } from "../i18n";
import { PROFILE_DEFAULTS, valueOf } from "../settings/profileMatrix";
import { formatToggle, TOGGLES } from "../settings/toggles";

export default function ProfileCard(props: { id: string; anchor: HTMLElement; profile: Profile; onClose: () => void }) {
  const name = () => t(`profile.${props.profile}.name`);
  const changed = (id: string) => session()?.banner.deviations.includes(id) ?? false;
  const count = () => TOGGLES.filter((def) => changed(def.id)).length;
  return (
    <Popover
      anchor={props.anchor}
      id={props.id}
      label={t("settings.profile_card.title", { profile: name() })}
      onClose={props.onClose}
      align="end"
      testid="profile-card"
      class="top-card profile-card"
    >
      <h2 class="popover-title">{t("settings.profile_card.title", { profile: name() })}</h2>
      <p class="muted">{t(`profile.${props.profile}.description`)}</p>
      <table class="plain card-toggles" aria-label={t("settings.profile_card.table", { profile: name() })}>
        <thead>
          <tr>
            <th scope="col">{t("settings.profile_card.col.setting")}</th>
            <th scope="col">{t("settings.profile_card.col.value", { profile: name() })}</th>
          </tr>
        </thead>
        <tbody>
          <For each={TOGGLES}>
            {(def) => (
              <tr data-testid="profile-card-toggle" data-toggle={def.id} data-changed={changed(def.id) ? "true" : undefined}>
                <th scope="row">{t(def.name)}</th>
                <td>
                  {formatToggle(def.setting, valueOf(PROFILE_DEFAULTS[props.profile], def.setting))}
                  <Show when={changed(def.id)}>
                    {" "}
                    <span class="tag discrepancy">{t("settings.profile_card.changed")}</span>
                  </Show>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
      <p class="muted" data-testid="profile-card-summary">
        {t("settings.profile_card.summary", { count: count() })}
      </p>
      <Show when={isAdmin()}>
        <A class="btn sm" href={paths.settings("security")} onClick={() => props.onClose()} data-testid="profile-card-open">
          {t("settings.profile_card.open")}
        </A>
      </Show>
    </Popover>
  );
}
