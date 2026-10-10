// The sub-navigation of Settings: the security profile, users, updates and the operator
// secrets. The settings pages show it under their head, and the secrets page, which has a route
// of its own, shows it to administrators so that the pages stay one place.
import { A } from "@solidjs/router";
import { For } from "solid-js";
import { paths } from "../app/paths";
import { t, type MessageKey } from "../i18n";
import { SECRETS_PATH } from "../secrets/paths";
import { UPDATES_PATH } from "../updates/paths";

interface Tab {
  id: "security" | "users" | "updates" | "secrets";
  href: string;
  label: MessageKey;
}

const TABS: readonly Tab[] = [
  { id: "security", href: paths.settings("security"), label: "settings.nav.security" },
  { id: "users", href: paths.settings("users"), label: "settings.nav.users" },
  { id: "updates", href: UPDATES_PATH, label: "settings.nav.updates" },
  { id: "secrets", href: SECRETS_PATH, label: "settings.nav.secrets" },
];

export function SettingsNav() {
  return (
    <nav class="subnav" aria-label={t("settings.nav.label")} data-testid="settings-nav">
      <For each={TABS}>
        {(tab) => (
          <A href={tab.href} data-testid="settings-nav-link" data-key={tab.id}>
            {t(tab.label)}
          </A>
        )}
      </For>
    </nav>
  );
}
