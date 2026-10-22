// The sub-navigation of Settings: the security profile, users, updates and the operator
// secrets, then access, audit export, the vault keys, backup, the reconciler, the guardrails, the
// DNS settings of the node (read-only) and language packs. The settings
// pages show it under their head, and the pages that have a route of their own (secrets and the
// later ones) show it to administrators so that the pages stay one place.
import { A } from "@solidjs/router";
import { For } from "solid-js";
import { paths } from "../app/paths";
import { t, type MessageKey } from "../i18n";
import { DNS_SETTINGS_PATH } from "./dns/paths";
// WP7.4
import { DHCP_SETTINGS_PATH } from "../dhcp/paths";
import { GUARDRAILS_PATH } from "./guardrails/paths";
import { RECONCILER_PATH } from "./reconciler/paths";
import { SECRETS_PATH } from "../secrets/paths";
import { UPDATES_PATH } from "../updates/paths";

interface Tab {
  id: "security" | "users" | "updates" | "secrets" | "access" | "audit-export" | "vault" | "backup" | "reconciler" | "guardrails" | "dns" | "dhcp" | "languages";
  href: string;
  label: MessageKey;
}

const TABS: readonly Tab[] = [
  { id: "security", href: paths.settings("security"), label: "settings.nav.security" },
  { id: "users", href: paths.settings("users"), label: "settings.nav.users" },
  { id: "updates", href: UPDATES_PATH, label: "settings.nav.updates" },
  { id: "secrets", href: SECRETS_PATH, label: "settings.nav.secrets" },
  { id: "access", href: paths.settings("access"), label: "settings.nav.access" },
  { id: "audit-export", href: paths.settings("audit-export"), label: "settings.nav.audit_export" },
  { id: "vault", href: paths.settings("vault"), label: "settings.nav.vault" },
  { id: "backup", href: paths.settings("backup"), label: "settings.nav.backup" },
  { id: "reconciler", href: RECONCILER_PATH, label: "settings.nav.reconciler" },
  { id: "guardrails", href: GUARDRAILS_PATH, label: "settings.nav.guardrails" },
  { id: "dns", href: DNS_SETTINGS_PATH, label: "settings.nav.dns" },
  // WP7.4
  { id: "dhcp", href: DHCP_SETTINGS_PATH, label: "settings.nav.dhcp" },
  { id: "languages", href: paths.settings("languages"), label: "settings.nav.languages" },
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
