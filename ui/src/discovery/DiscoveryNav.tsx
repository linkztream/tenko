// The sub-navigation of the discovery area (tabs as links, like the IPAM area): the findings, the
// proposals with their states, and the observations.
import { A, useLocation } from "@solidjs/router";
import { For } from "solid-js";
import { paths } from "../app/paths";
import { t, type MessageKey } from "../i18n";

interface Tab {
  id: string;
  href: string;
  label: MessageKey;
  match: (path: string) => boolean;
}

const TABS: readonly Tab[] = [
  { id: "findings", href: paths.discovery(), label: "discovery.nav.findings", match: (p) => !p.startsWith("/discovery/observations") && !p.startsWith("/discovery/proposals") },
  { id: "proposals", href: paths.proposals(), label: "discovery.nav.proposals", match: (p) => p.startsWith("/discovery/proposals") },
  { id: "observations", href: paths.observations(), label: "discovery.nav.observations", match: (p) => p.startsWith("/discovery/observations") },
];

export function DiscoveryNav() {
  const location = useLocation();
  return (
    <nav class="subnav" aria-label={t("discovery.nav.label")} data-testid="discovery-nav">
      <For each={TABS}>
        {(tab) => (
          <A
            href={tab.href}
            end
            classList={{ active: tab.match(location.pathname) }}
            aria-current={tab.match(location.pathname) ? "page" : undefined}
            data-tab={tab.id}
          >
            {t(tab.label)}
          </A>
        )}
      </For>
    </nav>
  );
}
