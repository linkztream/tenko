// The sub-navigation of the DHCP area: scopes, shared networks, options, classes, policies, MAC
// filters, then the leases and the history, which come with later packages.
import { A, useLocation } from "@solidjs/router";
import { For } from "solid-js";
import { t, type MessageKey } from "../i18n";
import { dhcpPaths } from "./paths";

interface Tab {
  id: string;
  href: string;
  label: MessageKey;
  match: (path: string) => boolean;
}

const TABS: readonly Tab[] = [
  { id: "scopes", href: dhcpPaths.scopes(), label: "dhcp.nav.scopes", match: (p) => p === "/dhcp" || p.startsWith("/dhcp/scopes") },
  { id: "shared-networks", href: dhcpPaths.sharedNetworks(), label: "dhcp.nav.shared_networks", match: (p) => p.startsWith("/dhcp/shared-networks") },
  { id: "options", href: dhcpPaths.options(), label: "dhcp.nav.options", match: (p) => p.startsWith("/dhcp/options") },
  { id: "classes", href: dhcpPaths.classes(), label: "dhcp.nav.classes", match: (p) => p.startsWith("/dhcp/classes") },
  { id: "policies", href: dhcpPaths.policies(), label: "dhcp.nav.policies", match: (p) => p.startsWith("/dhcp/policies") },
  { id: "filters", href: dhcpPaths.filters(), label: "dhcp.nav.filters", match: (p) => p.startsWith("/dhcp/filters") },
  { id: "leases", href: dhcpPaths.leases(), label: "dhcp.nav.leases", match: (p) => p.startsWith("/dhcp/leases") },
  { id: "history", href: dhcpPaths.history(), label: "dhcp.nav.history", match: (p) => p.startsWith("/dhcp/history") },
];

export function DhcpNav() {
  const location = useLocation();
  return (
    <nav class="subnav" aria-label={t("dhcp.nav.label")} data-testid="dhcp-nav">
      <For each={TABS}>
        {(tab) => (
          <A
            href={tab.href}
            end
            classList={{ active: tab.match(location.pathname) }}
            aria-current={tab.match(location.pathname) ? "page" : undefined}
            data-tab={tab.id}
            data-testid="dhcp-nav-link"
            data-key={tab.id}
          >
            {t(tab.label)}
          </A>
        )}
      </For>
    </nav>
  );
}
