// The sub-navigation of the IPAM area (tabs as links, like the settings pages): networks,
// addresses, hosts, VLANs, sites, tenants and VRFs, tags, custom fields and import.
import { A, useLocation } from "@solidjs/router";
import { For } from "solid-js";
import { paths } from "../app/paths";
import { t, type MessageKey } from "../i18n";

interface Tab {
  id: string;
  href: string;
  label: MessageKey;
  /** Paths that belong to the tab besides its own. */
  match: (path: string) => boolean;
}

const TABS: readonly Tab[] = [
  { id: "networks", href: paths.ipam(), label: "ipam.nav.networks", match: (p) => p === "/ipam" || p.startsWith("/ipam/prefixes") || p.startsWith("/ipam/move") },
  { id: "addresses", href: paths.addresses(), label: "ipam.nav.addresses", match: (p) => p.startsWith("/ipam/addresses") },
  { id: "hosts", href: paths.hosts(), label: "ipam.nav.hosts", match: (p) => p.startsWith("/ipam/hosts") || p.startsWith("/ipam/macs") },
  { id: "vlans", href: paths.vlans(), label: "ipam.nav.vlans", match: (p) => p.startsWith("/ipam/vlans") },
  { id: "sites", href: paths.sites(), label: "ipam.nav.sites", match: (p) => p.startsWith("/ipam/sites") },
  { id: "tenancy", href: paths.tenancy(), label: "ipam.nav.tenancy", match: (p) => p.startsWith("/ipam/tenants") },
  { id: "tags", href: paths.tags(), label: "ipam.nav.tags", match: (p) => p.startsWith("/ipam/tags") },
  { id: "fields", href: paths.customFields(), label: "ipam.nav.custom_fields", match: (p) => p.startsWith("/ipam/custom-fields") },
  { id: "import", href: paths.imports(), label: "ipam.nav.import", match: (p) => p.startsWith("/ipam/import") },
];

export function IpamNav() {
  const location = useLocation();
  return (
    <nav class="subnav" aria-label={t("ipam.nav.label")} data-testid="ipam-nav">
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
