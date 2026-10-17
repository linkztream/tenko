// The sub-navigation of the DNS area: zones, access lists and, for holders of `dns.keys`, the
// TSIG keys. Views, forwarders and block lists join in later slices.
import { A, useLocation } from "@solidjs/router";
import { For, Show } from "solid-js";
import { t, type MessageKey } from "../i18n";
import { mayKeys } from "./access";
import { dnsPaths } from "./paths";

interface Tab {
  id: string;
  href: string;
  label: MessageKey;
  match: (path: string) => boolean;
  shown: () => boolean;
}

const TABS: readonly Tab[] = [
  {
    id: "zones",
    href: dnsPaths.zones(),
    label: "dns.nav.zones",
    match: (p) => p === "/dns" || p.startsWith("/dns/zones") || p.startsWith("/dns/import"),
    shown: () => true,
  },
  { id: "acls", href: dnsPaths.acls(), label: "dns.nav.acls", match: (p) => p.startsWith("/dns/acls"), shown: () => true },
  { id: "keys", href: dnsPaths.keys(), label: "dns.nav.keys", match: (p) => p.startsWith("/dns/keys"), shown: mayKeys },
];

export function DnsNav() {
  const location = useLocation();
  return (
    <nav class="subnav" aria-label={t("dns.nav.label")} data-testid="dns-nav">
      <For each={TABS}>
        {(tab) => (
          <Show when={tab.shown()}>
            <A
              href={tab.href}
              end
              classList={{ active: tab.match(location.pathname) }}
              aria-current={tab.match(location.pathname) ? "page" : undefined}
              data-tab={tab.id}
              data-testid="dns-nav-link"
              data-key={tab.id}
            >
              {t(tab.label)}
            </A>
          </Show>
        )}
      </For>
    </nav>
  );
}
