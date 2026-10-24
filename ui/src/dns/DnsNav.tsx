// The sub-navigation of the DNS area: zones, views (WP6.4), forwarders, block lists, the blocking
// view, access lists, for holders of `dns.keys` the TSIG keys, the query log, and the cache of a node.
import { A, useLocation } from "@solidjs/router";
import { For, Show } from "solid-js";
import { t, type MessageKey } from "../i18n";
import { mayKeys } from "./access";
import { dnsPaths } from "./paths";
import { recursionPath } from "./recursion/paths";

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
  // WP6.4
  { id: "views", href: dnsPaths.views(), label: "dns.nav.views", match: (p) => p.startsWith("/dns/views"), shown: () => true },
  { id: "forwarders", href: dnsPaths.forwarders(), label: "dns.nav.forwarders", match: (p) => p.startsWith("/dns/forwarders"), shown: () => true },
  { id: "lists", href: dnsPaths.lists(), label: "dns.nav.lists", match: (p) => p.startsWith("/dns/lists"), shown: () => true },
  { id: "blocking", href: dnsPaths.blocking(), label: "dns.nav.blocking", match: (p) => p.startsWith("/dns/blocking"), shown: () => true },
  { id: "acls", href: dnsPaths.acls(), label: "dns.nav.acls", match: (p) => p.startsWith("/dns/acls"), shown: () => true },
  { id: "keys", href: dnsPaths.keys(), label: "dns.nav.keys", match: (p) => p.startsWith("/dns/keys"), shown: mayKeys },
  // WP10.0
  { id: "recursion", href: recursionPath, label: "dns.nav.recursion", match: (p) => p.startsWith(recursionPath), shown: () => true },
  { id: "log", href: dnsPaths.log(), label: "dns.nav.log", match: (p) => p.startsWith("/dns/log"), shown: () => true },
  { id: "cache", href: dnsPaths.cache(), label: "dns.nav.cache", match: (p) => p.startsWith("/dns/cache"), shown: () => true },
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
