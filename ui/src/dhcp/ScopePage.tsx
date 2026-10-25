// One scope (/dhcp/scopes/:prefix/:tab?): the network it serves, its family and whether it is enabled,
// and six tabs: the settings with the utilization figures, the pools, the exclusions, the options
// with the effective options of a client, DDNS and network boot (WP8.6). A DHCPv6 scope (WP9.4) has
// a DHCPv6 tab after the settings and no network boot tab: an old link to it shows the line that
// says why. The scope follows the `dhcp` topic; a switched-off module or a server without the
// service shows the notice.
import { A, useNavigate, useParams } from "@solidjs/router";
import { createSignal, For, Match, Show, Switch } from "solid-js";
import { createLiveQuery, latest } from "../api/live";
import { decodeSegment, paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";
import { mayWriteDhcp } from "./access";
import { getScope, type Scope } from "./api";
import { DhcpNav } from "./DhcpNav";
import { DhcpProblem, unavailable } from "./Parts";
import { isV6 } from "./model";
import { dhcpPaths, type ScopeTab } from "./paths";
import { DeleteScopeDialog } from "./ScopeDialogs";
import { ExclusionsTab, PoolsTab } from "./ScopeLists";
import { OptionsTab } from "./ScopeOptions";
import { SettingsTab } from "./ScopeSettings";
// WP9.4: the DHCPv6 tab, and the line for what only DHCPv4 has.
import { ScopeV6Tab } from "./v6/ScopeV6";
import { V4Only } from "./v6/V4Only";
// WP8.6: the DDNS and the network boot tabs.
import { BootTab } from "./boot/ScopeBoot";
import { DdnsTab } from "./ddns/ScopeDdns";
import "./dhcp.css";

/** Every tab a path can name. */
const TABS: readonly ScopeTab[] = ["settings", "v6", "pools", "exclusions", "options", "ddns", "boot"];

/** The tabs a scope shows: the DHCPv6 tab only for a DHCPv6 scope, network boot only for a DHCPv4 one. */
function tabsOf(scope: Scope): readonly ScopeTab[] {
  return TABS.filter((name) => (name === "v6" ? isV6(scope) : name === "boot" ? !isV6(scope) : true));
}

export default function ScopePage() {
  const params = useParams<{ prefix: string; tab?: string }>();
  const navigate = useNavigate();
  const id = () => decodeSegment(params.prefix);
  // The tab of the path; the DHCPv6 tab of a DHCPv4 scope is the settings. The boot tab of a DHCPv6 scope stays what the path says, to show its line.
  const tabOf = (scope: Scope): ScopeTab => {
    const name = params.tab as ScopeTab;
    if (!TABS.includes(name) || (name === "v6" && !isV6(scope))) return "settings";
    return name;
  };
  const [deleting, setDeleting] = createSignal(false);

  const query = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const scope = await getScope(id(), signal);
      return { value: scope, revision: scope.revision };
    },
  });
  const [saved, setSaved] = createSignal<Scope | null>(null);
  // A save answers the new scope before the event arrives; show it at once.
  const current = () => {
    const s = latest(query);
    const k = saved();
    return k && s && k.prefix === s.prefix && k.revision >= s.revision ? k : s;
  };

  return (
    <div class="page dhcp-page" data-testid="page-dhcp-scope" data-id={id()}>
      <DhcpNav />
      <Show
        when={current()}
        fallback={
          <>
            <PageHead title={t("dhcp.scope.title")} />
            <div class="page-body">
              <Show when={query.value.error} fallback={<p class="muted">{t("common.loading")}</p>}>
                {(err) => (
                  <Show when={unavailable(err())} fallback={<ErrorNotice error={err()} />}>
                    <DhcpProblem error={err()} />
                  </Show>
                )}
              </Show>
            </div>
          </>
        }
      >
        {(s) => (
          <>
            <PageHead
              crumbs={<A href={dhcpPaths.scopes()}>{t("dhcp.scopes.title")}</A>}
              title={<span class="mono" data-testid="scope-name">{s().cidr}</span>}
              sub={
                <>
                  <span class={s().enabled === false ? "tag" : "tag accent"} data-testid="scope-state" data-key={s().enabled === false ? "off" : "on"}>
                    {s().enabled === false ? t("dhcp.scope.disabled") : t("dhcp.scope.enabled")}
                  </span>{" "}
                  {/* WP9.4: DHCPv4 or DHCPv6. */}
                  <span class="tag" data-testid="scope-family" data-key={isV6(s()) ? "v6" : "v4"}>
                    {isV6(s()) ? t("dhcp.family.v6") : t("dhcp.family.v4")}
                  </span>{" "}
                  <Show when={s().description}>
                    <span class="muted">{s().description}</span>
                  </Show>
                </>
              }
              actions={
                <>
                  <A class="btn" href={paths.prefix(s().cidr)} data-testid="scope-ipam-link">
                    {t("dhcp.scope.in_ipam")}
                  </A>
                  <Show when={mayWriteDhcp()}>
                    <button type="button" class="btn danger" data-testid="dhcp-scope-delete" onClick={() => setDeleting(true)}>
                      <Icon name="trash" />
                      {t("dhcp.do.delete")}
                    </button>
                  </Show>
                </>
              }
            />
            <div class="tabs" role="tablist" aria-label={t("dhcp.scope.tabs")}>
              <For each={tabsOf(s())}>
                {(name) => (
                  <button
                    type="button"
                    role="tab"
                    aria-selected={tabOf(s()) === name}
                    data-testid={`scope-tab-${name}`}
                    onClick={() => navigate(dhcpPaths.scope(s().prefix, name))}
                  >
                    {t(`dhcp.scope.tab.${name}`)}
                  </button>
                )}
              </For>
            </div>
            <Switch>
              <Match when={tabOf(s()) === "settings"}>
                <SettingsTab
                  scope={s()}
                  onSaved={(next) => {
                    setSaved(next);
                    query.refetch();
                  }}
                />
              </Match>
              {/* WP9.4: the DHCPv6 settings. */}
              <Match when={tabOf(s()) === "v6"}>
                <ScopeV6Tab
                  scope={s()}
                  onSaved={(next) => {
                    setSaved(next);
                    query.refetch();
                  }}
                />
              </Match>
              <Match when={tabOf(s()) === "pools"}>
                <PoolsTab scope={s()} />
              </Match>
              <Match when={tabOf(s()) === "exclusions"}>
                <ExclusionsTab scope={s()} />
              </Match>
              <Match when={tabOf(s()) === "options"}>
                <OptionsTab scope={s()} />
              </Match>
              {/* WP8.6: DDNS and network boot. */}
              <Match when={tabOf(s()) === "ddns"}>
                <DdnsTab
                  scope={s()}
                  onSaved={(next) => {
                    setSaved(next);
                    query.refetch();
                  }}
                />
              </Match>
              <Match when={tabOf(s()) === "boot"}>
                <Show
                  when={!isV6(s())}
                  fallback={
                    <div class="page-body dhcp-tab" data-testid="scope-boot-v6">
                      <V4Only part="boot" />
                    </div>
                  }
                >
                  <BootTab scope={s()} />
                </Show>
              </Match>
            </Switch>
            <Show when={deleting()}>
              <DeleteScopeDialog
                scope={s()}
                onClose={() => setDeleting(false)}
                onDone={() => {
                  setDeleting(false);
                  navigate(dhcpPaths.scopes());
                }}
              />
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}
