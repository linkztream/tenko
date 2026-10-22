// One scope (/dhcp/scopes/:prefix/:tab?): the network it serves and whether it is enabled, and four
// tabs: the settings with the utilization figures, the pools, the exclusions and the options with
// the effective options of a client. The scope follows the `dhcp` topic; a switched-off module or a
// server without the service shows the notice.
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
import { dhcpPaths, type ScopeTab } from "./paths";
import { DeleteScopeDialog } from "./ScopeDialogs";
import { ExclusionsTab, PoolsTab } from "./ScopeLists";
import { OptionsTab } from "./ScopeOptions";
import { SettingsTab } from "./ScopeSettings";
import "./dhcp.css";

const TABS: readonly ScopeTab[] = ["settings", "pools", "exclusions", "options"];

export default function ScopePage() {
  const params = useParams<{ prefix: string; tab?: string }>();
  const navigate = useNavigate();
  const id = () => decodeSegment(params.prefix);
  const tab = (): ScopeTab => (TABS.includes(params.tab as ScopeTab) ? (params.tab as ScopeTab) : "settings");
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
              <For each={TABS}>
                {(name) => (
                  <button
                    type="button"
                    role="tab"
                    aria-selected={tab() === name}
                    data-testid={`scope-tab-${name}`}
                    onClick={() => navigate(dhcpPaths.scope(s().prefix, name))}
                  >
                    {t(`dhcp.scope.tab.${name}`)}
                  </button>
                )}
              </For>
            </div>
            <Switch>
              <Match when={tab() === "settings"}>
                <SettingsTab
                  scope={s()}
                  onSaved={(next) => {
                    setSaved(next);
                    query.refetch();
                  }}
                />
              </Match>
              <Match when={tab() === "pools"}>
                <PoolsTab scope={s()} />
              </Match>
              <Match when={tab() === "exclusions"}>
                <ExclusionsTab scope={s()} />
              </Match>
              <Match when={tab() === "options"}>
                <OptionsTab scope={s()} />
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
