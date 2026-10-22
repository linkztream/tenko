// The DHCP scopes (/dhcp): one row per IPAM network that is served, with its pools, its active
// leases and how full it is (read per row for the rows in view), and the scope's description. Create
// a scope for a network that has none, open one, delete one. A 409 `dhcp.module.disabled` or a 404
// of the route shows the module-off state, a 501 the not-available notice.
import { A, useNavigate } from "@solidjs/router";
import { createSignal, Show } from "solid-js";
import { createLiveQuery, latest } from "../api/live";
import { Icon } from "../components/Icon";
import { PageHead } from "../components/PageHead";
import { DataGrid } from "../grid/DataGrid";
import type { Column, RowAction } from "../grid/types";
import { formatNumber, t } from "../i18n";
import { mayWriteDhcp } from "./access";
import { listScopes, type Scope } from "./api";
import { DhcpNav } from "./DhcpNav";
import { DhcpProblem, unavailable } from "./Parts";
import { dhcpPaths } from "./paths";
import { CreateScopeDialog, DeleteScopeDialog } from "./ScopeDialogs";
import { UtilizationBar } from "./UtilizationBar";
import "./dhcp.css";

export default function ScopesPage() {
  const navigate = useNavigate();
  const [dialog, setDialog] = createSignal<{ kind: "create" } | { kind: "delete"; scope: Scope } | null>(null);
  const query = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const page = await listScopes(signal);
      return { value: page.items, revision: page.revision };
    },
  });
  const blocked = () => unavailable(query.value.error);
  const scopes = () => latest(query);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };

  const columns: Column<Scope>[] = [
    {
      id: "network",
      header: () => t("dhcp.col.network"),
      width: 180,
      fixed: true,
      text: (s) => s.cidr,
      render: (s) => (
        <A class="mono" href={dhcpPaths.scope(s.prefix)} data-testid="scope-link">
          {s.cidr}
        </A>
      ),
    },
    {
      id: "enabled",
      header: () => t("dhcp.col.enabled"),
      width: 110,
      text: (s) => (s.enabled === false ? t("dhcp.scope.disabled") : t("dhcp.scope.enabled")),
      render: (s) => (
        <span class={s.enabled === false ? "tag" : "tag accent"} data-testid="scope-enabled" data-key={s.enabled === false ? "off" : "on"}>
          {s.enabled === false ? t("dhcp.scope.disabled") : t("dhcp.scope.enabled")}
        </span>
      ),
    },
    { id: "pools", header: () => t("dhcp.col.pools"), width: 80, align: "right", text: (s) => String(s.pools), render: (s) => <span class="num">{formatNumber(s.pools)}</span> },
    { id: "leases", header: () => t("dhcp.col.leases"), width: 120, align: "right", text: (s) => String(s.leases), render: (s) => <span class="num">{formatNumber(s.leases)}</span> },
    {
      id: "utilization",
      header: () => t("dhcp.col.utilization"),
      width: 200,
      text: () => "",
      render: (s) => <UtilizationBar prefix={s.prefix} revision={query.revision()} />,
    },
    { id: "description", header: () => t("dhcp.col.description"), render: (s) => <span class="muted">{s.description ?? ""}</span> },
  ];
  const actions: RowAction<Scope>[] = [
    { id: "open", label: () => t("dhcp.do.open"), run: (s) => navigate(dhcpPaths.scope(s.prefix)) },
    { id: "delete", label: () => t("dhcp.do.delete"), danger: true, hidden: () => !mayWriteDhcp(), run: (s) => setDialog({ kind: "delete", scope: s }) },
  ];

  return (
    <div class="page dhcp-page list-page" data-testid="page-dhcp-scopes">
      <DhcpNav />
      <PageHead
        title={t("dhcp.scopes.title")}
        sub={t("dhcp.scopes.sub")}
        actions={
          <Show when={mayWriteDhcp() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dhcp-scope-create" onClick={() => setDialog({ kind: "create" })}>
              <Icon name="plus" />
              {t("dhcp.scope.create")}
            </button>
          </Show>
        }
      />
      <Show
        when={!blocked()}
        fallback={
          <div class="page-body">
            <DhcpProblem error={query.value.error} />
          </div>
        }
      >
        <div class="dhcp-list-body">
          <DataGrid
            id="dhcp-scopes"
            label={t("dhcp.scopes.title")}
            noSelection
            columns={columns}
            rows={scopes() ?? []}
            rowId={(s) => s.prefix}
            rowKey={(s) => s.cidr}
            rowLabel={(s) => s.cidr}
            loading={query.value.loading}
            initial={scopes() === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(s) => navigate(dhcpPaths.scope(s.prefix))}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dhcp-scopes-empty">
                <h3>{t("dhcp.scopes.empty")}</h3>
                <p>{t("dhcp.scopes.empty_body")}</p>
              </div>
            }
          />
        </div>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "create" ? (
            <CreateScopeDialog scopes={scopes() ?? []} onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <DeleteScopeDialog scope={d.scope} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
