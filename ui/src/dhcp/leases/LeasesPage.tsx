// The leases (/dhcp/leases, WP7.5): every lease the server holds, by address, in a grid read page
// by page, with filters for the scope, the address (a prefix of its text), the MAC address, the
// name and the state; they live in the URL. A status strip shows what this node's role does. The
// view is live: it follows the `dhcp` event topic and reads the visible page again when the lease
// table changed, sampled (sampler.ts), and says how many changes it folded when the server is
// busier than the page can follow; the Live toggle pauses it. Principals with `dhcp.write` release
// an active lease, with an optional reason. A 409 `dhcp.module.disabled` or a 404 of the route
// shows the module-off state, a 501 the not-available notice.
import { A, useNavigate, useSearchParams } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, Show } from "solid-js";
import { Icon } from "../../components/Icon";
import { PageHead } from "../../components/PageHead";
import { DataGrid } from "../../grid/DataGrid";
import { createListSource } from "../../grid/source";
import type { Column, RowAction } from "../../grid/types";
import { formatDateTime, formatRelative, t } from "../../i18n";
import { mayWriteDhcp } from "../access";
import { listScopes, type Scope } from "../api";
import { DhcpNav } from "../DhcpNav";
import { DhcpProblem, unavailable } from "../Parts";
import { SelectFilter, TextFilter } from "./Filters";
import { createLiveRefresh, LEASE_TABLE, LiveControls } from "./live";
import {
  anyFilter,
  BINDING_STATES,
  clientIdOf,
  historyHref,
  leaseKey,
  leaseQuery,
  LEASE_FILTER_NAMES,
  macOf,
  macProblem,
  nameOf,
  readLeaseFilters,
  type Lease,
} from "./model";
import { NodeStrip } from "./NodeStrip";
import { ReleaseDialog } from "./ReleaseDialog";
import "../dhcp.css";
import "./leases.css";

const ENDS: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "medium" };

export default function LeasesPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useSearchParams();
  const filters = createMemo(() => readLeaseFilters(search));
  const query = createMemo(() => leaseQuery(filters()), undefined, { equals: (a, b) => JSON.stringify(a) === JSON.stringify(b) });
  const [dialog, setDialog] = createSignal<Lease | null>(null);
  const [stripVersion, setStripVersion] = createSignal(0);

  // The scopes name the network of a lease; without them the identifier is shown.
  const [scopes] = createResource<Scope[]>(async () => {
    try {
      return (await listScopes()).items;
    } catch {
      return [];
    }
  });
  const scopeList = () => (scopes.error ? [] : (scopes.latest ?? []));
  const networkOf = (id: string) => scopeList().find((s) => s.prefix === id)?.cidr ?? id;

  const list = createListSource<Lease>({
    path: "/api/v1/dhcp/leases",
    query,
    rowId: leaseKey,
    pageSize: 100,
    // The row changes when the store row does; the flash marks it.
    signature: (lease) => `${lease.revision}/${lease.state}`,
  });

  const reload = () => {
    list.reload();
    setStripVersion((v) => v + 1);
  };
  const live = createLiveRefresh({ table: LEASE_TABLE, revision: list.revision, refresh: reload });

  const change = (name: (typeof LEASE_FILTER_NAMES)[number], value: string) => setSearch({ [name]: value === "" ? undefined : value }, { replace: true });
  const reset = () => setSearch(Object.fromEntries(LEASE_FILTER_NAMES.map((name) => [name, undefined])), { replace: true });

  const blocked = () => unavailable(list.error());

  const columns: Column<Lease>[] = [
    {
      id: "addr",
      header: () => t("dhcp.col.address"),
      width: 150,
      fixed: true,
      text: (l) => l.addr,
      render: (l) => (
        <A class="mono" href={historyHref(l.addr)} title={t("dhcp.lease.history_link")} data-testid="lease-history-link">
          {l.addr}
        </A>
      ),
    },
    {
      id: "state",
      header: () => t("dhcp.col.state"),
      width: 110,
      text: (l) => t(`dhcp.leases.state.${l.state}`),
      render: (l) => (
        <span class={l.state === "active" ? "tag accent" : l.state === "abandoned" || l.state === "reset" ? "tag conflict" : "tag"} data-testid="lease-state" data-key={l.state}>
          {t(`dhcp.leases.state.${l.state}`)}
        </span>
      ),
    },
    { id: "mac", header: () => t("dhcp.col.client_mac"), width: 150, text: (l) => macOf(l.client), render: (l) => <span class="mono">{macOf(l.client)}</span> },
    {
      id: "client_id",
      header: () => t("dhcp.col.client_id"),
      width: 170,
      hidden: true,
      text: (l) => clientIdOf(l.client) ?? "",
      render: (l) => <span class="mono muted">{clientIdOf(l.client) ?? ""}</span>,
    },
    {
      id: "name",
      header: () => t("dhcp.col.host_name"),
      width: 220,
      text: (l) => nameOf(l).name,
      render: (l) => {
        const n = nameOf(l);
        return (
          <span>
            {n.name}
            <Show when={n.extra !== ""}>
              {" "}
              <span class="muted">({n.extra})</span>
            </Show>
          </span>
        );
      },
    },
    { id: "scope", header: () => t("dhcp.col.scope"), width: 150, text: (l) => networkOf(l.scope), render: (l) => <span class="mono">{networkOf(l.scope)}</span> },
    {
      id: "ends",
      header: () => t("dhcp.col.ends"),
      width: 210,
      text: (l) => formatDateTime(l.ends, ENDS),
      render: (l) => (
        <span class="dhcp-ends" data-testid="lease-ends">
          <span>{formatRelative(l.ends)}</span>
          <time class="muted" datetime={l.ends}>
            {formatDateTime(l.ends, ENDS)}
          </time>
        </span>
      ),
    },
    {
      id: "reserved",
      header: () => t("dhcp.col.reserved"),
      width: 100,
      text: (l) => (l.reserved ? t("dhcp.lease.reserved") : ""),
      render: (l) => (
        <Show when={l.reserved}>
          <span class="tag" data-testid="lease-reserved">
            {t("dhcp.lease.reserved")}
          </span>
        </Show>
      ),
    },
    {
      id: "relay",
      header: () => t("dhcp.col.relay"),
      width: 130,
      text: (l) => l.relay?.giaddr ?? "",
      render: (l) => <span class="mono muted">{l.relay?.giaddr ?? ""}</span>,
    },
  ];

  const actions: RowAction<Lease>[] = [
    { id: "history", label: () => t("dhcp.do.history"), run: (l) => navigate(historyHref(l.addr)) },
    {
      id: "release",
      label: () => t("dhcp.lease.release"),
      danger: true,
      hidden: () => !mayWriteDhcp(),
      disabled: (l) => l.state !== "active",
      run: (l) => setDialog(l),
    },
  ];

  return (
    <div class="page dhcp-page list-page" data-testid="page-dhcp-leases">
      <DhcpNav />
      <PageHead
        title={t("dhcp.leases.title")}
        sub={t("dhcp.leases.sub")}
        actions={
          <Show when={!blocked()}>
            <LiveControls live={live} testid="leases" />
            <button type="button" class="btn" data-testid="leases-refresh" onClick={reload}>
              <Icon name="refresh" />
              {t("dhcp.do.refresh")}
            </button>
          </Show>
        }
      />
      <Show
        when={!blocked()}
        fallback={
          <div class="page-body">
            <DhcpProblem error={list.error()} />
          </div>
        }
      >
        <NodeStrip version={stripVersion} />
        <form class="dhcp-filters" role="search" aria-label={t("dhcp.leases.filters")} data-testid="leases-filters" onSubmit={(e) => e.preventDefault()}>
          <SelectFilter id="scope" label={t("dhcp.lfilter.scope")} onCommit={(v) => change("scope", v)}>
            <option value="" selected={filters().scope === ""}>
              {t("dhcp.lfilter.scope_any")}
            </option>
            <For each={scopeList()}>
              {(s) => (
                <option value={s.prefix} selected={filters().scope === s.prefix}>
                  {s.cidr}
                </option>
              )}
            </For>
            <Show when={filters().scope !== "" && !scopeList().some((s) => s.prefix === filters().scope)}>
              <option value={filters().scope} selected>
                {filters().scope}
              </option>
            </Show>
          </SelectFilter>
          <TextFilter id="addr" label={t("dhcp.lfilter.addr")} value={filters().addr} placeholder={t("dhcp.lfilter.addr_placeholder")} mono onCommit={(v) => change("addr", v)} />
          <TextFilter
            id="mac"
            label={t("dhcp.lfilter.mac")}
            value={filters().mac}
            placeholder={t("dhcp.example.mac")}
            mono
            problem={macProblem(filters().mac) ? t("dhcp.lfilter.mac_invalid") : undefined}
            onCommit={(v) => change("mac", v)}
          />
          <TextFilter id="name" label={t("dhcp.lfilter.name")} value={filters().name} placeholder={t("dhcp.lfilter.name_placeholder")} onCommit={(v) => change("name", v)} />
          <SelectFilter id="state" label={t("dhcp.lfilter.state")} onCommit={(v) => change("state", v)}>
            <option value="" selected={filters().state === ""}>
              {t("dhcp.lfilter.state_any")}
            </option>
            <For each={BINDING_STATES}>
              {(state) => (
                <option value={state} selected={filters().state === state}>
                  {t(`dhcp.leases.state.${state}`)}
                </option>
              )}
            </For>
          </SelectFilter>
          <Show when={anyFilter(filters())}>
            <div class="dhcp-filter-actions">
              <button type="button" class="btn" data-testid="leases-reset" onClick={reset}>
                {t("dhcp.lfilter.reset")}
              </button>
            </div>
          </Show>
        </form>
        <div class="dhcp-list-body">
          <DataGrid
            id="dhcp-leases"
            label={t("dhcp.leases.title")}
            noSelection
            statusBar={false}
            columns={columns}
            rows={list.rows()}
            rowId={leaseKey}
            rowKey={(l) => l.addr}
            rowLabel={(l) => l.addr}
            loading={list.loading()}
            initial={list.initial()}
            hasMore={list.hasMore()}
            onLoadMore={list.loadMore}
            error={list.error()}
            onRetry={list.reload}
            flashed={list.flashed}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dhcp-leases-empty" data-filtered={anyFilter(filters()) ? "true" : "false"}>
                <h3>{anyFilter(filters()) ? t("dhcp.leases.empty_filtered") : t("dhcp.leases.empty")}</h3>
                <p>{anyFilter(filters()) ? t("dhcp.leases.empty_filtered_body") : t("dhcp.leases.empty_body")}</p>
              </div>
            }
          />
        </div>
        <Show when={list.hasMore()}>
          <div class="dhcp-actions">
            <button type="button" class="btn" data-testid="leases-more" disabled={list.loading()} onClick={list.loadMore}>
              {t("dhcp.leases.more")}
            </button>
          </div>
        </Show>
      </Show>
      <Show when={dialog()} keyed>
        {(lease) => (
          <ReleaseDialog
            lease={lease}
            onClose={() => setDialog(null)}
            onDone={() => {
              setDialog(null);
              reload();
            }}
            onRefused={reload}
          />
        )}
      </Show>
    </div>
  );
}
