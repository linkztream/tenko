// The lease history (/dhcp/history, WP7.5): what happened to the leases of both address families
// (WP9.4), newest first, in a grid read page by page. Filters for the address, the MAC address, the
// DUID of a DHCPv6 client, the address family, the scope, the kind of event and a time range live in the URL, so the lease list links to the history of one address. Like the lease
// list the view is live and sampled; the Live toggle pauses it.
import { A, useSearchParams } from "@solidjs/router";
import { createMemo, createResource, For, Show } from "solid-js";
import { Icon } from "../../components/Icon";
import { PageHead } from "../../components/PageHead";
import { DataGrid } from "../../grid/DataGrid";
import { createListSource } from "../../grid/source";
import type { Column } from "../../grid/types";
import { formatDateTime, t } from "../../i18n";
import { listScopes, type Scope } from "../api";
import { DhcpNav } from "../DhcpNav";
import { DhcpProblem, unavailable } from "../Parts";
import { SelectFilter, TextFilter, TimeFilter } from "../leases/Filters";
import { createLiveRefresh, HISTORY_TABLE, LiveControls } from "../leases/live";
import {
  anyFilter,
  eventKey,
  clientMac,
  colons,
  duidProblem,
  EVENT_KINDS,
  familyName,
  FAMILIES,
  HISTORY_FILTER_NAMES,
  historyQuery,
  macProblem,
  readHistoryFilters,
  shortDuid,
  type LeaseEvent,
} from "../leases/model";
import "../dhcp.css";
import "../leases/leases.css";

const TIME: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "medium" };

export default function HistoryPage() {
  const [search, setSearch] = useSearchParams();
  const filters = createMemo(() => readHistoryFilters(search));
  const query = createMemo(() => historyQuery(filters()), undefined, { equals: (a, b) => JSON.stringify(a) === JSON.stringify(b) });

  const [scopes] = createResource<Scope[]>(async () => {
    try {
      return (await listScopes()).items;
    } catch {
      return [];
    }
  });
  const scopeList = () => (scopes.error ? [] : (scopes.latest ?? []));
  const networkOf = (id: string) => scopeList().find((s) => s.prefix === id)?.cidr ?? id;

  const list = createListSource<LeaseEvent>({
    path: "/api/v1/dhcp/history",
    query,
    rowId: eventKey,
    pageSize: 100,
    // An event never changes: new ones appear, none flashes.
    signature: () => "",
  });
  const live = createLiveRefresh({ table: HISTORY_TABLE, revision: list.revision, refresh: () => list.reload() });

  const change = (name: (typeof HISTORY_FILTER_NAMES)[number], value: string) => setSearch({ [name]: value === "" ? undefined : value }, { replace: true });
  const reset = () => setSearch(Object.fromEntries(HISTORY_FILTER_NAMES.map((name) => [name, undefined])), { replace: true });

  const blocked = () => unavailable(list.error());

  const columns: Column<LeaseEvent>[] = [
    {
      id: "at",
      header: () => t("dhcp.col.time"),
      width: 180,
      fixed: true,
      text: (e) => formatDateTime(e.at, TIME),
      render: (e) => (
        <time datetime={e.at} class="nowrap">
          {formatDateTime(e.at, TIME)}
        </time>
      ),
    },
    {
      id: "kind",
      header: () => t("dhcp.col.event"),
      width: 120,
      text: (e) => t(`dhcp.event.${e.kind}`),
      render: (e) => (
        <span class={e.kind === "conflict" || e.kind === "declined" ? "tag conflict" : e.kind === "granted" ? "tag accent" : "tag"} data-testid="event-kind" data-key={e.kind}>
          {t(`dhcp.event.${e.kind}`)}
        </span>
      ),
    },
    {
      id: "addr",
      header: () => t("dhcp.col.address"),
      width: 140,
      text: (e) => e.addr,
      render: (e) => (
        <A class="mono" href={`/dhcp/leases?addr=${encodeURIComponent(e.addr)}`} title={t("dhcp.history.lease_link")} data-testid="event-lease-link">
          {e.addr}
        </A>
      ),
    },
    {
      id: "family",
      header: () => t("dhcp.leases6.col_family"),
      width: 100,
      text: (e) => familyName(e.family),
      render: (e) => (
        <span class="tag" data-testid="event-family" data-key={e.family}>
          {familyName(e.family)}
        </span>
      ),
    },
    { id: "mac", header: () => t("dhcp.col.client_mac"), width: 150, text: clientMac, render: (e) => <span class="mono">{clientMac(e)}</span> },
    {
      id: "duid",
      header: () => t("dhcp.leases6.col_duid"),
      width: 200,
      text: (e) => (e.duid ? colons(e.duid) : ""),
      render: (e) => (
        <Show when={e.duid}>
          {(duid) => (
            <span class="mono" title={colons(duid())} data-testid="event-duid" data-key={duid()}>
              {shortDuid(duid())}
            </span>
          )}
        </Show>
      ),
    },
    {
      id: "state",
      header: () => t("dhcp.col.state_after"),
      width: 120,
      text: (e) => t(`dhcp.leases.state.${e.state}`),
      render: (e) => <span data-testid="event-state" data-key={e.state}>{t(`dhcp.leases.state.${e.state}`)}</span>,
    },
    {
      id: "ends",
      header: () => t("dhcp.col.ends"),
      width: 180,
      text: (e) => formatDateTime(e.ends, TIME),
      render: (e) => (
        <time datetime={e.ends} class="nowrap">
          {formatDateTime(e.ends, TIME)}
        </time>
      ),
    },
    { id: "name", header: () => t("dhcp.col.host_name"), width: 200, text: (e) => e.hostname ?? "", render: (e) => <span>{e.hostname ?? ""}</span> },
    { id: "node", header: () => t("dhcp.col.node"), width: 80, align: "right", text: (e) => String(e.node), render: (e) => <span class="num">{e.node}</span> },
    { id: "scope", header: () => t("dhcp.col.scope"), width: 150, hidden: true, text: (e) => networkOf(e.scope), render: (e) => <span class="mono">{networkOf(e.scope)}</span> },
  ];

  return (
    <div class="page dhcp-page list-page" data-testid="page-dhcp-history">
      <DhcpNav />
      <PageHead
        title={t("dhcp.history.title")}
        sub={t("dhcp.history.sub")}
        actions={
          <Show when={!blocked()}>
            <LiveControls live={live} testid="history" />
            <button type="button" class="btn" data-testid="history-refresh" onClick={() => list.reload()}>
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
        <form class="dhcp-filters" role="search" aria-label={t("dhcp.history.filters")} data-testid="history-filters" onSubmit={(e) => e.preventDefault()}>
          <TextFilter id="addr" label={t("dhcp.lfilter.addr_exact")} value={filters().addr} placeholder={t("dhcp.example.addr")} mono onCommit={(v) => change("addr", v)} />
          <TextFilter
            id="mac"
            label={t("dhcp.lfilter.mac")}
            value={filters().mac}
            placeholder={t("dhcp.example.mac")}
            mono
            problem={macProblem(filters().mac) ? t("dhcp.lfilter.mac_invalid") : undefined}
            onCommit={(v) => change("mac", v)}
          />
          <TextFilter
            id="duid"
            label={t("dhcp.leases6.lfilter_duid")}
            value={filters().duid}
            placeholder={t("dhcp.leases6.lfilter_duid_placeholder")}
            mono
            problem={duidProblem(filters().duid) ? t("dhcp.leases6.lfilter_duid_invalid") : undefined}
            onCommit={(v) => change("duid", v)}
          />
          <SelectFilter id="family" label={t("dhcp.leases6.lfilter_family")} onCommit={(v) => change("family", v)}>
            <option value="" selected={filters().family === ""}>
              {t("dhcp.leases6.lfilter_family_any")}
            </option>
            <For each={FAMILIES}>
              {(family) => (
                <option value={family} selected={filters().family === family}>
                  {familyName(family)}
                </option>
              )}
            </For>
          </SelectFilter>
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
          <SelectFilter id="kind" label={t("dhcp.lfilter.kind")} onCommit={(v) => change("kind", v)}>
            <option value="" selected={filters().kind === ""}>
              {t("dhcp.lfilter.kind_any")}
            </option>
            <For each={EVENT_KINDS}>
              {(kind) => (
                <option value={kind} selected={filters().kind === kind}>
                  {t(`dhcp.event.${kind}`)}
                </option>
              )}
            </For>
          </SelectFilter>
          <TimeFilter id="from" label={t("dhcp.lfilter.from")} value={filters().from} onCommit={(v) => change("from", v)} />
          <TimeFilter id="to" label={t("dhcp.lfilter.to")} value={filters().to} onCommit={(v) => change("to", v)} />
          <Show when={anyFilter(filters())}>
            <div class="dhcp-filter-actions">
              <button type="button" class="btn" data-testid="history-reset" onClick={reset}>
                {t("dhcp.lfilter.reset")}
              </button>
            </div>
          </Show>
        </form>
        <div class="dhcp-list-body">
          <DataGrid
            id="dhcp-history"
            label={t("dhcp.history.title")}
            noSelection
            statusBar={false}
            columns={columns}
            rows={list.rows()}
            rowId={eventKey}
            rowKey={(e) => `${e.addr} ${e.kind}`}
            rowLabel={(e) => `${e.addr} ${t(`dhcp.event.${e.kind}`)}`}
            loading={list.loading()}
            initial={list.initial()}
            hasMore={list.hasMore()}
            onLoadMore={list.loadMore}
            error={list.error()}
            onRetry={list.reload}
            empty={
              <div class="empty" data-testid="dhcp-history-empty" data-filtered={anyFilter(filters()) ? "true" : "false"}>
                <h3>{anyFilter(filters()) ? t("dhcp.history.empty_filtered") : t("dhcp.history.empty")}</h3>
                <p>{anyFilter(filters()) ? t("dhcp.history.empty_filtered_body") : t("dhcp.history.empty_body")}</p>
              </div>
            }
          />
        </div>
        <Show when={list.hasMore()}>
          <div class="dhcp-actions">
            <button type="button" class="btn" data-testid="history-more" disabled={list.loading()} onClick={list.loadMore}>
              {t("dhcp.history.more")}
            </button>
          </div>
        </Show>
      </Show>
    </div>
  );
}
