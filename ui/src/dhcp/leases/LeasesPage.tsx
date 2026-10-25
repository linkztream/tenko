// The leases (/dhcp/leases, WP7.5): every lease the server holds, DHCPv4 first and then DHCPv6 (WP9.4),
// by address, in a grid read page by page, with filters for the scope, the address family, what a
// DHCPv6 lease holds (an address or a delegated prefix, WP9.2), the address (a prefix of its text;
// an IPv6 address or prefix also finds the delegated prefixes that hold it and the leases inside
// it), the MAC address, the DUID of a DHCPv6 client, the name and the state; they live in the URL.
// A client that has a lease in both families shows the address of the other one as a link to the
// list narrowed to it (the peer, correlated by MAC address); a delegated prefix also links to the
// address lease of its client (the router's own address). A status strip shows what this node's role does. The
// view is live: it follows the `dhcp` event topic and reads the visible page again when the lease
// table changed, sampled (sampler.ts), and says how many changes it folded when the server is
// busier than the page can follow; the Live toggle pauses it. The live strip (WP8.6) names the
// scope filter, shows how full the scope (or each of the first scopes) is and counts the leases
// granted since the page was opened; the bars and the count are read again with each refresh. Principals with `dhcp.write` release
// an active lease, with an optional reason. A lease that is not its client's reservation is
// reserved from the row menu (the reserve dialog, prefilled from the lease) by a principal who may
// write DHCP and IPAM in the scope's network; a lease that is one says Reserved and links to the
// host. A 409 `dhcp.module.disabled` or a 404 of the route
// shows the module-off state, a 501 the not-available notice.
import { A, useNavigate, useSearchParams } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, lazy, Show } from "solid-js";
import { api } from "../../api/client";
import { paths } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { PageHead } from "../../components/PageHead";
import { DataGrid } from "../../grid/DataGrid";
import { createListSource } from "../../grid/source";
import type { Column, RowAction } from "../../grid/types";
import { toast } from "../../components/toast";
import { formatDateTime, formatRelative, t } from "../../i18n";
import { mayWriteDhcp } from "../access";
import { listScopes, type Scope } from "../api";
import { DhcpNav } from "../DhcpNav";
import { DhcpProblem, unavailable } from "../Parts";
import { mayReserveIn } from "../reservations/gate";
import { SelectFilter, TextFilter } from "./Filters";
import { createLiveRefresh, LEASE_TABLE, LiveControls } from "./live";
import { LiveStrip } from "./LiveStrip";
import {
  anyFilter,
  BINDING_STATES,
  clientIdOf,
  clientMac,
  colons,
  displayAddr,
  duidProblem,
  familyName,
  FAMILIES,
  historyHref,
  kindOf,
  LEASE_KINDS,
  leaseKey,
  leaseQuery,
  LEASE_FILTER_NAMES,
  macProblem,
  nameOf,
  peerHref,
  readLeaseFilters,
  shortDuid,
  type Lease,
} from "./model";
import { NodeStrip } from "./NodeStrip";
import { ReleaseDialog } from "./ReleaseDialog";
import "../dhcp.css";
import "./leases.css";

const ENDS: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "medium" };

const ReserveDialog = lazy(() => import("../reservations/ReserveDialog"));

/** The names of reserved hosts by id, read once per page. */
const hostNames = new Map<string, Promise<string | undefined>>();

function hostName(id: string): Promise<string | undefined> {
  let found = hostNames.get(id);
  if (!found) {
    found = api
      .get("/api/v1/hosts/{id}", { path: { id } })
      .then((h) => h.name)
      .catch(() => undefined);
    hostNames.set(id, found);
  }
  return found;
}

/** The link to the reserved host of a lease, once its name is read. */
function HostLink(props: { id: string }) {
  const [name] = createResource(() => props.id, hostName);
  return (
    <Show when={name()}>
      {(n) => (
        <>
          {" "}
          <A href={paths.host(n())} data-testid="lease-reserved-host">
            {n()}
          </A>
        </>
      )}
    </Show>
  );
}

export default function LeasesPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useSearchParams();
  const filters = createMemo(() => readLeaseFilters(search));
  const query = createMemo(() => leaseQuery(filters()), undefined, { equals: (a, b) => JSON.stringify(a) === JSON.stringify(b) });
  const [dialog, setDialog] = createSignal<Lease | null>(null);
  const [reserving, setReserving] = createSignal<Lease | null>(null);
  const [stripVersion, setStripVersion] = createSignal(0);
  // When the page was opened (or the counter reset): the leases granted since are the new ones.
  const [opened, setOpened] = createSignal(new Date().toISOString());

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
  const scopeIndex = createMemo(() => new Map(scopeList().map((s) => [s.prefix, s] as const)));
  // WP9.4: the reserve dialog keys a reservation by a MAC address or a client identifier of DHCPv4; a
  // DHCPv6 lease is reserved from the host page (the interface's DUID), so the row menu hides it.
  /** Whether the row menu offers to reserve the lease's address. */
  const mayReserveLease = (l: Lease) => l.family === "v4" && !l.reserved && mayReserveIn(l.scope, scopeIndex());
  const openHost = async (l: Lease) => {
    const name = l.host ? await hostName(l.host) : undefined;
    if (name) navigate(paths.host(name));
    else toast({ kind: "bad", title: t("dhcp.lease.host_missing") });
  };

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
      width: 170,
      fixed: true,
      text: displayAddr,
      render: (l) => (
        <A class="mono" href={historyHref(l.addr)} title={t("dhcp.lease.history_link")} data-testid="lease-history-link">
          {displayAddr(l)}
        </A>
      ),
    },
    {
      id: "family",
      header: () => t("dhcp.leases6.col_family"),
      width: 100,
      text: (l) => familyName(l.family),
      render: (l) => (
        <span class="tag" data-testid="lease-family" data-key={l.family}>
          {familyName(l.family)}
        </span>
      ),
    },
    {
      id: "kind",
      header: () => t("dhcp.leases6.col_kind"),
      width: 100,
      text: (l) => t(`dhcp.leases6.kind_${kindOf(l)}`),
      render: (l) => (
        <span data-testid="lease-kind" data-key={kindOf(l)}>
          {t(`dhcp.leases6.kind_${kindOf(l)}`)}
        </span>
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
    { id: "mac", header: () => t("dhcp.col.client_mac"), width: 150, text: clientMac, render: (l) => <span class="mono">{clientMac(l)}</span> },
    {
      id: "duid",
      header: () => t("dhcp.leases6.col_duid"),
      width: 200,
      text: (l) => (l.duid ? colons(l.duid) : ""),
      render: (l) => (
        <Show when={l.duid}>
          {(duid) => (
            <span>
              <span class="mono" title={colons(duid())} data-testid="lease-duid" data-key={duid()}>
                {shortDuid(duid())}
              </span>
              <Show when={l.iaid !== null && l.iaid !== undefined}>
                {" "}
                <span class="muted" data-testid="lease-iaid" data-key={String(l.iaid)}>
                  {t("dhcp.leases6.iaid", { iaid: l.iaid ?? 0 })}
                </span>
              </Show>
            </span>
          )}
        </Show>
      ),
    },
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
      id: "peer",
      header: () => t("dhcp.leases6.col_same_client"),
      width: 260,
      text: (l) => (l.peer ? `${familyName(l.peer.family)} ${l.peer.addr}` : ""),
      render: (l) => (
        <Show when={l.peer}>
          {(peer) => (
            <span data-testid="lease-peer" data-family={peer().family} data-state={peer().state}>
              <span class="muted">{t("dhcp.leases6.peer_also", { family: familyName(peer().family) })}</span>{" "}
              <A
                class="mono"
                href={peerHref(peer())}
                title={t("dhcp.leases6.peer_title", { family: familyName(peer().family), state: t(`dhcp.leases.state.${peer().state}`) })}
                data-testid="lease-peer-link"
              >
                {peer().addr}
              </A>
              <Show when={peer().state !== "active"}>
                {" "}
                <span class="muted">({t(`dhcp.leases.state.${peer().state}`)})</span>
              </Show>
            </span>
          )}
        </Show>
      ),
    },
    {
      // WP9.2: a delegated prefix links to the address lease of the same client (by DUID), the address the router holds.
      id: "address_lease",
      header: () => t("dhcp.leases6.col_address_lease"),
      width: 200,
      text: (l) => l.address_lease?.addr ?? "",
      render: (l) => (
        <Show when={l.address_lease}>
          {(lease) => (
            <span data-testid="lease-address-lease" data-state={lease().state}>
              <A
                class="mono"
                href={peerHref(lease())}
                title={t("dhcp.leases6.address_lease_title", { state: t(`dhcp.leases.state.${lease().state}`) })}
                data-testid="lease-address-lease-link"
              >
                {lease().addr}
              </A>
              <Show when={lease().state !== "active"}>
                {" "}
                <span class="muted">({t(`dhcp.leases.state.${lease().state}`)})</span>
              </Show>
            </span>
          )}
        </Show>
      ),
    },
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
      width: 180,
      text: (l) => (l.reserved ? t("dhcp.lease.reserved") : ""),
      render: (l) => (
        <Show when={l.reserved}>
          <span class="tag" data-testid="lease-reserved">
            {t("dhcp.lease.reserved")}
          </span>
          <Show when={l.host}>{(id) => <HostLink id={id()} />}</Show>
        </Show>
      ),
    },
    {
      id: "relay",
      header: () => t("dhcp.col.relay"),
      width: 130,
      text: (l) => l.relay?.giaddr ?? l.relay6?.link_address ?? "",
      render: (l) => <span class="mono muted">{l.relay?.giaddr ?? l.relay6?.link_address ?? ""}</span>,
    },
  ];

  const actions: RowAction<Lease>[] = [
    { id: "history", label: () => t("dhcp.do.history"), run: (l) => navigate(historyHref(l.addr)) },
    { id: "reserve", label: () => t("dhcp.lease.reserve"), hidden: (l) => !mayReserveLease(l), run: (l) => setReserving(l) },
    { id: "open_host", label: () => t("dhcp.lease.open_host"), hidden: (l) => !(l.reserved && l.host), run: (l) => void openHost(l) },
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
        <LiveStrip
          scope={filters().scope}
          scopes={scopeList()}
          networkOf={networkOf}
          version={stripVersion}
          live={live.live}
          since={opened()}
          onReset={() => setOpened(new Date().toISOString())}
          onPick={(prefix) => change("scope", prefix)}
        />
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
          <SelectFilter id="kind" label={t("dhcp.leases6.lfilter_kind")} onCommit={(v) => change("kind", v)}>
            <option value="" selected={filters().kind === ""}>
              {t("dhcp.leases6.lfilter_kind_any")}
            </option>
            <For each={LEASE_KINDS}>
              {(kind) => (
                <option value={kind} selected={filters().kind === kind}>
                  {t(`dhcp.leases6.lfilter_kind_${kind}`)}
                </option>
              )}
            </For>
          </SelectFilter>
          <TextFilter
            id="addr"
            label={t("dhcp.lfilter.addr")}
            value={filters().addr}
            placeholder={t("dhcp.lfilter.addr_placeholder")}
            help={t("dhcp.leases6.lfilter_addr_help")}
            mono
            onCommit={(v) => change("addr", v)}
          />
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
      <Show when={reserving()} keyed>
        {(lease) => <ReserveDialog source={{ lease }} onClose={() => setReserving(null)} onDone={reload} />}
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
