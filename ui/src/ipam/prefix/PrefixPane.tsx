// One prefix (the right side of the IPAM view, section 5.2 of the UI plan): the page header with
// the prefix and its facts (description, VLAN, site, tenant and VRF) and the actions, one
// utilization meter with the alarm line beside the small panels of a network (its DHCP scope,
// the findings inside it, its recent changes), and tabs: a network's addresses (the address map
// above the address grid with the free gaps), its ranges, a supernet's networks (one sortable,
// filterable table), the adoption policy (WP2.9) and the history. The address grid is where hosts are selected, edited in place, and
// dragged onto the tree to move them (or moved with M). In a network with a DHCP scope the row
// menu reserves an address in DHCP.
import { useNavigate } from "@solidjs/router";
import { createEffect, createMemo, createResource, createSignal, For, lazy, Match, on, onCleanup, onMount, Show, Switch, untrack } from "solid-js";
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { createLiveQuery } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import type { Address, AddressRow, Prefix, Range, Site, TreeNode, TreeResponse, Vrf } from "../../api/types";
import type { MapFinding } from "../../components/addressMapCells";
import { PageHeader } from "../../components/PageHeader";
import { paths } from "../../app/paths";
import { may } from "../../auth/gate";
import { Addr } from "../../components/Addr";
import { Icon } from "../../components/Icon";
import { Kbd } from "../../components/Kbd";
import { toast } from "../../components/toast";
import { ActionBar, ActionButton } from "../../grid/ActionBar";
import { Count, DeletedTag, StatusBadge, Tags } from "../../grid/cells";
import { createGridSelection, DataGrid } from "../../grid/DataGrid";
import type { DragItem } from "../../grid/dnd";
import { FilterBar, ToggleChip } from "../../grid/FilterBar";
import { createColumnState } from "../../grid/prefs";
import { createListSource } from "../../grid/source";
import { TextEditor } from "../../grid/TextEditor";
import type { RowAction } from "../../grid/types";
import { createScopeIndex, mayReserve } from "../../dhcp/reservations/gate";
import { formatDuration, t, tDynamic, tx, withPacks } from "../../i18n";
import { isTyping } from "../../shell/keyboard";
import { addressColumns, addressRowId, addressRowKey, rowAddress, type PrefixRow } from "../address/columns";
import { addressesCsv } from "../address/csv";
import { DeleteDialog } from "../DeleteDialog";
import { HistoryPanel } from "../history/HistoryPanel";
import { MoveDialog } from "../move/MoveDialog";
import { alarmWord, allocationWords, prefixRoleWord, rangeRoleWord } from "../words";
import { AddressMapPanel } from "./AddressMapPanel";
import { ChildrenTable } from "./ChildrenTable";
import { ChangesPanel, DhcpPanel, FindingsPanel } from "./PrefixPanels";
import { UsageMeter } from "./UsageMeter";
import { NextFreeAddressDialog, NextFreePrefixDialog } from "./NextFreeDialogs";
import { PrefixForm } from "./PrefixForm";
import { delegationWords } from "./delegation";
import { RangeForm } from "./RangeForm";
import { VlanChip } from "../vlan/VlanChip";
import type { VlanStyle } from "../vlan/palette";
import { saveTextFile } from "../../hosts/handoff";
import { useWriteToast } from "../plan/PlanDialog";
import { AdoptionPanel } from "./AdoptionPanel";
import { ScanNowLazy } from "../../scans/ScanNowLazy";

const ReserveDialog = lazy(withPacks(["dhcp"], () => import("../../dhcp/reservations/ReserveDialog")));

type Tab = "addresses" | "children" | "ranges" | "adoption" | "history";

export interface PrefixPaneProps {
  prefix: Prefix;
  node: TreeNode | undefined;
  tree: TreeResponse | undefined;
  vrf: Vrf | undefined;
  /** The tenant of the VRF, by name. */
  tenant?: string | undefined;
  vlanOf: (id: string) => { vid: number; name: string; style?: VlanStyle | undefined } | undefined;
  onChanged: () => void;
}

type Finding = components["schemas"]["Finding"];

/** The findings inside a prefix with an address, for the map and the findings panel; live. */
function usePrefixFindings(prefixId: () => string) {
  const live = createLiveQuery<MapFinding[]>({
    topics: ["findings"],
    relevant: () => true,
    fetch: async (signal) => {
      const all = await fetchAll<Finding>("/api/v1/findings", { query: { prefix: prefixId() }, limit: 1000, max: 5000, signal });
      const items = all.items.map((f) => ({
        ip: f.subject.ip ?? "",
        severity: f.severity,
        label: tDynamic(`discovery.findings.kind.${f.kind}`) ?? f.kind,
      }));
      return { value: items, revision: all.revision as number };
    },
  });
  createEffect(on(prefixId, () => live.refetch(), { defer: true }));
  return () => (live.value.state === "ready" || live.value.state === "refreshing" ? live.value() : undefined);
}

export function PrefixPane(props: PrefixPaneProps) {
  const navigate = useNavigate();
  const writeToast = useWriteToast();
  const isNetwork = () => props.prefix.role === "network";
  const [tab, setTab] = createSignal<Tab>(untrack(() => (props.prefix.role === "network" ? "addresses" : "children")));
  const [dialog, setDialog] = createSignal<
    | { kind: "edit" }
    | { kind: "delete" }
    | { kind: "claim" }
    | { kind: "next_prefix" }
    | { kind: "range"; range?: Range }
    | { kind: "delete_range"; range: Range }
    | { kind: "delete_address"; address: Address }
    | { kind: "reserve"; address: AddressRow }
    | { kind: "move"; items: DragItem[] }
    | null
  >(null);

  const length = () => Number(props.prefix.cidr.split("/")[1] ?? 24);
  const deleted = () => !!props.prefix.meta.deleted;
  // What the principal may change here (display gating; the server decides every request).
  const writable = () => may.prefix(props.prefix.id);
  const mayClaim = () => writable() && may.create("address");
  /** An address row (not a free gap) the principal may change: judged by the address's own prefix. */
  const rowWritable = (r: PrefixRow) => r.type === "address" && may.inPrefix(r.data.prefix);
  const mayWriteAddress = (a: AddressRow) => may.inPrefix(a.prefix);

  // ---------------------------------------------------------------------------
  // Ranges (for the summary facts, the next free dialog and the ranges tab)

  const [ranges, setRanges] = createSignal<Range[]>([]);
  const loadRanges = async () => {
    if (!isNetwork()) return setRanges([]);
    try {
      const all = await fetchAll<Range>("/api/v1/prefixes/{id}/ranges", { path: { id: props.prefix.id } });
      setRanges(all.items);
    } catch {
      setRanges([]);
    }
  };
  createEffect(
    on(
      () => [props.prefix.id, props.prefix.meta.revision],
      () => void loadRanges(),
    ),
  );

  // ---------------------------------------------------------------------------
  // Addresses

  const [showFree, setShowFree] = createSignal(true);
  const [text, setText] = createSignal("");
  const source = createListSource<PrefixRow>({
    path: "/api/v1/prefixes/{id}/addresses",
    pathParams: () => ({ id: props.prefix.id }),
    query: () => ({ include_free: showFree() ? true : undefined, expand: "host" }),
    rowId: addressRowId,
    pageSize: 500,
    enabled: () => isNetwork() || tab() === "addresses",
    topics: ["ipam"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => o.kind === "address" || o.kind === "interface" || o.kind === "host"),
  });
  const rows = createMemo(() => {
    const q = text().trim().toLowerCase();
    if (!q) return source.rows();
    return source.rows().filter((r) => {
      if (r.type === "free") return false;
      const a = r.data;
      return a.ip.includes(q) || (a.dns_name ?? "").toLowerCase().includes(q) || (a.meta.description ?? "").toLowerCase().includes(q);
    });
  });
  /** The address rows shown, without the free gaps: the "recorded" figure of the summary. */
  const recordedShown = () => (scopes.settled() ? rows() : []).filter((r) => r.type === "address").length;
  const selectable = (r: PrefixRow) => r.type === "address" && !r.data.meta.deleted;
  const selection = createGridSelection(rows, addressRowId, selectable);
  const columns = addressColumns<PrefixRow>(rowAddress, { prefixLength: untrack(length), mayWrite: mayWriteAddress });
  const columnState = createColumnState("prefix-addresses", () => columns);
  const selectedAddresses = () => rows().filter((r) => selection.has(addressRowId(r))).map(rowAddress).filter((a): a is AddressRow => !!a);

  const dragItems = (list: PrefixRow[]): DragItem[] =>
    list
      .map(rowAddress)
      .filter((a): a is Address => !!a)
      .map((a) => ({ kind: "address", id: a.id, label: a.dns_name ?? a.ip, ip: a.ip }));

  const saveDns = async (address: Address, value: string) => {
    const result = await api.patch("/api/v1/addresses/{id}", {
      path: { id: address.id },
      body: { dns_name: value === "" ? null : value },
      ifMatch: address.meta.revision,
    });
    writeToast(t("ipam.address.renamed", { ip: address.ip, name: value || "–" }), result);
    source.reload();
  };

  const claimGap = async (first: string) => {
    try {
      const result = await api.post("/api/v1/addresses", { body: { ip: first, vrf: props.prefix.vrf } });
      writeToast(t("ipam.address.claimed", { ip: first }), result);
      source.reload();
    } catch (err) {
      toast({ kind: "bad", title: t("ipam.address.claim_failed", { ip: first }), body: (await import("../../api/problem")).errorMessage(err) });
    }
  };

  const scopes = createScopeIndex();
  const rowActions: RowAction<PrefixRow>[] = [
    { id: "open", label: () => t("ipam.do.open"), run: (r) => r.type === "address" && navigate(paths.address(r.data.ip)) },
    {
      id: "move",
      label: () => t("ipam.do.move"),
      disabled: (r) => !selectable(r),
      hidden: (r) => !rowWritable(r),
      run: (r) => setDialog({ kind: "move", items: dragItems([r]) }),
    },
    {
      id: "reserve",
      label: () => t("ipam.do.reserve"),
      hidden: (r) => r.type !== "address" || !mayReserve(r.data, scopes()),
      run: (r) => r.type === "address" && setDialog({ kind: "reserve", address: r.data }),
    },
    {
      id: "delete",
      label: () => t("ipam.do.delete"),
      danger: true,
      disabled: (r) => !selectable(r),
      hidden: (r) => !rowWritable(r),
      run: (r) => r.type === "address" && setDialog({ kind: "delete_address", address: r.data }),
    },
  ];

  /** The write actions of the bar: every selected address must be inside the principal's scope. */
  const maySelection = () => {
    const chosen = rows().filter((r) => selection.has(addressRowId(r)));
    return chosen.length > 0 && chosen.every(rowWritable);
  };

  const moveSelection = () => {
    if (!maySelection()) return;
    const items = selection.count() > 0 ? dragItems(rows().filter((r) => selection.has(addressRowId(r)))) : [];
    if (items.length > 0) setDialog({ kind: "move", items });
  };

  const exportSelection = () => {
    const vrf = props.vrf;
    const csv = addressesCsv(selectedAddresses(), (id) => (id === vrf?.id ? vrf.name : id));
    saveTextFile(`addresses-${props.prefix.cidr.replace(/[/:]/g, "_")}.csv`, csv, "text/csv;charset=utf-8");
  };

  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || isTyping(e) || e.ctrlKey || e.metaKey || e.altKey || dialog()) return;
      if (document.querySelector("[aria-modal='true']")) return;
      if (e.key === "n" && isNetwork() && !deleted() && mayClaim()) {
        e.preventDefault();
        setDialog({ kind: "claim" });
      } else if ((e.key === "m" || e.key === "M") && !e.shiftKey && tab() === "addresses") {
        e.preventDefault();
        moveSelection();
      }
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  // ---------------------------------------------------------------------------
  // Head and summary

  const ancestors = createMemo(() => {
    const nodes = props.tree?.nodes ?? [];
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const out: TreeNode[] = [];
    let cur = props.node?.parent ? byId.get(props.node.parent) : undefined;
    while (cur) {
      out.unshift(cur);
      cur = cur.parent ? byId.get(cur.parent) : undefined;
    }
    return out;
  });
  const children = createMemo(() => (props.tree?.nodes ?? []).filter((n) => n.parent === props.prefix.id));
  const vlan = () => (props.prefix.vlan ? props.vlanOf(props.prefix.vlan) : undefined);
  const u = () => props.node?.utilization;
  const findings = usePrefixFindings(() => props.prefix.id);
  const mapFindings = () => (findings() ?? []).filter((f) => f.ip !== "");
  const [sites] = createResource(
    () => props.prefix.site ?? false,
    async () => {
      try {
        return new Map((await fetchAll<Site>("/api/v1/sites")).items.map((s) => [s.id, s.name] as const));
      } catch {
        return new Map<string, string>();
      }
    },
  );
  const siteName = () => (props.prefix.site ? (sites.latest?.get(props.prefix.site) ?? null) : null);

  const tabs = (): { id: Tab; label: string }[] => [
    ...(isNetwork()
      ? [
          { id: "addresses" as const, label: t("ipam.prefix.tab.addresses") },
          { id: "ranges" as const, label: t("ipam.prefix.tab.ranges") },
        ]
      : [
          { id: "children" as const, label: t("ipam.prefix.tab.children") },
          { id: "addresses" as const, label: t("ipam.prefix.tab.addresses") },
        ]),
    { id: "adoption", label: t("ipam.prefix.tab.adoption") },
    { id: "history", label: t("ipam.prefix.tab.history") },
  ];

  return (
    <div class="prefix-pane" data-testid="prefix-pane" data-id={props.prefix.id} data-key={props.prefix.cidr}>
      <PageHeader
        title={props.prefix.cidr}
        crumbs={
          <nav class="crumbs" aria-label={t("ipam.prefix.crumbs")}>
            <span>{props.vrf?.name}</span>
            <For each={ancestors()}>
              {(a) => (
                <>
                  <Icon name="chev-r" />
                  <a href={paths.prefix(a.cidr)} onClick={(e) => (e.preventDefault(), navigate(paths.prefix(a.cidr)))}>
                    {a.cidr}
                  </a>
                </>
              )}
            </For>
          </nav>
        }
        sub={
          <span class="prefix-facts" data-testid="prefix-facts">
            <Show when={props.prefix.meta.description}>
              <span class="fact description">{props.prefix.meta.description}</span>
            </Show>
            <span class="fact">{prefixRoleWord(props.prefix.role)}</span>
            <span class="fact">
              <Show when={vlan()} fallback={<span class="muted">{t("ipam.prefix.fact.no_vlan")}</span>}>
                {(v) => <VlanChip vid={v().vid} name={v().name} style={v().style} />}
              </Show>
            </span>
            <span class="fact">{siteName() ?? <span class="muted">{t("ipam.prefix.fact.no_site")}</span>}</span>
            <Show when={props.vrf}>
              {(v) => <span class="fact">{t("ipam.prefix.fact.scope", { tenant: props.tenant ?? "", vrf: v().name })}</span>}
            </Show>
            <Show when={props.prefix.status !== "active"}>
              <span class="fact">
                <StatusBadge status={props.prefix.status} />
              </span>
            </Show>
            <DeletedTag deleted={props.prefix.meta.deleted} />
          </span>
        }
        actions={
          <Show when={!deleted() && writable()}>
            <ScanNowLazy kind="prefix" value={props.prefix.id} label={props.prefix.cidr} />
            <button type="button" class="btn" data-testid="prefix-edit" onClick={() => setDialog({ kind: "edit" })}>
              <Icon name="settings" />
              {t("ipam.do.edit")}
            </button>
            <button type="button" class="btn danger" data-testid="prefix-delete" onClick={() => setDialog({ kind: "delete" })}>
              <Icon name="trash" />
              {t("ipam.do.delete")}
            </button>
            <Show
              when={isNetwork()}
              fallback={
                <Show when={may.create("prefix")}>
                  <button type="button" class="btn primary" data-testid="prefix-next-free-prefix" onClick={() => setDialog({ kind: "next_prefix" })}>
                    <Icon name="plus" />
                    {t("ipam.do.next_free_prefix")}
                  </button>
                </Show>
              }
            >
              <Show when={mayClaim()}>
                <button type="button" class="btn primary" data-testid="prefix-next-free-address" onClick={() => setDialog({ kind: "claim" })}>
                  <Icon name="plus" />
                  {t("ipam.do.next_free_address")}
                  <Kbd keys={["N"]} />
                </button>
              </Show>
            </Show>
          </Show>
        }
      />

      <div class="summary prefix-overview" data-testid="prefix-summary">
        <Show when={u()}>
          {(use) => (
            <div class="use">
              <UsageMeter use={use()} level={props.node?.level ?? "normal"} alarm={props.prefix.alarm} />
              {/* What "in use" is made of: the Addresses tab lists the recorded addresses. */}
              <div class="parts muted" data-testid="prefix-usage-parts" title={t("ipam.prefix.usage_parts_hint")}>
                {tx("ipam.prefix.usage_parts", {
                  recorded: <Count value={use().used} />,
                  held: <Count value={use().reserved} />,
                })}
              </div>
              {/* A supernet's allocation to child prefixes, labelled apart from the meter. */}
              <Show when={props.node && allocationWords(props.node)}>
                {(words) => (
                  <div class="allocation muted" data-testid="prefix-allocation" title={t("ipam.allocation.hint")}>
                    {words()}
                  </div>
                )}
              </Show>
              <Show when={use().by_role.length > 0}>
                <div class="legend">
                  <For each={use().by_role}>
                    {(r) => (
                      <span>
                        {rangeRoleWord(r.role)} <Count value={r.size} />
                      </span>
                    )}
                  </For>
                </div>
              </Show>
            </div>
          )}
        </Show>
        <div class="panels">
          <Show when={isNetwork()}>
            <DhcpPanel prefixId={props.prefix.id} revision={props.prefix.meta.revision} />
          </Show>
          <FindingsPanel prefixId={props.prefix.id} findings={findings()} />
          <ChangesPanel prefixId={props.prefix.id} revision={props.prefix.meta.revision} onAll={() => setTab("history")} />
        </div>
        <dl class="facts">
          <dt>{t("ipam.prefix.alloc")}</dt>
          <dt>{t("ipam.prefix.alarm")}</dt>
          <dd>{props.prefix.alloc === "highest" ? t("ipam.prefix.alloc_highest") : t("ipam.prefix.alloc_lowest")}</dd>
          <dd>
            <Show when={props.prefix.alarm} fallback="–">
              {(a) => (
                <span title={props.node ? alarmWord(props.node.level) : undefined}>
                  {t("ipam.prefix.alarm_value", { warn: a().warn_pct, crit: a().crit_pct })}
                </span>
              )}
            </Show>
          </dd>
        </dl>
        <Tags tags={props.prefix.meta.tags} max={6} />
      </div>

      <div class="tabs" role="tablist" aria-label={t("ipam.prefix.tabs")}>
        <For each={tabs()}>
          {(item) => (
            <button
              type="button"
              role="tab"
              id={`prefix-tab-${item.id}`}
              aria-selected={tab() === item.id}
              aria-controls="prefix-tabpanel"
              data-testid={`prefix-tab-${item.id}`}
              onClick={() => setTab(item.id)}
            >
              {item.label}
            </button>
          )}
        </For>
      </div>

      <div class="prefix-tabpanel" id="prefix-tabpanel" role="tabpanel" aria-labelledby={`prefix-tab-${tab()}`}>
        <Switch>
          <Match when={tab() === "addresses"}>
            <Show when={isNetwork()}>
              <AddressMapPanel
                prefixId={props.prefix.id}
                cidr={props.prefix.cidr}
                version={source.revision()}
                network
                ranges={ranges()}
                findings={mapFindings()}
              />
            </Show>
            <FilterBar
              label={t("ipam.addresses.filter_label")}
              placeholder={t("ipam.addresses.filter_placeholder")}
              value={text()}
              onInput={setText}
              columns={columnState}
              testid="filterbar-prefix-addresses"
            >
              <ToggleChip pressed={showFree()} onToggle={() => setShowFree(!showFree())} testid="toggle-free">
                {t("ipam.addresses.show_free")}
              </ToggleChip>
            </FilterBar>
            <DataGrid
              id="prefix-addresses"
              label={t("ipam.addresses.grid", { cidr: props.prefix.cidr })}
              columns={columns}
              columnState={columnState}
              rows={scopes.settled() ? rows() : []}
              count={{
                value: recordedShown(),
                noun: t("ipam.addresses.count", { count: recordedShown() }),
                title: t("ipam.addresses.count_hint"),
              }}
              rowId={addressRowId}
              rowKey={addressRowKey}
              rowLabel={(r) => addressRowKey(r)}
              selectable={selectable}
              selection={selection}
              rowClass={(r) => (r.type === "free" ? "free" : r.data.meta.deleted ? "deleted" : undefined)}
              fullRow={(r) =>
                r.type === "free" ? (
                  <span class="free-cell">
                    <Addr value={r.data.first} prefixLength={length()} />
                    <Show when={r.data.first !== r.data.last}>
                      <span class="muted"> – </span>
                      <Addr value={r.data.last} prefixLength={length()} />
                    </Show>
                    <span class="muted">
                      {" "}
                      <Count value={r.data.size} /> {t("ipam.addresses.free", { count: Number(r.data.size) || 0 })}
                    </span>
                    <Show when={!deleted() && mayClaim()}>
                      <button
                        type="button"
                        class="btn sm ghost"
                        tabIndex={-1}
                        data-testid="claim-gap"
                        onClick={() => void claimGap(r.data.first)}
                      >
                        {t("ipam.addresses.claim", { ip: r.data.first })}
                      </button>
                    </Show>
                  </span>
                ) : null
              }
              loading={source.loading() || !scopes.settled()}
              initial={source.initial() || !scopes.settled()}
              hasMore={source.hasMore()}
              onLoadMore={source.loadMore}
              error={source.error()}
              onRetry={source.reload}
              flashed={source.flashed}
              onOpen={(r) => r.type === "address" && navigate(paths.address(r.data.ip))}
              onOpenPage={(r) => r.type === "address" && navigate(paths.address(r.data.ip))}
              rowActions={rowActions}
              draggable={rowWritable}
              dragItems={(list) => {
                if (!list.every(rowWritable)) return null;
                const items = dragItems(list);
                return items.length ? items : null;
              }}
              dragLabel={(items) => t("ipam.move.dragging", { count: items.length })}
              editors={{
                dns_name: (p) => {
                  const a = rowAddress(p.row) as Address;
                  return (
                    <TextEditor
                      value={a.dns_name ?? ""}
                      label={t("ipam.col.dns_name")}
                      hint={t("ipam.addresses.dns_hint")}
                      commit={(v) => saveDns(a, v)}
                      close={p.close}
                    />
                  );
                },
              }}
              empty={
                <div class="empty">
                  <h3>{text() ? t("grid.empty.filtered") : t("ipam.addresses.empty")}</h3>
                </div>
              }
            />
            <ActionBar count={selection.count()} onClear={selection.clear}>
              <Show when={maySelection()}>
                <ActionButton primary icon="move" label={t("ipam.do.move")} keys={["M"]} onClick={moveSelection} testid="action-move" />
              </Show>
              <ActionButton icon="export" label={t("ipam.do.export_csv")} onClick={exportSelection} testid="action-export" />
            </ActionBar>
          </Match>
          <Match when={tab() === "children"}>
            <ChildrenTable supernet={props.prefix} rows={children()} vlanOf={props.vlanOf} />
          </Match>
          <Match when={tab() === "ranges"}>
            <Show when={writable() && may.create("range")}>
              <div class="tab-tools">
                <button type="button" class="btn sm" data-testid="range-add" disabled={deleted()} onClick={() => setDialog({ kind: "range" })}>
                  <Icon name="plus" size="sm" />
                  {t("ipam.range.add")}
                </button>
              </div>
            </Show>
            <DataGrid
              id="prefix-ranges"
              label={t("ipam.prefix.ranges_grid", { cidr: props.prefix.cidr })}
              noSelection
              columns={[
                {
                  id: "range",
                  header: () => t("ipam.col.range"),
                  width: 260,
                  fixed: true,
                  text: (r: Range) => `${r.first} - ${r.last}`,
                  render: (r) => (
                    <>
                      <Addr value={r.first} prefixLength={length()} /> <span class="muted">–</span> <Addr value={r.last} prefixLength={length()} />
                    </>
                  ),
                },
                { id: "role", header: () => t("ipam.col.role"), width: 140, render: (r) => rangeRoleWord(r.role) },
                { id: "status", header: () => t("ipam.col.status"), width: 110, render: (r) => <StatusBadge status={r.status} /> },
                {
                  id: "lease",
                  header: () => t("ipam.col.lease"),
                  width: 110,
                  render: (r) => ((r.role === "dhcp_pool" || r.role === "dhcp_pd_pool") && r.lease_secs ? formatDuration(r.lease_secs) : ""),
                },
                // WP9.2: the length of the prefixes a delegation pool hands out and how many it holds.
                {
                  id: "delegation",
                  header: () => t("ipam.col.delegation"),
                  width: 170,
                  text: (r: Range) => (r.role === "dhcp_pd_pool" ? delegationWords(r) : ""),
                  render: (r) => (r.role === "dhcp_pd_pool" ? <span data-testid="range-delegation">{delegationWords(r)}</span> : ""),
                },
                { id: "description", header: () => t("ipam.col.description"), render: (r) => r.meta.description ?? "" },
              ]}
              rows={ranges()}
              rowId={(r) => r.id}
              rowKey={(r) => `${r.first}-${r.last}`}
              onOpen={(r) => may.inPrefix(r.prefix) && setDialog({ kind: "range", range: r })}
              rowActions={[
                { id: "edit", label: () => t("ipam.do.edit"), hidden: (r) => !may.inPrefix(r.prefix), run: (r) => setDialog({ kind: "range", range: r }) },
                { id: "delete", label: () => t("ipam.do.delete"), danger: true, hidden: (r) => !may.inPrefix(r.prefix), run: (r) => setDialog({ kind: "delete_range", range: r }) },
              ]}
              empty={
                <div class="empty">
                  <h3>{t("ipam.range.empty")}</h3>
                </div>
              }
            />
          </Match>
          <Match when={tab() === "adoption"}>
            <AdoptionPanel prefix={props.prefix} />
          </Match>
          <Match when={tab() === "history"}>
            <HistoryPanel
              collection="prefixes"
              id={props.prefix.id}
              deleted={deleted()}
              mayRestore={writable()}
              revision={props.prefix.meta.revision}
              label={props.prefix.cidr}
              onRestored={props.onChanged}
            />
          </Match>
        </Switch>
      </div>

      <Switch>
        <Match when={dialog()?.kind === "edit"}>
          <PrefixForm
            vrf={props.vrf as Vrf}
            prefix={props.prefix}
            onClose={() => setDialog(null)}
            onDone={(p) => {
              setDialog(null);
              props.onChanged();
              if (p.cidr !== props.prefix.cidr) navigate(paths.prefix(p.cidr));
            }}
          />
        </Match>
        <Match when={dialog()?.kind === "delete"}>
          <DeleteDialog
            collection="prefixes"
            id={props.prefix.id}
            kind="prefix"
            label={props.prefix.cidr}
            revision={props.prefix.meta.revision}
            cascade
            onClose={() => setDialog(null)}
            onDone={() => {
              setDialog(null);
              props.onChanged();
            }}
          />
        </Match>
        <Match when={dialog()?.kind === "claim"}>
          <NextFreeAddressDialog
            prefix={props.prefix}
            ranges={ranges()}
            onClose={() => setDialog(null)}
            onDone={() => {
              setDialog(null);
              source.reload();
            }}
          />
        </Match>
        <Match when={dialog()?.kind === "next_prefix"}>
          <NextFreePrefixDialog
            prefix={props.prefix}
            onClose={() => setDialog(null)}
            onDone={(p) => {
              setDialog(null);
              props.onChanged();
              navigate(paths.prefix(p.cidr));
            }}
          />
        </Match>
        <Match when={dialog()?.kind === "range"}>
          <RangeForm
            prefix={props.prefix}
            range={(dialog() as { range?: Range }).range}
            onClose={() => setDialog(null)}
            onDone={() => {
              setDialog(null);
              void loadRanges();
              props.onChanged();
            }}
          />
        </Match>
        <Match when={dialog()?.kind === "delete_range"}>
          {(() => {
            const r = (dialog() as { range: Range }).range;
            return (
              <DeleteDialog
                collection="ranges"
                id={r.id}
                kind="range"
                label={`${r.first} - ${r.last}`}
                revision={r.meta.revision}
                onClose={() => setDialog(null)}
                onDone={() => {
                  setDialog(null);
                  void loadRanges();
                  props.onChanged();
                }}
              />
            );
          })()}
        </Match>
        <Match when={dialog()?.kind === "delete_address"}>
          {(() => {
            const a = (dialog() as { address: Address }).address;
            return (
              <DeleteDialog
                collection="addresses"
                id={a.id}
                kind="address"
                label={a.ip}
                revision={a.meta.revision}
                onClose={() => setDialog(null)}
                onDone={() => {
                  setDialog(null);
                  source.reload();
                }}
              />
            );
          })()}
        </Match>
        <Match when={dialog()?.kind === "reserve"}>
          <ReserveDialog source={{ address: (dialog() as { address: AddressRow }).address }} onClose={() => setDialog(null)} onDone={() => source.reload()} />
        </Match>
        <Match when={dialog()?.kind === "move"}>
          <MoveDialog tree={props.tree} items={(dialog() as { items: DragItem[] }).items} onClose={() => setDialog(null)} />
        </Match>
      </Switch>
    </div>
  );
}
