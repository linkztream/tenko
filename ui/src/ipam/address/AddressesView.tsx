// Every address of the VRF in view (/ipam/addresses): the server filters, sorts and pages
// (GET /addresses with `status`, `tag`, `within`, `q`, `sort`, `deleted`), the grid shows
// the pages as they scroll in. The filter field takes `status:active tag:camera
// within:192.0.2.0/24` terms; the soft-deleted filter shows deleted addresses for restore. The row
// menu reserves an address in DHCP when its prefix has a scope and the principal may write IPAM
// there and DHCP.
import { useNavigate, useSearchParams } from "@solidjs/router";
import { createMemo, createSignal, lazy, onCleanup, onMount, Show } from "solid-js";
import type { AddressRow as Address } from "../../api/types";
import { STATUSES } from "../../api/types";
import { paths } from "../../app/paths";
import { may } from "../../auth/gate";
import { ActionBar, ActionButton } from "../../grid/ActionBar";
import { createGridSelection, DataGrid } from "../../grid/DataGrid";
import type { DragItem } from "../../grid/dnd";
import { FilterBar, type DeletedFilter } from "../../grid/FilterBar";
import { createColumnState } from "../../grid/prefs";
import { parseQuery, type QueryField } from "../../grid/query";
import { createListSource } from "../../grid/source";
import { sortParam, type RowAction, type SortState } from "../../grid/types";
import { saveTextFile } from "../../hosts/handoff";
import { createScopeIndex, mayReserve } from "../../dhcp/reservations/gate";
import { t, withPacks } from "../../i18n";
import { isTyping } from "../../shell/keyboard";
import { DeleteDialog, RestoreDialog } from "../DeleteDialog";
import { HistoryDialog } from "../history/HistoryPanel";
import { IpamNav } from "../IpamNav";
import { MoveDialog } from "../move/MoveDialog";
import { useScope } from "../scope";
import { ScopeSwitcher } from "../ScopeSwitcher";
import { useTree } from "../tree/PrefixTree";
import { addressColumns } from "./columns";
import { addressesCsv } from "./csv";
import "../ipam.css";

const ReserveDialog = lazy(withPacks(["dhcp"], () => import("../../dhcp/reservations/ReserveDialog")));

const FIELDS: readonly QueryField[] = [
  { name: "status", values: STATUSES, multi: true },
  { name: "tag" },
  { name: "within" },
];

export default function AddressesView() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const scope = useScope();
  const tree = useTree(() => scope.vrf()?.id);
  const initial = typeof params.q === "string" ? params.q : "";
  const [text, setText] = createSignal(initial);
  const [applied, setApplied] = createSignal(initial);
  const [deleted, setDeleted] = createSignal<DeletedFilter>(
    params.deleted === "include" || params.deleted === "only" ? params.deleted : "exclude",
  );
  const [sort, setSort] = createSignal<SortState | null>({ field: "ip", desc: false });
  const [dialog, setDialog] = createSignal<
    | { kind: "move"; items: DragItem[] }
    | { kind: "delete"; address: Address }
    | { kind: "restore"; address: Address }
    | { kind: "history"; address: Address }
    | { kind: "reserve"; address: Address }
    | null
  >(null);

  let timer: ReturnType<typeof setTimeout> | undefined;
  const onInput = (value: string) => {
    setText(value);
    clearTimeout(timer);
    timer = setTimeout(() => {
      setApplied(value);
      setParams({ q: value || undefined });
    }, 250);
  };
  onCleanup(() => clearTimeout(timer));

  const parsed = createMemo(() => parseQuery(applied(), FIELDS));
  const source = createListSource<Address>({
    path: "/api/v1/addresses",
    query: () => ({
      expand: "host",
      vrf: scope.vrf()?.id,
      ...parsed().params,
      deleted: deleted() === "exclude" ? undefined : deleted(),
      sort: sortParam(sort()),
    }),
    rowId: (a) => a.id,
    enabled: () => !!scope.vrf(),
    topics: ["ipam"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => ["address", "interface", "host"].includes(o.kind)),
  });

  const scopes = createScopeIndex();
  /** Whether the principal may change this address: it is judged by the address's own prefix. */
  const mayRow = (a: Address) => may.inPrefix(a.prefix);
  const prefixes = createMemo(() => new Map((tree.tree()?.nodes ?? []).map((n) => [n.id, n.cidr])));
  const columns = addressColumns<Address>((a) => a, { withPrefix: (a) => prefixes().get(a.prefix), mayWrite: mayRow });
  const columnState = createColumnState("addresses", () => columns);
  const selectable = (a: Address) => !a.meta.deleted;
  const selection = createGridSelection(source.rows, (a) => a.id, selectable);
  const selected = () => source.rows().filter((a) => selection.has(a.id));
  /** The write actions of the bar: every selected row must be inside the principal's scope. */
  const maySelected = () => selected().length > 0 && selected().every(mayRow);
  const items = (list: Address[]): DragItem[] =>
    list.map((a) => ({ kind: "address", id: a.id, label: a.dns_name ?? a.ip, ip: a.ip }));

  const actions: RowAction<Address>[] = [
    { id: "open", label: () => t("ipam.do.open"), run: (a) => navigate(paths.address(a.ip, a.vrf)) },
    { id: "move", label: () => t("ipam.do.move"), disabled: (a) => !!a.meta.deleted, hidden: (a) => !mayRow(a), run: (a) => setDialog({ kind: "move", items: items([a]) }) },
    { id: "history", label: () => t("ipam.do.history"), run: (a) => setDialog({ kind: "history", address: a }) },
    { id: "reserve", label: () => t("ipam.do.reserve"), hidden: (a) => !mayReserve(a, scopes()), run: (a) => setDialog({ kind: "reserve", address: a }) },
    { id: "restore", label: () => t("ipam.do.restore"), disabled: (a) => !a.meta.deleted, hidden: (a) => !mayRow(a), run: (a) => setDialog({ kind: "restore", address: a }) },
    { id: "delete", label: () => t("ipam.do.delete"), danger: true, disabled: (a) => !!a.meta.deleted, hidden: (a) => !mayRow(a), run: (a) => setDialog({ kind: "delete", address: a }) },
  ];

  const move = () => {
    const list = selected();
    if (list.length && maySelected()) setDialog({ kind: "move", items: items(list) });
  };

  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || isTyping(e) || e.ctrlKey || e.metaKey || e.altKey || dialog()) return;
      if (document.querySelector("[aria-modal='true']")) return;
      if (e.key === "m" || e.key === "M") {
        e.preventDefault();
        move();
      }
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  return (
    <div class="page list-page" data-testid="page-ipam-addresses">
      <IpamNav />
      <div class="page-head">
        <div>
          <h1 tabIndex={-1}>{t("ipam.nav.addresses")}</h1>
        </div>
        <div class="actions">
          <ScopeSwitcher scope={scope} />
        </div>
      </div>
      <FilterBar
        label={t("ipam.addresses.filter_label")}
        placeholder={t("ipam.addresses.filter_terms")}
        value={text()}
        onInput={onInput}
        parsed={parsed()}
        deleted={deleted()}
        onDeleted={(v) => {
          setDeleted(v);
          setParams({ deleted: v === "exclude" ? undefined : v });
        }}
        columns={columnState}
      />
      <div class="list-body">
        <DataGrid
          id="addresses"
          label={t("ipam.nav.addresses")}
          columns={columns}
          columnState={columnState}
          rows={scopes.settled() ? source.rows() : []}
          rowId={(a) => a.id}
          rowKey={(a) => a.ip}
          rowLabel={(a) => a.ip}
          rowClass={(a) => (a.meta.deleted ? "deleted" : undefined)}
          selectable={selectable}
          selection={selection}
          sort={sort()}
          onSort={setSort}
          loading={source.loading() || !scopes.settled()}
          initial={source.initial() || !scopes.settled()}
          hasMore={source.hasMore()}
          onLoadMore={source.loadMore}
          error={source.error()}
          onRetry={source.reload}
          flashed={source.flashed}
          onOpen={(a) => navigate(paths.address(a.ip, a.vrf))}
          onOpenPage={(a) => navigate(paths.address(a.ip, a.vrf))}
          rowActions={actions}
          dragItems={(list) => (list.length && list.every(mayRow) ? items(list) : null)}
          draggable={mayRow}
          dragLabel={(list) => t("ipam.move.dragging", { count: list.length })}
          empty={
            <div class="empty">
              <h3>{applied() ? t("grid.empty.filtered") : t("ipam.addresses.none")}</h3>
            </div>
          }
        />
        <ActionBar count={selection.count()} onClear={selection.clear}>
          <Show when={maySelected()}>
            <ActionButton primary icon="move" label={t("ipam.do.move")} keys={["M"]} onClick={move} testid="action-move" />
          </Show>
          <ActionButton
            icon="export"
            label={t("ipam.do.export_csv")}
            testid="action-export"
            onClick={() => saveTextFile("addresses.csv", addressesCsv(selected(), (id) => scope.vrfById(id)?.name ?? id), "text/csv;charset=utf-8")}
          />
        </ActionBar>
      </div>
      <Show when={dialog()} keyed>
        {(current) => {
          switch (current.kind) {
            case "move":
              return <MoveDialog tree={tree.tree()} items={current.items} onClose={() => setDialog(null)} />;
            case "delete":
              return (
                <DeleteDialog
                  collection="addresses"
                  id={current.address.id}
                  kind="address"
                  label={current.address.ip}
                  revision={current.address.meta.revision}
                  onClose={() => setDialog(null)}
                  onDone={() => {
                    setDialog(null);
                    source.reload();
                  }}
                />
              );
            case "restore":
              return (
                <RestoreDialog
                  collection="addresses"
                  id={current.address.id}
                  kind="address"
                  label={current.address.ip}
                  revision={current.address.meta.revision}
                  onClose={() => setDialog(null)}
                  onDone={() => {
                    setDialog(null);
                    source.reload();
                  }}
                />
              );
            case "reserve":
              return <ReserveDialog source={{ address: current.address }} onClose={() => setDialog(null)} onDone={() => source.reload()} />;
            case "history":
              return (
                <HistoryDialog
                  collection="addresses"
                  id={current.address.id}
                  label={current.address.ip}
                  deleted={!!current.address.meta.deleted}
                  mayRestore={mayRow(current.address)}
                  revision={current.address.meta.revision}
                  onClose={() => setDialog(null)}
                />
              );
          }
        }}
      </Show>
    </div>
  );
}
