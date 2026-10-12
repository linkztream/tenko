// The hosts (/ipam/hosts): the unit of intent (IPAM-12) with its assignment mode (IPAM-14)
// and lock (IPAM-16). The server filters (`mode`, `locked`, `tag`, `site`, `q`, `deleted`)
// and sorts (`name`, `mode`). Bulk actions on the selection: move to a network (M), set the
// mode (Shift+M), lock or unlock (L), export CSV; each one previews its plan first.
import { useNavigate, useSearchParams } from "@solidjs/router";
import { createMemo, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { api } from "../api/client";
import type { AssignmentMode, BulkResponse, Host, IpamCommand, Site, Tenant } from "../api/types";
import { ASSIGNMENT_MODES } from "../api/types";
import { fetchAll } from "../api/paginate";
import { createLiveQuery } from "../api/live";
import { paths } from "../app/paths";
import { may } from "../auth/gate";
import { Icon } from "../components/Icon";
import { ActionBar, ActionButton } from "../grid/ActionBar";
import { DeletedTag, LockFlag, ModeBadge, Tags, TimeAgo } from "../grid/cells";
import { createGridSelection, DataGrid } from "../grid/DataGrid";
import type { DragItem } from "../grid/dnd";
import { FilterBar, ToggleChip, type DeletedFilter } from "../grid/FilterBar";
import { Menu } from "../grid/Menu";
import { createColumnState } from "../grid/prefs";
import { parseQuery, type QueryField } from "../grid/query";
import { createListSource } from "../grid/source";
import { sortParam, type Column, type RowAction, type SortState } from "../grid/types";
import { t } from "../i18n";
import { DeleteDialog, RestoreDialog } from "../ipam/DeleteDialog";
import { HistoryDialog } from "../ipam/history/HistoryPanel";
import { IpamNav } from "../ipam/IpamNav";
import { MoveDialog } from "../ipam/move/MoveDialog";
import { writeQuery } from "../ipam/plan/describe";
import { PlanDialog, useWriteToast } from "../ipam/plan/PlanDialog";
import { useScope } from "../ipam/scope";
import { useTree } from "../ipam/tree/PrefixTree";
import { modeHint, modeWord } from "../ipam/words";
import { isTyping } from "../shell/keyboard";
import { hostsCsv } from "./csv";
import { HostForm } from "./HostForm";
import { saveTextFile } from "./handoff";
import "../ipam/ipam.css";
import "./hosts.css";

const FIELDS: readonly QueryField[] = [
  { name: "mode", values: ASSIGNMENT_MODES },
  { name: "tag" },
  { name: "site" },
];

type Bulk = { kind: "mode"; mode: AssignmentMode } | { kind: "lock"; lock: boolean };

export default function HostsView() {
  const navigate = useNavigate();
  const writeToast = useWriteToast();
  const [params, setParams] = useSearchParams();
  const scope = useScope();
  const tree = useTree(() => scope.vrf()?.id);
  const initial = typeof params.q === "string" ? params.q : "";
  const [text, setText] = createSignal(initial);
  const [applied, setApplied] = createSignal(initial);
  const [locked, setLocked] = createSignal(params.locked === "true");
  const [deleted, setDeleted] = createSignal<DeletedFilter>(
    params.deleted === "include" || params.deleted === "only" ? params.deleted : "exclude",
  );
  const [sort, setSort] = createSignal<SortState | null>({ field: "name", desc: false });
  const [dialog, setDialog] = createSignal<
    | { kind: "create" }
    | { kind: "move"; items: DragItem[] }
    | { kind: "bulk"; bulk: Bulk; hosts: Host[] }
    | { kind: "delete"; host: Host }
    | { kind: "restore"; host: Host }
    | { kind: "history"; host: Host }
    | null
  >(null);
  const [modeMenu, setModeMenu] = createSignal<HTMLElement | null>(null);

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

  const lookups = createLiveQuery<{ sites: Site[]; tenants: Tenant[] }>({
    topics: ["ipam"],
    relevant: (e) => e.objects.some((o) => o.kind === "site" || o.kind === "tenant"),
    fetch: async (signal) => {
      const [sites, tenants] = await Promise.all([
        fetchAll<Site>("/api/v1/sites", { signal }),
        fetchAll<Tenant>("/api/v1/tenants", { signal }),
      ]);
      return { value: { sites: sites.items, tenants: tenants.items } };
    },
  });
  const siteName = (id?: string | null) => (id ? lookups.latest()?.sites.find((s) => s.id === id)?.name : undefined);
  const tenantName = (id: string) => lookups.latest()?.tenants.find((tn) => tn.id === id)?.name ?? "";

  const parsed = createMemo(() => parseQuery(applied(), FIELDS));
  const source = createListSource<Host>({
    path: "/api/v1/hosts",
    query: () => {
      const p = { ...parsed().params };
      // `site:Home` is typed by name; the API filters by id.
      if (p.site) p.site = lookups.latest()?.sites.find((s) => s.name.toLowerCase() === p.site?.toLowerCase())?.id ?? p.site;
      return {
        ...p,
        locked: locked() ? true : undefined,
        deleted: deleted() === "exclude" ? undefined : deleted(),
        sort: sortParam(sort()),
      };
    },
    rowId: (h) => h.id,
    topics: ["ipam"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => o.kind === "host" || o.kind === "interface"),
  });

  const columns: Column<Host>[] = [
    {
      id: "name",
      header: () => t("ipam.col.name"),
      width: 220,
      sort: "name",
      fixed: true,
      text: (h) => h.name,
      render: (h) => <span class="hostname">{h.name}</span>,
    },
    {
      id: "mode",
      header: () => t("ipam.col.mode"),
      width: 160,
      sort: "mode",
      text: (h) => modeWord(h.mode),
      render: (h) => (
        <>
          <ModeBadge mode={h.mode} /> <LockFlag locked={h.lock} />
        </>
      ),
    },
    { id: "site", header: () => t("ipam.col.site"), width: 120, render: (h) => siteName(h.site) ?? "" },
    { id: "tenant", header: () => t("ipam.col.tenant"), width: 120, hidden: true, render: (h) => tenantName(h.tenant) },
    { id: "description", header: () => t("ipam.col.description"), render: (h) => h.meta.description ?? "" },
    { id: "tags", header: () => t("ipam.col.tags"), width: 180, render: (h) => <Tags tags={h.meta.tags} /> },
    {
      id: "updated",
      header: () => t("ipam.col.updated"),
      width: 130,
      sort: "updated",
      render: (h) => (
        <>
          <TimeAgo at={h.meta.updated.at} /> <DeletedTag deleted={h.meta.deleted} />
        </>
      ),
    },
  ];
  const columnState = createColumnState("hosts", () => columns);
  const selectable = (h: Host) => !h.meta.deleted;
  const selection = createGridSelection(source.rows, (h) => h.id, selectable);
  const selected = () => source.rows().filter((h) => selection.has(h.id));
  /** Whether the principal may change this host: judged by the anchors of the host (docs/access.md 3.2). */
  const mayRow = (h: Host) => may.host(h);
  /** The write actions of the bar: every selected host must be inside the principal's scope. */
  const maySelected = () => selected().length > 0 && selected().every(mayRow);
  const items = (list: Host[]): DragItem[] => list.map((h) => ({ kind: "host", id: h.id, label: h.name }));

  const actions: RowAction<Host>[] = [
    { id: "open", label: () => t("ipam.do.open"), run: (h) => navigate(paths.host(h.name)) },
    { id: "move", label: () => t("ipam.do.move"), disabled: (h) => !!h.meta.deleted, hidden: (h) => !mayRow(h), run: (h) => setDialog({ kind: "move", items: items([h]) }) },
    {
      id: "lock",
      label: () => t("hosts.do.toggle_lock"),
      disabled: (h) => !!h.meta.deleted,
      hidden: (h) => !mayRow(h),
      run: (h) => setDialog({ kind: "bulk", bulk: { kind: "lock", lock: !h.lock }, hosts: [h] }),
    },
    { id: "history", label: () => t("ipam.do.history"), run: (h) => setDialog({ kind: "history", host: h }) },
    { id: "restore", label: () => t("ipam.do.restore"), disabled: (h) => !h.meta.deleted, hidden: (h) => !mayRow(h), run: (h) => setDialog({ kind: "restore", host: h }) },
    { id: "delete", label: () => t("ipam.do.delete"), danger: true, disabled: (h) => !!h.meta.deleted, hidden: (h) => !mayRow(h), run: (h) => setDialog({ kind: "delete", host: h }) },
  ];

  const bulkSend = (bulk: Bulk, hosts: Host[]) => (o: { dryRun: boolean; acknowledge: string[] }) => {
    const operations: IpamCommand[] = hosts.map((h) =>
      bulk.kind === "mode"
        ? ({ op: "set_mode", args: { host: h.id, mode: bulk.mode, expected: h.meta.revision ?? null } } as IpamCommand)
        : ({ op: "set_lock", args: { host: h.id, lock: bulk.lock, expected: h.meta.revision ?? null } } as IpamCommand),
    );
    return api.post("/api/v1/hosts/bulk", { query: writeQuery(o.dryRun, o.acknowledge), body: { operations } }) as Promise<BulkResponse>;
  };

  const move = () => {
    const list = selected();
    if (list.length && maySelected()) setDialog({ kind: "move", items: items(list) });
  };
  const toggleLock = () => {
    const list = selected();
    if (list.length && maySelected()) setDialog({ kind: "bulk", bulk: { kind: "lock", lock: !list.every((h) => h.lock) }, hosts: list });
  };

  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || isTyping(e) || e.ctrlKey || e.metaKey || e.altKey || dialog()) return;
      if (document.querySelector("[aria-modal='true']")) return;
      if (e.key === "M" && e.shiftKey) {
        e.preventDefault();
        const button = document.querySelector<HTMLElement>("[data-testid='action-mode']");
        if (button && maySelected()) setModeMenu(button);
      } else if (e.key === "m") {
        e.preventDefault();
        move();
      } else if (e.key === "l" || e.key === "L") {
        e.preventDefault();
        toggleLock();
      }
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  const bulkTitle = (bulk: Bulk, count: number) =>
    bulk.kind === "mode"
      ? t("hosts.bulk.mode_title", { count, mode: modeWord(bulk.mode) })
      : bulk.lock
        ? t("hosts.bulk.lock_title", { count })
        : t("hosts.bulk.unlock_title", { count });

  return (
    <div class="page list-page" data-testid="page-hosts">
      <IpamNav />
      <div class="page-head">
        <div>
          <h1 tabIndex={-1}>{t("ipam.nav.hosts")}</h1>
        </div>
        <div class="actions">
          <Show when={may.create("host")}>
            <button type="button" class="btn primary" data-testid="hosts-create" onClick={() => setDialog({ kind: "create" })}>
              <Icon name="plus" />
              {t("hosts.do.create")}
            </button>
          </Show>
        </div>
      </div>
      <FilterBar
        label={t("hosts.filter.label")}
        placeholder={t("hosts.filter.placeholder")}
        value={text()}
        onInput={onInput}
        parsed={parsed()}
        deleted={deleted()}
        onDeleted={(v) => {
          setDeleted(v);
          setParams({ deleted: v === "exclude" ? undefined : v });
        }}
        columns={columnState}
      >
        <ToggleChip
          pressed={locked()}
          testid="filter-locked"
          onToggle={() => {
            setLocked(!locked());
            setParams({ locked: locked() ? "true" : undefined });
          }}
        >
          <Icon name="lock" />
          {t("hosts.filter.locked")}
        </ToggleChip>
      </FilterBar>
      <div class="list-body">
        <DataGrid
          id="hosts"
          label={t("ipam.nav.hosts")}
          columns={columns}
          columnState={columnState}
          rows={source.rows()}
          rowId={(h) => h.id}
          rowKey={(h) => h.name}
          rowLabel={(h) => h.name}
          rowClass={(h) => (h.meta.deleted ? "deleted" : h.mode === "unmanaged" ? "unmanaged" : undefined)}
          selectable={selectable}
          selection={selection}
          sort={sort()}
          onSort={setSort}
          loading={source.loading()}
          initial={source.initial()}
          hasMore={source.hasMore()}
          onLoadMore={source.loadMore}
          error={source.error()}
          onRetry={source.reload}
          flashed={source.flashed}
          onOpen={(h) => navigate(paths.host(h.name))}
          onOpenPage={(h) => navigate(paths.host(h.name))}
          rowActions={actions}
          dragItems={(list) => (list.length && list.every(mayRow) ? items(list) : null)}
          draggable={mayRow}
          dragLabel={(list) => t("ipam.move.dragging", { count: list.length })}
          empty={
            <div class="empty">
              <h3>{applied() || locked() ? t("grid.empty.filtered") : t("hosts.empty")}</h3>
            </div>
          }
        />
        <ActionBar count={selection.count()} onClear={selection.clear}>
          <Show when={maySelected()}>
            <ActionButton primary icon="move" label={t("ipam.do.move")} keys={["M"]} onClick={move} testid="action-move" />
            <ActionButton
              label={t("hosts.do.set_mode")}
              keys={["Shift", "M"]}
              testid="action-mode"
              onClick={() => setModeMenu(document.querySelector<HTMLElement>("[data-testid='action-mode']"))}
            />
            <ActionButton icon="lock" label={t("hosts.do.toggle_lock")} keys={["L"]} onClick={toggleLock} testid="action-lock" />
          </Show>
          <ActionButton
            icon="export"
            label={t("ipam.do.export_csv")}
            testid="action-export"
            onClick={() => void hostsCsv(selected(), tenantName, (id) => siteName(id) ?? "").then((csv) => saveTextFile("hosts.csv", csv, "text/csv;charset=utf-8"))}
          />
        </ActionBar>
      </div>
      <Show when={modeMenu()}>
        {(anchor) => (
          <Menu
            anchor={anchor()}
            label={t("hosts.do.set_mode")}
            testid="mode-menu"
            onClose={() => setModeMenu(null)}
            items={ASSIGNMENT_MODES.map((mode) => ({
              id: mode,
              label: modeWord(mode),
              hint: modeHint(mode),
              run: () => setDialog({ kind: "bulk", bulk: { kind: "mode", mode }, hosts: selected() }),
            }))}
          />
        )}
      </Show>
      <Show when={dialog()} keyed>
        {(d) => {
          switch (d.kind) {
            case "create":
              return (
                <HostForm
                  onClose={() => setDialog(null)}
                  onDone={(h) => {
                    setDialog(null);
                    navigate(paths.host(h.name));
                  }}
                />
              );
            case "move":
              return <MoveDialog tree={tree.tree()} items={d.items} onClose={() => setDialog(null)} />;
            case "bulk":
              return (
                <PlanDialog
                  title={bulkTitle(d.bulk, d.hosts.length)}
                  confirmLabel={bulkTitle(d.bulk, d.hosts.length)}
                  send={bulkSend(d.bulk, d.hosts)}
                  testid="dialog-hosts-bulk"
                  onClose={() => setDialog(null)}
                  onDone={(r) => {
                    setDialog(null);
                    selection.clear();
                    source.reload();
                    writeToast(bulkTitle(d.bulk, d.hosts.length), r);
                  }}
                  intro={
                    <ul class="plain-list mono">
                      <For each={d.hosts.slice(0, 12)}>{(h) => <li>{h.name}</li>}</For>
                    </ul>
                  }
                />
              );
            case "delete":
              return (
                <DeleteDialog
                  collection="hosts"
                  id={d.host.id}
                  kind="host"
                  label={d.host.name}
                  revision={d.host.meta.revision}
                  cascade
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
                  collection="hosts"
                  id={d.host.id}
                  kind="host"
                  label={d.host.name}
                  revision={d.host.meta.revision}
                  onClose={() => setDialog(null)}
                  onDone={() => {
                    setDialog(null);
                    source.reload();
                  }}
                />
              );
            case "history":
              return (
                <HistoryDialog
                  collection="hosts"
                  id={d.host.id}
                  label={d.host.name}
                  deleted={!!d.host.meta.deleted}
                  mayRestore={mayRow(d.host)}
                  revision={d.host.meta.revision}
                  onClose={() => setDialog(null)}
                />
              );
          }
        }}
      </Show>
    </div>
  );
}
