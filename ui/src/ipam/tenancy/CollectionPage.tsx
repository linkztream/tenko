// The frame of the simple IPAM collections (VLANs, sites, tenants, VRFs): a filter bar with
// the soft-deleted filter, a server-sorted grid, and the row actions every collection has:
// edit, history, delete and restore (IPAM-09). The view supplies the columns and the forms.
import { useSearchParams } from "@solidjs/router";
import { createMemo, createSignal, onCleanup, Show, untrack, type JSX } from "solid-js";
import type { PathsWith } from "../../api/client";
import type { Meta } from "../../api/types";
import { writesAll } from "../../auth/gate";
import { DataGrid } from "../../grid/DataGrid";
import { FilterBar, type DeletedFilter } from "../../grid/FilterBar";
import { createColumnState } from "../../grid/prefs";
import { parseQuery, type QueryField } from "../../grid/query";
import { createListSource, type ListSource } from "../../grid/source";
import { sortParam, type Column, type RowAction, type SortState } from "../../grid/types";
import { t } from "../../i18n";
import type { Collection } from "../collections";
import { DeleteDialog, RestoreDialog } from "../DeleteDialog";
import { HistoryDialog } from "../history/HistoryPanel";

export interface CollectionRow {
  id: string;
  meta: Meta;
}

export interface CollectionPageProps<T extends CollectionRow> {
  /** Grid id and test hook: `grid-<id>`. */
  id: string;
  collection: Collection;
  kind: string;
  path: PathsWith<"get">;
  label: string;
  filterLabel: string;
  filterPlaceholder: string;
  fields?: readonly QueryField[];
  defaultSort: SortState;
  columns: readonly Column<T>[];
  rowLabel: (row: T) => string;
  /** Extra query parameters (a tenant filter, for example). */
  extraQuery?: () => Record<string, string | undefined>;
  /** The edit form of a row; the page closes it on done or cancel. */
  edit: (row: T, close: (changed: boolean) => void) => JSX.Element;
  empty: JSX.Element;
  /** Receives the source, for a view that refreshes after its own create form. */
  sourceRef?: (source: ListSource<T>) => void;
  /** Row actions of the view, after the built-in ones (edit, history, restore, delete). */
  actions?: RowAction<T>[];
  /**
   * Whether the principal may change a row (display gating, IAM-01): edit, restore and delete are
   * left out for the others. Without it only a global writer may, which is right for the kinds
   * a scoped grant does not reach (tenants, VRFs).
   */
  mayWrite?: (row: T) => boolean;
  /** Where the grid lives inside the page (default: fills the page). */
  class?: string;
}

export function CollectionPage<T extends CollectionRow>(props: CollectionPageProps<T>) {
  // The grid id, the path and the source callback are fixed for the life of the page.
  const { id, path, sourceRef } = untrack(() => ({ id: props.id, path: props.path, sourceRef: props.sourceRef }));
  const [params, setParams] = useSearchParams();
  const qKey = `${id}_q`;
  const initial = typeof params[qKey] === "string" ? (params[qKey] as string) : "";
  const [text, setText] = createSignal(initial);
  const [applied, setApplied] = createSignal(initial);
  const [deleted, setDeleted] = createSignal<DeletedFilter>("exclude");
  const [sort, setSort] = createSignal<SortState | null>(props.defaultSort);
  const [dialog, setDialog] = createSignal<{ kind: "edit" | "delete" | "restore" | "history"; row: T } | null>(null);

  let timer: ReturnType<typeof setTimeout> | undefined;
  const onInput = (value: string) => {
    setText(value);
    clearTimeout(timer);
    timer = setTimeout(() => {
      setApplied(value);
      setParams({ [qKey]: value || undefined });
    }, 250);
  };
  onCleanup(() => clearTimeout(timer));

  const parsed = createMemo(() => parseQuery(applied(), props.fields ?? []));
  const source = createListSource<T>({
    path,
    query: () => ({
      ...parsed().params,
      ...props.extraQuery?.(),
      deleted: deleted() === "exclude" ? undefined : deleted(),
      sort: sortParam(sort()),
    }),
    rowId: (r) => r.id,
    topics: ["ipam"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => o.kind === props.kind),
  });
  sourceRef?.(source);
  const columnState = createColumnState(id, () => props.columns);

  const mayRow = (r: T) => props.mayWrite?.(r) ?? writesAll();
  const actions: RowAction<T>[] = [
    { id: "edit", label: () => t("ipam.do.edit"), disabled: (r) => !!r.meta.deleted, hidden: (r) => !mayRow(r), run: (r) => setDialog({ kind: "edit", row: r }) },
    { id: "history", label: () => t("ipam.do.history"), run: (r) => setDialog({ kind: "history", row: r }) },
    { id: "restore", label: () => t("ipam.do.restore"), disabled: (r) => !r.meta.deleted, hidden: (r) => !mayRow(r), run: (r) => setDialog({ kind: "restore", row: r }) },
    { id: "delete", label: () => t("ipam.do.delete"), danger: true, disabled: (r) => !!r.meta.deleted, hidden: (r) => !mayRow(r), run: (r) => setDialog({ kind: "delete", row: r }) },
    // The view's own actions come after the built-in ones; the list is fixed for the life of the page.
    ...untrack(() => props.actions ?? []),
  ];
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) source.reload();
  };

  return (
    <div class={props.class ?? "collection"}>
      <FilterBar
        label={props.filterLabel}
        placeholder={props.filterPlaceholder}
        value={text()}
        onInput={onInput}
        parsed={parsed()}
        deleted={deleted()}
        onDeleted={setDeleted}
        columns={columnState}
        slashFocus={props.class === undefined}
        testid={`filterbar-${props.id}`}
      />
      <div class="list-body">
        <DataGrid
          id={props.id}
          label={props.label}
          noSelection
          columns={props.columns}
          columnState={columnState}
          rows={source.rows()}
          rowId={(r) => r.id}
          rowKey={props.rowLabel}
          rowLabel={props.rowLabel}
          rowClass={(r) => (r.meta.deleted ? "deleted" : undefined)}
          sort={sort()}
          onSort={setSort}
          loading={source.loading()}
          initial={source.initial()}
          hasMore={source.hasMore()}
          onLoadMore={source.loadMore}
          error={source.error()}
          onRetry={source.reload}
          flashed={source.flashed}
          onOpen={(r) => setDialog({ kind: r.meta.deleted || !mayRow(r) ? "history" : "edit", row: r })}
          rowActions={actions}
          empty={applied() ? <div class="empty"><h3>{t("grid.empty.filtered")}</h3></div> : props.empty}
        />
      </div>
      <Show when={dialog()} keyed>
        {(d) => {
          switch (d.kind) {
            case "edit":
              return props.edit(d.row, close);
            case "delete":
              return (
                <DeleteDialog
                  collection={props.collection}
                  id={d.row.id}
                  kind={props.kind}
                  label={props.rowLabel(d.row)}
                  revision={d.row.meta.revision}
                  onClose={() => close(false)}
                  onDone={() => close(true)}
                />
              );
            case "restore":
              return (
                <RestoreDialog
                  collection={props.collection}
                  id={d.row.id}
                  kind={props.kind}
                  label={props.rowLabel(d.row)}
                  revision={d.row.meta.revision}
                  onClose={() => close(false)}
                  onDone={() => close(true)}
                />
              );
            case "history":
              return (
                <HistoryDialog
                  collection={props.collection}
                  id={d.row.id}
                  label={props.rowLabel(d.row)}
                  deleted={!!d.row.meta.deleted}
                  mayRestore={mayRow(d.row)}
                  revision={d.row.meta.revision}
                  onClose={() => close(false)}
                />
              );
          }
        }}
      </Show>
    </div>
  );
}
