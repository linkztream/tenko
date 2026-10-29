// A supernet's networks (section 5.2 of the UI plan): today's columns in one sortable, filterable
// table, sorted by utilization (fullest first) until the person picks another sort, which is kept
// with the table's layout. Description, role, VLAN and utilization are shown by default because
// they are what people look prefixes up by; status says "Active" once in its header when every
// row shares it (Column.majority), and only a row that differs carries a badge. "No VLAN" and
// "No description" are filter chips. The rows are the supernet's direct children from the tree,
// so sorting and filtering happen here, not on the server; no group rows (one level of children
// rarely runs long enough to need them, and the tree already groups by supernet).
import { useNavigate } from "@solidjs/router";
import { createMemo, createSignal } from "solid-js";
import type { TreeNode } from "../../api/types";
import { paths } from "../../app/paths";
import { Addr } from "../../components/Addr";
import { StatusBadge, UtilizationMeter } from "../../grid/cells";
import { DataGrid } from "../../grid/DataGrid";
import { FilterBar, ToggleChip } from "../../grid/FilterBar";
import { createColumnState } from "../../grid/prefs";
import type { Column, SortState } from "../../grid/types";
import { t } from "../../i18n";
import { compareCidr, parseCidr } from "../ip";
import { VlanRef } from "../vlan/VlanRef";
import type { VlanStyle } from "../vlan/palette";
import { allocationWords, prefixRoleWord, statusWord } from "../words";

/** The sort of the table when the person chose none: fullest first. */
export const DEFAULT_SORT: SortState = { field: "use", desc: true };

function compare(a: TreeNode, b: TreeNode, field: string): number {
  switch (field) {
    case "use":
      return a.utilization.percent - b.utilization.percent;
    case "description":
      return (a.description ?? "").localeCompare(b.description ?? "");
    case "role":
      return a.role.localeCompare(b.role);
    case "status":
      return a.status.localeCompare(b.status);
    default: {
      const x = parseCidr(a.cidr);
      const y = parseCidr(b.cidr);
      return x && y ? compareCidr(x, y) : a.cidr.localeCompare(b.cidr);
    }
  }
}

/** The rows in the order of `sort`; ties keep the address order. */
export function sortChildren(rows: readonly TreeNode[], sort: SortState | null): TreeNode[] {
  const s = sort ?? DEFAULT_SORT;
  return [...rows].sort((a, b) => {
    const c = compare(a, b, s.field);
    return (s.desc ? -c : c) || compare(a, b, "cidr");
  });
}

export function ChildrenTable(props: {
  supernet: { id: string; cidr: string };
  rows: readonly TreeNode[];
  vlanOf: (id: string) => { vid: number; name: string; style?: VlanStyle | undefined } | undefined;
}) {
  const navigate = useNavigate();
  const [text, setText] = createSignal("");
  const [noVlan, setNoVlan] = createSignal(false);
  const [noDescription, setNoDescription] = createSignal(false);

  const columns: Column<TreeNode>[] = [
    { id: "cidr", header: () => t("ipam.col.prefix"), width: 190, fixed: true, sort: "cidr", render: (n) => <Addr value={n.cidr} />, text: (n) => n.cidr },
    { id: "description", header: () => t("ipam.col.description"), sort: "description", render: (n) => n.description ?? "", text: (n) => n.description ?? "" },
    { id: "role", header: () => t("ipam.col.role"), width: 110, sort: "role", render: (n) => prefixRoleWord(n.role), text: (n) => prefixRoleWord(n.role) },
    { id: "vlan", header: () => t("ipam.col.vlan"), width: 120, render: (n) => <VlanRef id={n.vlan} vlanOf={props.vlanOf} /> },
    {
      id: "use",
      header: () => t("ipam.col.utilization"),
      width: 160,
      sort: "use",
      render: (n) => <UtilizationMeter percent={n.utilization.percent} level={n.level} used={n.utilization.in_use} capacity={n.utilization.capacity} />,
    },
    {
      id: "status",
      header: () => t("ipam.col.status"),
      width: 110,
      sort: "status",
      render: (n) => <StatusBadge status={n.status} />,
      text: (n) => statusWord(n.status),
      majority: (n) => statusWord(n.status),
    },
    {
      id: "allocated",
      header: () => t("ipam.col.allocated"),
      width: 220,
      hidden: true,
      text: (n) => allocationWords(n) ?? "",
      render: (n) => <span class="muted">{allocationWords(n) ?? ""}</span>,
    },
  ];
  const columnState = createColumnState("prefix-children", () => columns);
  const sort = () => {
    const saved = columnState.sort();
    return saved ? { field: saved.column, desc: saved.desc } : DEFAULT_SORT;
  };

  const matches = (n: TreeNode) => {
    const q = text().trim().toLowerCase();
    if (q && !n.cidr.toLowerCase().includes(q) && !(n.description ?? "").toLowerCase().includes(q)) return false;
    if (noVlan() && n.vlan) return false;
    if (noDescription() && (n.description ?? "").trim() !== "") return false;
    return true;
  };
  const rows = createMemo(() => sortChildren(props.rows.filter(matches), sort()));
  const countOf = (keep: (n: TreeNode) => boolean) => props.rows.filter(keep).length;

  return (
    <div class="children-table" data-testid="children-table">
      <FilterBar
        label={t("ipam.children.filter_label")}
        placeholder={t("ipam.children.filter_placeholder")}
        value={text()}
        onInput={setText}
        columns={columnState}
        testid="filterbar-prefix-children"
      >
        <ToggleChip pressed={noVlan()} onToggle={() => setNoVlan(!noVlan())} count={countOf((n) => !n.vlan)} testid="chip-no-vlan">
          {t("ipam.children.no_vlan")}
        </ToggleChip>
        <ToggleChip
          pressed={noDescription()}
          onToggle={() => setNoDescription(!noDescription())}
          count={countOf((n) => (n.description ?? "").trim() === "")}
          testid="chip-no-description"
        >
          {t("ipam.children.no_description")}
        </ToggleChip>
      </FilterBar>
      <DataGrid
        id="prefix-children"
        label={t("ipam.prefix.children_grid", { cidr: props.supernet.cidr })}
        noSelection
        columns={columns}
        columnState={columnState}
        rows={rows()}
        count={{ value: rows().length, noun: t("ipam.children.count", { count: rows().length }) }}
        rowId={(n) => n.id}
        rowKey={(n) => n.cidr}
        sort={sort()}
        onSort={(next) => {
          // From the default (fullest first) a click on the utilization header sorts it the other way.
          const atDefault = sort().field === DEFAULT_SORT.field && sort().desc === DEFAULT_SORT.desc;
          if (next) columnState.saveSort({ column: next.field, desc: next.desc });
          else columnState.saveSort(atDefault ? { column: DEFAULT_SORT.field, desc: false } : null);
        }}
        onOpen={(n) => navigate(paths.prefix(n.cidr))}
        empty={
          <div class="empty">
            <h3>{props.rows.length === 0 ? t("ipam.prefix.no_children") : t("ipam.children.empty_filtered")}</h3>
          </div>
        }
      />
    </div>
  );
}
