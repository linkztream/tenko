// The prefix tree of one VRF (GET /prefixes/tree): supernets and networks with their
// utilization bars, VLAN and alarm level, kept current with the `ipam` and `system` topics.
//
// UI-Q7 of the UI plan: the supernets and top-level networks are always shown, each with its
// number of child prefixes; children are collapsed and never unfolded by the tree itself, so a
// supernet with 150 networks keeps the tree short. Only the person opens a node (its chevron,
// Right, or holding a drag over it); a filter shows the matches with their ancestors. The open
// nodes are kept per VRF for the session. When the selected prefix sits inside a closed node,
// that node is marked as holding the selection and is the tree's active item.
//
// Keyboard (WAI-ARIA tree): Up and Down move, Right opens a node or goes to its first child,
// Left closes it or goes to its parent, Home and End jump, Enter opens the prefix. The list
// keeps the DOM focus and points at the active node with aria-activedescendant.
//
// The tree is the only drop target of the move gesture (design decision 5): dragging hosts
// or addresses over a network highlights it, a supernet refuses with a reason, and the drop
// opens the move preview. Nothing changes until the preview is confirmed.
import { createEffect, createMemo, createSignal, For, on, onCleanup, Show } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery } from "../../api/live";
import type { TreeNode, TreeResponse } from "../../api/types";
import { may } from "../../auth/gate";
import { Addr } from "../../components/Addr";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { AlarmFlag, StatusBadge, UtilizationMeter } from "../../grid/cells";
import { dragged, type DragItem } from "../../grid/dnd";
import { logicalArrow } from "../../grid/focus";
import { t } from "../../i18n";
import { VlanChip } from "../vlan/VlanChip";
import type { VlanStyle } from "../vlan/palette";
import { allocationWords } from "../words";
import "./tree.css";

export interface PrefixTreeProps {
  /** The tree of the VRF in view (see useTree), undefined while it loads. */
  tree: TreeResponse | undefined;
  error?: unknown;
  selectedId?: string | null | undefined;
  onOpen: (node: TreeNode) => void;
  /** Hosts or addresses dropped on a network. */
  onDrop?: (node: TreeNode, items: readonly DragItem[]) => void;
  /** VLAN numbers by VLAN id, for the chips. */
  vlanOf?: (vlanId: string) => { vid: number; name: string; style?: VlanStyle | undefined } | undefined;
  /** Called with the list element, for the `[` key of the page. */
  ref?: (el: HTMLUListElement) => void;
  filter?: string;
}

/** The nodes a filter keeps: the matches and their ancestors. */
export function filterTree(nodes: readonly TreeNode[], text: string): TreeNode[] {
  const q = text.trim().toLowerCase();
  if (!q) return [...nodes];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const keep = new Set<string>();
  for (const n of nodes) {
    if (n.cidr.toLowerCase().includes(q) || (n.description ?? "").toLowerCase().includes(q)) {
      let cur: TreeNode | undefined = n;
      while (cur && !keep.has(cur.id)) {
        keep.add(cur.id);
        cur = cur.parent ? byId.get(cur.parent) : undefined;
      }
    }
  }
  return nodes.filter((n) => keep.has(n.id));
}

/** The open nodes of each VRF's tree, for the session. */
const openByTree = new Map<string, ReadonlySet<string>>();

/** How long a drag rests on a closed node before it opens, in milliseconds. */
export const SPRING_OPEN_MS = 700;

/** For tests: every tree closed again. */
export function resetTreeStateForTest(): void {
  openByTree.clear();
}

/** The tree of one VRF, kept current with the `ipam` and `system` topics (call inside a component). */
export function useTree(vrfId: () => string | undefined) {
  const live = createLiveQuery<TreeResponse>({
    topics: ["ipam", "system"],
    relevant: (e) =>
      e.topic === "system"
        ? e.data.kind === "ipam.prefix.alarm" || (Array.isArray(e.data.tables) && e.data.tables.includes("ipam.alarms"))
        : [...e.objects, ...e.deleted].some((o) => ["prefix", "range", "address", "vlan"].includes(o.kind)),
    fetch: async (signal) => {
      const vrf = vrfId();
      const tree = await api.get("/api/v1/prefixes/tree", { query: { vrf }, signal });
      return { value: tree, revision: tree.revision };
    },
  });
  createEffect(on(vrfId, () => live.refetch(), { defer: true }));
  return {
    tree: () => (live.value.state === "ready" || live.value.state === "refreshing" ? live.value() : undefined),
    error: () => live.value.error,
    refetch: live.refetch,
  };
}

export function PrefixTree(props: PrefixTreeProps) {
  let list!: HTMLUListElement;
  const nodes = () => props.tree?.nodes ?? [];
  const treeKey = () => props.tree?.vrf ?? "";
  const [opened, setOpened] = createSignal<ReadonlySet<string>>(new Set<string>());
  createEffect(on(treeKey, (key) => setOpened(openByTree.get(key) ?? new Set<string>())));
  const saveOpened = (next: ReadonlySet<string>) => {
    setOpened(next);
    openByTree.set(treeKey(), next);
  };
  const [activeId, setActiveId] = createSignal<string | null>(null);
  const [dropId, setDropId] = createSignal<string | null>(null);
  const [refused, setRefused] = createSignal<string | null>(null);

  const filtered = createMemo(() => filterTree(nodes(), props.filter ?? ""));
  const filtering = () => (props.filter ?? "").trim() !== "";

  const byId = createMemo(() => new Map(nodes().map((n) => [n.id, n])));

  /** The nodes shown: every node whose ancestors are all open. */
  const visible = createMemo(() => {
    const out: TreeNode[] = [];
    const hiddenUnder = new Set<string>();
    for (const n of filtered()) {
      if (n.parent && hiddenUnder.has(n.parent)) {
        hiddenUnder.add(n.id);
        continue;
      }
      out.push(n);
      if (!filtering() && !opened().has(n.id)) hiddenUnder.add(n.id);
    }
    return out;
  });

  /** The visible node that shows the selection: the selected node, or its nearest shown ancestor. */
  const selectionShownAt = createMemo(() => {
    const sel = props.selectedId;
    if (!sel) return null;
    const shown = new Set(visible().map((n) => n.id));
    let cur = byId().get(sel);
    while (cur && !shown.has(cur.id)) cur = cur.parent ? byId().get(cur.parent) : undefined;
    return cur?.id ?? null;
  });
  createEffect(() => {
    const at = selectionShownAt();
    if (at && activeId() === null) setActiveId(at);
  });

  const hasChildren = (n: TreeNode) => n.children > 0;
  const isOpen = (n: TreeNode) => hasChildren(n) && (filtering() || opened().has(n.id));
  const toggle = (n: TreeNode, open?: boolean) => {
    const next = new Set(opened());
    const shouldOpen = open ?? !next.has(n.id);
    if (shouldOpen) next.add(n.id);
    else next.delete(n.id);
    saveOpened(next);
  };

  // A drag that rests on a closed node opens it, so a network inside a supernet can take a drop.
  let spring: ReturnType<typeof setTimeout> | undefined;
  let springId: string | null = null;
  const armSpring = (n: TreeNode) => {
    if (springId === n.id || !hasChildren(n) || isOpen(n)) return;
    clearTimeout(spring);
    springId = n.id;
    spring = setTimeout(() => {
      springId = null;
      if (dragged()) toggle(n, true);
    }, SPRING_OPEN_MS);
  };
  const disarmSpring = () => {
    clearTimeout(spring);
    springId = null;
  };
  onCleanup(disarmSpring);

  const nodeId = (id: string) => `tree-${id}`;
  const activeIndex = () => {
    const id = activeId();
    const i = visible().findIndex((n) => n.id === id);
    return i < 0 ? 0 : i;
  };
  const moveTo = (i: number) => {
    const n = visible()[Math.max(0, Math.min(visible().length - 1, i))];
    if (!n) return;
    setActiveId(n.id);
    document.getElementById(nodeId(n.id))?.scrollIntoView?.({ block: "nearest" });
  };

  const onKeyDown = (e: KeyboardEvent) => {
    const list = visible();
    const i = activeIndex();
    const n = list[i];
    if (!n) return;
    // In a right-to-left layout ArrowLeft opens and ArrowRight closes (grid/focus.ts).
    switch (logicalArrow(e.key, e.currentTarget as Element)) {
      case "ArrowDown":
        e.preventDefault();
        moveTo(i + 1);
        break;
      case "ArrowUp":
        e.preventDefault();
        moveTo(i - 1);
        break;
      case "Home":
        e.preventDefault();
        moveTo(0);
        break;
      case "End":
        e.preventDefault();
        moveTo(list.length - 1);
        break;
      case "ArrowRight":
        e.preventDefault();
        if (hasChildren(n) && !isOpen(n)) toggle(n, true);
        else if (isOpen(n)) moveTo(i + 1);
        break;
      case "ArrowLeft": {
        e.preventDefault();
        if (isOpen(n) && !filtering()) toggle(n, false);
        else if (n.parent) {
          const p = list.findIndex((x) => x.id === n.parent);
          if (p >= 0) moveTo(p);
        }
        break;
      }
      case "Enter":
        e.preventDefault();
        props.onOpen(n);
        break;
    }
  };

  // Only a network the principal may write takes a drop; the preview is read-only otherwise.
  const accepts = (n: TreeNode) => n.role === "network" && may.prefix(n.id);
  const onDragOver = (e: DragEvent, n: TreeNode) => {
    if (!dragged()) return;
    armSpring(n);
    if (!accepts(n)) {
      setRefused(n.id);
      return;
    }
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
    setDropId(n.id);
  };
  const onDrop = (e: DragEvent, n: TreeNode) => {
    const items = dragged();
    disarmSpring();
    setDropId(null);
    setRefused(null);
    if (!items || !accepts(n)) return;
    e.preventDefault();
    props.onDrop?.(n, items);
  };

  const vlan = (n: TreeNode) => (n.vlan ? props.vlanOf?.(n.vlan) : undefined);

  return (
    <div class="tree-scroll" data-testid="ipam-tree">
      <Show when={props.error}>
        <div class="tree-msg">
          <ErrorNotice error={props.error} />
        </div>
      </Show>
      <Show when={props.tree && nodes().length === 0}>
        <p class="tree-msg muted">{t("ipam.tree.empty")}</p>
      </Show>
      <ul
        ref={(el) => {
          list = el;
          props.ref?.(el);
        }}
        class="tree"
        role="tree"
        aria-label={t("ipam.tree.label")}
        tabIndex={0}
        aria-activedescendant={visible().length ? nodeId(visible()[activeIndex()]?.id ?? "") : undefined}
        onKeyDown={onKeyDown}
      >
        <For each={visible()}>
          {(n) => (
            <li
              role="treeitem"
              id={nodeId(n.id)}
              aria-level={n.depth + 1}
              aria-expanded={hasChildren(n) ? isOpen(n) : undefined}
              aria-selected={n.id === props.selectedId}
              aria-label={
                !hasChildren(n)
                  ? `${n.cidr}${n.description ? ` ${n.description}` : ""}`
                  : n.description
                    ? t("ipam.tree.node_children", { cidr: n.cidr, description: n.description, count: n.children })
                    : t("ipam.tree.node_children_plain", { cidr: n.cidr, count: n.children })
              }
              data-testid="tree-node"
              data-id={n.id}
              data-key={n.cidr}
              data-role={n.role}
            >
              <div
                class="tnode"
                classList={{
                  drop: dropId() === n.id,
                  dim: refused() === n.id,
                  active: n.id === visible()[activeIndex()]?.id,
                  supernet: n.role === "supernet",
                  selected: n.id === props.selectedId,
                  "holds-selection": n.id !== props.selectedId && n.id === selectionShownAt(),
                }}
                title={refused() === n.id ? t("ipam.tree.drop_refused") : undefined}
                style={{ "--depth": n.depth }}
                onClick={() => {
                  setActiveId(n.id);
                  list.focus({ preventScroll: true });
                  props.onOpen(n);
                }}
                onDragOver={(e) => onDragOver(e, n)}
                onDragEnter={(e) => onDragOver(e, n)}
                onDragLeave={() => {
                  if (springId === n.id) disarmSpring();
                  if (dropId() === n.id) setDropId(null);
                  if (refused() === n.id) setRefused(null);
                }}
                onDrop={(e) => onDrop(e, n)}
              >
                <span
                  class="tw"
                  onClick={(e) => {
                    e.stopPropagation();
                    if (hasChildren(n)) toggle(n);
                  }}
                >
                  <Show when={hasChildren(n)}>
                    <Icon name={isOpen(n) ? "chev-d" : "chev-r"} />
                  </Show>
                </span>
                <span class="lbl">
                  <Addr value={n.cidr} />
                  <span class="name">
                    {n.description ?? (n.role === "supernet" ? t("ipam.tree.supernet") : "")}
                  </span>
                </span>
                <Show when={hasChildren(n)}>
                  <span class="child-count" title={t("ipam.tree.children_count", { count: n.children })} data-testid="tree-child-count">
                    {n.children}
                  </span>
                </Show>
                <Show when={vlan(n)}>{(v) => <VlanChip vid={v().vid} style={v().style} />}</Show>
                <Show when={n.status !== "active"}>
                  <StatusBadge status={n.status} />
                </Show>
                <AlarmFlag level={n.level} />
                <UtilizationMeter
                  percent={n.utilization.percent}
                  level={n.level}
                  used={n.utilization.in_use}
                  capacity={n.utilization.capacity}
                  note={allocationWords(n)}
                  compact
                />
              </div>
            </li>
          )}
        </For>
      </ul>
      <Show when={dropId()}>
        {(id) => {
          const node = () => nodes().find((n) => n.id === id());
          return (
            <div class="drop-tip" role="status">
              {t("ipam.tree.drop_hint", { count: dragged()?.length ?? 0, cidr: node()?.cidr ?? "" })}
            </div>
          );
        }}
      </Show>
    </div>
  );
}
