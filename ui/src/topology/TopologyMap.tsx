// The drawing of the topology map: the layout of the graph in view as SVG. Edges are drawn
// first and the devices on top with an opaque fill, because a spanning-tree edge can pass
// behind a leaf of the grid under its parent. Every device and every group of hidden devices
// is one focusable element; exactly one of them is in the tab order (roving tabindex).
//
// Keys: arrows move to the nearest device in that direction, Enter and Space select a device
// or open a group, Escape clears the selection, "+", "-" and "0" zoom and fit. The wheel
// zooms at the pointer and dragging the background pans.
//
// U7: a link only a MAC table names is dashed with a question mark; a device with a hashed
// name (`host-00005e005301`) gets its vendor and address as a second line; a group of
// endpoints on one port or SSID names that port or SSID beside its count.
import { createEffect, createMemo, createSignal, For, on, onCleanup, onMount, Show } from "solid-js";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import type { VlanStyle } from "../ipam/vlan/palette";
import type { TopologyEdge, TopologyNode } from "./api";
import type { Layout, PlacedEdge } from "./layout";
import { edgeClass, groupBucket, isGroupId, nodeAriaLabel, nodeSecondLine, SHAPES, shortLabel } from "./model";
import { centreOn, fit, nearestInDirection, pan, transformOf, zoomAt, type Direction, type View } from "./viewport";

export interface TopologyMapProps {
  layout: Layout;
  /** The devices of the graph by id (kind, label), for the shapes and the names. */
  nodes: ReadonlyMap<string, TopologyNode>;
  /** The edges of the graph by id, for their VLAN. */
  edges: ReadonlyMap<string, TopologyEdge>;
  /** The selected device. */
  selected: string | undefined;
  /** The device that starts a path between two devices. */
  pathStart: string | undefined;
  /** The placed ids (devices and groups) on the highlighted path. */
  pathNodes: ReadonlySet<string>;
  /** The edge ids on the highlighted path (the original ids, not the merged ones). */
  pathEdges: ReadonlySet<string>;
  /** The color and shape of a VLAN, when it has one. */
  vlanStyle: (vid: number) => VlanStyle | undefined;
  /** Changes when the data of another filter arrives: the drawing is fitted again. */
  fitKey: string;
  onSelect: (id: string) => void;
  onClear: () => void;
  /** Opens a group of hidden devices (its group id). */
  onOpenGroup: (groupId: string) => void;
}

/** The size the drawing is fitted to when the element has none (tests, hidden panes). */
const FALLBACK_SIZE = { w: 1000, h: 640 };
/** The zoom step of the buttons and keys. */
const ZOOM_STEP = 1.25;
/** The wheel zooms by this factor per pixel of delta. */
const WHEEL_RATE = 0.0015;
/** A focused device nearer than this to the edge of the screen is brought to the centre. */
const EDGE_MARGIN = 48;

const KEY_DIRECTIONS: Readonly<Record<string, Direction>> = {
  ArrowUp: "up",
  ArrowDown: "down",
  ArrowLeft: "left",
  ArrowRight: "right",
};

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** The VLAN of a drawn edge: the one all its original edges share, if any. */
function edgeVlan(edge: PlacedEdge, edges: ReadonlyMap<string, TopologyEdge>): number | undefined {
  let vid: number | undefined;
  for (const id of edge.members) {
    const v = edges.get(id)?.vlan;
    if (v === null || v === undefined) continue;
    if (vid === undefined) vid = v;
    else if (vid !== v) return undefined;
  }
  return vid;
}

/** A slightly bent line between the ends of an edge that is not part of the spanning tree. */
function curve(e: PlacedEdge): string {
  const mx = (e.x1 + e.x2) / 2;
  const my = (e.y1 + e.y2) / 2;
  const cx = mx + (e.y2 - e.y1) * 0.2;
  const cy = my - (e.x2 - e.x1) * 0.2;
  return `M${e.x1} ${e.y1}Q${cx} ${cy} ${e.x2} ${e.y2}`;
}

export function TopologyMap(props: TopologyMapProps) {
  let svg!: SVGSVGElement;
  const elements = new Map<string, SVGGElement>();
  const [view, setView] = createSignal<View>({ x: 0, y: 0, scale: 1 });
  // Whether the view is still the fitted one. A fitted view follows the size of the canvas (the
  // panel docks and undocks); a view the person zoomed or panned stays where it is.
  let fitted = true;
  const adjust = (change: (v: View) => View) => {
    fitted = false;
    setView(change);
  };
  const [size, setSize] = createSignal(FALLBACK_SIZE);
  const [focusId, setFocusId] = createSignal<string | undefined>();
  let pendingFocus: string | undefined;

  const placedById = createMemo(() => new Map(props.layout.nodes.map((n) => [n.id, n])));
  const nodeIds = createMemo(() => props.layout.nodes.map((n) => n.id), [], { equals: sameList });
  const edgeIds = createMemo(() => props.layout.edges.map((e) => e.id), [], { equals: sameList });
  const edgeById = createMemo(() => new Map(props.layout.edges.map((e) => [e.id, e])));

  /** The one device or group in the tab order: where the focus was, else the selection, else the first router, else the first device. */
  const tabbable = createMemo(() => {
    const placed = placedById();
    const focused = focusId();
    if (focused !== undefined && placed.has(focused)) return focused;
    const selected = props.selected === undefined ? undefined : props.layout.position.get(props.selected)?.id;
    if (selected !== undefined) return selected;
    const nodes = props.layout.nodes;
    return (nodes.find((n) => n.kind === "router") ?? nodes[0])?.id;
  });

  // ----- size and view

  const measure = () => {
    const box = svg.getBoundingClientRect();
    setSize(box.width > 0 && box.height > 0 ? { w: box.width, h: box.height } : FALLBACK_SIZE);
  };
  const refit = () => {
    measure();
    fitted = true;
    setView(fit(props.layout.width, props.layout.height, size().w, size().h));
  };
  // Called by the browser, outside any reactive scope.
  const onResize = () => {
    measure();
    if (fitted) setView(fit(props.layout.width, props.layout.height, size().w, size().h));
  };
  const zoomBy = (factor: number) => {
    const { w, h } = size();
    adjust((v) => zoomAt(v, factor, w / 2, h / 2));
  };

  onMount(() => {
    refit();
    if (typeof ResizeObserver !== "undefined") {
      const observer = new ResizeObserver(onResize);
      observer.observe(svg);
      onCleanup(() => observer.disconnect());
    }
  });
  createEffect(on(() => props.fitKey, refit, { defer: true }));

  // The tab stop follows the selection, also when it is made elsewhere (the panel).
  createEffect(
    on(
      () => props.selected,
      (selected) => {
        const placed = selected === undefined ? undefined : props.layout.position.get(selected)?.id;
        if (placed !== undefined) setFocusId(placed);
      },
      { defer: true },
    ),
  );

  // After a group opened, the focus moves to its first device (the group is gone).
  createEffect(
    on(
      () => props.layout,
      () => {
        const id = pendingFocus;
        const el = id === undefined ? undefined : elements.get(id);
        if (id !== undefined && el) {
          pendingFocus = undefined;
          setFocusId(id);
          el.focus();
        }
      },
    ),
  );

  const keepInView = (id: string) => {
    const p = placedById().get(id);
    if (!p) return;
    const v = view();
    const { w, h } = size();
    const sx = (p.x - v.x) * v.scale;
    const sy = (p.y - v.y) * v.scale;
    if (sx < EDGE_MARGIN || sx > w - EDGE_MARGIN || sy < EDGE_MARGIN || sy > h - EDGE_MARGIN) {
      adjust(() => centreOn(v, p.x, p.y, w, h));
    }
  };

  const focusNode = (id: string) => {
    setFocusId(id);
    elements.get(id)?.focus();
    keepInView(id);
  };

  const activate = (id: string) => {
    if (!isGroupId(id)) {
      props.onSelect(id);
      return;
    }
    pendingFocus = placedById().get(id)?.members?.[0];
    props.onOpenGroup(id);
  };

  // ----- keyboard and pointer

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const id = (e.target as Element).closest<SVGGElement>("[data-id]")?.dataset.id;
    const direction = KEY_DIRECTIONS[e.key];
    if (direction) {
      if (id === undefined) return;
      e.preventDefault();
      const points = props.layout.nodes.map((n) => ({ id: n.id, x: n.x, y: n.y }));
      const next = nearestInDirection(points, id, direction);
      if (next !== null) focusNode(next);
      return;
    }
    switch (e.key) {
      case "Enter":
      case " ":
        if (id === undefined) return;
        e.preventDefault();
        activate(id);
        break;
      case "Escape":
        e.stopPropagation();
        props.onClear();
        break;
      case "+":
      case "=":
        e.preventDefault();
        zoomBy(ZOOM_STEP);
        break;
      case "-":
      case "_":
        e.preventDefault();
        zoomBy(1 / ZOOM_STEP);
        break;
      case "0":
        e.preventDefault();
        refit();
        break;
    }
  };

  const onWheel = (e: WheelEvent) => {
    e.preventDefault();
    const box = svg.getBoundingClientRect();
    const delta = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
    adjust((v) => zoomAt(v, Math.exp(-delta * WHEEL_RATE), e.clientX - box.left, e.clientY - box.top));
  };

  let drag: { pointer: number; x: number; y: number } | undefined;
  const onPointerDown = (e: PointerEvent) => {
    if (e.button !== 0 || (e.target as Element).closest("[data-id]")) return;
    drag = { pointer: e.pointerId, x: e.clientX, y: e.clientY };
    svg.setPointerCapture?.(e.pointerId);
  };
  const onPointerMove = (e: PointerEvent) => {
    if (!drag || e.pointerId !== drag.pointer) return;
    const dx = e.clientX - drag.x;
    const dy = e.clientY - drag.y;
    drag.x = e.clientX;
    drag.y = e.clientY;
    adjust((v) => pan(v, dx, dy));
  };
  const onPointerEnd = (e: PointerEvent) => {
    if (!drag || e.pointerId !== drag.pointer) return;
    drag = undefined;
    if (svg.hasPointerCapture?.(e.pointerId)) svg.releasePointerCapture(e.pointerId);
  };

  // ----- parts

  const EdgeShape = (p: { id: string }) => {
    const edge = () => edgeById().get(p.id);
    const vlan = () => {
      const e = edge();
      const vid = e ? edgeVlan(e, props.edges) : undefined;
      return vid === undefined ? undefined : props.vlanStyle(vid);
    };
    const attrs = () => {
      const e = edge();
      const style = vlan();
      return {
        class: `${e ? edgeClass(e.kind) : "topology-edge"}${style ? " has-vlan" : ""}${e?.inferred ? " edge-inferred" : ""}`,
        "data-testid": "topology-edge",
        "data-id": p.id,
        "data-kind": e?.kind,
        "data-inferred": e?.inferred ? "true" : undefined,
        "data-vlan": style?.vid,
        "data-path": e?.members.some((m) => props.pathEdges.has(m)) ? "true" : undefined,
        style: style ? { "--vlan": style.hex } : undefined,
      };
    };
    const mid = () => {
      const e = edge();
      return e ? { x: (e.x1 + e.x2) / 2, y: (e.y1 + e.y2) / 2 } : { x: 0, y: 0 };
    };
    return (
      <>
        <Show
          when={edge()?.tree}
          fallback={<path {...attrs()} d={edge() ? curve(edge() as PlacedEdge) : ""} />}
        >
          <line {...attrs()} x1={edge()?.x1} y1={edge()?.y1} x2={edge()?.x2} y2={edge()?.y2} />
        </Show>
        <Show when={edge()?.inferred}>
          <text class="edge-mark" data-testid="topology-edge-inferred" x={mid().x} y={mid().y} text-anchor="middle" dominant-baseline="central">
            <title>{t("topology.edge.inferred")}</title>?
          </text>
        </Show>
      </>
    );
  };

  const NodeShape = (p: { id: string }) => {
    const placed = () => placedById().get(p.id);
    const info = () => props.nodes.get(p.id);
    const kind = () => info()?.kind ?? "device";
    const label = () => info()?.label ?? p.id;
    const selected = () => props.selected === p.id;
    return (
      <g
        ref={(el) => {
          elements.set(p.id, el);
          onCleanup(() => elements.delete(p.id));
        }}
        class={`topology-node kind-${kind()}`}
        classList={{ selected: selected(), "on-path": props.pathNodes.has(p.id), start: props.pathStart === p.id }}
        data-testid="topology-node"
        data-id={p.id}
        data-kind={kind()}
        data-selected={selected() ? "true" : undefined}
        data-path={props.pathNodes.has(p.id) ? "true" : undefined}
        data-path-start={props.pathStart === p.id ? "true" : undefined}
        role="button"
        aria-label={nodeAriaLabel({ label: label(), kind: kind() })}
        aria-current={selected() ? "true" : undefined}
        tabindex={tabbable() === p.id ? 0 : -1}
        transform={`translate(${placed()?.x ?? 0} ${placed()?.y ?? 0})`}
        onClick={() => props.onSelect(p.id)}
        onFocus={() => setFocusId(p.id)}
      >
        <title>{label()}</title>
        <path class="shape" d={SHAPES[kind()]} />
        <text class="label" y="30" text-anchor="middle">
          {shortLabel(label())}
        </text>
        <Show when={info() && nodeSecondLine(info() as TopologyNode)}>
          {(line) => (
            <text class="label sub" data-testid="topology-node-second" y="42" text-anchor="middle">
              {shortLabel(line(), 32)}
            </text>
          )}
        </Show>
      </g>
    );
  };

  const GroupShape = (p: { id: string }) => {
    const placed = () => placedById().get(p.id);
    const count = () => placed()?.members?.length ?? 0;
    const bucket = () => groupBucket(p.id);
    const text = () => {
      const b = bucket();
      return b === undefined ? t("topology.group.label", { count: count() }) : t("topology.group.bucket", { count: count(), bucket: shortLabel(b, 16) });
    };
    return (
      <g
        ref={(el) => {
          elements.set(p.id, el);
          onCleanup(() => elements.delete(p.id));
        }}
        class="topology-node topology-group"
        classList={{ "on-path": props.pathNodes.has(p.id) }}
        data-testid="topology-group"
        data-id={p.id}
        data-count={count()}
        data-path={props.pathNodes.has(p.id) ? "true" : undefined}
        role="button"
        data-bucket={bucket()}
        aria-label={bucket() === undefined ? t("topology.group.aria", { count: count() }) : t("topology.group.bucket_aria", { count: count(), bucket: bucket() ?? "" })}
        aria-expanded="false"
        tabindex={tabbable() === p.id ? 0 : -1}
        transform={`translate(${placed()?.x ?? 0} ${placed()?.y ?? 0})`}
        onClick={() => activate(p.id)}
        onFocus={() => setFocusId(p.id)}
      >
        <path class="shape" d={SHAPES.group} />
        <text class="count" y="0" text-anchor="middle" dominant-baseline="central">
          {text()}
        </text>
      </g>
    );
  };

  return (
    <div class="topology-canvas">
      <svg
        ref={svg}
        class="topology-svg"
        data-testid="topology-map"
        role="group"
        aria-label={t("topology.map.label")}
        onKeyDown={onKeyDown}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerEnd}
        onPointerCancel={onPointerEnd}
      >
        <g
          data-testid="topology-drawing"
          class="topology-drawing"
          classList={{ "has-path": props.pathNodes.size > 0 }}
          transform={transformOf(view())}
        >
          <g class="topology-edges">
            <For each={edgeIds()}>{(id) => <EdgeShape id={id} />}</For>
          </g>
          <g class="topology-nodes">
            <For each={nodeIds()}>{(id) => (isGroupId(id) ? <GroupShape id={id} /> : <NodeShape id={id} />)}</For>
          </g>
        </g>
      </svg>
      <div class="topology-zoom" role="group" aria-label={t("topology.zoom.label")}>
        <button type="button" class="icon-btn" data-testid="topology-zoom-in" aria-label={t("topology.zoom.in")} title={t("topology.zoom.in")} onClick={() => zoomBy(ZOOM_STEP)}>
          <Icon name="plus" />
        </button>
        <button type="button" class="icon-btn" data-testid="topology-zoom-out" aria-label={t("topology.zoom.out")} title={t("topology.zoom.out")} onClick={() => zoomBy(1 / ZOOM_STEP)}>
          <svg class="i" aria-hidden="true">
            <path d="M3.5 8h9" />
          </svg>
        </button>
        <button type="button" class="icon-btn" data-testid="topology-fit" aria-label={t("topology.zoom.fit")} title={t("topology.zoom.fit")} onClick={refit}>
          <Icon name="expand" />
        </button>
      </div>
    </div>
  );
}
