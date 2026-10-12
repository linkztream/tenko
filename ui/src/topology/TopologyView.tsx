// The topology map (/topology, /topology/<id>): the network drawn as a graph (docs/topology.md,
// section 6). The server computes the graph and filters it (site, VLAN, kinds, text); this view
// lays it out in the browser, draws it, follows live changes of observations and intent, and
// docks the panel of the selected device beside it.
//
// Filters and the selected device live in the URL, so a filtered map is a link that can be
// shared: `/topology/<id>?site=...&vlan=30&kind=router,switch&q=...`.
import { A, useLocation, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createResource, createSignal, For, Match, on, onCleanup, onMount, Show, Switch } from "solid-js";
import { createLiveQuery, latest } from "../api/live";
import { decodeSegment, paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { TimeAgo } from "../grid/cells";
import { t, tDynamic } from "../i18n";
import { createVlanStyles } from "../ipam/vlan/palette";
import { VlanChip } from "../ipam/vlan/VlanChip";
import { isTyping } from "../shell/keyboard";
import { getTopology, listSites, listVlans, type ControllerStatus, type TopologyEdge, type TopologyGraph, type TopologyNode } from "./api";
import { layout as computeLayout, type LayoutEdge, type LayoutNode } from "./layout";
import {
  EDGE_KINDS,
  edgeClass,
  edgeWord,
  filterKey,
  filterParams,
  groupParent,
  isFiltered,
  kindIcon,
  kindWord,
  NODE_KINDS,
  parseFilter,
  SHAPES,
  toggleKind,
  topologyPath,
  VLAN_COLOR_LIMIT,
  vlanColorIds,
} from "./model";
import { NodePanel } from "./NodePanel";
import { edgesOnPath, pathToRouter, placedPath, shortestPath } from "./path";
import { TopologyMap } from "./TopologyMap";
import "./topology.css";

/** A graph with the key of the filter it answers. */
interface Loaded {
  graph: TopologyGraph;
  key: string;
}

/** The path on the map: from a device to the nearest router, or between two devices. */
interface ShownPath {
  from: string;
  to?: string;
}

/** How long typing in the search field pauses before the filter is applied. */
const TYPING_PAUSE_MS = 300;

const NO_IDS: ReadonlySet<string> = new Set();

/** The controller status line: the devices it read and when, or why the read failed. */
function ControllerLine(props: { controller: ControllerStatus }) {
  const failure = () => {
    const err = props.controller.error;
    if (!err) return undefined;
    return tDynamic(`errors.${err.code}`, err.params) ?? t("topology.controller.error_generic", { code: err.code });
  };
  return (
    <li
      class="topology-controller"
      data-testid="topology-controller"
      data-id={props.controller.connector}
      data-state={props.controller.error ? "error" : "ok"}
    >
      <Icon name={props.controller.error ? "alert" : "check"} size="xs" />
      <strong>{props.controller.name}</strong>
      <Show
        when={failure()}
        fallback={
          <span class="muted">
            {t("topology.controller.ok", { count: props.controller.devices })}
            <Show when={props.controller.observed_at}>
              {" "}
              <TimeAgo at={props.controller.observed_at} />
            </Show>
          </span>
        }
      >
        {(text) => <span class="topology-controller-error">{text()}</span>}
      </Show>
    </li>
  );
}

export default function TopologyView() {
  const params = useParams<{ id?: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const [search, setSearch] = useSearchParams();

  const selectedId = createMemo(() => (params.id ? decodeSegment(params.id) : undefined));
  const filter = createMemo(() => parseFilter(search), undefined, { equals: (a, b) => filterKey(a) === filterKey(b) });

  // ----- the search field: typed here, applied to the URL after a pause

  let input!: HTMLInputElement;
  const [text, setText] = createSignal(filter().q);
  let typing: ReturnType<typeof setTimeout> | undefined;
  const onText = (value: string) => {
    setText(value);
    clearTimeout(typing);
    typing = setTimeout(() => setSearch({ q: value.trim() || undefined }, { replace: true }), TYPING_PAUSE_MS);
  };
  onCleanup(() => clearTimeout(typing));
  // A text that changes in the URL (a cleared filter, a pasted link) shows in the field. The
  // field itself is only overwritten when the URL text changes, never while a pause is pending.
  const urlText = createMemo(() => filter().q);
  createEffect(
    on(
      urlText,
      (q) => {
        if (q !== text().trim()) setText(q);
      },
      { defer: true },
    ),
  );
  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented || isTyping(e)) return;
      if (document.querySelector("[aria-modal='true']")) return;
      e.preventDefault();
      input.focus();
      input.select();
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  // ----- the graph

  const live = createLiveQuery<Loaded>({
    topics: ["discovery", "ipam"],
    fetch: async (signal) => {
      const f = filter();
      const graph = await getTopology(f, signal);
      return { value: { graph, key: filterKey(f) }, revision: graph.revision };
    },
  });
  createEffect(on(() => filterKey(filter()), () => live.refetch(), { defer: true }));

  const loaded = () => live.latest();
  const graph = () => loaded()?.graph;
  const summary = () => graph()?.summary;
  const nodes = createMemo<TopologyNode[]>(() => graph()?.nodes ?? []);
  const edges = createMemo<TopologyEdge[]>(() => graph()?.edges ?? []);
  const nodeMap = createMemo(() => new Map(nodes().map((n) => [n.id, n])));
  const edgeMap = createMemo(() => new Map(edges().map((e) => [e.id, e])));

  const layoutNodes = createMemo<LayoutNode[]>(() => nodes().map((n) => ({ id: n.id, kind: n.kind, label: n.label })));
  const layoutEdges = createMemo<LayoutEdge[]>(() => edges().map((e) => ({ id: e.id, kind: e.kind, a: e.a, b: e.b })));

  // The groups of hidden devices the person opened (by parent id).
  const [expanded, setExpanded] = createSignal<ReadonlySet<string>>(new Set());
  const openGroup = (parent: string) => setExpanded((prev) => new Set(prev).add(parent));
  const lay = createMemo(() => computeLayout(layoutNodes(), layoutEdges(), { expanded: expanded() }));

  // A device chosen by a link or from the panel that sits in a closed group opens the group.
  let revealed: string | undefined;
  createEffect(() => {
    const id = selectedId();
    const l = lay();
    if (id === undefined) {
      revealed = undefined;
      return;
    }
    if (revealed === id || !l.position.has(id)) return;
    revealed = id;
    const group = l.hidden.get(id);
    if (group !== undefined) openGroup(groupParent(group));
  });

  // ----- sites, VLANs and their colors

  const [sites] = createResource(async () => {
    try {
      return await listSites();
    } catch {
      return [];
    }
  });
  const [ipamVlans] = createResource(async () => {
    try {
      return await listVlans();
    } catch {
      return [];
    }
  });

  const vlansInView = () => summary()?.vlans ?? [];
  const styles = createVlanStyles(() => vlanColorIds(vlansInView(), filter().vlan));
  const vlanStyle = (vid: number) => styles().get(vid);
  // With many VLANs in view only the colored ones are listed in the legend.
  const manyVlans = () => vlansInView().length >= VLAN_COLOR_LIMIT;
  const legendVlans = () => (manyVlans() ? vlansInView().filter((v) => styles().has(v.vid)) : vlansInView());
  const vlanNames = createMemo(() => {
    const names = new Map<number, string>();
    for (const v of latest(ipamVlans) ?? []) names.set(v.vid, v.name);
    for (const v of vlansInView()) if (v.name) names.set(v.vid, v.name);
    return names;
  });
  const vlanName = (vid: number) => vlanNames().get(vid);

  const siteOptions = createMemo(() => {
    const list = [...(latest(sites) ?? [])].sort((a, b) => a.name.localeCompare(b.name));
    const options = list.map((s) => ({ value: s.id, label: s.name }));
    const current = filter().site;
    if (current && !options.some((o) => o.value === current)) {
      options.push({ value: current, label: t("topology.filter.unknown_site", { id: current.slice(0, 8) }) });
    }
    return options;
  });
  const vlanOptions = createMemo(() => {
    const vids = new Set<number>([...(latest(ipamVlans) ?? []).map((v) => v.vid), ...vlansInView().map((v) => v.vid)]);
    const options = [...vids].sort((a, b) => a - b).map((vid) => ({ value: String(vid), label: `${vid} ${vlanNames().get(vid) ?? ""}`.trim() }));
    const current = filter().vlan;
    if (current && !options.some((o) => o.value === current)) {
      options.push({ value: current, label: t("topology.filter.unknown_vlan", { id: current.slice(0, 8) }) });
    }
    return options;
  });

  // ----- selection, paths

  const withSearch = (id?: string) => topologyPath(id, location.search);
  const select = (id: string) => navigate(withSearch(id));
  const clearSelection = () => {
    if (selectedId() !== undefined) navigate(withSearch());
  };

  const [pathStart, setPathStart] = createSignal<string | undefined>();
  const [shown, setShown] = createSignal<ShownPath | null>(null);
  // A highlighted path belongs to the device it was asked for.
  createEffect(on(selectedId, () => setShown(null), { defer: true }));

  const pathIds = createMemo(() => {
    const s = shown();
    if (!s) return null;
    return s.to === undefined ? pathToRouter(layoutNodes(), layoutEdges(), s.from) : shortestPath(layoutEdges(), s.from, s.to);
  });
  const pathNodes = createMemo<ReadonlySet<string>>(() => {
    const ids = pathIds();
    return ids ? new Set(placedPath(ids, lay().hidden)) : NO_IDS;
  });
  const pathEdges = createMemo<ReadonlySet<string>>(() => {
    const ids = pathIds();
    return ids ? edgesOnPath(layoutEdges(), ids) : NO_IDS;
  });
  const startLabel = () => {
    const id = pathStart();
    return id === undefined ? undefined : { id, label: nodeMap().get(id)?.label ?? id };
  };

  // ----- filter actions

  const setFilter = (change: Parameters<typeof filterParams>[0]) => setSearch(filterParams(change));
  const clearFilters = () => {
    clearTimeout(typing);
    setText("");
    setSearch({ site: undefined, vlan: undefined, kind: undefined, q: undefined });
  };

  const filtered = () => isFiltered(filter());

  return (
    <div class="page topology-page" data-testid="page-topology">
      <PageHead
        title={t("shell.nav.topology")}
        actions={
          <Show when={expanded().size > 0}>
            <button type="button" class="btn" data-testid="topology-groups-close" onClick={() => setExpanded(new Set())}>
              <Icon name="layers" />
              {t("topology.group.close_all")}
            </button>
          </Show>
        }
      />
      <div class="filterbar" role="toolbar" aria-label={t("topology.filter.label")} data-testid="filterbar">
        <label class="query">
          <Icon name="search" size="sm" />
          <input
            ref={input}
            value={text()}
            placeholder={t("topology.filter.placeholder")}
            aria-label={t("topology.filter.label")}
            spellcheck={false}
            autocomplete="off"
            data-testid="filter-input"
            onInput={(e) => onText(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape" && text() !== "") {
                e.preventDefault();
                e.stopPropagation();
                onText("");
              }
            }}
          />
          <span class="kbd">/</span>
        </label>
        <select
          class="select"
          aria-label={t("topology.filter.site")}
          data-testid="filter-site"
          onChange={(e) => setFilter({ ...filter(), site: e.currentTarget.value || undefined })}
        >
          <option value="" selected={!filter().site}>
            {t("topology.filter.site_all")}
          </option>
          <For each={siteOptions()}>
            {(o) => (
              <option value={o.value} selected={filter().site === o.value}>
                {o.label}
              </option>
            )}
          </For>
        </select>
        <select
          class="select"
          aria-label={t("topology.filter.vlan")}
          data-testid="filter-vlan"
          onChange={(e) => setFilter({ ...filter(), vlan: e.currentTarget.value || undefined })}
        >
          <option value="" selected={!filter().vlan}>
            {t("topology.filter.vlan_all")}
          </option>
          <For each={vlanOptions()}>
            {(o) => (
              <option value={o.value} selected={filter().vlan === o.value}>
                {o.label}
              </option>
            )}
          </For>
        </select>
        <span class="divider" />
        <For each={NODE_KINDS}>
          {(kind) => (
            <button
              type="button"
              class="chip"
              aria-pressed={filter().kinds.includes(kind)}
              data-testid={`filter-kind-${kind}`}
              onClick={() => setFilter({ ...filter(), kinds: toggleKind(filter().kinds, kind) })}
            >
              <Icon name={kindIcon(kind)} />
              {kindWord(kind)}
            </button>
          )}
        </For>
        <Show when={filtered()}>
          <button type="button" class="btn ghost sm" data-testid="filter-clear" onClick={clearFilters}>
            <Icon name="x" />
            {t("topology.filter.clear")}
          </button>
        </Show>
      </div>

      <Show when={summary()}>
        {(s) => (
          <div class="topology-status">
            <p class="topology-summary" role="status" data-testid="topology-summary">
              {t("topology.summary", { nodes: s().nodes, total_nodes: s().total_nodes, edges: s().edges, total_edges: s().total_edges })}
            </p>
            <Show when={s().truncated}>
              <Notice kind="warn" testid="topology-truncated">
                {t("topology.truncated")}
              </Notice>
            </Show>
            <Show when={s().controllers.length > 0}>
              <ul class="topology-controllers" aria-label={t("topology.controller.label")}>
                <For each={s().controllers}>{(c) => <ControllerLine controller={c} />}</For>
              </ul>
            </Show>
          </div>
        )}
      </Show>

      <div class="topology-split" classList={{ "with-panel": selectedId() !== undefined }}>
        <div class="topology-main">
          <Switch>
            <Match when={live.value.error}>
              <div class="topology-state" data-testid="topology-error">
                <ErrorNotice error={live.value.error} />
                <button type="button" class="btn" data-testid="topology-retry" onClick={() => live.refetch()}>
                  <Icon name="refresh" />
                  {t("common.action.retry")}
                </button>
              </div>
            </Match>
            <Match when={graph() === undefined}>
              <p class="topology-state muted" role="status" data-testid="topology-loading">
                {t("topology.loading")}
              </p>
            </Match>
            <Match when={nodes().length === 0}>
              <div class="empty" data-testid="topology-empty">
                <Show
                  when={filtered()}
                  fallback={
                    <>
                      <h2>{t("topology.empty.title")}</h2>
                      <p>{t("topology.empty.body")}</p>
                      <A class="btn" href={paths.connectors()}>
                        <Icon name="ext" />
                        {t("topology.empty.link")}
                      </A>
                    </>
                  }
                >
                  <h2>{t("topology.empty.filtered")}</h2>
                  <p>{t("topology.empty.filtered_hint")}</p>
                </Show>
              </div>
            </Match>
            <Match when={true}>
              <TopologyMap
                layout={lay()}
                nodes={nodeMap()}
                edges={edgeMap()}
                selected={selectedId()}
                pathStart={pathStart()}
                pathNodes={pathNodes()}
                pathEdges={pathEdges()}
                vlanStyle={vlanStyle}
                fitKey={loaded()?.key ?? ""}
                onSelect={select}
                onClear={clearSelection}
                onOpenGroup={openGroup}
              />
              <section class="topology-legend" aria-label={t("topology.legend.label")} data-testid="topology-legend">
                <div class="legend-block">
                  <h2>{t("topology.legend.vlans")}</h2>
                  <Show when={vlansInView().length > 0} fallback={<span class="muted">{t("topology.legend.vlans_none")}</span>}>
                    <ul class="legend-list">
                      <For each={legendVlans()}>
                        {(v) => (
                          <li data-testid="legend-vlan" data-vid={v.vid}>
                            <VlanChip vid={v.vid} name={v.name ?? vlanName(v.vid)} style={vlanStyle(v.vid)} />
                          </li>
                        )}
                      </For>
                    </ul>
                    <Show when={manyVlans()}>
                      <span class="muted" data-testid="legend-vlans-neutral">
                        {t("topology.legend.too_many", { count: vlansInView().length })}
                      </span>
                    </Show>
                  </Show>
                </div>
                <div class="legend-block">
                  <h2>{t("topology.legend.edges")}</h2>
                  <ul class="legend-list">
                    <For each={EDGE_KINDS.filter((k) => (summary()?.by_edge_kind[k] ?? 0) > 0)}>
                      {(kind) => (
                        <li data-testid="legend-edge" data-kind={kind}>
                          <svg class="legend-sample" viewBox="0 0 40 8" aria-hidden="true">
                            <line class={edgeClass(kind)} x1="2" y1="4" x2="38" y2="4" />
                          </svg>
                          {edgeWord(kind)}
                        </li>
                      )}
                    </For>
                  </ul>
                </div>
                <div class="legend-block">
                  <h2>{t("topology.legend.kinds")}</h2>
                  <ul class="legend-list">
                    <For each={NODE_KINDS.filter((k) => (summary()?.by_kind[k] ?? 0) > 0)}>
                      {(kind) => (
                        <li data-testid="legend-kind" data-kind={kind}>
                          <svg class="legend-sample shape-sample" viewBox="-22 -16 44 32" aria-hidden="true">
                            <path class="legend-shape" d={SHAPES[kind]} />
                          </svg>
                          {kindWord(kind)}
                        </li>
                      )}
                    </For>
                  </ul>
                </div>
              </section>
            </Match>
          </Switch>
        </div>
        <Show when={selectedId()} keyed>
          {(id) => {
            const routerReachable = createMemo(() => pathToRouter(layoutNodes(), layoutEdges(), id) !== null);
            const startReachable = createMemo(() => {
              const start = pathStart();
              return start !== undefined && shortestPath(layoutEdges(), start, id) !== null;
            });
            return (
              <NodePanel
                id={id}
                onSelect={select}
                onClose={clearSelection}
                pathStart={startLabel()}
                routerReachable={routerReachable()}
                startReachable={startReachable()}
                pathShown={shown() !== null}
                onPathRouter={() => setShown({ from: id })}
                onPathStart={() => setPathStart(id)}
                onPathShow={() => {
                  const start = pathStart();
                  if (start !== undefined) setShown({ from: start, to: id });
                }}
                onPathClear={() => {
                  setShown(null);
                  setPathStart(undefined);
                }}
                vlanStyle={vlanStyle}
                vlanName={vlanName}
              />
            );
          }}
        </Show>
      </div>
    </div>
  );
}
