// One device, docked beside the map (/topology/<id>): what it is and what the sources know
// about it, its ports and what hangs on each, its neighbours, the host of intent with its
// addresses, links to the host page and the observations, and the path actions. The panel
// follows the `discovery` and `ipam` topics, so a change of the graph shows up at once.
import { A } from "@solidjs/router";
import { createResource, createSignal, createUniqueId, For, Match, Show, Switch } from "solid-js";
import { createLiveQuery } from "../api/live";
import { errorMessage } from "../api/problem";
import { paths } from "../app/paths";
import { Addr, Mac } from "../components/Addr";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { TimeAgo } from "../grid/cells";
import { formatList, t } from "../i18n";
import type { VlanStyle } from "../ipam/vlan/palette";
import { VlanChip } from "../ipam/vlan/VlanChip";
import { getNode, isNodeGone, type Neighbour, type TopologyNodeView, type TopologyPort } from "./api";
import { edgeWord, kindWord, portStateWord, portTitle, sourceWord } from "./model";

export interface NodePanelProps {
  id: string;
  /** Selects another device (a neighbour). */
  onSelect: (id: string) => void;
  onClose: () => void;
  /** The device that starts a path between two devices, when one was remembered. */
  pathStart: { id: string; label: string } | undefined;
  /** Whether the graph in view joins this device to a router. */
  routerReachable: boolean;
  /** Whether the graph in view joins the remembered start to this device. */
  startReachable: boolean;
  /** Whether a path is highlighted on the map now. */
  pathShown: boolean;
  onPathRouter: () => void;
  onPathStart: () => void;
  onPathShow: () => void;
  onPathClear: () => void;
  vlanStyle: (vid: number) => VlanStyle | undefined;
  /** The name of a VLAN in view. */
  vlanName: (vid: number) => string | undefined;
}

/** The ports, edge kind and wireless network of a link, in words. */
function linkText(n: Neighbour): string {
  const parts: string[] = [edgeWord(n.edge_kind)];
  if (n.port) parts.push(t("topology.neighbour.local", { port: n.port }));
  if (n.remote_port) parts.push(t("topology.neighbour.remote", { port: n.remote_port }));
  if (n.ssid) parts.push(t("topology.neighbour.ssid", { ssid: n.ssid }));
  return formatList(parts, "unit");
}

export function NodePanel(props: NodePanelProps) {
  const live = createLiveQuery<TopologyNodeView>({
    topics: ["discovery", "ipam"],
    fetch: async (signal) => {
      const view = await getNode(props.id, undefined, signal);
      return { value: view, revision: view.revision };
    },
  });
  const view = () => live.latest();

  // The port whose neighbours are listed: one more read, for that port only.
  const [openPort, setOpenPort] = createSignal<string | null>(null);
  const [portView] = createResource(
    () => {
      const port = openPort();
      return port === null ? false : { port, revision: view()?.revision };
    },
    ({ port }) => getNode(props.id, port),
  );
  const portNeighbours = (): Neighbour[] => portView()?.ports[0]?.neighbours ?? [];
  const listId = createUniqueId();

  const intentVlan = (vid: number | null | undefined) =>
    vid === null || vid === undefined ? undefined : { vid, name: props.vlanName(vid), style: props.vlanStyle(vid) };

  const NeighbourButton = (p: { neighbour: Neighbour; testid: string }) => (
    <li>
      <button
        type="button"
        class="neighbour"
        data-testid={p.testid}
        data-id={p.neighbour.node}
        data-edge={p.neighbour.edge}
        data-kind={p.neighbour.kind}
        onClick={() => props.onSelect(p.neighbour.node)}
      >
        <span class="neighbour-name">
          <strong>{p.neighbour.label}</strong>
          <span class="muted">{kindWord(p.neighbour.kind)}</span>
        </span>
        <span class="neighbour-link muted">{linkText(p.neighbour)}</span>
        <Show when={p.neighbour.vlan}>
          {(vid) => <VlanChip vid={vid()} name={props.vlanName(vid())} style={props.vlanStyle(vid())} />}
        </Show>
      </button>
    </li>
  );

  const PortItem = (p: { port: TopologyPort }) => {
    const open = () => openPort() === p.port.port;
    const count = () => p.port.neighbours.length;
    const vlan = () => intentVlan(p.port.native_vlan);
    return (
      <li class="topology-port" data-testid="node-port" data-key={p.port.port}>
        <div class="port-head">
          <span class="mono port-name">{portTitle(p.port)}</span>
          <Show when={p.port.uplink}>
            <span class="tag accent" data-testid="port-uplink">
              {t("topology.port.uplink")}
            </span>
          </Show>
          <Show when={vlan()}>
            {(v) => (
              <span class="port-vlan" data-testid="port-vlan" title={t("topology.port.vlan")}>
                <VlanChip vid={v().vid} name={v().name} style={v().style} />
              </span>
            )}
          </Show>
          <span class="port-state muted" data-testid="port-state" data-state={p.port.up === true ? "up" : p.port.up === false ? "down" : "unknown"}>
            {portStateWord(p.port.up)}
          </span>
          <span class="port-count muted" data-testid="port-count">
            {t("topology.port.count", { count: count() })}
          </span>
          <button
            type="button"
            class="btn sm"
            data-testid="node-port-open"
            aria-expanded={open()}
            aria-controls={`${listId}-${p.port.port}`}
            aria-label={open() ? t("topology.port.hide_aria", { port: p.port.port }) : t("topology.port.open_aria", { port: p.port.port })}
            disabled={count() === 0}
            onClick={() => setOpenPort(open() ? null : p.port.port)}
          >
            {open() ? t("topology.port.hide") : t("topology.port.open")}
          </button>
        </div>
        <Show when={open()}>
          <div id={`${listId}-${p.port.port}`} data-testid="port-neighbours" data-key={p.port.port}>
            <Switch>
              <Match when={portView.error}>
                <ErrorNotice error={portView.error} />
              </Match>
              <Match when={portView.loading && portView() === undefined}>
                <p class="muted" role="status">
                  {t("common.loading")}
                </p>
              </Match>
              <Match when={portNeighbours().length === 0}>
                <p class="muted">{t("topology.port.nothing")}</p>
              </Match>
              <Match when={true}>
                <ul class="neighbour-list" aria-label={t("topology.port.connected", { port: p.port.port })}>
                  <For each={portNeighbours()}>{(n) => <NeighbourButton neighbour={n} testid="port-neighbour" />}</For>
                </ul>
              </Match>
            </Switch>
          </div>
        </Show>
      </li>
    );
  };

  const routerReason = (kind: string): string | undefined =>
    kind === "router" ? t("topology.path.is_router") : props.routerReachable ? undefined : t("topology.path.none");
  const showReason = () => (props.startReachable ? undefined : t("topology.path.no_route"));

  return (
    <aside
      class="panel topology-panel"
      aria-label={t("topology.panel.label")}
      data-testid="node-panel"
      data-id={props.id}
      onKeyDown={(e) => {
        if (e.key === "Escape" && !document.querySelector("[aria-modal='true']")) {
          e.stopPropagation();
          props.onClose();
        }
      }}
    >
      <Show
        when={view()}
        fallback={
          <div class="panel-body section">
            <Switch>
              <Match when={live.value.error && isNodeGone(live.value.error)}>
                <Notice kind="warn" role="alert" testid="node-not-found">
                  {errorMessage(live.value.error)}
                </Notice>
              </Match>
              <Match when={live.value.error}>
                <ErrorNotice error={live.value.error} />
              </Match>
              <Match when={true}>
                <p class="muted" role="status">
                  {t("common.loading")}
                </p>
              </Match>
            </Switch>
            <div class="topology-actions">
              <button type="button" class="btn" data-testid="node-panel-back" onClick={() => props.onClose()}>
                {t("topology.panel.back")}
              </button>
              <Show when={live.value.error && !isNodeGone(live.value.error)}>
                <button type="button" class="btn" onClick={() => live.refetch()}>
                  {t("common.action.retry")}
                </button>
              </Show>
            </div>
          </div>
        }
      >
        {(v) => {
          const node = () => v().node;
          const sources = () => [...new Set(node().sources.map(sourceWord))];
          return (
            <>
              <div class="panel-head">
                <div class="grow">
                  <div class="topology-badges">
                    <span class="tag" data-testid="node-kind" data-kind={node().kind}>
                      {kindWord(node().kind)}
                    </span>
                  </div>
                  <h2 data-testid="node-label">{node().label}</h2>
                  <div class="meta mono">{node().id}</div>
                </div>
                <div class="acts">
                  <button type="button" class="icon-btn" data-testid="node-panel-close" aria-label={t("common.action.close")} title={t("common.action.close")} onClick={() => props.onClose()}>
                    <Icon name="x" />
                  </button>
                </div>
              </div>
              <div class="panel-body">
                <section class="section" aria-labelledby={`${listId}-paths`}>
                  <h3 id={`${listId}-paths`}>{t("topology.panel.paths")}</h3>
                  <div class="topology-actions">
                    <button
                      type="button"
                      class="btn"
                      data-testid="node-path-router"
                      disabled={routerReason(node().kind) !== undefined}
                      aria-describedby={routerReason(node().kind) ? `${listId}-router-reason` : undefined}
                      onClick={() => props.onPathRouter()}
                    >
                      <Icon name="router" />
                      {t("topology.path.router")}
                    </button>
                    <button
                      type="button"
                      class="btn"
                      data-testid="node-path-from"
                      aria-pressed={props.pathStart?.id === node().id}
                      onClick={() => props.onPathStart()}
                    >
                      <Icon name="pin" />
                      {t("topology.path.from")}
                    </button>
                    <Show when={props.pathStart && props.pathStart.id !== node().id}>
                      <button
                        type="button"
                        class="btn"
                        data-testid="node-path-show"
                        disabled={showReason() !== undefined}
                        aria-describedby={showReason() ? `${listId}-show-reason` : undefined}
                        onClick={() => props.onPathShow()}
                      >
                        <Icon name="arrow-r" />
                        {t("topology.path.show")}
                      </button>
                    </Show>
                    <Show when={props.pathStart || props.pathShown}>
                      <button type="button" class="btn ghost" data-testid="node-path-clear" onClick={() => props.onPathClear()}>
                        <Icon name="x" />
                        {t("topology.path.clear")}
                      </button>
                    </Show>
                  </div>
                  <Show when={routerReason(node().kind)}>
                    {(reason) => (
                      <p class="muted topology-reason" id={`${listId}-router-reason`} data-testid="node-path-router-reason">
                        {reason()}
                      </p>
                    )}
                  </Show>
                  <Show when={props.pathStart}>
                    {(start) => (
                      <p class="muted topology-reason" data-testid="node-path-start">
                        {start().id === node().id ? t("topology.path.start_here") : t("topology.path.start", { label: start().label })}
                      </p>
                    )}
                  </Show>
                  <Show when={props.pathStart && props.pathStart.id !== node().id && showReason()}>
                    {(reason) => (
                      <p class="muted topology-reason" id={`${listId}-show-reason`} data-testid="node-path-show-reason">
                        {reason()}
                      </p>
                    )}
                  </Show>
                </section>

                <section class="section" aria-labelledby={`${listId}-details`}>
                  <h3 id={`${listId}-details`}>{t("topology.panel.details")}</h3>
                  <dl class="kv">
                    <Show when={(node().ips?.length ?? 0) > 0}>
                      <dt>{t("topology.panel.ips")}</dt>
                      <dd class="value-list" data-testid="node-ips">
                        <For each={node().ips ?? []}>{(ip) => <Addr value={ip} />}</For>
                      </dd>
                    </Show>
                    <Show when={(node().macs?.length ?? 0) > 0}>
                      <dt>{t("topology.panel.macs")}</dt>
                      <dd class="value-list" data-testid="node-macs">
                        <For each={node().macs ?? []}>{(mac) => <Mac value={mac} />}</For>
                      </dd>
                    </Show>
                    <Show when={node().vendor}>
                      {(vendor) => (
                        <>
                          <dt>{t("topology.panel.vendor")}</dt>
                          <dd data-testid="node-vendor">{vendor()}</dd>
                        </>
                      )}
                    </Show>
                    <Show when={node().model}>
                      {(model) => (
                        <>
                          <dt>{t("topology.panel.model")}</dt>
                          <dd data-testid="node-model">{model()}</dd>
                        </>
                      )}
                    </Show>
                    <Show when={node().os}>
                      {(os) => (
                        <>
                          <dt>{t("topology.panel.os")}</dt>
                          <dd data-testid="node-os">{os()}</dd>
                        </>
                      )}
                    </Show>
                    <Show when={(node().vlans?.length ?? 0) > 0}>
                      <dt>{t("topology.panel.vlans")}</dt>
                      <dd class="value-list" data-testid="node-vlans">
                        <For each={node().vlans ?? []}>
                          {(vid) => <VlanChip vid={vid} name={props.vlanName(vid)} style={props.vlanStyle(vid)} />}
                        </For>
                      </dd>
                    </Show>
                    <Show when={(node().ssids?.length ?? 0) > 0}>
                      <dt>{t("topology.panel.ssids")}</dt>
                      <dd data-testid="node-ssids">{formatList(node().ssids ?? [], "unit")}</dd>
                    </Show>
                    <dt>{t("topology.panel.sources")}</dt>
                    <dd data-testid="node-sources">{formatList(sources(), "unit")}</dd>
                    <Show when={node().last_seen}>
                      <dt>{t("topology.panel.last_seen")}</dt>
                      <dd data-testid="node-last-seen">
                        <TimeAgo at={node().last_seen} />
                      </dd>
                    </Show>
                  </dl>
                  <div class="topology-actions topology-links">
                    <Show when={v().intent}>
                      {(intent) => (
                        <A class="btn sm" href={paths.host(intent().name)} data-testid="node-host-link">
                          <Icon name="ext" />
                          {t("topology.panel.host_link")}
                        </A>
                      )}
                    </Show>
                    <Show when={node().subject}>
                      {(subject) => (
                        <A class="btn sm" href={paths.observation(subject())} data-testid="node-observation-link">
                          <Icon name="eye" />
                          {t("topology.panel.observation_link")}
                        </A>
                      )}
                    </Show>
                  </div>
                </section>

                <section class="section" aria-labelledby={`${listId}-intent`} data-testid="node-intent">
                  <h3 id={`${listId}-intent`}>{t("topology.panel.intent")}</h3>
                  <Show when={v().intent} fallback={<p class="muted">{t("topology.panel.intent_none")}</p>}>
                    {(intent) => (
                      <>
                        <p>
                          <strong>{intent().name}</strong>
                        </p>
                        <Show
                          when={intent().addresses.length > 0}
                          fallback={<p class="muted">{t("topology.panel.intent_no_addresses")}</p>}
                        >
                          <ul class="intent-list" aria-label={t("topology.panel.intent_addresses")}>
                            <For each={intent().addresses}>
                              {(a) => (
                                <li data-testid="intent-address" data-key={a.ip}>
                                  <Addr value={a.ip} />
                                  <span class="muted">
                                    <Addr value={a.cidr} />
                                  </span>
                                  <Show when={a.vid}>
                                    {(vid) => <VlanChip vid={vid()} name={props.vlanName(vid())} style={props.vlanStyle(vid())} />}
                                  </Show>
                                </li>
                              )}
                            </For>
                          </ul>
                        </Show>
                      </>
                    )}
                  </Show>
                </section>

                <section class="section" aria-labelledby={`${listId}-ports`}>
                  <h3 id={`${listId}-ports`}>
                    {t("topology.panel.ports")}
                    <span class="more muted">{v().ports.length}</span>
                  </h3>
                  <Show when={v().ports.length > 0} fallback={<p class="muted">{t("topology.panel.ports_none")}</p>}>
                    <ul class="port-list" data-testid="node-ports" aria-label={t("topology.panel.ports")}>
                      <For each={v().ports}>{(port) => <PortItem port={port} />}</For>
                    </ul>
                  </Show>
                </section>

                <section class="section" aria-labelledby={`${listId}-neighbours`}>
                  <h3 id={`${listId}-neighbours`}>
                    {t("topology.panel.neighbours")}
                    <span class="more muted">{v().neighbours.length}</span>
                  </h3>
                  <Show when={v().neighbours.length > 0} fallback={<p class="muted">{t("topology.panel.neighbours_none")}</p>}>
                    <ul class="neighbour-list" data-testid="node-neighbours" aria-label={t("topology.panel.neighbours")}>
                      <For each={v().neighbours}>{(n) => <NeighbourButton neighbour={n} testid="neighbour" />}</For>
                    </ul>
                  </Show>
                </section>
              </div>
            </>
          );
        }}
      </Show>
    </aside>
  );
}
