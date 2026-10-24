// The networks the network controllers report (TopologySummary.networks): name, VLAN, subnet,
// what the controller does for DHCP and whether Tenko or the controller is reached through
// the network. Shown under the controller lines of the map and in the panel of a controller's
// gateway; the reconciler turns the same networks into VLAN proposals (docs/topology.md).
import { For, Show } from "solid-js";
import { Addr } from "../components/Addr";
import { t } from "../i18n";
import type { VlanStyle } from "../ipam/vlan/palette";
import { VlanChip } from "../ipam/vlan/VlanChip";
import type { NetworkDhcp, NetworkInView } from "./api";

/** What the controller does for DHCP on a network, in words. */
export function dhcpWord(dhcp: NetworkDhcp): string {
  return t(`topology.networks.dhcp.${dhcp}`);
}

export function NetworkList(props: {
  networks: readonly NetworkInView[];
  vlanStyle: (vid: number) => VlanStyle | undefined;
  /** The name of the controller of a network, shown when the list mixes controllers. */
  controllerName?: ((connector: string) => string | undefined) | undefined;
  testid?: string;
}) {
  return (
    <Show when={props.networks.length > 0} fallback={<p class="muted">{t("topology.networks.none")}</p>}>
      <ul class="topology-networks" data-testid={props.testid ?? "network-list"} aria-label={t("topology.networks.title")}>
        <For each={props.networks}>
          {(n) => (
            <li class="topology-network" data-testid="controller-network" data-key={n.id} data-vlan={n.vlan ?? ""}>
              <strong class="network-name">{n.name}</strong>
              <Show when={n.vlan} fallback={<span class="muted">{t("topology.networks.untagged")}</span>}>
                {(vid) => <VlanChip vid={vid()} style={props.vlanStyle(vid())} />}
              </Show>
              <Show when={n.subnet} fallback={<span class="muted">{t("topology.networks.no_subnet")}</span>}>
                {(subnet) => <Addr value={subnet()} />}
              </Show>
              <Show when={n.dhcp}>
                {(dhcp) => (
                  <span class="tag" data-testid="network-dhcp" data-dhcp={dhcp()}>
                    {dhcpWord(dhcp())}
                  </span>
                )}
              </Show>
              <Show when={n.management}>
                <span class="tag accent" data-testid="network-management">
                  {t("topology.networks.management")}
                </span>
              </Show>
              <Show when={props.controllerName}>
                {(name) => <span class="muted">{name()(n.connector) ?? n.connector.slice(0, 8)}</span>}
              </Show>
            </li>
          )}
        </For>
      </ul>
    </Show>
  );
}
