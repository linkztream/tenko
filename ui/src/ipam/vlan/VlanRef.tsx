// A VLAN chip for a VLAN id of the API, resolved through the VLANs of the view.
import { Show } from "solid-js";
import type { VlanStyle } from "./palette";
import { VlanChip } from "./VlanChip";

export type VlanLookup = (id: string) => { vid: number; name: string; style?: VlanStyle | undefined } | undefined;

export function VlanRef(props: { id?: string | null | undefined; vlanOf: VlanLookup; withName?: boolean }) {
  const vlan = () => (props.id ? props.vlanOf(props.id) : undefined);
  return (
    <Show when={vlan()}>
      {(v) => <VlanChip vid={v().vid} name={props.withName === false ? undefined : v().name} style={v().style} />}
    </Show>
  );
}
