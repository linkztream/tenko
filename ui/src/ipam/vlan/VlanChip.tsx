import { Show } from "solid-js";
import type { VlanStyle } from "./palette";
import "./vlan.css";

/**
 * A VLAN: swatch, id and optional name. The swatch takes its color from `style` (see
 * `assignVlanStyles`) and its shape from the `vlan-shape-*` class; the id is always text, so
 * color and shape are never the only cue. Without `style` the swatch keeps the default gray.
 */
export function VlanChip(props: { vid: number; name?: string | null; style?: VlanStyle | undefined; class?: string }) {
  const cls = () => {
    let out = "vlan";
    if (props.style) out += ` vlan-shape-${props.style.shape}`;
    if (props.class) out += ` ${props.class}`;
    return out;
  };
  return (
    <span class={cls()} data-vid={props.vid} style={props.style ? { "--vlan": props.style.hex } : undefined}>
      <span class="id">{props.vid}</span>
      <Show when={props.name}>
        <span class="name">{props.name}</span>
      </Show>
    </span>
  );
}
