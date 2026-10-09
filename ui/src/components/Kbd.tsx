import { For } from "solid-js";

/** Key caps, for example `<Kbd keys={["Ctrl", "K"]} />`. Key names are not translated. */
export function Kbd(props: { keys: readonly string[] }) {
  return (
    <For each={props.keys}>
      {(k) => <span class="kbd">{k}</span>}
    </For>
  );
}
