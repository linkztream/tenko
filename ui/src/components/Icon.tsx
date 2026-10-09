import { For } from "solid-js";
import { ICON_PATHS, type IconName } from "./icons";

export type { IconName } from "./icons";

/** One icon from the sprite. Decorative: give the surrounding control its accessible name. */
export function Icon(props: { name: IconName; size?: "sm" | "xs" | undefined; class?: string | undefined }) {
  const cls = () => ["i", props.size, props.class].filter(Boolean).join(" ");
  return (
    <svg class={cls()} aria-hidden="true">
      <use href={`#i-${props.name}`} />
    </svg>
  );
}

/** The sprite every <Icon> refers to. Rendered once at the root of the application. */
export function IconSprite() {
  const entries = Object.entries(ICON_PATHS) as [IconName, string][];
  return (
    <svg xmlns="http://www.w3.org/2000/svg" class="icon-sprite" aria-hidden="true">
      <For each={entries}>
        {([name, body]) => (
          // eslint-disable-next-line solid/no-innerhtml -- constant path data from icons.ts, never user input
          <symbol id={`i-${name}`} viewBox="0 0 16 16" innerHTML={body} />
        )}
      </For>
    </svg>
  );
}
