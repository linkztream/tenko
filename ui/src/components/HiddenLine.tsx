// The Hidden line (design/README.md, component inventory, decision 20): one line at the foot of
// a view that names what it does not draw and why ("host CPU and memory (not read on this
// host)"), so an empty block is never drawn and nothing disappears without a word. The toggle
// draws the hidden things for the session; it is a real button with its pressed state. Without
// anything hidden and with the toggle off the line is not drawn.
//
// Test ids: `hidden-line` (`data-count` the number of items), `hidden-line-item` per item with
// `data-item` (its key), `hidden-line-toggle`.
import { For, Show } from "solid-js";
import { Icon } from "./Icon";
import "./hidden-line.css";

export interface HiddenItem {
  /** A stable key, for tests. */
  key: string;
  /** What is not drawn and why, in words. */
  text: string;
}

export function HiddenLine(props: {
  /** "Hidden:" in the language of the UI. */
  label: string;
  items: readonly HiddenItem[];
  /** The toggle's text while it is off and while it is on. */
  show: string;
  hide: string;
  shown: boolean;
  onToggle: (shown: boolean) => void;
}) {
  return (
    <Show when={props.items.length > 0 || props.shown}>
      <div class="hidden-line" data-testid="hidden-line" data-count={props.items.length}>
        <Icon name="eye" size="sm" />
        <Show when={props.items.length > 0}>
          <p>
            <span class="hidden-line-label">{props.label}</span>{" "}
            <For each={props.items}>
              {(item, i) => (
                <>
                  {i() > 0 ? " · " : ""}
                  <span data-testid="hidden-line-item" data-item={item.key}>
                    {item.text}
                  </span>
                </>
              )}
            </For>
          </p>
        </Show>
        <button
          type="button"
          class="btn sm"
          aria-pressed={props.shown}
          data-testid="hidden-line-toggle"
          onClick={() => props.onToggle(!props.shown)}
        >
          {props.shown ? props.hide : props.show}
        </button>
      </div>
    </Show>
  );
}
