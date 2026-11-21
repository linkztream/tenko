// A "?" beside a heading: its text shows under the heading on hover and on keyboard focus, stays
// while the pointer is on it, and Esc hides it without closing a dialog around it. The button
// names it as its description for a screen reader.
import { createSignal, createUniqueId } from "solid-js";
import "./hint.css";

export function Hint(props: { label: string; text: string; testid?: string }) {
  const id = createUniqueId();
  const [off, setOff] = createSignal(false);
  return (
    <span
      class="hint"
      classList={{ "hint-off": off() }}
      onMouseEnter={() => setOff(false)}
      onFocusIn={() => setOff(false)}
      onKeyDown={(e) => {
        if (e.key !== "Escape" || off()) return;
        e.stopPropagation();
        setOff(true);
      }}
    >
      <button type="button" class="hint-btn" aria-label={props.label} aria-describedby={id} data-testid={props.testid}>
        ?
      </button>
      <span role="tooltip" id={id} class="hint-text">
        {props.text}
      </span>
    </span>
  );
}
