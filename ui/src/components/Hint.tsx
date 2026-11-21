// A "?" beside a heading: its text shows on hover and on keyboard focus, and the button names
// it as its description for a screen reader.
import { createUniqueId } from "solid-js";
import "./hint.css";

export function Hint(props: { label: string; text: string; testid?: string }) {
  const id = createUniqueId();
  return (
    <span class="hint">
      <button type="button" class="hint-btn" aria-label={props.label} aria-describedby={id} data-testid={props.testid}>
        ?
      </button>
      <span role="tooltip" id={id} class="hint-text">
        {props.text}
      </span>
    </span>
  );
}
