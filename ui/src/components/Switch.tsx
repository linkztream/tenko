import type { JSX } from "solid-js";

/** A toggle switch with its label (design.css `.switch`). */
export function Switch(props: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: JSX.Element;
  hint?: JSX.Element;
  disabled?: boolean;
  id?: string;
}) {
  return (
    <label class={props.hint ? "pref switch" : "switch"}>
      <span>{props.label}</span>
      <input
        id={props.id}
        type="checkbox"
        role="switch"
        checked={props.checked}
        disabled={props.disabled}
        onChange={(e) => props.onChange(e.currentTarget.checked)}
      />
      {props.hint ? <small>{props.hint}</small> : null}
    </label>
  );
}
