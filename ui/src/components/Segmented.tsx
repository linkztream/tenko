import { For } from "solid-js";

export interface SegmentOption<T extends string> {
  value: T;
  label: string;
}

/** A segmented control: one choice of a few, each a pressed or unpressed button. */
export function Segmented<T extends string>(props: {
  label: string;
  value: T;
  options: readonly SegmentOption<T>[];
  onChange: (value: T) => void;
}) {
  return (
    <div class="seg" role="group" aria-label={props.label}>
      <For each={props.options}>
        {(o) => (
          <button type="button" aria-pressed={o.value === props.value} onClick={() => props.onChange(o.value)}>
            {o.label}
          </button>
        )}
      </For>
    </div>
  );
}
