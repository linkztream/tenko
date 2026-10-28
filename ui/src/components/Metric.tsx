// The metric block (design/README.md, component inventory): a label (12 px, --ink-3), the value
// (24 px, an SI number that never grows its block), its unit and one line of context. A block
// with a destination is a real link, so the whole block takes the focus and opens it; without
// one it is plain text. `tone="act"` draws the context line in the color of a finding to act on
// (only act-now findings color a surface, ui-plan section 2.3). A metric without a source is not
// drawn at all: it joins the view's Hidden line instead.
//
// Test ids: the `testid` given, with `data-value` (the raw number, absent while unknown).
import { A } from "@solidjs/router";
import { Show, type JSX } from "solid-js";
import { Si } from "./Si";
import "./metric.css";

export function Metric(props: {
  label: string;
  /** A number (drawn with an SI suffix), or a text such as "2/2"; null or undefined while unknown. */
  value: number | string | null | undefined;
  unit?: string;
  /** One line of context under the value. */
  context?: JSX.Element;
  href?: string;
  tone?: "act";
  testid?: string;
  /** The value's raw number for tests, when `value` is a text. */
  data?: number;
}) {
  const raw = () => (typeof props.value === "number" ? props.value : props.data);
  const body = () => (
    <>
      <span class="metric-label">{props.label}</span>
      <span class="metric-value">
        <Show when={props.value != null} fallback={<span class="num unknown">–</span>}>
          <Show when={typeof props.value === "number"} fallback={<span class="num">{props.value}</span>}>
            <Si value={props.value as number} />
          </Show>
        </Show>
        <Show when={props.unit && props.value != null}>
          <span class="metric-unit"> {props.unit}</span>
        </Show>
      </span>
      <Show when={props.context}>
        <span class="metric-context" classList={{ act: props.tone === "act" }}>
          {props.context}
        </span>
      </Show>
    </>
  );
  return (
    <Show
      when={props.href}
      fallback={
        <div class="metric" data-testid={props.testid} data-value={raw() ?? undefined}>
          {body()}
        </div>
      }
    >
      {(href) => (
        <A class="metric" href={href()} data-testid={props.testid} data-value={raw() ?? undefined}>
          {body()}
        </A>
      )}
    </Show>
  );
}
