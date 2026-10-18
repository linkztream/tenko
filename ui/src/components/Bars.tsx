// A small bar chart beside a number: one bar per bucket, oldest first, the newest at the inline
// end, drawn in inline SVG without a library. Like the sparkline it is decoration beside a
// number, so it is hidden from assistive technology; the `title` shows as a tooltip. A value is a
// fraction from 0 to 1 of the full height; a missing value draws no bar, a present zero draws a
// hairline at the baseline so that "all misses" differs from "no queries".
import { createMemo, For } from "solid-js";
import "./bars.css";

/** The size of the drawing in its own units: ten per bucket, a bar seven wide with a gap of three. */
const HEIGHT = 20;
const SLOT = 10;
const BAR = 7;
/** The least height of a present bar, so a zero shows. */
const HAIRLINE = 1;

export interface BarRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

const round = (n: number) => Math.round(n * 100) / 100;

/** The bars of `values` (the last `buckets` of them, right-aligned), in viewBox units. */
export function barRects(values: readonly (number | null | undefined)[], buckets: number): BarRect[] {
  const shown = values.slice(-buckets);
  const offset = buckets - shown.length;
  const rects: BarRect[] = [];
  shown.forEach((v, i) => {
    if (typeof v !== "number" || !Number.isFinite(v)) return;
    const height = round(Math.max(HAIRLINE, Math.min(1, Math.max(0, v)) * HEIGHT));
    rects.push({ x: round((offset + i) * SLOT + (SLOT - BAR) / 2), y: round(HEIGHT - height), width: BAR, height });
  });
  return rects;
}

export function Bars(props: {
  values: readonly (number | null | undefined)[];
  /** The description of the series, translated: what it shows and its values. */
  title: string;
  buckets: number;
  testId?: string;
}) {
  const rects = createMemo(() => barRects(props.values, props.buckets));
  return (
    <svg
      class="bars"
      viewBox={`0 0 ${props.buckets * SLOT} ${HEIGHT}`}
      preserveAspectRatio="none"
      aria-hidden="true"
      data-testid={props.testId}
      data-buckets={props.buckets}
    >
      <title>{props.title}</title>
      <For each={rects()}>{(r) => <rect x={r.x} y={r.y} width={r.width} height={r.height} />}</For>
    </svg>
  );
}
