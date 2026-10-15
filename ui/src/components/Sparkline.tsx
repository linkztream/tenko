// A sparkline: the last values of a series as a line, drawn in inline SVG without a library.
// It is decoration beside a number, so it is hidden from assistive technology; the `title` (a
// translated description of the series) shows as a tooltip. The newest value is at the inline
// end; a missing value breaks the line. The scale starts at zero unless a value is negative,
// so a flat series reads as a flat line and a series of zeros as a line on the baseline.
import { createMemo, For } from "solid-js";
import "./sparkline.css";

/** Values a sparkline shows: one per second for a minute. */
export const SPARKLINE_POINTS = 60;

/** The height of the drawing in its own units; the width is one unit per point. */
const HEIGHT = 20;

/** The polylines of `values`: one per run of present values, in viewBox units. */
export function sparklinePaths(values: readonly (number | null | undefined)[], points = SPARKLINE_POINTS): string[] {
  const shown = values.slice(-points);
  const present = shown.filter(isValue);
  if (present.length === 0) return [];
  const low = Math.min(0, ...present);
  const span = Math.max(...present) - low;
  const offset = points - shown.length;
  const y = (v: number) => Math.round((span > 0 ? HEIGHT - ((v - low) / span) * HEIGHT : HEIGHT) * 100) / 100;
  const runs: [number, number][][] = [];
  let run: [number, number][] = [];
  shown.forEach((v, i) => {
    if (isValue(v)) {
      run.push([offset + i, y(v)]);
    } else if (run.length > 0) {
      runs.push(run);
      run = [];
    }
  });
  if (run.length > 0) runs.push(run);
  return runs.map((r) => {
    // A lone point draws as a short level line, so it shows.
    const line = r.length === 1 ? [[r[0]![0] - 0.5, r[0]![1]] as [number, number], r[0]!] : r;
    return line.map(([px, py]) => `${px},${py}`).join(" ");
  });
}

function isValue(v: number | null | undefined): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

export function Sparkline(props: {
  values: readonly (number | null | undefined)[];
  /** The description of the series, translated: what it shows and its values. */
  title: string;
  points?: number;
  testId?: string;
}) {
  const points = () => props.points ?? SPARKLINE_POINTS;
  const paths = createMemo(() => sparklinePaths(props.values, points()));
  return (
    <svg
      class="sparkline"
      viewBox={`0 -1 ${points() - 1} ${HEIGHT + 2}`}
      preserveAspectRatio="none"
      aria-hidden="true"
      data-testid={props.testId}
      data-points={props.values.slice(-points()).length}
    >
      <title>{props.title}</title>
      <For each={paths()}>{(p) => <polyline points={p} />}</For>
    </svg>
  );
}
