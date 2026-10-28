// The queries chart of the DNS panel (U3): the mean queries per second of every 5-second bucket
// of the last five minutes as bars, hand-drawn SVG without a library. The buckets have fixed
// edges on the controller's clock (`rateBuckets` of metrics.ts), so a bar is born on the right
// and walks left one step per bucket; the bucket still filling is drawn lighter. Every chart
// names its window and its scale: the axis says its top, its middle and zero, and the window runs
// from "−5 min" to "now". The SVG is an image with a label that says both, so a screen reader
// hears what a sighted reader sees.
//
// Test ids: `dashboard-dns-chart` (`data-max` the top of the axis, `data-bars` the bars drawn),
// `dashboard-dns-scale` (the top's text).
import { createMemo, For } from "solid-js";
import { si } from "../app/format/si";
import { formatNumber, locale, t } from "../i18n";
import { niceCeiling } from "./metrics";

/** The drawing in its own units: the plot area right of the axis labels, above the window labels. */
const WIDTH = 400;
const LEFT = 30;
const TOP = 6;
const BASE = 90;
const HEIGHT = 110;
/** The least height of a present bar, so a quiet bucket shows. */
const HAIRLINE = 0.75;

function axis(value: number): string {
  if (value >= 1000) return si(value, locale());
  return formatNumber(value, { maximumFractionDigits: value < 10 ? 1 : 0 });
}

export function QueriesChart(props: { values: readonly (number | null)[] }) {
  const max = createMemo(() => niceCeiling(Math.max(0, ...props.values.filter((v): v is number => v !== null))));
  const slot = () => (WIDTH - LEFT) / Math.max(1, props.values.length);
  const bars = createMemo(() =>
    props.values.flatMap((v, i) => {
      if (v === null) return [];
      const h = Math.max(HAIRLINE, (Math.min(v, max()) / max()) * (BASE - TOP));
      return [{ x: LEFT + i * slot() + slot() * 0.15, y: BASE - h, width: slot() * 0.7, height: h, partial: i === props.values.length - 1 }];
    }),
  );
  const top = () => t("dashboard.dns.scale_top", { value: axis(max()) });
  return (
    <svg
      class="dash-chart"
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      role="img"
      aria-label={t("dashboard.dns.chart_label", { max: axis(max()) })}
      data-testid="dashboard-dns-chart"
      data-max={max()}
      data-bars={bars().length}
    >
      <line class="grid" x1={LEFT} y1={TOP} x2={WIDTH} y2={TOP} />
      <line class="grid" x1={LEFT} y1={(TOP + BASE) / 2} x2={WIDTH} y2={(TOP + BASE) / 2} />
      <line class="axis" x1={LEFT} y1={BASE} x2={WIDTH} y2={BASE} />
      <text x="0" y={TOP + 4} data-testid="dashboard-dns-scale">
        {top()}
      </text>
      <text x="0" y={(TOP + BASE) / 2 + 4}>{axis(max() / 2)}</text>
      <text x="0" y={BASE + 4}>
        0
      </text>
      <For each={bars()}>{(b) => <rect x={b.x} y={b.y} width={b.width} height={b.height} classList={{ partial: b.partial }} />}</For>
      <text x={LEFT} y={HEIGHT - 2}>
        {t("dashboard.dns.window_start")}
      </text>
      <text x={WIDTH} y={HEIGHT - 2} text-anchor="end">
        {t("dashboard.dns.window_end")}
      </text>
    </svg>
  );
}
