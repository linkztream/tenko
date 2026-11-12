// The history chart of a metric tile (OPS-20): two days of one figure on the continuous axis of
// history.ts, drawn on a canvas (a repaint strokes some 270 buckets, about 45 grid lines and a
// few labels; rebuilding that many SVG elements ten times a second for 25 tiles would cost style
// and layout work a canvas never does). Every tile uses this one component; a tile passes its name,
// title and unit.
//
// Motion (docs/plans/dashboard-history-plan.md, sections 1 and 6): one frame loop per page repaints
// every chart that is on screen (IntersectionObserver) and not held by the pointer or the keyboard,
// at 10 frames a second, at the controller's time (`LiveMetrics.clock`). After five frames in a row
// over 8 ms the page steps once a second until it is reloaded. Under reduced motion a chart is
// redrawn in place every 10 s; "Pause motion" stops every chart. Nothing is drawn while the tab is
// hidden or a chart is off screen, and the loop stops while no chart is on screen; the text
// alternatives are refreshed every 5 s on the same terms.
//
// Keyboard and screen readers: the chart is one tab stop with the role `slider`; its value is a
// bucket, the oldest 0, and its value text the readout. Left and Right (and Down and Up) move one
// bucket (Shift: ten), Page Up goes to the next finer tier and Page Down to the next coarser, Home
// and End go to the oldest and the newest, Escape closes the readout. Test ids:
// `metrics-history-<name>` on the slider (`data-top` the top of the scale, `data-buckets` the
// buckets with data), `metrics-history-readout`, `metrics-history-alt`.
import { batch, createSignal, createUniqueId, For, onCleanup, onMount, Show } from "solid-js";
import { Portal } from "solid-js/web";
import { motionPaused } from "../app/prefs";
import { formatDuration, t } from "../i18n";
import { AGE_LABELS, axisX, bucketsAt, forEachGridLine, place, REACH, scaleTop, type Bucket, type FigureHistory } from "./history";
import { altText, readout, readoutText, withUnit, type ChartContext, type Readout } from "./historyWords";
import type { LiveMetrics } from "./liveMetrics";
import { PERCENT_TILES, type TileName } from "./metrics";

/** Height of the row of age labels under the plot. */
const AXIS = 14;
/** Room above the highest value, for the caret of a needle above the scale. */
const TOP = 3;
/** Milliseconds between frames while gliding: 10 a second. */
const FRAME_MS = 100;
/** A frame slower than this, five times in a row, makes the page step once a second. */
const SLOW_MS = 8;

// ---------------------------------------------------------------------------------------------
// The page's one frame loop

interface Chart {
  /** On screen. */
  visible: boolean;
  /** Held by the pointer or the keyboard. */
  held: boolean;
  /** Whether the last drawing had a figure. */
  drawnFigure: boolean;
  /** The plot's size from the ResizeObserver; -1 until it reported. */
  width: number;
  height: number;
  draw(): void;
  refreshAlt(): void;
}

/** The charts by their plot element. */
const charts = new Map<Element, Chart>();
let raf = 0;
/** The wait for the next frame: a timer, so the browser is asked for 10 frames a second, not one at every refresh of the screen. */
let pause: ReturnType<typeof setTimeout> | undefined;
let slow = 0;
let fellBack = false;
let ticks = 0;
let timer: ReturnType<typeof setInterval> | undefined;
let observer: IntersectionObserver | undefined;
let resizer: ResizeObserver | undefined;
let themes: MutationObserver | undefined;
/** Reduced motion, forced colors and the dark scheme of the system: a change redraws every chart. */
let queries: MediaQueryList[] = [];

const hidden = () => typeof document !== "undefined" && document.hidden;
const reduced = () => queries[0]?.matches ?? false;

/** Whether the charts glide: neither reduced motion, nor "Pause motion", nor a slow device. */
function gliding(): boolean {
  return !reduced() && !motionPaused() && !fellBack;
}

/** True while a frame is asked for or waited for: the loop runs. */
export function frameLoopRunning(): boolean {
  return raf !== 0 || pause !== undefined;
}

function frame(): void {
  raf = 0;
  if (!gliding() || hidden()) return;
  const start = performance.now();
  let drawn = false;
  for (const chart of charts.values()) {
    if (!chart.visible || chart.held) continue;
    chart.draw();
    drawn = true;
  }
  // Nothing on screen: the loop stops, and a chart that comes into view starts it again.
  if (!drawn) return;
  const took = performance.now() - start;
  slow = took > SLOW_MS ? slow + 1 : 0;
  if (slow >= 5) fellBack = true;
  // Half a screen refresh early: the animation frame that follows waits for the next refresh.
  pause = setTimeout(() => {
    pause = undefined;
    wake();
  }, Math.max(0, FRAME_MS - took - 8));
}

/** Starts the loop when the charts glide and the page is visible; the loop stops itself otherwise. */
function wake(): void {
  if (raf === 0 && pause === undefined && gliding() && !hidden() && charts.size > 0 && typeof requestAnimationFrame === "function") raf = requestAnimationFrame(frame);
}

/** Once a second: the text alternatives every 5 s, and the drawing of charts that do not glide. */
function tick(): void {
  if (hidden()) return;
  ticks += 1;
  const glide = gliding();
  for (const chart of charts.values()) {
    if (!chart.visible) continue;
    if (ticks % 5 === 0) chart.refreshAlt();
    if (glide || chart.held) continue;
    if (motionPaused() ? !chart.drawnFigure : !reduced() || ticks % 10 === 0 || !chart.drawnFigure) chart.draw();
  }
  wake();
}

/** Every chart on screen again, as it stands: after a change of the theme or of the motion setting. */
export function redrawCharts(): void {
  colorsCache = null;
  for (const chart of charts.values()) if (chart.visible) chart.draw();
  wake();
}

/** The chart of an observed element, with what the observer saw. */
function observed<E extends { target: Element }>(update: (chart: Chart, entry: E) => void) {
  return (entries: E[]) => {
    for (const entry of entries) {
      const chart = charts.get(entry.target);
      if (!chart) continue;
      update(chart, entry);
      if (chart.visible && !hidden()) chart.draw();
    }
    wake();
  };
}

function register(chart: Chart, plot: HTMLElement): () => void {
  if (charts.size === 0) {
    queries = typeof matchMedia === "function" ? ["(prefers-reduced-motion: reduce)", "(forced-colors: active)", "(prefers-color-scheme: dark)"].map((q) => matchMedia(q)) : [];
    for (const q of queries) q.addEventListener("change", redrawCharts);
    themes = new MutationObserver(redrawCharts);
    themes.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    timer = setInterval(tick, 1000);
    document.addEventListener("visibilitychange", wake);
    if (typeof IntersectionObserver === "function") observer = new IntersectionObserver(observed((c, e) => (c.visible = e.isIntersecting)));
    if (typeof ResizeObserver === "function") {
      resizer = new ResizeObserver(
        observed((c, e) => {
          c.width = e.contentRect.width;
          c.height = e.contentRect.height;
        }),
      );
    }
  }
  charts.set(plot, chart);
  // Without an observer (tests, very old browsers) a chart counts as on screen.
  if (observer) observer.observe(plot);
  else chart.visible = true;
  resizer?.observe(plot);
  wake();
  return () => {
    charts.delete(plot);
    observer?.unobserve(plot);
    resizer?.unobserve(plot);
    if (charts.size > 0) return;
    clearInterval(timer);
    clearTimeout(pause);
    pause = undefined;
    if (raf !== 0) cancelAnimationFrame(raf);
    raf = 0;
    observer?.disconnect();
    resizer?.disconnect();
    themes?.disconnect();
    observer = resizer = themes = undefined;
    for (const q of queries) q.removeEventListener("change", redrawCharts);
    document.removeEventListener("visibilitychange", wake);
  };
}

// ---------------------------------------------------------------------------------------------
// Colors: the tokens of the theme, or the system colors in forced-colors mode

interface Colors {
  series: string;
  grid: string;
  axis: string;
  ink: string;
  ink3: string;
  surface: string;
  accent: string;
  font: string;
  forced: boolean;
  hatch: CanvasPattern | null;
}
let colorsCache: Colors | null = null;

function colors(ctx: CanvasRenderingContext2D): Colors {
  if (colorsCache) return colorsCache;
  const style = getComputedStyle(document.documentElement);
  const v = (name: string) => style.getPropertyValue(name).trim();
  const forced = queries[1]?.matches ?? false;
  const c: Colors = forced
    ? { series: "CanvasText", grid: "GrayText", axis: "CanvasText", ink: "CanvasText", ink3: "CanvasText", surface: "Canvas", accent: "Highlight", font: "", forced, hatch: null }
    : { series: v("--series-1"), grid: v("--chart-grid"), axis: v("--chart-axis"), ink: v("--chart-ink"), ink3: v("--ink-3"), surface: v("--surface"), accent: v("--accent"), font: "", forced, hatch: null };
  c.font = `${v("--fs-11") || "11px"} ${v("--font-ui") || "sans-serif"}`;
  // The hatch of no data: sparse diagonal lines in the chart's ink on the surface.
  const tile = document.createElement("canvas");
  tile.width = tile.height = 7;
  const p = tile.getContext("2d");
  if (p) {
    p.fillStyle = c.surface;
    p.fillRect(0, 0, 7, 7);
    p.strokeStyle = c.ink;
    path(p, [[-1, 8], [8, -1]], [[-1, 1], [1, -1]], [[6, 8], [8, 6]]);
    p.stroke();
    c.hatch = ctx.createPattern(tile, "repeat");
  }
  colorsCache = c;
  return c;
}

// ---------------------------------------------------------------------------------------------
// Painting

/** Begins a path of the given polylines. */
function path(ctx: CanvasRenderingContext2D, ...lines: (readonly [number, number])[][]): void {
  ctx.beginPath();
  for (const points of lines) points.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
}

interface Frame {
  buckets: Bucket[];
  top: number;
  scale: string;
  at: number;
  width: number;
  height: number;
  sel: number | null;
  restarts: number[];
  /** A run of buckets covered by fewer controllers than this has a lighter band and a bar. */
  controllers: number;
}

function paint(ctx: CanvasRenderingContext2D, f: Frame): void {
  const C = colors(ctx);
  const { buckets, top, at, width: W } = f;
  const PH = f.height - AXIS;
  const y = (v: number) => Math.min(PH - 1, TOP + (PH - TOP) * (1 - Math.min(v, top) / top));
  ctx.clearRect(0, 0, W, f.height);
  ctx.lineWidth = 1;
  ctx.globalAlpha = 1;
  // The baseline, under the series, so a series at zero stays visible on it; the quarters of the scale.
  ctx.strokeStyle = C.axis;
  path(ctx, [[0, PH - 0.5], [W, PH - 0.5]]);
  ctx.stroke();
  ctx.strokeStyle = C.grid;
  path(ctx, ...[0, 0.25, 0.5, 0.75].map((q) => Math.round(TOP + (PH - TOP) * q) + 0.5).map((yy) => [[0, yy], [W, yy]] as [number, number][]));
  ctx.stroke();
  // The moments, where they stand.
  forEachGridLine(at, W, (_moment, _step, x, alpha) => {
    ctx.globalAlpha = alpha;
    path(ctx, [[x, TOP], [x, PH]]);
    ctx.stroke();
  });
  ctx.globalAlpha = 1;
  // No data, hatched.
  let gap: number | null = null;
  buckets.forEach((b, i) => {
    if (!b.data && gap === null) gap = b.x0;
    const end = !b.data && (i === buckets.length - 1 || buckets[i + 1]!.data);
    if (end && gap !== null && C.hatch) {
      ctx.fillStyle = C.hatch;
      ctx.fillRect(gap, TOP, Math.max(1, b.x1 - gap), PH - TOP);
    }
    if (b.data || end) gap = null;
  });
  // Band, upper edge, halo and mean, in runs of buckets with data; a run is cut where the coverage of
  // the controllers changes, and the mean line bridges that cut from the run before.
  const line = (list: readonly Bucket[], value: (b: Bucket) => number) =>
    list.length === 1 ? path(ctx, [[list[0]!.x0, y(value(list[0]!))], [list[0]!.x1, y(value(list[0]!))]]) : path(ctx, list.map((b) => [b.cx, y(value(b))] as const));
  const runs: { part: boolean; list: Bucket[]; bridge: Bucket | null }[] = [];
  let prev: Bucket | null = null;
  for (const b of buckets) {
    if (!b.data) {
      prev = null;
      continue;
    }
    const part = b.controllers < f.controllers;
    const run = runs[runs.length - 1];
    if (run && prev && run.part === part) run.list.push(b);
    else runs.push({ part, list: [b], bridge: prev });
    prev = b;
  }
  ctx.strokeStyle = ctx.fillStyle = C.series;
  ctx.lineJoin = "round";
  ctx.lineCap = "round";
  for (const { part, list, bridge } of runs) {
    if (!C.forced) {
      ctx.fillStyle = C.series;
      ctx.globalAlpha = part ? 0.08 : 0.18;
      if (list.length === 1) {
        const b = list[0]!;
        ctx.beginPath();
        ctx.rect(b.x0, y(b.h), Math.max(1, b.x1 - b.x0), Math.max(0.5, y(b.l) - y(b.h)));
      } else path(ctx, [...list.map((b) => [b.cx, y(b.h)] as const), ...[...list].reverse().map((b) => [b.cx, y(b.l)] as const)]);
      ctx.fill();
      ctx.globalAlpha = 1;
    }
    // The upper edge shows a short burst in a wide bucket, so it is drawn in forced colors too.
    ctx.lineWidth = 1;
    line(list, (b) => b.h);
    ctx.stroke();
    const mean = bridge ? [bridge, ...list] : list;
    // The halo: a wide, faint stroke under the mean.
    if (!C.forced) {
      ctx.globalAlpha = 0.16;
      ctx.lineWidth = 5;
      line(mean, (b) => b.m);
      ctx.stroke();
      ctx.globalAlpha = 1;
    }
    ctx.lineWidth = 1.5;
    line(mean, (b) => b.m);
    ctx.stroke();
    if (part) {
      ctx.fillStyle = C.ink;
      ctx.fillRect(list[0]!.x0, PH + 1, Math.max(1, list[list.length - 1]!.x1 - list[0]!.x0), 2);
    }
  }
  ctx.lineWidth = 1;
  // A needle above the scale: a caret at the top.
  ctx.fillStyle = C.series;
  for (const b of buckets) {
    if (!b.data || b.highest <= top) continue;
    path(ctx, [[b.cx - 3.5, TOP + 5], [b.cx, TOP - 1], [b.cx + 3.5, TOP + 5]]);
    ctx.fill();
  }
  // Where a controller started: a hairline with a mark at the top.
  ctx.strokeStyle = ctx.fillStyle = C.ink3;
  for (const started of f.restarts) {
    const x = Math.round(axisX(at - started, W)) + 0.5;
    path(ctx, [[x, TOP], [x, PH]]);
    ctx.stroke();
    path(ctx, [[x - 3.5, TOP], [x + 3.5, TOP], [x, TOP + 4]]);
    ctx.fill();
  }
  // The newest value: the line runs on to the right edge, where the end marker sits, so the end glides.
  const last = buckets.findLast((b) => b.data);
  if (last && last.step < 60) {
    ctx.strokeStyle = C.series;
    ctx.lineWidth = 1.5;
    path(ctx, [[last.cx, y(last.m)], [W - 3, y(last.m)]]);
    ctx.stroke();
    dot(ctx, W - 3, y(last.m), 3, C);
  }
  // The bucket under the pointer or the focus.
  const sel = f.sel === null ? undefined : buckets[f.sel];
  if (sel) {
    ctx.globalAlpha = 0.14;
    ctx.fillStyle = C.accent;
    ctx.fillRect(Math.min(sel.x0, sel.cx - 2), TOP, Math.max(4, sel.x1 - sel.x0), PH - TOP);
    ctx.globalAlpha = 1;
    ctx.strokeStyle = C.accent;
    ctx.lineWidth = 1;
    path(ctx, [[sel.cx, TOP], [sel.cx, PH]]);
    ctx.stroke();
    if (sel.data) dot(ctx, sel.cx, y(sel.m), 3.5, C);
  }
  // The ages under the axis, with a short tick; "now" at the right end, the reach at the left.
  ctx.font = C.font;
  ctx.textBaseline = "alphabetic";
  ctx.fillStyle = C.ink;
  ctx.strokeStyle = C.axis;
  for (const label of labels(ctx, W)) {
    ctx.fillText(label.text, label.left, f.height - 2);
    if (label.tick === null) continue;
    path(ctx, [[label.tick, PH], [label.tick, PH + 3]]);
    ctx.stroke();
  }
  // The scale, inside the plot.
  ctx.lineWidth = 4;
  ctx.strokeStyle = C.surface;
  ctx.lineJoin = "round";
  ctx.strokeText(f.scale, 2, TOP + 11);
  ctx.fillText(f.scale, 2, TOP + 11);
  ctx.lineWidth = 1;
}

function dot(ctx: CanvasRenderingContext2D, x: number, y: number, r: number, C: Colors): void {
  ctx.beginPath();
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.fillStyle = C.series;
  ctx.strokeStyle = C.surface;
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.fill();
  ctx.lineWidth = 1;
}

interface Label {
  text: string;
  left: number;
  tick: number | null;
}
const labelCache = new Map<string, Label[]>();

/** The age labels of a chart `width` wide that do not overlap, "now" and the reach first; they stand still. */
function labels(ctx: CanvasRenderingContext2D, width: number): Label[] {
  const now = t("metrics.history.now");
  const key = `${width}|${ctx.font}|${now}`;
  const hit = labelCache.get(key);
  if (hit) return hit;
  const wanted = [
    { text: now, x: width, edge: "end" as const },
    { text: formatDuration(REACH), x: 0, edge: "start" as const },
    ...AGE_LABELS.map((age) => ({ text: formatDuration(age), x: axisX(age, width), edge: null })),
  ];
  const placed: Label[] = [];
  const spans: [number, number][] = [];
  for (const l of wanted) {
    const w = ctx.measureText(l.text).width;
    const left = l.edge === "end" ? l.x - w : l.edge === "start" ? 0 : l.x - w / 2;
    if (spans.some(([a, b]) => left < b + 6 && left + w > a - 6)) continue;
    spans.push([left, left + w]);
    placed.push({ text: l.text, left, tick: l.edge ? null : l.x });
  }
  if (labelCache.size > 32) labelCache.clear();
  labelCache.set(key, placed);
  return placed;
}

// ---------------------------------------------------------------------------------------------
// The component

export function HistoryChart(props: { name: TileName; title: string; unit: string; value: number | null; live: LiveMetrics }) {
  let plot!: HTMLDivElement;
  let canvas!: HTMLCanvasElement;
  const altId = createUniqueId();
  const [alt, setAlt] = createSignal("");
  const [tip, setTip] = createSignal<{ r: Readout; left: number; top: number; below: boolean } | null>(null);
  const [held, setHeld] = createSignal(false);
  const [valueText, setValueText] = createSignal<string>();
  const [count, setCount] = createSignal(0);
  const [total, setTotal] = createSignal(0);
  const [top, setTop] = createSignal(1);
  const [sel, setSel] = createSignal<number | null>(null);

  let second = Number.NaN;
  let seen: FigureHistory | undefined;
  let buckets: Bucket[] = [];
  let scale = "";
  let heldAt: number | null = null;
  let drawnAt = 0;

  const figure = () => props.live.tiers()?.figures.get(props.name);
  const context = (): ChartContext => ({
    title: props.title,
    unit: props.unit,
    merge: figure()?.merge ?? "sum",
    controllers: props.live.tiers()?.controllers ?? [],
    top: top(),
  });
  /** The moment drawn: the held one, or the controller's time now. */
  const moment = () => heldAt ?? props.live.clock() ?? Date.now() / 1000;

  /** The buckets at `at`, placed on the plot; rebuilt when the second or the figure changes. */
  function layout(at: number): number {
    const f = figure();
    if (Math.floor(at) !== second || f !== seen) {
      second = Math.floor(at);
      seen = f;
      buckets = bucketsAt(f, at);
      const t = scaleTop(buckets, PERCENT_TILES.has(props.name) ? 100 : undefined);
      scale = withUnit(t, props.unit);
      batch(() => {
        setTop(t);
        setCount(buckets.reduce((n, b) => n + (b.data ? 1 : 0), 0));
        setTotal(buckets.length);
      });
    }
    const width = chart.width >= 0 ? chart.width : plot.clientWidth;
    place(buckets, at, width);
    return width;
  }

  const chart: Chart = {
    visible: false,
    held: false,
    drawnFigure: false,
    width: -1,
    height: -1,
    draw() {
      const at = gliding() || heldAt !== null ? moment() : Math.floor(moment());
      const width = layout(at);
      const height = chart.height >= 0 ? chart.height : plot.clientHeight;
      if (width < 40 || height < 30) return;
      const dpr = window.devicePixelRatio || 1;
      const w = Math.round(width * dpr);
      const h = Math.round(height * dpr);
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
      }
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const ctrl = props.live.tiers()?.controllers ?? [];
      const restarts = ctrl.filter((c) => c.started !== null && !c.unsupported && at - c.started < REACH).map((c) => c.started!);
      paint(ctx, { buckets, top: top(), scale, at, width, height, sel: sel(), restarts, controllers: ctrl.length });
      drawnAt = at;
      chart.drawnFigure = figure() !== undefined;
      if (!alt()) chart.refreshAlt();
    },
    refreshAlt() {
      // Its own buckets: those drawn keep their places for the pointer.
      const at = moment();
      setAlt(altText(context(), bucketsAt(figure(), at), at, props.value));
    },
  };

  function hold(on: boolean): void {
    chart.held = on;
    setHeld(on);
    if (on && heldAt === null) heldAt = drawnAt || moment();
    if (!on) {
      heldAt = null;
      select(null);
    }
  }

  function select(i: number | null): void {
    setSel(i);
    chart.draw();
    const b = i === null ? undefined : buckets[i];
    if (!b) {
      setTip(null);
      setValueText(undefined);
      return;
    }
    const at = heldAt ?? moment();
    setValueText(readoutText(context(), b, at));
    const rect = plot.getBoundingClientRect();
    // Above the chart, or under it near the top of the window; never past the window's sides.
    const below = rect.top < 160;
    const left = Math.min(Math.max(rect.left + (b.x0 + b.x1) / 2, 150), window.innerWidth - 150);
    setTip({ r: readout(context(), b, at), left, top: below ? rect.bottom : rect.top, below });
  }

  const pointer = (e: PointerEvent) => {
    hold(true);
    layout(heldAt!);
    const x = e.clientX - plot.getBoundingClientRect().left;
    let best: number | null = null;
    let distance = Infinity;
    buckets.forEach((b, i) => {
      const d = x < b.x0 ? b.x0 - x : x > b.x1 ? x - b.x1 : 0;
      if (d < distance) {
        distance = d;
        best = i;
      }
    });
    if (best !== sel()) select(best);
  };

  const keydown = (e: KeyboardEvent) => {
    layout(moment());
    const n = buckets.length;
    const current = sel();
    let i = current ?? n - 1;
    const tier = buckets[i]?.tier ?? 0;
    const by = e.shiftKey ? 10 : 1;
    switch (e.key) {
      case "ArrowLeft":
      case "ArrowDown":
        i = Math.max(0, i - by);
        break;
      case "ArrowRight":
      case "ArrowUp":
        i = Math.min(n - 1, i + by);
        break;
      case "Home":
        i = 0;
        break;
      case "End":
        i = n - 1;
        break;
      case "PageUp":
      case "PageDown": {
        // The finer tier is newer, so up; the coarser older, so down: to its bucket next to this tier.
        const tiers = buckets.map((b) => b.tier);
        const j = e.key === "PageUp" ? tiers.indexOf(tier - 1) : tiers.lastIndexOf(tier + 1);
        if (j >= 0) i = j;
        break;
      }
      case "Escape":
        e.preventDefault();
        select(null);
        return;
      default:
        return;
    }
    e.preventDefault();
    // After Escape an arrow brings the readout back where it was left: on the newest bucket.
    select(current === null && e.key.startsWith("Arrow") ? n - 1 : i);
  };

  onMount(() => onCleanup(register(chart, plot)));

  return (
    <div class="metrics-history">
      <div
        ref={plot}
        class="metrics-history-plot"
        classList={{ "is-held": held() }}
        tabindex="0"
        role="slider"
        aria-label={t("metrics.history.label", { name: props.title })}
        aria-describedby={altId}
        aria-valuemin={0}
        aria-valuemax={Math.max(0, total() - 1)}
        aria-valuenow={sel() ?? Math.max(0, total() - 1)}
        aria-valuetext={valueText() ?? props.title}
        data-testid={`metrics-history-${props.name}`}
        data-top={top()}
        data-buckets={count()}
        onPointerMove={pointer}
        onPointerDown={pointer}
        onPointerLeave={(e) => {
          if (e.pointerType === "mouse" && document.activeElement !== plot) hold(false);
        }}
        onFocus={() => {
          hold(true);
          layout(heldAt!);
          // A tap selected its bucket before the focus came.
          if (sel() === null && buckets.length) select(buckets.length - 1);
        }}
        onBlur={() => hold(false)}
        onKeyDown={keydown}
      >
        <canvas ref={canvas} aria-hidden="true" />
        <span class="metrics-history-held" aria-hidden="true">
          {t("metrics.history.held")}
        </span>
      </div>
      <p class="sr-only" id={altId} data-testid="metrics-history-alt">
        {alt()}
      </p>
      <Show when={tip()}>
        {(open) => (
          <Portal>
            <div class="metrics-history-readout" classList={{ below: open().below }} aria-hidden="true" data-testid="metrics-history-readout" style={{ left: `${open().left}px`, top: `${open().top}px` }}>
              <div class="when">{open().r.when}</div>
              <div class="value">{open().r.value}</div>
              <For each={open().r.rows}>{(row) => <div class="row">{row}</div>}</For>
              <For each={open().r.notes}>{(note) => <div class="note">{note}</div>}</For>
            </div>
          </Portal>
        )}
      </Show>
    </div>
  );
}
