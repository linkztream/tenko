// TEST DATA, not a model of the server: a deterministic two days of every tile's figure in the
// shape of a `metrics.history` event, for the unit tests of the chart's geometry and words and the
// end-to-end test's screenshots and drawing cost. The server's sampler builds the real history; the
// mock API serves the golden example (docs/api/examples/metrics-stream.jsonl). Each figure waves
// with the time of day around its own level, with a little noise, a burst of five seconds two hours
// back, and optional gaps and a restart.
import type { HistoryFrame, MetricsMerge } from "./history";
import { DHCP_TILES, DNS_TILES, HOST_TILES, RECURSION_TILES, TILES, type TileName } from "./metrics";

/** The tiers: step in seconds and ring, those of the contract with an hour ring that holds two days; a ratio's finest tier is 15 buckets of 5 s. */
const TIERS = [
  [1, 71],
  [10, 61],
  [60, 61],
  [600, 37],
  [3600, 49],
] as const;

const RATIOS: readonly TileName[] = ["dns-cache", "dns-answers"];
const HIGHEST: readonly TileName[] = ["commit", "raft", "jobs", "host-cpu", "dhcp-ack", "dhcp-pools"];
const LEAST: readonly TileName[] = ["host-memory", "host-disk"];

export function testMerge(name: TileName): MetricsMerge {
  return RATIOS.includes(name) ? "ratio" : HIGHEST.includes(name) ? "highest" : LEAST.includes(name) ? "least_available" : "sum";
}

export interface TestHistoryOptions {
  /** The figures; all 25 by default. */
  figures?: readonly TileName[];
  /** Seconds of `at`, the end of the history. */
  at: number;
  /** The controller started this many seconds before `at`: nothing before. */
  startedAgo?: number;
  /** Spans without data, as [from, to] in seconds before `at`. */
  gaps?: readonly (readonly [number, number])[];
  /** The age in seconds of the five-second burst; 7,200 by default. */
  burstAgo?: number;
}

function noise(t: number, seed: number): number {
  const x = Math.sin(t * 12.9898 + seed * 78.233) * 43758.5453;
  return x - Math.floor(x);
}

/** The figure's value at second `t`: a daily wave around its level, with noise and the burst. */
function valueAt(name: TileName, seed: number, t: number, burst: number): number {
  if (RATIOS.includes(name) || name === "dhcp-pools" || name === "host-memory") return 40 + 30 * Math.sin(t / 7200 + seed) + 10 * noise(Math.floor(t / 5), seed);
  const level = 10 ** (seed % 4);
  const day = 0.5 - 0.5 * Math.cos((2 * Math.PI * (t % 86_400)) / 86_400);
  const v = level * (0.4 + day + 0.25 * noise(t, seed));
  return t >= burst && t < burst + 5 ? v * 10 : v;
}

/** The whole history of every figure at `at`, every ring full. */
export function testHistory(options: TestHistoryOptions): HistoryFrame {
  const { at } = options;
  const names = options.figures ?? [...TILES, ...HOST_TILES, ...DNS_TILES, ...RECURSION_TILES, ...DHCP_TILES];
  const burst = Math.floor(at - (options.burstAgo ?? 7200));
  const startedAt = options.startedAgo === undefined ? at - 3 * 86_400 : at - options.startedAgo;
  const none = (t: number) => t < startedAt || (options.gaps ?? []).some(([from, to]) => t >= at - from && t < at - to);
  const iso = (s: number) => new Date(s * 1000).toISOString();
  const figures = names.map((name, seed) => {
    const merge = testMerge(name);
    const tiers = TIERS.map(([base, baseRing]) => {
      const [step, ring] = merge === "ratio" && base === 1 ? [5, 15] : [base, baseRing];
      const newest = Math.floor(at / step) * step;
      const columns = { lowest: [] as (number | null)[], highest: [] as (number | null)[], mean: [] as (number | null)[], covered_ms: [] as number[], controllers: [] as number[] };
      for (let i = ring - 1; i >= 0; i--) {
        const start = newest - i * step;
        const end = Math.min(start + step, at);
        // At most 60 readings a bucket, and the burst's seconds when it falls inside.
        const stride = Math.max(1, Math.floor(step / 60));
        let lowest = Infinity;
        let highest = -Infinity;
        let sum = 0;
        let covered = 0;
        for (let t = start; t < end; ) {
          const dt = Math.min(t >= burst - stride && t < burst + 5 ? 1 : stride, end - t);
          if (!none(t)) {
            const v = valueAt(name, seed, t, burst);
            lowest = Math.min(lowest, v);
            highest = Math.max(highest, v);
            sum += v * dt;
            covered += dt;
          }
          t += dt;
        }
        const data = covered > 0;
        columns.lowest.push(data ? lowest : null);
        columns.highest.push(data ? highest : null);
        columns.mean.push(data ? sum / covered : null);
        columns.covered_ms.push(Math.round(covered * 1000));
        columns.controllers.push(data ? 1 : 0);
      }
      return { step_ms: step * 1000, start: iso(newest), open: true, ring, ...columns };
    });
    return { figure: name, merge, tiers };
  });
  return { at: iso(at), controllers: [{ node: 1, started: iso(startedAt) }], figures };
}
