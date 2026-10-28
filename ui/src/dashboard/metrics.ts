// The live metrics of the start page (OPS-20): the samples of the `metrics` topic of the event
// stream, one snapshot per second while the page is open, kept for a minute per controller and
// for the cluster. No request module: the data arrives on the stream only.
import type { components } from "../api/generated/schema";

type S = components["schemas"];
export type MetricsSnapshot = S["MetricsSnapshot"];
export type MetricsSample = S["MetricsSample"];
export type MetricsDns = S["MetricsDns"];
// WP8.7: the `dhcp` part of a sample.
export type MetricsDhcp = S["MetricsDhcp"];
// OPS-20: the `host` part of a sample.
export type MetricsHost = S["MetricsHost"];

/** The `kind` of the events of the `metrics` topic. */
export const SNAPSHOT_KIND = "metrics.snapshot";
/** Samples kept per series: one minute. */
export const HISTORY = 60;
/**
 * U3: samples of the cluster kept by the start page, five minutes, for the queries chart of the
 * DNS panel (60 buckets of 5 seconds). The tiles still draw the newest minute of them.
 */
export const LONG_HISTORY = 300;

/** The samples of the last minute, oldest first: the cluster's and each controller's. */
export interface MetricsHistory {
  cluster: readonly MetricsSample[];
  nodes: ReadonlyMap<number, readonly MetricsSample[]>;
  latest: MetricsSnapshot | null;
}

export function emptyHistory(): MetricsHistory {
  return { cluster: [], nodes: new Map(), latest: null };
}

function keep<T>(list: readonly T[], item: T, limit = HISTORY): T[] {
  const next = [...list, item];
  return next.length > limit ? next.slice(next.length - limit) : next;
}

/**
 * The history with one more snapshot; a controller that left the snapshot is dropped. The
 * cluster's series keeps `clusterLimit` samples (a minute, or `LONG_HISTORY` on the start page),
 * each controller's a minute.
 */
export function pushSnapshot(history: MetricsHistory, snapshot: MetricsSnapshot, clusterLimit = HISTORY): MetricsHistory {
  const nodes = new Map<number, readonly MetricsSample[]>();
  for (const sample of snapshot.nodes) {
    if (sample.node == null) continue;
    nodes.set(sample.node, keep(history.nodes.get(sample.node) ?? [], sample));
  }
  return { cluster: keep(history.cluster, snapshot.cluster, clusterLimit), nodes, latest: snapshot };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/** The snapshot an event of the topic carries, or null for anything else. */
export function snapshotOf(data: Record<string, unknown>): MetricsSnapshot | null {
  if (data.kind !== SNAPSHOT_KIND) return null;
  const metrics = data.metrics;
  if (!isObject(metrics) || !Array.isArray(metrics.nodes) || !isObject(metrics.cluster)) return null;
  return metrics as unknown as MetricsSnapshot;
}

/** The tiles, in the order they are shown; each is `metrics-tile-<name>`. */
export const TILES = ["requests", "commit", "store", "raft", "jobs", "ingest", "sse", "nodes"] as const;
/**
 * The tiles of the `dns` role, after the others while the sample has `dns`; `dns-encrypted`
 * has no number while the role serves neither DoT nor DoH.
 */
export const DNS_TILES = ["dns-queries", "dns-cache", "dns-answers", "dns-blocked", "dns-upstreams", "dns-encrypted"] as const;
export type DnsTileName = (typeof DNS_TILES)[number];
// WP8.7: the tiles of the `dhcp` role (OPS-20), after the DNS tiles while the sample has `dhcp`.
/**
 * The tiles of the `dhcp` role: leases granted per second, the REQUEST to ACK p99, the active
 * leases, the fullest pool with the three fullest scopes, NAKs and DECLINEs, DDNS outcomes. Six,
 * so the group fills its rows three to a row as the DNS group does.
 */
export const DHCP_TILES = ["dhcp-leases", "dhcp-ack", "dhcp-active", "dhcp-pools", "dhcp-naks", "dhcp-ddns"] as const;
export type DhcpTileName = (typeof DHCP_TILES)[number];

/** The DDNS outcomes the DDNS tile lists, in order. */
export const DDNS_OUTCOMES = ["written", "removed", "refused", "failed"] as const;

function isDhcpTile(name: TileName): name is DhcpTileName {
  return name.startsWith("dhcp-");
}

function dhcpValue(name: DhcpTileName, dhcp: MetricsDhcp): number | null {
  switch (name) {
    case "dhcp-leases":
      return dhcp.leases_per_second;
    case "dhcp-ack":
      return dhcp.ack_p99_ms ?? null;
    case "dhcp-active":
      return dhcp.active_leases;
    case "dhcp-pools":
      return dhcp.fullest[0] ? dhcp.fullest[0].utilization * 100 : null;
    case "dhcp-naks":
      return dhcp.naks_per_second + dhcp.declines_per_second;
    case "dhcp-ddns":
      return dhcp.ddns.written;
  }
}
// WP10.4: the recursive resolver's tiles beside the upstream tile, while the sample's DNS part
// has `recursion` (the resolver runs): the queries it sent to authorities per second, and the
// validation outcomes per second (secure, insecure and bogus; indeterminate counts in the total).
export const RECURSION_TILES = ["dns-subqueries", "dns-validation"] as const;
export type RecursionTileName = (typeof RECURSION_TILES)[number];

/** The validation outcomes a tile names, in their order. */
export const VALIDATION_STATES = ["secure", "insecure", "bogus"] as const;

function recursionValue(name: RecursionTileName, dns: MetricsDns): number | null {
  const r = dns.recursion;
  if (!r) return null;
  if (name === "dns-subqueries") return r.subqueries_per_second;
  const v = r.validation;
  return v.secure + v.insecure + v.bogus + v.indeterminate;
}
// WP10.4: end.

// OPS-20: the host's tiles, in a group after the controller's while the sample has `host`: the busy
// share of the CPU, the memory in use and the space available on the data directory's file system.
export const HOST_TILES = ["host-cpu", "host-memory", "host-disk"] as const;
export type HostTileName = (typeof HOST_TILES)[number];

/** The code of the status warning that the disk tile turns to the warning style for. */
export const DISK_LOW_WARNING = "node.disk.low";

/** Bytes in a GiB, the unit of the memory and disk tiles. */
export const GIB = 1024 ** 3;

/** The memory in use in bytes: the total less what a program can use without swapping; null if either is unknown. */
export function memoryUsed(host: MetricsHost): number | null {
  if (host.memory_total == null || host.memory_available == null) return null;
  return Math.max(0, host.memory_total - host.memory_available);
}

/** The memory in use as a share of the total, in percent; null when it is not known or the total is zero. */
export function memoryPercent(host: MetricsHost): number | null {
  const used = memoryUsed(host);
  return used == null || !host.memory_total ? null : (used * 100) / host.memory_total;
}

function isHostTile(name: TileName): name is HostTileName {
  return name.startsWith("host-");
}

function hostValue(name: HostTileName, host: MetricsHost): number | null {
  switch (name) {
    case "host-cpu":
      return host.cpu_percent ?? null;
    case "host-memory":
      return memoryPercent(host);
    case "host-disk":
      return host.disk_available == null ? null : host.disk_available / GIB;
  }
}

export type TileName = (typeof TILES)[number] | DnsTileName | DhcpTileName | RecursionTileName | HostTileName;

/** The RCODEs of the answers tile, in the order they are listed. */
export const RCODES = ["noerror", "nxdomain", "servfail", "refused", "other"] as const;

/** The share of the answers in `rcode`, in percent; null without answers. */
export function rcodeShare(dns: MetricsDns, rcode: (typeof RCODES)[number]): number | null {
  const all = RCODES.reduce((sum, code) => sum + dns.rcodes[code], 0);
  return all > 0 ? (dns.rcodes[rcode] * 100) / all : null;
}

/** The queries blocked per second over every list. */
export function blockedTotal(dns: MetricsDns): number {
  return dns.blocked.reduce((sum, list) => sum + list.per_second, 0);
}

/** The three lists that blocked most in the sample, the most first; lists that blocked nothing are left out. */
export function topLists(dns: MetricsDns): MetricsDns["blocked"] {
  return dns.blocked
    .filter((list) => list.per_second > 0)
    .sort((a, b) => b.per_second - a.per_second || a.list.localeCompare(b.list))
    .slice(0, 3);
}

function isDnsTile(name: TileName): name is DnsTileName {
  // WP10.4: the recursion tiles are DNS tiles with values of their own.
  return name.startsWith("dns-") && !(RECURSION_TILES as readonly string[]).includes(name);
}

function dnsValue(name: DnsTileName, dns: MetricsDns): number | null {
  switch (name) {
    case "dns-queries":
      return dns.queries_per_second;
    case "dns-cache":
      return dns.cache.hit_ratio == null ? null : dns.cache.hit_ratio * 100;
    case "dns-answers":
      return rcodeShare(dns, "noerror");
    case "dns-blocked":
      return blockedTotal(dns);
    case "dns-upstreams":
      return dns.upstreams.queries_per_second;
    case "dns-encrypted":
      return dns.connections ? dns.connections.dot + dns.connections.doh : null;
  }
}

/** The highest replication lag of a sample. */
export function highestLag(sample: MetricsSample): number {
  return sample.raft.lag.reduce((max, lag) => Math.max(max, lag.entries), 0);
}

/** The batches waiting in the buffers of the connected nodes of a sample. */
export function bufferedBatches(sample: MetricsSample): number {
  return sample.nodes.reduce((sum, node) => sum + node.buffer_batches, 0);
}

/** The batches the connected nodes dropped; null when no node reports it. */
export function droppedBatches(sample: MetricsSample): number | null {
  const known = sample.nodes.filter((node) => node.drops != null);
  return known.length === 0 ? null : known.reduce((sum, node) => sum + (node.drops ?? 0), 0);
}

/** The number a tile shows for a sample; null when the sample has none. */
export function tileValue(name: TileName, sample: MetricsSample): number | null {
  if (isDnsTile(name)) return sample.dns ? dnsValue(name, sample.dns) : null;
  // WP10.4: the recursion tiles.
  if (name === "dns-subqueries" || name === "dns-validation") return sample.dns ? recursionValue(name, sample.dns) : null;
  // WP8.7: the DHCP tiles.
  if (isDhcpTile(name)) return sample.dhcp ? dhcpValue(name, sample.dhcp) : null;
  // OPS-20: the host tiles.
  if (isHostTile(name)) return sample.host ? hostValue(name, sample.host) : null;
  switch (name) {
    case "requests":
      return sample.api.requests_per_second;
    case "commit":
      return sample.store.commit_p99_ms ?? null;
    case "store":
      return sample.store.file_bytes ?? sample.store.data_bytes;
    case "raft":
      return highestLag(sample);
    case "jobs":
      return sample.jobs.running;
    case "ingest":
      return sample.ingest.facts_per_second;
    case "sse":
      return sample.sse.subscribers;
    case "nodes":
      return bufferedBatches(sample);
  }
}

/** The lag of controller `node` as the cluster reports it (the leader knows every member's). */
export function lagOf(snapshot: MetricsSnapshot, node: number): number | null {
  const own = snapshot.nodes.find((sample) => sample.node === node);
  const entry =
    snapshot.cluster.raft.lag.find((lag) => lag.node === node) ?? own?.raft.lag.find((lag) => lag.node === node);
  return entry?.entries ?? null;
}

/** A sample's state for its row: current, stale (no answer) or unsupported (an older build). */
export function sampleState(sample: MetricsSample): "current" | "stale" | "unsupported" {
  if (sample.unsupported) return "unsupported";
  return sample.stale ? "stale" : "current";
}

/** The tiles whose figure is a share over a window rather than the share of one second. */
export type RatioTile = "dns-cache" | "dns-answers";
/** Seconds per bar of a ratio tile's bar chart; the edges of a bar are multiples of it on the controller's clock. */
export const BUCKET_SECONDS = 5;
/** Completed buckets behind the headline of a ratio tile and the rates beside it: 30 seconds. */
export const COMPLETED_BUCKETS = 6;
/** Seconds behind the headline of a ratio tile. */
export const RATIO_WINDOW = COMPLETED_BUCKETS * BUCKET_SECONDS;
/** Bars of a ratio tile's bar chart: the completed buckets and the one in progress, the newest, at the end. */
export const BUCKETS = COMPLETED_BUCKETS + 1;

/** A sample of the cluster with the bucket its own timestamp falls in: `floor(t / bucketSeconds)`. */
interface Placed {
  bucket: number;
  sample: MetricsSample;
}

/**
 * The samples with their buckets. A bucket is a pure function of the sample's own time (the
 * controller's clock), never of how many samples came after it, so a new sample inside a bucket
 * cannot move an older one into another bucket. A sample with a time that does not parse is left out.
 */
function placeSamples(samples: readonly MetricsSample[], bucketSeconds: number): Placed[] {
  const out: Placed[] = [];
  for (const sample of samples) {
    const ms = Date.parse(sample.at);
    if (Number.isFinite(ms)) out.push({ bucket: Math.floor(ms / (bucketSeconds * 1000)), sample });
  }
  return out;
}

/** The bucket the newest sample is in: the one in progress; null without samples. */
function newestBucket(placed: readonly Placed[]): number | null {
  const last = placed[placed.length - 1];
  return last ? last.bucket : null;
}

/**
 * The samples behind the headline and the rates of a ratio tile: those of the last
 * `COMPLETED_BUCKETS` buckets before the one in progress, so the window only moves when a bucket
 * boundary passes and it is the same set of samples as the bars before the lighter one. While no
 * completed bucket holds a sample (the page just opened) it is the samples of the bucket in progress.
 */
function windowSamples(history: MetricsHistory): MetricsSample[] {
  const placed = placeSamples(history.cluster, BUCKET_SECONDS);
  const newest = newestBucket(placed);
  if (newest === null) return [];
  const completed = placed.filter((p) => p.bucket < newest && p.bucket >= newest - COMPLETED_BUCKETS);
  const chosen = completed.length > 0 ? completed : placed.filter((p) => p.bucket === newest);
  return chosen.map((p) => p.sample);
}

/**
 * What a sample adds to the share of a ratio tile: the rate that counts (hits, NOERROR answers)
 * and the rate of everything (hits and misses, all answers). A sample without the `dns` part adds nothing.
 */
function ratioParts(tile: RatioTile, sample: MetricsSample): readonly [number, number] {
  const dns = sample.dns;
  if (!dns) return [0, 0];
  if (tile === "dns-cache") return [dns.cache.hits_per_second, dns.cache.hits_per_second + dns.cache.misses_per_second];
  return [dns.rcodes.noerror, RCODES.reduce((sum, code) => sum + dns.rcodes[code], 0)];
}

/**
 * The share over `samples` as a fraction: the sum of the counting rates over the sum of all rates,
 * never an average of per-second shares, so a quiet second weighs nothing. Null when no query fell in them.
 */
function sharedRatio(tile: RatioTile, samples: readonly MetricsSample[]): number | null {
  let part = 0;
  let all = 0;
  for (const sample of samples) {
    const [p, a] = ratioParts(tile, sample);
    part += p;
    all += a;
  }
  return all > 0 ? part / all : null;
}

/**
 * The share of a ratio tile over its window (the completed buckets of the last 30 seconds, see
 * `windowSamples`) in percent; null without queries. It is the share of the bars before the one in
 * progress taken together, and changes when a bucket completes.
 */
export function windowRatio(history: MetricsHistory, tile: RatioTile): number | null {
  const ratio = sharedRatio(tile, windowSamples(history));
  return ratio === null ? null : ratio * 100;
}

/**
 * The mean per second of a DNS rate over the same window as `windowRatio`: the counts (rate times the
 * sample's interval) over the seconds. The per-second figure of one sample is a count over one
 * second, so under light load it reads zero while the share of a bucket is a share of real queries;
 * the mean over 30 seconds is the rate the bars and the headline are made of. Null without a `dns` sample.
 */
export function windowRate(history: MetricsHistory, pick: (dns: MetricsDns) => number): number | null {
  return windowMean(history, (sample) => (sample.dns ? pick(sample.dns) : null));
}

/**
 * U3: the mean per second of any rate of a sample over the window of `windowRate` (the DHCP panel's
 * leases, NAKs and DDNS); a sample whose `pick` is null (it lacks the part) adds nothing. Null
 * without a sample that has it.
 */
export function windowMean(history: MetricsHistory, pick: (sample: MetricsSample) => number | null | undefined): number | null {
  let count = 0;
  let seconds = 0;
  for (const sample of windowSamples(history)) {
    const value = pick(sample);
    if (value == null || !(sample.interval_ms > 0)) continue;
    const dt = sample.interval_ms / 1000;
    count += value * dt;
    seconds += dt;
  }
  return seconds > 0 ? count / seconds : null;
}

/**
 * The share per bucket as a fraction (0 to 1), oldest bucket first, always `buckets` long. The buckets
 * have fixed edges (`floor(t / bucketSeconds)` of the samples' own times) and the last one is the bucket
 * of the newest sample, still filling: a sample inside it changes that bar only, and the bars shift one
 * step when a sample of the next bucket arrives. A bucket without queries (or without samples, early in
 * the page's life or after a gap) is null. Defaults to the cache tile.
 */
export function ratioBuckets(
  history: MetricsHistory,
  bucketSeconds: number,
  buckets: number,
  tile: RatioTile = "dns-cache",
): (number | null)[] {
  const placed = placeSamples(history.cluster, bucketSeconds);
  const newest = newestBucket(placed);
  const out: (number | null)[] = Array.from({ length: buckets }, () => null);
  if (newest === null) return out;
  const groups = new Map<number, MetricsSample[]>();
  for (const { bucket, sample } of placed) {
    if (bucket > newest || bucket <= newest - buckets) continue;
    const group = groups.get(bucket);
    if (group) group.push(sample);
    else groups.set(bucket, [sample]);
  }
  for (const [bucket, samples] of groups) out[buckets - 1 - (newest - bucket)] = sharedRatio(tile, samples);
  return out;
}

// U3: the queries chart of the DNS panel: the mean rate per 5-second bucket over five minutes,
// with the same fixed bucket edges as the ratio tiles, so a bar is born on the right and walks
// left one step per bucket, and the scale of its axis.

/** Bars of the queries chart: five minutes of 5-second buckets, the one in progress last. */
export const RATE_BUCKETS = LONG_HISTORY / BUCKET_SECONDS;

/**
 * The mean per second of a DNS rate per bucket, oldest first, always `buckets` long: the counts
 * (rate times the sample's interval) of the samples of a bucket over their seconds. The buckets
 * have the fixed edges of `ratioBuckets`; the last is the bucket of the newest sample, still
 * filling. A bucket without a `dns` sample is null.
 */
export function rateBuckets(
  history: MetricsHistory,
  pick: (dns: MetricsDns) => number,
  bucketSeconds = BUCKET_SECONDS,
  buckets = RATE_BUCKETS,
): (number | null)[] {
  const placed = placeSamples(history.cluster, bucketSeconds);
  const newest = newestBucket(placed);
  const out: (number | null)[] = Array.from({ length: buckets }, () => null);
  if (newest === null) return out;
  const count = new Map<number, number>();
  const seconds = new Map<number, number>();
  for (const { bucket, sample } of placed) {
    if (bucket > newest || bucket <= newest - buckets) continue;
    if (!sample.dns || !(sample.interval_ms > 0)) continue;
    const dt = sample.interval_ms / 1000;
    count.set(bucket, (count.get(bucket) ?? 0) + pick(sample.dns) * dt);
    seconds.set(bucket, (seconds.get(bucket) ?? 0) + dt);
  }
  for (const [bucket, s] of seconds) out[buckets - 1 - (newest - bucket)] = (count.get(bucket) ?? 0) / s;
  return out;
}

/**
 * The top of a chart's axis for values up to `max`: the next of 1, 2, 2.5 and 5 times a power of
 * ten at or above it, so the axis reads in round numbers; 1 for an empty or quiet chart.
 */
export function niceCeiling(max: number): number {
  if (!(max > 0) || !Number.isFinite(max)) return 1;
  const power = 10 ** Math.floor(Math.log10(max));
  for (const step of [1, 2, 2.5, 5, 10]) {
    const top = step * power;
    if (top >= max * (1 - 1e-9)) return Number(top.toPrecision(12));
  }
  return 10 * power;
}
