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

/** The `kind` of the events of the `metrics` topic. */
export const SNAPSHOT_KIND = "metrics.snapshot";
/** Samples kept per series: one minute. */
export const HISTORY = 60;

/** The samples of the last minute, oldest first: the cluster's and each controller's. */
export interface MetricsHistory {
  cluster: readonly MetricsSample[];
  nodes: ReadonlyMap<number, readonly MetricsSample[]>;
  latest: MetricsSnapshot | null;
}

export function emptyHistory(): MetricsHistory {
  return { cluster: [], nodes: new Map(), latest: null };
}

function keep<T>(list: readonly T[], item: T): T[] {
  const next = [...list, item];
  return next.length > HISTORY ? next.slice(next.length - HISTORY) : next;
}

/** The history with one more snapshot; a controller that left the snapshot is dropped. */
export function pushSnapshot(history: MetricsHistory, snapshot: MetricsSnapshot): MetricsHistory {
  const nodes = new Map<number, readonly MetricsSample[]>();
  for (const sample of snapshot.nodes) {
    if (sample.node == null) continue;
    nodes.set(sample.node, keep(history.nodes.get(sample.node) ?? [], sample));
  }
  return { cluster: keep(history.cluster, snapshot.cluster), nodes, latest: snapshot };
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

export type TileName = (typeof TILES)[number] | DnsTileName | DhcpTileName | RecursionTileName;

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
/** Seconds (samples) behind the headline of a ratio tile. */
export const RATIO_WINDOW = 30;
/** Seconds per bar of a ratio tile's bar chart. */
export const BUCKET_SECONDS = 5;
/** Bars of a ratio tile's bar chart: the last minute. */
export const BUCKETS = HISTORY / BUCKET_SECONDS;

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

/** The share of a ratio tile over the last `seconds` samples of the cluster, in percent; null without queries. */
export function windowRatio(history: MetricsHistory, tile: RatioTile, seconds = RATIO_WINDOW): number | null {
  const ratio = sharedRatio(tile, history.cluster.slice(-seconds));
  return ratio === null ? null : ratio * 100;
}

/**
 * The share per bucket as a fraction (0 to 1), oldest bucket first, always `buckets` long. The newest
 * bucket ends at the newest sample and each holds `bucketSeconds` samples; a bucket without queries
 * (or without samples, early in the page's life) is null. Defaults to the cache tile.
 */
export function ratioBuckets(
  history: MetricsHistory,
  bucketSeconds: number,
  buckets: number,
  tile: RatioTile = "dns-cache",
): (number | null)[] {
  const samples = history.cluster;
  const out: (number | null)[] = [];
  for (let i = buckets - 1; i >= 0; i--) {
    const end = samples.length - i * bucketSeconds;
    const start = Math.max(0, end - bucketSeconds);
    out.push(end > 0 ? sharedRatio(tile, samples.slice(start, end)) : null);
  }
  return out;
}
