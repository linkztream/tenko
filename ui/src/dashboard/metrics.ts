// The live metrics of the start page (OPS-20): the samples of the `metrics` topic of the event
// stream, one snapshot per second while the page is open, kept for a minute per controller and
// for the cluster. No request module: the data arrives on the stream only.
import type { components } from "../api/generated/schema";

type S = components["schemas"];
export type MetricsSnapshot = S["MetricsSnapshot"];
export type MetricsSample = S["MetricsSample"];
export type MetricsDns = S["MetricsDns"];

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
 * only while the role serves DoT or DoH.
 */
export const DNS_TILES = ["dns-queries", "dns-cache", "dns-answers", "dns-blocked", "dns-upstreams", "dns-encrypted"] as const;
export type DnsTileName = (typeof DNS_TILES)[number];
export type TileName = (typeof TILES)[number] | DnsTileName;

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
  return name.startsWith("dns-");
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
