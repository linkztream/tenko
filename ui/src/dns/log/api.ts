// The requests of the query log page (WP5.4): the node this server is, the DNS role of a node
// with its query log, a page of the log through the node command `dns.log.read`, and the kill
// switch (`dns.log.stop`, `dns.log.start`). In Phase 2 the role runs in the controller's own
// process, so the one node to choose is this one; Phase 5 adds the remote nodes.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";

export type QueryLogLine = components["schemas"]["QueryLogLine"];
export type QueryLogStatus = components["schemas"]["QueryLogStatus"];
export type DnsNodeStatus = components["schemas"]["DnsNodeStatus"];

export interface LogPage {
  items: QueryLogLine[];
  next: string | null;
}

/** The query of a log read, as the API takes it. */
export interface LogQuery {
  cursor?: string;
  limit?: number;
  qname?: string;
  client?: string;
  rcode?: number;
  from?: string;
  until?: string;
}

/** The nodes whose log may be read: this server's node, when it has one. */
export async function logNodes(signal?: AbortSignal): Promise<number[]> {
  const status = await api.get("/api/v1/system/status", { signal });
  const id = status.node.id;
  return id === null || id === undefined ? [] : [Number(id)];
}

export function nodeDns(id: number, signal?: AbortSignal): Promise<DnsNodeStatus> {
  return api.get("/api/v1/nodes/{id}/dns", { path: { id }, signal });
}

export async function readLog(id: number, query: LogQuery, signal?: AbortSignal): Promise<LogPage> {
  const page = await api.get("/api/v1/nodes/{id}/dns/log", { path: { id }, query: { ...query }, signal });
  return { items: page.items, next: page.next_cursor ?? null };
}

export async function switchLog(id: number, stop: boolean): Promise<void> {
  if (stop) await api.post("/api/v1/nodes/{id}/dns/log/stop", { path: { id } });
  else await api.post("/api/v1/nodes/{id}/dns/log/start", { path: { id } });
}
