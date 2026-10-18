// The requests of the forwarders page (docs/dns-resolver.md section 2.1): the forwarding rules
// with their revision, create, change (with `If-Match`) and delete. `all_views` in a change
// makes a rule apply in every view again; an empty `tls_name` or `description` clears it.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { fetchAll } from "../../api/paginate";

type S = components["schemas"];
export type ForwarderItem = S["ForwarderItem"];
export type ForwarderCreate = S["ForwarderCreate"];
export type ForwarderPatch = S["ForwarderPatch"];

export async function listForwarders(signal?: AbortSignal): Promise<{ items: ForwarderItem[]; revision: number }> {
  const all = await fetchAll<ForwarderItem>("/api/v1/dns/forwarders", { signal });
  return { items: all.items, revision: Number(all.revision) };
}

export function createForwarder(body: ForwarderCreate): Promise<ForwarderItem> {
  return api.post("/api/v1/dns/forwarders", { body });
}

export function updateForwarder(rule: Pick<ForwarderItem, "id" | "revision">, patch: ForwarderPatch): Promise<ForwarderItem> {
  return api.patch("/api/v1/dns/forwarders/{id}", { path: { id: rule.id }, body: patch, ifMatch: rule.revision });
}

export async function deleteForwarder(rule: Pick<ForwarderItem, "id" | "revision">): Promise<void> {
  await api.delete("/api/v1/dns/forwarders/{id}", { path: { id: rule.id }, ifMatch: rule.revision });
}
