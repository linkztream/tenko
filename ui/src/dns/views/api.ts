// The requests of the views page (DNS-20, docs/dns.md section 11): the views in order with
// their revision, create, change (with `If-Match`; a new `order` moves the view and the others
// make room) and delete. `default_recursion` in a change makes the view follow the profile's
// default again; an empty `description` clears it.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { fetchAll } from "../../api/paginate";

type S = components["schemas"];
export type ViewItem = S["ViewItem"];
export type ViewCreate = S["ViewCreate"];
export type ViewPatch = S["ViewPatch"];

export async function listViews(signal?: AbortSignal): Promise<{ items: ViewItem[]; revision: number }> {
  const all = await fetchAll<ViewItem>("/api/v1/dns/views", { signal });
  return { items: all.items, revision: Number(all.revision) };
}

export function createView(body: ViewCreate): Promise<ViewItem> {
  return api.post("/api/v1/dns/views", { body });
}

export function updateView(view: Pick<ViewItem, "id" | "revision">, patch: ViewPatch): Promise<ViewItem> {
  return api.patch("/api/v1/dns/views/{id}", { path: { id: view.id }, body: patch, ifMatch: view.revision });
}

export async function deleteView(view: Pick<ViewItem, "id" | "revision">): Promise<void> {
  await api.delete("/api/v1/dns/views/{id}", { path: { id: view.id }, ifMatch: view.revision });
}
