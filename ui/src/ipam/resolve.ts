// Hosts by id, read once per tab: the jobs views name the hosts a job targets. Address rows
// carry their interface and host themselves (`expand=host` on the address lists), so this is
// the only lookup left. An `ipam` event that touches a cached host drops it.
import { api } from "../api/client";
import { events } from "../api/events";
import type { Host } from "../api/types";

const hosts = new Map<string, Promise<Host | null>>();

/** A host by id, cached for the tab; null when it cannot be read. */
export function readHost(id: string): Promise<Host | null> {
  let p = hosts.get(id);
  if (!p) {
    p = api.get("/api/v1/hosts/{id}", { path: { id } }).catch(() => null);
    hosts.set(id, p);
  }
  return p;
}

/** Forgets every cached host (tests start each one from a fresh mock). */
export function forgetHosts(): void {
  hosts.clear();
}

events.subscribe("ipam", (e) => {
  for (const ref of [...e.objects, ...e.deleted]) if (ref.kind === "host") hosts.delete(ref.id);
});
events.onReset("ipam", forgetHosts);
