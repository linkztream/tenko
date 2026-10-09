// Helpers of the move scenario (WP1.11): the network a move starts from, the gesture that
// drops a row of a grid on a node of the prefix tree, and small readers of the move's
// results through the API.
//
// The addresses follow the documentation ranges (RFC 5737, RFC 7042 MAC, `.test` names), and
// the host is `reserved` with a DNS name, so its move has a DHCP task, a DNS task, an L2 task
// and an observation task for a person: the manual steps of exit criterion E8.

import { expect, type Locator, type Page } from "@playwright/test";
import type { Api, Schemas } from "./api";

export const SOURCE_CIDR = "192.0.2.0/24";
export const TARGET_CIDR = "198.51.100.0/24";
export const HOST_NAME = "printer";
export const HOST_MAC = "00-00-5E-00-53-20";
export const OLD_IP = "192.0.2.15";
export const NEW_IP = "198.51.100.15";
export const DNS_NAME = "printer.example.test";

/** The tag a rolled-back move leaves on the object it was asked to move. */
export const MOVE_FAILED_TAG = "move-failed";

/** The manual step kinds of the job of a `reserved` host with a DNS name, in job order. */
export const MANUAL_STEP_KINDS = ["ipam.move.dhcp", "ipam.move.dns", "ipam.move.l2", "ipam.move.observe"] as const;

interface Items<T> {
  items: T[];
}

export interface MoveLab {
  source: Schemas["Prefix"];
  target: Schemas["Prefix"];
  host: Schemas["Host"];
  interface: Schemas["Interface"];
  address: Schemas["Address"];
}

/**
 * Two networks, a `reserved` host with one interface (the MAC above) and the address
 * 192.0.2.15 with a DNS name on that interface: what a move starts from.
 */
export async function arrangeMoveLab(api: Api): Promise<MoveLab> {
  const source = await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: SOURCE_CIDR, description: "Office" });
  const target = await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: TARGET_CIDR, description: "Printers" });
  const created = await api.post<Schemas["WriteResponse_Host"]>("/hosts", {
    name: HOST_NAME,
    mode: "reserved",
    interfaces: [{ name: "eth0", mac: HOST_MAC }],
  });
  const host = created.item!;
  const interfaces = await api.get<Items<Schemas["Interface"]>>(`/hosts/${host.id}/interfaces`);
  const nic = interfaces.items[0]!;
  const address = await api.post<Schemas["WriteResponse_Address"]>("/addresses", {
    ip: OLD_IP,
    interface: nic.id,
    dns_name: DNS_NAME,
  });
  return { source: source.item!, target: target.item!, host, interface: nic, address: address.item! };
}

/** The live addresses on the interfaces of a host, read through the API. */
export async function addressesOf(api: Api, hostId: string): Promise<Schemas["Address"][]> {
  const interfaces = await api.get<Items<Schemas["Interface"]>>(`/hosts/${hostId}/interfaces`);
  const all = await api.get<Items<Schemas["Address"]>>("/addresses", { limit: 1000 });
  const ids = new Set(interfaces.items.map((nic) => nic.id));
  return all.items.filter((address) => !address.meta.deleted && address.interface != null && ids.has(address.interface));
}

/** The jobs of moves, oldest first (the writes through the API leave short `ipam.edit` jobs). */
export async function moveJobs(api: Api): Promise<Schemas["JobSummary"][]> {
  const jobs = await api.get<Items<Schemas["JobSummary"]>>("/jobs", { kind: "ipam.move", limit: 1000 });
  return [...jobs.items].reverse();
}

/** The move jobs of one job group (the list has no group filter). */
export async function jobsOfGroup(api: Api, group: string): Promise<Schemas["JobSummary"][]> {
  return (await moveJobs(api)).filter((job) => job.group === group);
}

/** The job group a page shows (`/jobs?group=...`). */
export function groupOf(page: Page): string {
  const group = new URL(page.url()).searchParams.get("group");
  if (!group) throw new Error(`no job group in ${page.url()}`);
  return group;
}

/** The step of the job page at `index` (`job-step` carries `data-index`). */
export function stepAt(scope: Page | Locator, index: number): Locator {
  return scope.locator(`[data-testid="job-step"][data-index="${index}"]`);
}

/**
 * Drops `source` (a grid row, which is `draggable`) on `target` (a tree node). The UI listens
 * to the HTML5 drag events: `dragstart` on the row, `dragover` and `drop` on the node. In
 * Chromium `locator.dragTo` drives them with real mouse events (press on the row, moves,
 * release over the node), so no event has to be dispatched by hand.
 */
export async function dragOnto(source: Locator, target: Locator): Promise<void> {
  await expect(source).toBeVisible();
  await expect(target).toBeVisible();
  await source.dragTo(target);
}
