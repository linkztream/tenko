// The rows of the reconciliation view of the mock API (WP8.2), apart from the msw handler
// (routes-ipam-reconcile.ts) so that the end-to-end tests answer the route in the browser with the
// same data: the seeded rows, the filter and the truths of a host. It needs no IPAM state and no
// msw. The rows use the documentation ranges: 192.0.2.0/24, MAC addresses 00:00:5e:00:53:xx and
// names under example.test.
import type { components } from "../generated/schema";
import { iso, MINUTE } from "./util";

type S = components["schemas"];
export type ReconcileRow = S["ReconcileRow"];
export type HostTruths = S["HostTruths"];
export type OsField = S["OsField"];
type Kind = S["ReconcileKind"];
type Mode = S["AssignmentMode"];

/** The identifiers the rows refer to. */
export interface ReconcileIds {
  vrf: string;
  prefix: string;
  /** The id of a host by name. */
  host: (name: string) => string;
  /** The id of the open discovered-host proposal. */
  proposal: string;
}

export const KINDS: readonly Kind[] = ["ghost", "rogue", "orphan", "ptr_mismatch", "conflict"];

const mac = (xx: string) => `00:00:5e:00:53:${xx}`;
const DAY = 24 * 60 * MINUTE;

/** The OS field of a DHCP fingerprint (the `dhcp:1` source). */
export function dhcpOs(now: number): OsField {
  return { guess: "Windows 10 or 11 (or Server 2016 and later)", confidence: 85, source: "dhcp:1", truth: "lease", last_seen: iso(now - 4 * MINUTE) };
}

/** The rows of the view, in the order of the answer: by address, then kind. */
export function seedRows(ids: ReconcileIds, now = Date.now()): ReconcileRow[] {
  const base = { vrf: ids.vrf, prefix: ids.prefix };
  const rows: ReconcileRow[] = [
    // A reserved host that nothing has shown for days: intent wins.
    {
      ...base,
      key: "192.0.2.5|ghost",
      kind: "ghost",
      address: "192.0.2.5",
      host: ids.host("ap-garage"),
      intent: { host: ids.host("ap-garage"), host_name: "ap-garage", mode: "reserved", status: "active", macs: [mac("05")], dns_name: "ap-garage.example.test" },
      dns: { forward: ["ap-garage.example.test"], ptr: ["ap-garage.example.test"], zones: ["example.test"] },
      macs: [mac("05")],
      vendors: [],
      winner: "intent",
      rule_id: "intent_managed",
      rule: "intent wins for a managed host",
      last_seen: iso(now - 3 * DAY),
    },
    // A dynamic host that has not renewed: the lease wins.
    {
      ...base,
      key: "192.0.2.20|ghost",
      kind: "ghost",
      address: "192.0.2.20",
      host: ids.host("laptop-ak"),
      intent: { host: ids.host("laptop-ak"), host_name: "laptop-ak", mode: "dynamic", status: "active", macs: [mac("14")], dns_name: "laptop-ak.example.test" },
      lease: { macs: [mac("14")], sources: ["dhcp:1"], last_seen: iso(now - 2 * DAY), expires_at: iso(now - 2 * DAY + 8 * 60 * MINUTE) },
      dns: { forward: ["laptop-ak.example.test"], ptr: ["laptop-ak.example.test"], zones: ["example.test"] },
      macs: [mac("14")],
      vendors: [],
      winner: "lease",
      rule_id: "lease_dynamic",
      rule: "the lease wins for a dynamic host",
      last_seen: iso(now - 2 * DAY),
    },
    // A DNS record for an address no host holds, written by IPAM: the orphan rule.
    {
      ...base,
      key: "192.0.2.77|orphan",
      kind: "orphan",
      address: "192.0.2.77",
      dns: { forward: ["old-nas.example.test"], ptr: ["old-nas.example.test"], zones: ["example.test"] },
      macs: [],
      vendors: [],
      winner: "intent",
      rule_id: "orphan_rule",
      rule: "IPAM wrote the record; the orphan rule removes or proposes it",
    },
    // The same finding for a record written by hand: it stays.
    {
      ...base,
      key: "192.0.2.78|orphan",
      kind: "orphan",
      address: "192.0.2.78",
      dns: { forward: ["lab-box.example.test"], ptr: [], zones: ["example.test"] },
      macs: [],
      vendors: [],
      winner: "dns",
      rule_id: "manual_record",
      rule: "written by hand, it stays as written",
    },
    // A lease and a scan without intent, with the OS of the DHCP fingerprint and a proposal.
    {
      ...base,
      key: "192.0.2.150|rogue",
      kind: "rogue",
      address: "192.0.2.150",
      lease: { macs: [mac("d1")], sources: ["dhcp:1"], last_seen: iso(now - 4 * MINUTE), expires_at: iso(now + 8 * 60 * MINUTE) },
      scan: { macs: [mac("d1")], sources: ["probe:2:arp"], last_seen: iso(now - 9 * MINUTE) },
      macs: [mac("d1")],
      os: dhcpOs(now),
      vendors: ["MSFT 5.0"],
      winner: "lease",
      rule_id: "newest_sighting",
      rule: "without intent the newest sighting wins",
      proposal: ids.proposal,
      last_seen: iso(now - 4 * MINUTE),
    },
    // A device only a scan has seen, with no proposal yet.
    {
      ...base,
      key: "192.0.2.151|rogue",
      kind: "rogue",
      address: "192.0.2.151",
      scan: { macs: [mac("d2")], sources: ["probe:2:arp"], last_seen: iso(now - 12 * MINUTE) },
      macs: [mac("d2")],
      vendors: [],
      winner: "scan",
      rule_id: "newest_sighting",
      rule: "without intent the newest sighting wins",
      last_seen: iso(now - 12 * MINUTE),
    },
    // A PTR that disagrees with the name of intent: intent wins.
    {
      ...base,
      key: "192.0.2.30|ptr_mismatch",
      kind: "ptr_mismatch",
      address: "192.0.2.30",
      host: ids.host("printer-1"),
      intent: { host: ids.host("printer-1"), host_name: "printer-1", mode: "static", status: "active", macs: [mac("1e")], dns_name: "printer-1.example.test" },
      dns: { forward: ["printer-1.example.test"], ptr: ["printer.example.test"], zones: ["example.test"] },
      macs: [mac("1e")],
      vendors: [],
      winner: "intent",
      rule_id: "intent_managed",
      rule: "intent wins for a managed host",
    },
    // A PTR that disagrees with a forward record no intent names: the forward record wins.
    {
      ...base,
      key: "192.0.2.90|ptr_mismatch",
      kind: "ptr_mismatch",
      address: "192.0.2.90",
      dns: { forward: ["media.example.test"], ptr: ["tv.example.test"], zones: ["example.test"] },
      macs: [],
      vendors: [],
      winner: "dns",
      rule_id: "forward_record",
      rule: "the forward record wins",
    },
    // Two devices on the address of a reserved host: nobody wins.
    {
      ...base,
      key: "192.0.2.44|conflict",
      kind: "conflict",
      address: "192.0.2.44",
      host: ids.host("speaker-den"),
      intent: { host: ids.host("speaker-den"), host_name: "speaker-den", mode: "reserved", status: "active", macs: [mac("2c")], dns_name: "speaker-den.example.test" },
      lease: { macs: [mac("2c")], sources: ["dhcp:1"], last_seen: iso(now - 20 * MINUTE) },
      scan: { macs: [mac("c8")], sources: ["probe:2:arp"], last_seen: iso(now - 6 * MINUTE) },
      dns: { forward: ["speaker-den.example.test"], ptr: ["speaker-den.example.test"], zones: ["example.test"] },
      macs: [mac("2c"), mac("c8")],
      vendors: [],
      rule_id: "never_automatic",
      rule: "two MAC addresses on one address are never resolved automatically",
      last_seen: iso(now - 6 * MINUTE),
    },
    {
      ...base,
      key: "192.0.2.131|conflict",
      kind: "conflict",
      address: "192.0.2.131",
      lease: { macs: [mac("e1")], sources: ["dhcp:1"], last_seen: iso(now - 15 * MINUTE) },
      scan: { macs: [mac("e2")], sources: ["probe:2:arp"], last_seen: iso(now - 14 * MINUTE) },
      macs: [mac("e1"), mac("e2")],
      vendors: [],
      rule_id: "never_automatic",
      rule: "two MAC addresses on one address are never resolved automatically",
      last_seen: iso(now - 14 * MINUTE),
    },
  ];
  return rows.sort((a, b) => compareAddress(a.address, b.address) || KINDS.indexOf(a.kind) - KINDS.indexOf(b.kind));
}

function compareAddress(a: string, b: string): number {
  const x = a.split(".").map(Number);
  const y = b.split(".").map(Number);
  for (let i = 0; i < 4; i += 1) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** The rows a query keeps: a kind, a prefix id and a host id. */
export function filterRows(rows: readonly ReconcileRow[], query: { kind?: string | null; prefix?: string | null; host?: string | null }): ReconcileRow[] {
  return rows.filter(
    (r) => (!query.kind || r.kind === query.kind) && (!query.prefix || r.prefix === query.prefix) && (!query.host || r.host === query.host || r.intent?.host === query.host),
  );
}

/** The truths of a host: its OS field by precedence, every guess and the vendors. */
export function hostTruths(host: { id: string; name: string; mode: Mode }, macs: readonly string[], ips: readonly string[], now = Date.now()): HostTruths {
  const os = macs.length > 0 ? dhcpOs(now) : null;
  return {
    host: host.id,
    name: host.name,
    mode: host.mode,
    macs: [...macs],
    ips: [...ips],
    os,
    os_guesses: os ? [os] : [],
    vendors: macs.length > 0 ? ["MSFT 5.0"] : [],
  };
}
