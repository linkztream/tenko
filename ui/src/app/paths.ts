// Every deep link of the UI is built here, so routes and links agree. Paths carry FQDNs,
// IP addresses, prefixes and MACs as readable segments: a dot never marks a file (the
// server falls back to index.html for every path outside /assets/ and /api/, ADR 0008),
// and colons stay unescaped because they are valid in a path segment (RFC 3986 pchar).
// A prefix takes two segments, network and length: /ipam/prefixes/192.0.2.0/24.

/** Encodes one path segment, keeping ":" and "@" readable. */
export function seg(value: string | number): string {
  return encodeURIComponent(String(value)).replace(/%3A/gi, ":").replace(/%40/g, "@");
}

/**
 * Decodes a route parameter. @solidjs/router hands parameters over as they appear in the
 * URL, so a view reads `decodeSegment(params.fqdn)`; malformed escapes stay as they are.
 */
export function decodeSegment(value: string | undefined): string {
  if (value === undefined) return "";
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Splits "192.0.2.0/24" into its two path segments. */
function prefixSegments(cidr: string): string {
  const i = cidr.lastIndexOf("/");
  return i < 0 ? seg(cidr) : `${seg(cidr.slice(0, i))}/${seg(cidr.slice(i + 1))}`;
}

function withQuery(path: string, query?: Record<string, string | undefined>): string {
  if (!query) return path;
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== "") sp.set(k, v);
  const qs = sp.toString();
  return qs ? `${path}?${qs}` : path;
}

export type SettingsSection = "security" | "users";
export type AccountSection = "security" | "sessions" | "tokens";

/** Where an object of the move preview comes from: `host:<id>` or `address:<id>`. */
export interface MoveObject {
  kind: string;
  id: string;
}

export const paths = {
  dashboard: () => "/",
  // IPAM (views by WP1.10). A `vrf` query names the VRF when an identifier exists in several.
  ipam: () => "/ipam",
  prefix: (cidr: string, vrf?: string) => withQuery(`/ipam/prefixes/${prefixSegments(cidr)}`, { vrf }),
  addresses: (query?: Record<string, string | undefined>) => withQuery("/ipam/addresses", query),
  address: (ip: string, vrf?: string) => withQuery(`/ipam/addresses/${seg(ip)}`, { vrf }),
  hosts: (query?: Record<string, string | undefined>) => withQuery("/ipam/hosts", query),
  host: (fqdn: string) => `/ipam/hosts/${seg(fqdn)}`,
  mac: (mac: string) => `/ipam/macs/${seg(mac)}`,
  vlans: () => "/ipam/vlans",
  sites: () => "/ipam/sites",
  tenancy: () => "/ipam/tenants",
  tags: () => "/ipam/tags",
  customFields: () => "/ipam/custom-fields",
  move: (target: string, objects: readonly MoveObject[]) =>
    withQuery("/ipam/move", { target, objects: objects.map((o) => `${o.kind}:${o.id}`).join(",") }),
  imports: () => "/ipam/import",
  // DNS and DHCP (later phases)
  dns: () => "/dns",
  zone: (name: string) => `/dns/zones/${seg(name)}`,
  dhcp: () => "/dhcp",
  topology: () => "/topology",
  jobs: (query?: Record<string, string | undefined>) => withQuery("/jobs", query),
  job: (id: string) => `/jobs/${seg(id)}`,
  audit: (query?: Record<string, string | undefined>) => withQuery("/audit", query),
  auditRecord: (seq: number) => `/audit/${seq}`,
  // Settings and the account (WP1.9)
  settings: (section?: SettingsSection) => (section ? `/settings/${section}` : "/settings"),
  user: (id: string) => `/settings/users/${seg(id)}`,
  account: (section?: AccountSection) => (section ? `/account/${section}` : "/account"),
  // Focused pages
  signIn: (next?: string) => withQuery("/signin", { next: next && next !== "/" ? next : undefined }),
  setup: () => "/setup",
  search: (q: string) => withQuery("/search", { q }),
} as const;

/** A `next` parameter is only followed when it stays inside the application. */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  return next;
}
