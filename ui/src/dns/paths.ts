// The paths of the DNS area. The shared table of links (src/app/paths.ts) belongs to the
// application shell; the DNS area keeps its own entries here until they are folded in.
// Zones are addressed by their identifier; the name may repeat across views later.
import { seg } from "../app/paths";

/** The tabs of the zone page. */
export type ZoneTab = "records" | "settings" | "history";

export const dnsPaths = {
  zones: (q?: string) => (q ? `/dns?q=${encodeURIComponent(q)}` : "/dns"),
  zone: (id: string, tab?: ZoneTab) => (tab && tab !== "records" ? `/dns/zones/${seg(id)}/${tab}` : `/dns/zones/${seg(id)}`),
  zoneImport: (id: string) => `/dns/import/${seg(id)}`,
  acls: () => "/dns/acls",
  keys: () => "/dns/keys",
  log: () => "/dns/log",
  forwarders: () => "/dns/forwarders",
  lists: () => "/dns/lists",
  // WP6.4
  views: () => "/dns/views",
  /** The DNS settings of a node (read-only, administrators): settings/dns. */
  settings: () => "/settings/dns",
} as const;
