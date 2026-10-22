// The paths of the DHCP area. The shared table of links (src/app/paths.ts) belongs to the
// application shell; the DHCP area keeps its own entries here. A scope is addressed by the
// identifier of its IPAM prefix.
import { seg } from "../app/paths";

/** The tabs of the scope page; WP8.6 adds the DDNS and the network boot tabs. */
export type ScopeTab = "settings" | "pools" | "exclusions" | "options" | "ddns" | "boot";

export const DHCP_SETTINGS_PATH = "/settings/dhcp";

export const dhcpPaths = {
  scopes: () => "/dhcp",
  scope: (prefix: string, tab?: ScopeTab) => (tab && tab !== "settings" ? `/dhcp/scopes/${seg(prefix)}/${tab}` : `/dhcp/scopes/${seg(prefix)}`),
  sharedNetworks: () => "/dhcp/shared-networks",
  options: () => "/dhcp/options",
  classes: () => "/dhcp/classes",
  policies: () => "/dhcp/policies",
  filters: () => "/dhcp/filters",
  leases: () => "/dhcp/leases",
  history: () => "/dhcp/history",
  /** The server settings. */
  settings: () => DHCP_SETTINGS_PATH,
} as const;
