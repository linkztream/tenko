// The types of the DHCP area (WP7.4) and the pure readers that need no client: the views, the
// helpers (model.ts) and the mock service (src/api/mock/dhcp-model.ts, also run by the
// end-to-end fakes in Node) share them. api.ts re-exports them with the requests.
import type { components } from "../api/generated/schema";

type S = components["schemas"];

export type Scope = S["DhcpScopeItem"];
export type ScopeCreate = S["DhcpScopeCreate"];
export type ScopePatch = S["DhcpScopePatch"];
export type Utilization = S["DhcpScopeUtilization"];
export type Settings = S["DhcpSettingsItem"];
export type SettingsUpdate = S["DhcpSettingsUpdate"];
export type SharedNetwork = S["SharedNetworkItem"];
export type SharedNetworkCreate = S["SharedNetworkCreate"];
export type SharedNetworkPatch = S["SharedNetworkPatch"];
export type Pool = S["DhcpPoolItem"];
export type PoolSet = S["DhcpPoolSet"];
export type Exclusion = S["ExclusionItem"];
export type ExclusionCreate = S["ExclusionCreate"];
export type CatalogEntry = S["OptionCatalogItem"];
export type OptionDef = S["OptionDefItem"];
export type OptionDefCreate = S["OptionDefCreate"];
export type OptionDefPatch = S["OptionDefPatch"];
export type OptionSet = S["OptionSetItem"];
export type OptionSetPut = S["OptionSetPut"];
export type OptionValueItem = S["OptionValueItem"];
export type OptionValueInput = S["OptionValueInput"];
export type OptionData = S["OptionData"];
export type OptionKind = S["OptionKind"];
export type OptionLevel = S["OptionLevel"];
export type OptionOwner = S["OptionOwner"];
export type EffectiveOptions = S["EffectiveOptions"];
export type EffectiveOption = S["EffectiveOption"];
export type DhcpClass = S["DhcpClassItem"];
export type ClassCreate = S["DhcpClassCreate"];
export type ClassPatch = S["DhcpClassPatch"];
export type Match = S["Match"];
export type Condition = S["Condition"];
export type Term = S["Term"];
export type Join = S["Join"];
export type Policy = S["DhcpPolicyItem"];
export type PolicyCreate = S["DhcpPolicyCreate"];
export type PolicyPatch = S["DhcpPolicyPatch"];
export type PolicyAction = S["PolicyAction"];
export type MacFilter = S["DhcpFilterItem"];
export type FilterCreate = S["DhcpFilterCreate"];
export type FilterPatch = S["DhcpFilterPatch"];
export type FilterKind = S["FilterKind"];
export type LeaseTimes = S["LeaseTimes"];
export type DdnsPolicy = S["DdnsPolicy"];
export type Prefix = S["Prefix"];

/** The kinds of option data a value input edits, in the order the option type menu lists them. */
export const OPTION_KINDS: readonly OptionKind[] = [
  "ipv4_address",
  "ipv6_address",
  "ipv6_prefix",
  "u8",
  "u16",
  "u32",
  "i32",
  "bool",
  "string",
  "fqdn",
  "classless_routes",
  "binary",
  "empty",
];

/** The levels of the effective options, least specific first. */
export const OPTION_LEVELS: readonly OptionLevel[] = ["server", "shared_network", "scope", "pool", "policy", "host"];

/** The nil UUID: in a scope PATCH it leaves the shared network. */
export const NIL_ID = "00000000-0000-0000-0000-000000000000";

/** The longest lease the model accepts: one year (`tenko_core::dhcp::MAX_LEASE_SECS`). */
export const MAX_LEASE_SECS = 365 * 24 * 3600;
