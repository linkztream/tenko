// The common setup of the DHCP scenarios: a network, optionally a pool in it and a scope for it.

import type { Api, Schemas } from "./api";

export interface ScopeSetup {
  cidr: string;
  description: string;
  /** An address range with the role `dhcp_pool` in the network. */
  pool?: { first: string; last: string };
  /** The DHCP scope of the network: `false` for none, otherwise the fields besides the prefix (default: a scope of the prefix alone). */
  scope?: false | Record<string, unknown>;
}

/**
 * Creates the network and, as `setup` says, its pool and its scope. Answers the network and the pool.
 */
export async function arrangeScope(
  api: Api,
  setup: ScopeSetup & { pool: { first: string; last: string } },
): Promise<{ prefix: Schemas["Prefix"]; pool: Schemas["Range"] }>;
export async function arrangeScope(api: Api, setup: ScopeSetup): Promise<{ prefix: Schemas["Prefix"]; pool?: Schemas["Range"] }>;
export async function arrangeScope(api: Api, setup: ScopeSetup): Promise<{ prefix: Schemas["Prefix"]; pool?: Schemas["Range"] }> {
  const prefix = (await api.post<Schemas["WriteResponse_Prefix"]>("/prefixes", { cidr: setup.cidr, description: setup.description })).item!;
  const pool = setup.pool
    ? (await api.post<Schemas["WriteResponse_Range"]>(`/prefixes/${prefix.id}/ranges`, { ...setup.pool, role: "dhcp_pool" })).item!
    : undefined;
  if (setup.scope !== false) await api.post("/dhcp/scopes", { prefix: prefix.id, ...setup.scope });
  return { prefix, pool };
}
