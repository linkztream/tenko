// When the views offer to reserve an address in DHCP (docs/dhcp.md, section 12.1): the principal
// may write IPAM where the address lies and may write DHCP, and the address's prefix has a DHCP
// scope (enabled or not; the dialog says which). The scopes are read once per view; a principal
// who may not read DHCP, or a server with the DHCP module off, gets none, so nothing is offered.
// The server still decides the request: it checks the IPAM writes the reservation makes.
import { createResource, type Accessor } from "solid-js";
import type { AddressRow } from "../../api/types";
import { may } from "../../auth/gate";
import { mayWriteDhcp } from "../access";
import { listScopes, type Scope } from "../api";

/** The scopes by prefix, and whether the answer (empty when they cannot be read) has arrived. */
export type ScopeIndex = Accessor<ReadonlyMap<string, Scope>> & { settled: Accessor<boolean> };

/**
 * The DHCP scopes by the prefix they serve; empty when they cannot be read. A view shows the rows
 * the gate judges only once `settled()`, so a row menu has its final shape the first time it opens.
 */
export function createScopeIndex(): ScopeIndex {
  const [scopes] = createResource(async () => {
    if (!mayWriteDhcp()) return new Map<string, Scope>();
    try {
      return new Map((await listScopes()).items.map((s) => [s.prefix, s] as const));
    } catch {
      return new Map<string, Scope>();
    }
  });
  // eslint-disable-next-line solid/reactivity -- accessors: the caller reads them inside its own tracked scope
  return Object.assign(() => (scopes.error ? new Map<string, Scope>() : (scopes.latest ?? new Map<string, Scope>())), {
    settled: () => !scopes.loading,
  });
}

/** Whether the views offer to reserve the address of this prefix. */
export function mayReserveIn(prefix: string | null | undefined, scopes: ReadonlyMap<string, Scope>): boolean {
  return !!prefix && scopes.has(prefix) && mayWriteDhcp() && may.inPrefix(prefix);
}

/** Whether the views offer to reserve this IPAM address. */
export function mayReserve(address: Pick<AddressRow, "prefix" | "meta">, scopes: ReadonlyMap<string, Scope>): boolean {
  return !address.meta.deleted && mayReserveIn(address.prefix, scopes);
}
