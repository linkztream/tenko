// What other mock modules (the move mock, for one) use of the IPAM mock: read the state,
// find objects, list the addresses of a prefix, compute the next free address and apply a
// change through the same planner as the HTTP handlers.
import type { Address, AllocPolicy } from "../../types";
import { cidrOf, ipText } from "./net";
import "./reset";
import { store } from "./state";
import { addressesOfPrefix as addressesIn, findFreeAddress } from "./tree";

export { applyCommands, type ApplyOptions, type ApplyResult } from "./planner";
export { findAddress, findPrefix, ipamState } from "./state";
export { ADDRESS_IDS, HOST_IDS, INTERFACE_IDS, IPAM_IDS } from "./seed";

/** The live addresses of a prefix (those of its child prefixes too), in address order. */
export function addressesOfPrefix(prefixId: string): Address[] {
  const prefix = store.data.prefix.get(prefixId);
  return prefix ? addressesIn(store.data, prefix) : [];
}

export interface NextFreeOptions {
  /** Take the address with this host offset (for example the last octet of an IPv4 address) when it is free. */
  preferOffset?: bigint;
  /** Which end to allocate from; the policy of the prefix by default. */
  policy?: AllocPolicy;
}

/**
 * The next free address of a prefix as text: the address at `preferOffset` when that one is
 * free, else the lowest (or highest) address outside the DHCP pools, the reserved ranges
 * and the child prefixes. Null when the prefix is gone or full.
 */
export function nextFreeAddress(prefixId: string, options: NextFreeOptions = {}): string | null {
  const prefix = store.data.prefix.get(prefixId);
  if (!prefix || prefix.meta.deleted) return null;
  const value = findFreeAddress(store.data, prefix, {
    policy: options.policy ?? prefix.alloc ?? "lowest",
    preferOffset: options.preferOffset,
  });
  return value === null ? null : ipText(cidrOf(prefix.cidr).version, value);
}

/** The longest lease time in seconds among the live DHCP pools of a prefix, or null. */
export function longestLeaseSecs(prefixId: string): number | null {
  let longest: number | null = null;
  for (const range of store.data.range.values()) {
    if (range.prefix !== prefixId || range.meta.deleted || range.role !== "dhcp_pool") continue;
    if (typeof range.lease_secs === "number" && (longest === null || range.lease_secs > longest)) longest = range.lease_secs;
  }
  return longest;
}
