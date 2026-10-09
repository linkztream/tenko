// `expand=host` on the address lists (WP1.4c): every bound address row gains
// `interface_detail { id, name, mac, duid }` and `host { id, name, mode, lock }`. The
// parameter may repeat or hold a comma-separated list; any other value is refused.
import type { Address, AddressRow } from "../../types";
import { invalidQuery } from "./problems";
import type { IpamData } from "./state";

/** Whether the request asks for the host expansion (and nothing unknown). */
export function wantsHost(url: URL): boolean {
  const values = url.searchParams
    .getAll("expand")
    .flatMap((v) => v.split(","))
    .map((v) => v.trim())
    .filter(Boolean);
  for (const value of values) if (value !== "host") throw invalidQuery("expand", value, "expand must be host");
  return values.length > 0;
}

/** The row of an address, with its interface and host when they exist and are live. */
export function expandAddress(data: IpamData, address: Address): AddressRow {
  const iface = address.interface ? data.interface.get(address.interface) : undefined;
  if (!iface || iface.meta.deleted) return address;
  const host = data.host.get(iface.host);
  return {
    ...address,
    interface_detail: { id: iface.id, name: iface.name, mac: iface.mac ?? null, duid: iface.duid ?? null },
    host: host && !host.meta.deleted ? { id: host.id, name: host.name, mode: host.mode, lock: host.lock ?? false } : null,
  };
}
