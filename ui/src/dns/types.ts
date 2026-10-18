// The types of the DNS area and the pure readers of a zone, without the client: the views, the
// pure helpers (model.ts) and the mock service (src/api/mock/dns-model.ts, also run by the
// end-to-end fakes in Node) share them. api.ts re-exports them with the requests.
import type { components } from "../api/generated/schema";

type S = components["schemas"];

/** The RRsets of one origin in a zone (`ZoneItem.origins`, read as optional until WP4.2 lands it). */
export interface OriginCount {
  origin: S["Origin"];
  rrsets: number;
}
/**
 * A zone as the list and the zone page read it. The document flattens `Zone` (whose `serial` is
 * the policy) and adds `serial` (the number served now), one JSON key for two things; the lead
 * renames the number `soa_serial`. Read both through `servedSerial` and `serialPolicy`.
 */
export type Zone = Omit<S["Zone"], "serial"> & {
  revision: number;
  rrsets: number;
  serial?: S["SerialPolicy"] | number | null;
  soa_serial?: number;
  origins?: OriginCount[];
};

/** The SOA serial the zone serves now. */
export function servedSerial(zone: Pick<Zone, "serial" | "soa_serial">): number | undefined {
  if (typeof zone.soa_serial === "number") return zone.soa_serial;
  return typeof zone.serial === "number" ? zone.serial : undefined;
}

/** How the serial moves; the server's default (`date_counter`) when the answer does not say. */
export function serialPolicy(zone: Pick<Zone, "serial">): S["SerialPolicy"] {
  return typeof zone.serial === "string" ? zone.serial : "date_counter";
}
export type ZoneCreate = S["ZoneCreate"];
export type ZonePatch = S["ZonePatch"];
export type ZoneKind = S["ZoneKind"];
export type SerialPolicy = S["SerialPolicy"];
export type SoaDefaults = S["SoaDefaults"];
export type PrimaryServer = S["PrimaryServer"];
export type SecondarySource = S["SecondarySource"];
export type TransferPolicy = S["TransferPolicy"];
export type NotifyTarget = S["NotifyTarget"];
export type TransferStatus = S["TransferStatus"];
export type PrimaryState = S["PrimaryState"];
export type Origin = S["Origin"];
export type RrSet = S["RrSetItem"];
export type RecordData = S["RecordData"];
export type RecordOp = S["RecordOp"];
export type RecordDiff = S["RecordDiff"];
export type BatchResult = S["RecordBatchResult"];
export type Acl = S["AclItem"];
export type AclEntry = S["AclEntry"];
export type AclCreate = S["AclCreate"];
export type AclPatch = S["AclPatch"];
export type DnsKey = S["KeyItem"];
export type KeyCreate = S["KeyCreate"];
export type KeyCreated = S["KeyCreated"];
export type TsigAlgorithm = S["TsigAlgorithm"];
export type ImportLoss = S["ImportLoss"];
export type AuditRecord = S["AuditRecord"];

/** One change of a batch; `take_over` replaces an RRset of another origin (sent only when true). */
export type RecordChange = S["RecordChange"] & { take_over?: boolean };

/** The records of one type that a zone file brings. */
export interface TypeCount {
  rtype: string;
  records: number;
}

/** The import report: added, replaced, removed, the losses, and the counts per type when present. */
export type ImportReport = S["ZoneFileImportReport"] & { types?: TypeCount[] };

export const ZONE_KINDS: readonly ZoneKind[] = ["primary", "secondary", "stub", "forward", "rpz"];
export const SERIAL_POLICIES: readonly SerialPolicy[] = ["unixtime", "counter", "date_counter"];
export const ORIGINS: readonly Origin[] = ["manual", "ipam", "dynamic", "dhcp", "ad", "transfer"];
export const TSIG_ALGORITHMS: readonly TsigAlgorithm[] = ["hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-sha1"];
