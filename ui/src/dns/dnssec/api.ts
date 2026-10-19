// The DNSSEC requests of the zone page (WP6.3): the signing state of a zone, the start of a
// key rollover, and signing switched on and off through the zone's `dnssec` policy (one PATCH
// with the zone's revision). The DS lines are what the operator copies to the parent zone.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { updateZone, type Zone } from "../api";

type S = components["schemas"];

export type DnssecStatus = S["DnssecStatus"];
export type DnssecKey = S["DnssecKeyItem"];
export type DnssecPolicy = S["DnssecPolicy"];
export type DnssecAlgorithm = S["DnssecAlgorithm"];
export type KeyRole = S["KeyRole"];
export type KeyState = S["KeyState"];

export const ALGORITHMS: readonly DnssecAlgorithm[] = ["ecdsa_p256_sha256", "ed25519"];

/** The algorithm number of the DNSKEY, for the DS line. */
export function algorithmNumber(algorithm: DnssecAlgorithm): number {
  return algorithm === "ed25519" ? 15 : 13;
}

export function getDnssec(id: string, signal?: AbortSignal): Promise<DnssecStatus> {
  return api.get("/api/v1/dns/zones/{id}/dnssec", { path: { id }, signal });
}

export function startRollover(id: string, role: KeyRole): Promise<S["DnsJobStarted"]> {
  return api.post("/api/v1/dns/zones/{id}/dnssec/rollover", { path: { id }, body: { role } });
}

/** The zone's policy with `change` applied, saved with the zone's revision. */
export function savePolicy(zone: Pick<Zone, "id" | "revision" | "dnssec">, change: Partial<DnssecPolicy>): Promise<Zone> {
  return updateZone(zone, { dnssec: { ...(zone.dnssec ?? {}), ...change } });
}

/** The DS records of the status in presentation form: `example.test. IN DS 12345 13 2 ABCD…`. */
export function dsLines(apex: string, status: Pick<DnssecStatus, "ds">): string[] {
  const out: string[] = [];
  for (const record of status.ds) {
    if (record.type !== "DS") continue;
    out.push(`${apex}. IN DS ${record.key_tag} ${record.algorithm} ${record.digest_type} ${record.digest.toUpperCase()}`);
  }
  return out;
}

/** Whether the zone uses a combined key (CSK). */
export function usesCsk(zone: Pick<Zone, "dnssec">): boolean {
  return Boolean(zone.dnssec?.csk);
}

/** Whether a policy denies with NSEC3. */
export function isNsec3(policy: DnssecPolicy | null | undefined): boolean {
  return policy?.denial?.kind === "nsec3";
}
