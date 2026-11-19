// Integration certificates (ADR 0035, docs/integrations.md): the records grouped into
// lineages, one per enrolled host, and the state an administrator reads at a glance.
import type { components } from "../../api/generated/schema";

export type CertRecord = components["schemas"]["ClientCertRecord"];
export type EnrollmentCode = components["schemas"]["EnrollmentCodeView"];
export type CreatedCode = components["schemas"]["CreatedCode"];

/** What an enrolled host's certificate lineage is doing. */
export type LineageState = "active" | "expiring" | "lapsed" | "revoked";

/** One enrolled host: the certificates of one lineage. */
export interface Lineage {
  id: string;
  account: string;
  label: string;
  state: LineageState;
  /** The certificate in use, or the last one when none is. */
  current: CertRecord;
  /** A renewed certificate the host has not presented yet. */
  pending: CertRecord | undefined;
}

/** The order the list shows: what needs a person first. */
const ORDER: Record<LineageState, number> = { lapsed: 0, expiring: 1, active: 2, revoked: 3 };

/**
 * From when a lineage that has not renewed counts as expiring: the last sixth of its
 * certificate's lifetime, the server's rule for the alarm `integration.certificate_expiring`.
 */
export function alarmAfter(record: CertRecord): number {
  const from = Date.parse(record.not_before);
  return from + ((Date.parse(record.not_after) - from) * 5) / 6;
}

/** The records grouped by lineage, with their state at `now`, problems first. */
export function lineages(records: readonly CertRecord[], now: number): Lineage[] {
  const byLineage = new Map<string, CertRecord[]>();
  for (const record of records) {
    byLineage.set(record.lineage, [...(byLineage.get(record.lineage) ?? []), record]);
  }
  const out: Lineage[] = [];
  for (const [id, members] of byLineage) {
    const newest = [...members].sort((a, b) => Date.parse(b.issued_at) - Date.parse(a.issued_at));
    const current = members.find((r) => r.state === "current") ?? newest[0]!;
    const pending = members.find((r) => r.state === "pending");
    let state: LineageState;
    if (members.every((r) => r.state === "revoked" || r.state === "withdrawn")) state = "revoked";
    else if (current.state !== "current" || Date.parse(current.not_after) <= now) state = pending ? "active" : "lapsed";
    else if (!pending && now >= alarmAfter(current)) state = "expiring";
    else state = "active";
    out.push({ id, account: current.account, label: current.label, state, current, pending });
  }
  return out.sort((a, b) => ORDER[a.state] - ORDER[b.state] || a.label.localeCompare(b.label));
}

/**
 * Why hosts on the network cannot reach the integration listener of the controller that made
 * a code: it is closed, or it listens on loopback addresses only (the API's default host
 * when the API is kept on loopback). `undefined` when they can, or when the answer does not say.
 */
export function unreachableListener(listen: readonly string[] | null | undefined): "closed" | "loopback" | undefined {
  if (!listen) return undefined;
  if (listen.length === 0) return "closed";
  const loopback = (address: string) =>
    address.startsWith("127.") || address.startsWith("[::1]") || address.startsWith("[::ffff:127.");
  return listen.every(loopback) ? "loopback" : undefined;
}

/** The codes that can still be used at `now`. */
export function waitingCodes(codes: readonly EnrollmentCode[], now: number): EnrollmentCode[] {
  return codes.filter((code) => code.state.state === "pending" && Date.parse(code.expires_at) > now);
}
