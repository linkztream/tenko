// The lifecycle of a host: decommissioned (retired but kept on record, its addresses
// released) and reinstated. The writes of the decommission and reinstate routes and the
// operations of the bulk route, shared by the hosts list, the host page and the Discovery
// page. The server decides every request; the lifecycle needs the right to delete the host.
import { ANY_REVISION, api } from "../api/client";
import type { BulkResponse, Host, HostLifecycle, IpamCommand, PlanWarning, WriteResponse } from "../api/types";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { warningText, writeQuery } from "../ipam/plan/describe";
import type { WriteLike } from "../ipam/plan/PlanDialog";

export const LIFECYCLES: readonly HostLifecycle[] = ["active", "decommissioned", "all"];

/** The most bytes a decommission reason may have (as the reason of a proposal). */
export const MAX_REASON_BYTES = 1024;

/** The `lifecycle` filter in a query parameter; anything else is the default, `active`. */
export function lifecycleOf(value: string | string[] | undefined): HostLifecycle {
  return value === "decommissioned" || value === "all" ? value : "active";
}

export function isDecommissioned(host: Pick<Host, "decommissioned">): boolean {
  return !!host.decommissioned;
}

/** The size of a reason as the server counts it: UTF-8 bytes of the trimmed text. */
export function reasonBytes(text: string): number {
  return new TextEncoder().encode(text.trim()).length;
}

/** What a person chooses when decommissioning: an optional reason and whether the DNS names stay. */
export interface DecommissionChoice {
  reason: string;
  keepDns: boolean;
}

export interface WriteOptions {
  dryRun: boolean;
  acknowledge: readonly string[];
}

type HostRevision = Pick<Host, "id"> & { meta: Pick<Host["meta"], "revision"> };

/** Decommissions a host (or previews it): the revision the person saw goes in `If-Match`. */
export function decommissionHost(host: HostRevision, choice: DecommissionChoice, o: WriteOptions): Promise<WriteResponse<Host>> {
  const reason = choice.reason.trim();
  return api.post("/api/v1/hosts/{id}/decommission", {
    path: { id: host.id },
    query: writeQuery(o.dryRun, o.acknowledge),
    body: { reason: reason === "" ? null : reason, keep_dns: choice.keepDns },
    ifMatch: host.meta.revision ?? ANY_REVISION,
  }) as Promise<WriteResponse<Host>>;
}

/** Reinstates a decommissioned host (or previews it). */
export function reinstateHost(host: HostRevision, o: WriteOptions): Promise<WriteResponse<Host>> {
  return api.post("/api/v1/hosts/{id}/reinstate", {
    path: { id: host.id },
    query: writeQuery(o.dryRun, o.acknowledge),
    ifMatch: host.meta.revision ?? ANY_REVISION,
  }) as Promise<WriteResponse<Host>>;
}

/** The hosts of a bulk request, each at the revision the person saw. */
export function bulkDecommission(hosts: readonly HostRevision[], choice: DecommissionChoice, o: WriteOptions): Promise<BulkResponse> {
  const reason = choice.reason.trim();
  const operations = hosts.map(
    (h) =>
      ({
        op: "decommission_host",
        args: { host: h.id, reason: reason === "" ? null : reason, keep_dns: choice.keepDns, expected: h.meta.revision ?? null },
      }) as IpamCommand,
  );
  return bulk(operations, o);
}

export function bulkReinstate(hosts: readonly HostRevision[], o: WriteOptions): Promise<BulkResponse> {
  const operations = hosts.map((h) => ({ op: "reinstate_host", args: { host: h.id, expected: h.meta.revision ?? null } }) as IpamCommand);
  return bulk(operations, o);
}

export function bulkDelete(hosts: readonly HostRevision[], cascade: boolean, o: WriteOptions): Promise<BulkResponse> {
  const operations = hosts.map(
    (h) => ({ op: "delete", args: { object: { kind: "host", id: h.id }, expected: h.meta.revision ?? null, cascade } }) as IpamCommand,
  );
  return bulk(operations, o);
}

function bulk(operations: IpamCommand[], o: WriteOptions): Promise<BulkResponse> {
  return api.post("/api/v1/hosts/bulk", { query: writeQuery(o.dryRun, o.acknowledge), body: { operations } }) as Promise<BulkResponse>;
}

/** The addresses a reinstatement did not bind again (`ipam.host.reinstate_skipped`). */
export function skippedOf(result: Pick<WriteLike, "warnings">): PlanWarning[] {
  return result.warnings.filter((w) => w.code === "ipam.host.reinstate_skipped");
}

/** The toasts of a reinstatement: the write itself, and what was not bound again. */
export function reinstatedToasts(title: string, result: WriteLike, writeToast: (title: string, result: WriteLike) => void): void {
  writeToast(title, result);
  const skipped = skippedOf(result);
  if (skipped.length > 0) {
    toast({ kind: "info", title: t("hosts.reinstate.skipped_title", { count: skipped.length }), body: skipped.map((w) => warningText(w)).join(" "), sticky: true });
  }
}

/** A host by identifier whatever its lifecycle; null when it cannot be read. */
export async function readHost(id: string, signal?: AbortSignal): Promise<Host | null> {
  try {
    return (await api.get("/api/v1/hosts/{id}", { path: { id }, signal })) as Host;
  } catch {
    return null;
  }
}
