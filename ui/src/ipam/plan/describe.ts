// How plans, objects and warnings read in the UI: object labels from the IPAM objects of a
// plan, translated warning texts (falling back to the server's English), and the query of
// a write (`dry_run`, `acknowledge`).
import type { Query } from "../../api/client";
import type { CodedError, IpamObject, ObjectRef, PlanWarning, PlannedChange } from "../../api/types";
import { tDynamic } from "../../i18n";

/** The identifier a person knows the object by: a network, an address, a name. */
export function objectLabel(obj: IpamObject | null | undefined): string {
  if (!obj) return "";
  switch (obj.kind) {
    case "prefix":
      return obj.data.cidr;
    case "address":
      return obj.data.ip;
    case "range":
      return `${obj.data.first} - ${obj.data.last}`;
    case "vlan":
      return `${obj.data.vid} ${obj.data.name}`;
    case "custom_field":
      return obj.data.key;
    case "interface":
      return obj.data.mac ? `${obj.data.name} ${obj.data.mac}` : obj.data.name;
    default:
      return obj.data.name;
  }
}

/** The label of a planned change: from the object after the change, else before it. */
export function changeLabel(change: PlannedChange): string {
  return objectLabel(change.after ?? change.before) || change.object.id;
}

/** A reference's label when a plan or list knows the object, else its id. */
export function refLabel(ref: ObjectRef, changes: readonly PlannedChange[] = []): string {
  const change = changes.find((c) => c.object.kind === ref.kind && c.object.id === ref.id);
  return change ? changeLabel(change) : ref.id;
}

/** The translated text of a warning or coded error (`errors.<code>`), else the server's English. */
export function warningText(w: PlanWarning | CodedError): string {
  const params = Object.fromEntries(
    Object.entries(w.params ?? {}).map(([k, v]) => [k, /^-?\d+(\.\d+)?$/.test(v) ? Number(v) : v]),
  );
  const own = tDynamic(`errors.${w.code}`, params);
  if (own !== undefined) return own;
  return "message" in w ? w.message : w.detail;
}

/** The query of an IPAM write: a dry run, or the apply with the acknowledged warning codes. */
export function writeQuery(dryRun: boolean, acknowledge: readonly string[] = []): Query {
  return {
    dry_run: dryRun ? true : undefined,
    acknowledge: acknowledge.length > 0 ? [...acknowledge] : undefined,
  };
}

/** Warning codes that must be acknowledged before the plan may apply. */
export function codesToAcknowledge(warnings: readonly PlanWarning[]): string[] {
  return [...new Set(warnings.filter((w) => w.requires_ack && !w.acknowledged).map((w) => w.code))];
}
