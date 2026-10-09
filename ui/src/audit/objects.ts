// The objects a record names, with the label and the link the UI can offer for each.
//
// A record carries kind and id only. The UI has pages for prefixes (by CIDR), addresses (by
// IP address), hosts (by name) and jobs (by id). The CIDR, address and name of an object are
// not in the record unless its field changes name them, so a prefix, address or host is
// labeled and linked from the changes ("cidr", "ip", "name"); without them it is shown as
// its kind and the short form of its id, with no link. A deleted object is labeled but not
// linked, because its page no longer exists.
import type { AuditRecord, ObjectRef } from "../api/types";
import { paths } from "../app/paths";
import { shortId } from "../components/Principal";

export interface ObjectView {
  ref: ObjectRef;
  /** The text to show: the label from the changes, else the short form of the id. */
  text: string;
  /** Whether `text` is a label (an address, a name) rather than an id. */
  labeled: boolean;
  /** A page of the UI for the object, when there is one. */
  href: string | undefined;
}

/** The field of a change that names an object of this kind. */
const LABEL_FIELD: Readonly<Record<string, string>> = {
  prefix: "cidr",
  address: "ip",
  host: "name",
};

function sameObject(a: ObjectRef, b: ObjectRef): boolean {
  return a.kind === b.kind && a.id.toLowerCase() === b.id.toLowerCase();
}

/** The label the changes of a record give to one of its objects, if they name it. */
export function objectLabel(record: Pick<AuditRecord, "draft">, ref: ObjectRef): string | undefined {
  const field = LABEL_FIELD[ref.kind];
  if (!field) return undefined;
  const objects = record.draft.objects ?? [];
  const alone = objects.filter((o) => o.kind === ref.kind).length === 1;
  for (const change of record.draft.details?.changes ?? []) {
    if (change.field !== field) continue;
    // A change names its object when the draft names several; otherwise it belongs to the
    // only object of that kind.
    if (change.object ? !sameObject(change.object, ref) : !alone) continue;
    const value = change.new ?? change.old;
    if (value) return value;
  }
  return undefined;
}

function pageOf(record: Pick<AuditRecord, "draft">, ref: ObjectRef, label: string | undefined): string | undefined {
  if (ref.kind === "job") return paths.job(ref.id);
  if (!label) return undefined;
  // The object is gone after a delete.
  if (record.draft.action.endsWith(".delete")) return undefined;
  switch (ref.kind) {
    case "prefix":
      return paths.prefix(label);
    case "address":
      return paths.address(label);
    case "host":
      return paths.host(label);
    default:
      return undefined;
  }
}

/** The objects of a record in the order the record names them. */
export function objectViews(record: Pick<AuditRecord, "draft">): ObjectView[] {
  return (record.draft.objects ?? []).map((ref) => {
    const label = objectLabel(record, ref);
    return { ref, text: label ?? shortId(ref.id), labeled: label !== undefined, href: pageOf(record, ref, label) };
  });
}

/** The `object` filter value that selects one object. */
export function objectFilter(ref: ObjectRef): string {
  return `${ref.kind}:${ref.id.toLowerCase()}`;
}
