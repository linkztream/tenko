// The problem documents of the IPAM mock, with the stable codes, statuses and params of
// crates/tenko-ipam/src/error.rs. The builders return the `Problem`; callers throw it.
import type { FieldError } from "../../problem";
import { Problem, fieldError } from "../reply";

export function notFound(kind: string, id: string): Problem {
  return new Problem("ipam.not_found", { status: 404, detail: `${kind} ${id} does not exist`, params: { kind, id } });
}

export function revisionMismatch(kind: string, id: string, expected: number, actual: number): Problem {
  return new Problem("ipam.revision_mismatch", {
    status: 412,
    detail: `${kind} ${id} is at revision ${actual}, not ${expected}`,
    params: { kind, id, expected: String(expected), actual: String(actual) },
  });
}

export function objectDeleted(kind: string, id: string): Problem {
  return new Problem("ipam.object_deleted", {
    status: 409,
    detail: `${kind} ${id} is deleted; restore it first`,
    params: { kind, id },
  });
}

export function notDeleted(kind: string, id: string): Problem {
  return new Problem("ipam.not_deleted", { status: 409, detail: `${kind} ${id} is not deleted`, params: { kind, id } });
}

export function idTaken(kind: string, id: string): Problem {
  return new Problem("ipam.id_taken", { status: 409, detail: `${kind} ${id} exists already`, params: { kind, id } });
}

export function nameTaken(kind: string, name: string): Problem {
  return new Problem("ipam.name_taken", {
    status: 409,
    detail: `a ${kind} named ${name} exists already`,
    params: { kind, name },
    errors: [fieldError("name", "ipam.name_taken")],
  });
}

export function referenceMissing(field: string, kind: string, id: string): Problem {
  return new Problem("ipam.reference_missing", {
    status: 409,
    detail: `${field} refers to ${kind} ${id}, which does not exist or is deleted`,
    params: { kind, id, field },
    errors: [fieldError(field, "ipam.reference_missing")],
  });
}

export function inUse(kind: string, id: string, by: string, count: number): Problem {
  return new Problem("ipam.in_use", {
    status: 409,
    detail: `${kind} ${id} is still used by ${count} ${by}`,
    params: { kind, id, by, count: String(count) },
  });
}

/** `ipam.validation` for one field. */
export function invalid(field: string, detail: string): Problem {
  return new Problem("ipam.validation", {
    status: 400,
    detail,
    params: { field },
    errors: [fieldError(field, "ipam.validation")],
  });
}

/** `ipam.validation` for several fields; the first one is named in the params. */
export function invalidFields(errors: readonly { field: string; detail: string }[]): Problem {
  const first = errors[0];
  const list: FieldError[] = errors.map((e) => fieldError(e.field, "ipam.validation"));
  return new Problem("ipam.validation", {
    status: 400,
    detail: errors.length === 1 ? (first?.detail ?? "invalid request") : errors.map((e) => e.detail).join("; "),
    params: { field: first?.field ?? "" },
    errors: list,
  });
}

/** A body member the document does not know (the server refuses unknown members). */
export function unknownField(name: string, allowed: readonly string[]): Problem {
  return new Problem("sys.invalid_request", {
    status: 400,
    detail: `unknown field \`${name}\`, expected one of ${allowed.map((a) => `\`${a}\``).join(", ")}`,
    params: { part: "body" },
  });
}

/** A path identifier that is not a UUID. */
export function badPathId(value: string): Problem {
  return new Problem("sys.invalid_request", {
    status: 400,
    detail: `\`${value}\` is not a valid identifier`,
    params: { part: "path" },
  });
}

export function invalidQuery(name: string, value: string, detail?: string): Problem {
  return new Problem("sys.invalid_query", {
    status: 400,
    detail: detail ?? `the query parameter ${name} is not valid`,
    params: { name, value },
  });
}

export function planUnacknowledged(codes: readonly string[]): Problem {
  return new Problem("ipam.plan.unacknowledged", {
    status: 409,
    detail: `the plan has warnings that need an acknowledgement: ${codes.join(", ")}`,
    params: { codes: codes.join(",") },
  });
}
