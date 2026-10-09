// Checks of request values. The mock answers a bad value the way the backend does:
// `auth.invalid_request` with the field named in `params` and `errors`.
import type { FieldError } from "../problem";
import type { PolicyViolation, RoleName } from "../types";
import { violationCode, violationParams } from "./policy";
import { fail, fieldError } from "./reply";

export type Obj = Record<string, unknown>;

export function isRecord(value: unknown): value is Obj {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/** Fails with `auth.invalid_request` for `field`. */
export function invalid(field: string, reason: string): never {
  return fail("auth.invalid_request", {
    detail: `invalid ${field}: ${reason}`,
    params: { field, reason },
    errors: [fieldError(field, "auth.invalid_request")],
  });
}

export function reqString(body: Obj, key: string, field: string = key): string {
  const value = body[key];
  if (typeof value !== "string") return invalid(field, "a text is required");
  return value;
}

/** A text member, or undefined when absent or null. */
export function optString(body: Obj, key: string, field: string = key): string | undefined {
  const value = body[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") return invalid(field, "a text is required");
  return value;
}

export function optBool(body: Obj, key: string, field: string = key): boolean | undefined {
  const value = body[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "boolean") return invalid(field, "true or false is required");
  return value;
}

export function optInt(body: Obj, key: string, field: string = key): number | undefined {
  const value = body[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value)) return invalid(field, "a whole number is required");
  return value;
}

export function oneOf<T extends string>(value: unknown, allowed: readonly T[], field: string): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    return invalid(field, `one of ${allowed.join(", ")} is required`);
  }
  return value as T;
}

const MAX_NAME_CHARS = 64;

/** A login name: 1 to 64 characters without spaces or control characters. */
export function validUserName(raw: string, field = "name"): string {
  const name = raw.trim();
  if (name === "" || Array.from(name).length > MAX_NAME_CHARS || /[\s\p{Cc}]/u.test(name)) {
    return invalid(field, "1 to 64 characters without spaces or control characters");
  }
  return name;
}

/** A display name, defaulting to the login name: 1 to 128 visible characters. */
export function validDisplayName(raw: string | undefined, fallback: string, field = "display_name"): string {
  const text = (raw ?? fallback).trim();
  if (text === "" || Array.from(text).length > 128 || /\p{Cc}/u.test(text)) {
    return invalid(field, "1 to 128 visible characters");
  }
  return text;
}

export const LANGUAGES: readonly string[] = ["en", "sv"];

export function validLanguage(raw: string, field = "language"): string {
  if (!LANGUAGES.includes(raw)) return invalid(field, "supported languages are en and sv");
  return raw;
}

const ROLE_ORDER: readonly RoleName[] = ["admin", "operator", "viewer"];

/** Known roles, at least one, in the order admin, operator, viewer. */
export function validRoles(value: unknown, field = "roles"): RoleName[] {
  if (!Array.isArray(value)) return invalid(field, "a list of roles is required");
  for (const role of value) {
    if (typeof role !== "string" || !(ROLE_ORDER as readonly string[]).includes(role)) {
      return invalid(field, `unknown role ${JSON.stringify(role)}`);
    }
  }
  const roles = ROLE_ORDER.filter((r) => value.includes(r));
  if (roles.length === 0) return invalid(field, "at least one role");
  return roles;
}

/**
 * Whether the text is a host name for the TLS subject and the WebAuthn RP ID: DNS syntax,
 * no address (an RP ID cannot be one). Returns the normalized name or null.
 */
export function normalizeHostName(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  const bare = trimmed.replace(/^\[/, "").replace(/\]$/, "");
  if (bare.includes(":")) return null; // IPv6 address or something that is not a name
  const name = trimmed.toLowerCase().replace(/\.$/, "");
  if (name === "" || name.length > 253) return null;
  const labels = name.split(".");
  if (!labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return null;
  // Digits and dots only would be read as an address by browsers.
  if (labels.every((l) => /^[0-9]+$/.test(l))) return null;
  return name;
}

// ---------------------------------------------------------------------------------
// Password policy failures

/** One field error per violation, `auth.password.<kind>` with the violation's params. */
export function violationErrors(field: string, violations: readonly PolicyViolation[]): FieldError[] {
  return violations.map((v) => {
    const params = violationParams(v);
    return fieldError(field, violationCode(v), Object.keys(params).length > 0 ? params : undefined);
  });
}

/** Fails with `auth.password.policy` and the violations in `errors`. */
export function failPolicy(field: string, violations: readonly PolicyViolation[]): never {
  return fail("auth.password.policy", { errors: violationErrors(field, violations) });
}
