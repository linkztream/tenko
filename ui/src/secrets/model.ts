// What the secrets page shows and checks without touching the network: the words for kinds,
// roles and origins, the filter, the comma separated tag text and the mapping of the
// server's refusals to the form field they belong to.
import { errorMessage, fieldErrorMessage, isApiError } from "../api/problem";
import { t } from "../i18n";
import { SECRET_KINDS, type CredentialRole, type OperatorSecret, type SecretKind, type SecretOrigin } from "./api";

export const kindText = (kind: SecretKind): string => t(`secrets.kind.${kind}`);
export const roleText = (role: CredentialRole): string => t(`secrets.role.${role}`);
export const originText = (origin: SecretOrigin): string => t(`secrets.origin.${origin}`);

export { SECRET_KINDS };

/** The members of a secret a form can have an error on. */
export type SecretField = "name" | "kind" | "username" | "tags" | "notes" | "value";
const SECRET_FIELDS: readonly SecretField[] = ["name", "kind", "username", "tags", "notes", "value"];

/**
 * The message for `field` when the server refused the request because of it: 422
 * `vault.secret.invalid` names the field in `params.field` (and in `errors[]`), 413
 * `vault.secret.too_large` is always about the value. Undefined for every other refusal.
 */
export function fieldProblem(err: unknown, field: SecretField): string | undefined {
  if (!isApiError(err)) return undefined;
  if (err.is("vault.secret.too_large")) return field === "value" ? errorMessage(err) : undefined;
  if (!err.is("vault.secret.invalid")) return undefined;
  if (err.params.field === field) return errorMessage(err);
  const entry = err.fieldErrors.find((e) => e.field === field);
  return entry ? fieldErrorMessage({ ...entry, params: { field, ...entry.params } }) : undefined;
}

/** The error when it is not about one field of the form (those show next to their field). */
export function generalProblem(err: unknown): unknown {
  if (!err) return null;
  return SECRET_FIELDS.some((f) => fieldProblem(err, f) !== undefined) ? null : err;
}

/** Tags typed as a comma separated text: trimmed, lower case, without empty entries or repeats. */
export function parseTags(text: string): string[] {
  const tags = text
    .split(",")
    .map((tag) => tag.trim().toLowerCase())
    .filter((tag) => tag !== "");
  return [...new Set(tags)].sort();
}

/** The tags of a secret as the form shows them. */
export function tagsText(tags: readonly string[]): string {
  return tags.join(", ");
}

/** Whether a secret matches the words of the filter (name, user name and tags, all of them). */
export function matchesFilter(secret: OperatorSecret, text: string, kind: SecretKind | ""): boolean {
  if (kind !== "" && secret.kind !== kind) return false;
  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const hay = [secret.name, secret.username ?? "", ...secret.tags].join(" ").toLowerCase();
  return words.every((word) => hay.includes(word));
}

/** The revision to send with a change (the secret on screen), or none when the secret has none. */
export function revisionOf(secret: OperatorSecret): number | undefined {
  return secret.revision ?? undefined;
}
