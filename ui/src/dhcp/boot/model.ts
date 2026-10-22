// Pure helpers of the network boot tab of a scope (docs/dhcp.md, section 16.2): the six options
// the boot form edits (150, 66, 67, 209, 210, 211) and how a save replaces only those in a scope's
// option set, the client types of the "add a boot file" dialog with the matches of their classes,
// the policies of a scope that set a boot file, and the order of the iPXE chain policy. No DOM, no
// i18n: problems are short codes the views translate.
import { dataText, draftOfMatch, parseOptionText, type ValueProblem } from "../model";
import type { Match, OptionSet, OptionValueInput, OptionValueItem, Policy } from "../types";

const SPACE = "dhcp4";

// ---------------------------------------------------------------------------------
// The form

export type BootField = "next_server" | "tftp_name" | "file" | "pxe_config" | "pxe_prefix" | "pxe_reboot";

/** The fields in the order the form shows them. */
export const BOOT_FIELDS: readonly BootField[] = ["next_server", "tftp_name", "file", "pxe_config", "pxe_prefix", "pxe_reboot"];

/** The DHCPv4 option code of each field. */
export const BOOT_CODE: Readonly<Record<BootField, number>> = {
  next_server: 150,
  tftp_name: 66,
  file: 67,
  pxe_config: 209,
  pxe_prefix: 210,
  pxe_reboot: 211,
};

/** The field of an option code of the `dhcp4` space, or undefined when the code is not a boot option. */
export function fieldOfCode(code: number): BootField | undefined {
  return BOOT_FIELDS.find((f) => BOOT_CODE[f] === code);
}

/** The values as typed, one text per field. */
export type BootDraft = Record<BootField, string>;

export const EMPTY_DRAFT: Readonly<BootDraft> = { next_server: "", tftp_name: "", file: "", pxe_config: "", pxe_prefix: "", pxe_reboot: "" };

/** The longest value of a text option: its length is one octet. */
export const MAX_TEXT_OCTETS = 255;

/** The texts of the boot options in a set; a field the set does not hold is empty. */
export function draftOfSet(values: readonly OptionValueItem[]): BootDraft {
  const draft: BootDraft = { ...EMPTY_DRAFT };
  for (const item of values) {
    const field = item.space === SPACE ? fieldOfCode(item.code) : undefined;
    if (field && item.typed !== undefined && item.typed !== null) draft[field] = dataText(item.typed);
  }
  return draft;
}

export type BootProblem = ValueProblem | "long";

/** The octets of a text in UTF-8, which is what the length limit of a text option counts. */
function octets(text: string): number {
  return new TextEncoder().encode(text).length;
}

function parseField(field: BootField, text: string): { ok: true; input: OptionValueInput } | { ok: false; problem: BootProblem } {
  const code = BOOT_CODE[field];
  if (field === "next_server") {
    const parsed = parseOptionText({ kind: "ipv4_address", array: true }, text);
    return parsed.ok ? { ok: true, input: { code, typed: parsed.data } } : parsed;
  }
  if (field === "pxe_reboot") {
    const parsed = parseOptionText({ kind: "u32", array: false }, text);
    return parsed.ok ? { ok: true, input: { code, typed: parsed.data } } : parsed;
  }
  const parsed = parseOptionText({ kind: "string", array: false }, text);
  if (!parsed.ok) return parsed;
  if (octets(text.trim()) > MAX_TEXT_OCTETS) return { ok: false, problem: "long" };
  return { ok: true, input: { code, typed: parsed.data } };
}

/** A value as the server has it, sent back unchanged. */
function kept(item: OptionValueItem): OptionValueInput {
  return { ...(item.space === SPACE ? {} : { space: item.space }), code: item.code, data: item.data };
}

export type BuildResult =
  | { ok: true; values: OptionValueInput[]; changed: boolean }
  | { ok: false; errors: Partial<Record<BootField, BootProblem>> };

/**
 * The whole set to send: every value of `current` that is not a boot option as it is (with its
 * `data`), the boot options whose text did not change as they are, and the changed ones from the
 * typed text (an emptied field takes its option out). Texts are checked first; `changed` says
 * whether the set differs from `current` at all, so that nothing is sent when it does not.
 */
export function buildSet(current: readonly OptionValueItem[], draft: Readonly<BootDraft>): BuildResult {
  const original = draftOfSet(current);
  const same = (f: BootField) => draft[f].trim() === original[f].trim();
  const errors: Partial<Record<BootField, BootProblem>> = {};
  const fresh: OptionValueInput[] = [];
  for (const field of BOOT_FIELDS) {
    if (same(field) || draft[field].trim() === "") continue;
    const parsed = parseField(field, draft[field]);
    if (parsed.ok) fresh.push(parsed.input);
    else errors[field] = parsed.problem;
  }
  if (Object.keys(errors).length > 0) return { ok: false, errors };
  const values: OptionValueInput[] = [];
  for (const item of current) {
    const field = item.space === SPACE ? fieldOfCode(item.code) : undefined;
    if (field === undefined || same(field)) values.push(kept(item));
  }
  values.push(...fresh);
  return { ok: true, values, changed: BOOT_FIELDS.some((f) => !same(f)) };
}

// ---------------------------------------------------------------------------------
// The client types of the "add a boot file" dialog

export type BootKind = "bios" | "uefi-x64" | "uefi-arm64" | "http-x64" | "http" | "ipxe";

/** The client types in the order the choice lists them. */
export const BOOT_KINDS: readonly BootKind[] = ["bios", "uefi-x64", "uefi-arm64", "http-x64", "http", "ipxe"];

/** The matches of the class of a client type (architecture codes of RFC 4578 and the IANA registry). */
export function kindMatches(kind: BootKind): Match[] {
  switch (kind) {
    case "bios":
      return [{ architecture: { code: 0 } }];
    case "uefi-x64":
      return [{ architecture: { code: 7 } }, { architecture: { code: 9 } }];
    case "uefi-arm64":
      return [{ architecture: { code: 11 } }];
    case "http-x64":
      return [{ architecture: { code: 16 } }];
    case "http":
      return [{ vendor_class: { value: "HTTPClient", prefix: true } }];
    case "ipxe":
      return [{ user_class: { value: "iPXE" } }];
  }
}

/** The name a class and a policy of a client type start from: `boot-uefi-x64`. */
export function kindName(kind: BootKind): string {
  return `boot-${kind}`;
}

function matchKey(match: Match): string {
  const draft = draftOfMatch(match);
  return `${draft.kind}\u0000${draft.value}\u0000${draft.prefix ? 1 : 0}`;
}

/** Whether two lists of matches are the same set of matches, in any order. */
export function sameMatches(a: readonly Match[], b: readonly Match[]): boolean {
  if (a.length !== b.length) return false;
  const left = a.map(matchKey).sort();
  const right = b.map(matchKey).sort();
  return left.every((key, i) => key === right[i]);
}

/** `base`, else `base-2`, `base-3` and so on: the first name that is not taken. */
export function uniqueName(base: string, taken: ReadonlySet<string>): string {
  if (!taken.has(base)) return base;
  for (let n = 2; ; n += 1) {
    const name = `${base}-${n}`;
    if (!taken.has(name)) return name;
  }
}

/**
 * The order of the iPXE chain policy, which belongs before the others of its scope (firmware gets
 * iPXE, iPXE gets its script): one below the lowest order the scope's policies have, 0 at the
 * least, and 1 for a scope without policies. When the lowest order is already 0 the new policy
 * ties with it and the names decide, which the dialog tells.
 */
export function ipxeOrder(orders: readonly number[]): number {
  if (orders.length === 0) return 1;
  return Math.max(0, Math.min(...orders) - 1);
}

/** Whether the iPXE policy would not come strictly before the policies already in the scope. */
export function ipxeTies(orders: readonly number[]): boolean {
  return orders.length > 0 && Math.min(...orders) <= 0;
}

/** The boot file in the dialog: a TFTP path or a URL, 1 to 255 octets. */
export function checkBootFile(text: string): "empty" | "long" | null {
  const value = text.trim();
  if (value === "") return "empty";
  return octets(value) > MAX_TEXT_OCTETS ? "long" : null;
}

// ---------------------------------------------------------------------------------
// The policies of a scope that set a boot file

/** A policy of the scope with the boot file its option set holds. */
export interface BootPolicy {
  policy: Policy;
  file: string;
}

/** The boot file (option 67) of an option set, or undefined when it holds none. */
export function bootFileOf(set: Pick<OptionSet, "values"> | undefined): string | undefined {
  const item = set?.values.find((v) => v.space === SPACE && v.code === BOOT_CODE.file);
  if (!item) return undefined;
  return item.typed !== undefined && item.typed !== null ? dataText(item.typed) : item.data;
}

/** The policies of a scope whose option set holds option 67, in evaluation order: the lowest order first. */
export function bootPolicies(prefix: string, policies: readonly Policy[], sets: readonly OptionSet[]): BootPolicy[] {
  const byOwner = new Map(sets.map((s) => [s.path, s]));
  const out: BootPolicy[] = [];
  for (const policy of policies) {
    if (policy.scope !== prefix) continue;
    const file = bootFileOf(byOwner.get(`policy:${policy.id}`));
    if (file !== undefined) out.push({ policy, file });
  }
  return out.sort((a, b) => a.policy.order - b.policy.order || a.policy.name.localeCompare(b.policy.name));
}
