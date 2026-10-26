// Translated words for the IPAM enums: lifecycle status, assignment mode, roles, alarm levels,
// object kinds, change actions and custom field types. Pure functions over `t`, so a view
// never spells these words out itself and a language switch reaches all of them.
//
// Counts that are decimal strings (IPv6 sizes exceed 2^53) have their own formatters here:
// `siCount` for the compact form and `countTitle` for the exact value in a tooltip.
import type {
  AlarmLevel,
  AssignmentMode,
  ChangeAction,
  CustomKind,
  PrefixRole,
  RangeRole,
  Status,
  TreeNode,
} from "../api/types";
import { locale, t, tDynamic } from "../i18n";
import { si } from "../app/format/si";

/** "Planned", "Active", "Reserved", "Deprecated". */
export function statusWord(s: Status): string {
  return t(`ipam.status.${s}`);
}

/** The assignment mode in lowercase, as the grid shows it next to its glyph. */
export function modeWord(m: AssignmentMode): string {
  return t(`ipam.mode.${m}`);
}

/** What the assignment mode does, in one sentence (IPAM-14). */
export function modeHint(m: AssignmentMode): string {
  return t(`ipam.mode_hint.${m}`);
}

export function prefixRoleWord(r: PrefixRole): string {
  return t(`ipam.prefix_role.${r}`);
}

export function rangeRoleWord(r: RangeRole): string {
  return t(`ipam.range_role.${r}`);
}

export function alarmWord(level: AlarmLevel): string {
  return t(`ipam.alarm.${level}`);
}

/**
 * The lowercase noun of an object kind with its plural ("prefix", "prefixes"), for running text
 * and counts. A kind without a word (users, jobs, ...) comes back as it is.
 */
export function kindWord(kind: string, count = 1): string {
  return tDynamic(`ipam.kind.${kind}`, { count }) ?? kind;
}

/** The capitalized singular of an object kind for headings ("Prefix", "Custom field"). */
export function kindTitle(kind: string): string {
  return tDynamic(`ipam.kind_title.${kind}`) ?? kind;
}

/** What happened to how many objects: "3 created", "1 deleted". Agrees in number in Swedish. */
export function actionWord(action: ChangeAction, count: number): string {
  return t(`ipam.action.${action}`, { count });
}

/** The value type of a custom field. */
export function customKindWord(type: CustomKind["type"]): string {
  return t(`ipam.custom_kind.${type}`);
}

// ---------------------------------------------------------------------------------
// Counts as decimal strings

const exactFormats = new Map<string, Intl.NumberFormat>();
const tenthFormats = new Map<string, Intl.NumberFormat>();

function formatter(cache: Map<string, Intl.NumberFormat>, loc: string, options?: Intl.NumberFormatOptions) {
  let f = cache.get(loc);
  if (f === undefined) {
    f = new Intl.NumberFormat(loc, options);
    cache.set(loc, f);
  }
  return f;
}

type Count = { big: bigint } | { num: number } | { text: string };

/** An exact integer where there is one, else the number, else the text unchanged. */
function parseCount(value: string | number | bigint): Count {
  if (typeof value === "bigint") return { big: value };
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return { text: "" };
    return Number.isInteger(value) ? { big: BigInt(value) } : { num: value };
  }
  const text = value.trim();
  if (/^[+-]?\d+$/.test(text)) return { big: BigInt(text) };
  const n = Number(text);
  return text !== "" && Number.isFinite(n) ? { num: n } : { text: value };
}

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * Compact form of a count that may exceed 2^53. Up to `Number.MAX_SAFE_INTEGER` it is the SI
 * form of the design ("982", "1.2K", "4.3G"). Above, an exact power of two is `2^n` (an IPv6
 * prefix size: "2^64"), anything else the exponent form with one decimal ("1.8e19"). The exact
 * value belongs in the tooltip: see `countTitle`. Text that is not a number comes back as it is.
 */
export function siCount(value: string | number | bigint, loc: string = locale()): string {
  const count = parseCount(value);
  if ("text" in count) return count.text;
  if ("num" in count) return si(count.num, loc);

  const negative = count.big < 0n;
  const magnitude = negative ? -count.big : count.big;
  if (magnitude <= MAX_SAFE) return si(Number(count.big), loc);

  const sign = negative ? "-" : "";
  if ((magnitude & (magnitude - 1n)) === 0n) return `${sign}2^${magnitude.toString(2).length - 1}`;

  // Mantissa from the first three digits, rounded half up to one decimal.
  const digits = magnitude.toString();
  let exponent = digits.length - 1;
  let tenths = Math.round(Number(digits.slice(0, 3)) / 10);
  if (tenths >= 100) {
    tenths = 10;
    exponent += 1;
  }
  const mantissa = formatter(tenthFormats, loc, { minimumFractionDigits: 1, maximumFractionDigits: 1 });
  return `${sign}${mantissa.format(tenths / 10)}e${exponent}`;
}

/** The exact value with the grouping of the language ("4,294,967,296"), for a tooltip. BigInt-safe. */
export function countTitle(value: string | number | bigint, loc: string = locale()): string {
  const count = parseCount(value);
  if ("text" in count) return count.text;
  const format = formatter(exactFormats, loc);
  return "num" in count ? format.format(count.num) : format.format(count.big);
}

/**
 * The space of a supernet allocated to its child prefixes, a figure apart from the meter
 * (IPAM-10): "3.3K of 66K allocated to 13 prefixes". Undefined for a network.
 */
export function allocationWords(node: Pick<TreeNode, "role" | "children" | "utilization">): string | undefined {
  if (node.role !== "supernet") return undefined;
  return t("ipam.allocation.text", {
    covered: siCount(node.utilization.covered),
    size: siCount(node.utilization.size),
    count: node.children,
  });
}
