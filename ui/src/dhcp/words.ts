// The words for the DHCP objects: a match, a condition, an action and lease times as a sentence in
// the language of the UI. The pure helpers they build on are in model.ts.
import { formatDuration, formatList, formatNumber, t } from "../i18n";
import { normalizedDdns } from "./ddns/model";
import { isKnownArchitecture, matchKind } from "./model";
import type { Condition, DdnsPolicy, LeaseTimes, Match, OptionKind, PolicyAction, Term } from "./types";

/** A match in words: `vendor class starting with "MSFT"`. */
export function matchWords(match: Match): string {
  if ("vendor_class" in match) {
    const { value, prefix } = match.vendor_class;
    return prefix ? t("dhcp.match.vendor_class_prefix", { value }) : t("dhcp.match.vendor_class", { value });
  }
  if ("user_class" in match) return t("dhcp.match.user_class", { value: match.user_class.value });
  if ("mac" in match) return t("dhcp.match.mac", { value: match.mac.pattern });
  if ("client_id" in match) return t("dhcp.match.client_id", { value: match.client_id.value });
  if ("circuit_id" in match) return t("dhcp.match.circuit_id", { value: match.circuit_id.value });
  if ("remote_id" in match) return t("dhcp.match.remote_id", { value: match.remote_id.value });
  if ("architecture" in match) {
    const { code } = match.architecture;
    return isKnownArchitecture(code) ? t("dhcp.match.architecture_named", { name: t(`dhcp.arch.name.${code}`), code }) : t("dhcp.match.architecture", { value: code });
  }
  const { value, prefix } = match.host_name;
  return prefix ? t("dhcp.match.host_name_prefix", { value }) : t("dhcp.match.host_name", { value });
}

/** The matches of a class, joined by "or". */
export function matchesWords(matches: readonly Match[]): string {
  return formatList(matches.map(matchWords), "disjunction");
}

/** The word for the kind of a match, for the kind menu. */
export function matchKindWord(match: Match): string {
  return t(`dhcp.match.kind.${matchKind(match)}`);
}

/** One term of a condition in words; `className` turns a class identifier into its name. */
export function termWords(term: Term, className: (id: string) => string): string {
  if ("class" in term) return t("dhcp.term.class", { name: className(term.class) });
  if ("not_class" in term) return t("dhcp.term.not_class", { name: className(term.not_class) });
  if ("match" in term) return matchWords(term.match);
  return t("dhcp.term.not_match", { match: matchWords(term.not_match) });
}

/** A condition in words: its terms joined by "and" or "or". */
export function conditionWords(condition: Condition, className: (id: string) => string): string {
  return formatList(condition.terms.map((term) => termWords(term, className)), condition.join === "and" ? "conjunction" : "disjunction");
}

/** Lease times in words: `1 d, between 1 h and 7 d`. */
export function leaseWords(lease: LeaseTimes): string {
  return t("dhcp.lease.words", {
    default: formatDuration(lease.default_secs),
    min: formatDuration(lease.min_secs),
    max: formatDuration(lease.max_secs),
  });
}

/** A count of addresses; a pool of 2^32 or more says its size as a power of two (`pool_bits`), since the figure itself stops at 2^64 - 1. */
export function poolCountWords(value: number, bits: number | null | undefined): string {
  return bits === null || bits === undefined ? formatNumber(value) : t("dhcp.util.bits", { bits });
}

/** The type of an option in words: `IPv4 address, list`. */
export function kindWords(kind: OptionKind, array: boolean | undefined): string {
  const name = t(`dhcp.optset.kind.${kind}`);
  return array ? t("dhcp.optset.kind_list", { kind: name }) : name;
}

/**
 * What a policy does, in words. `zoneName` turns a forward zone identifier into its name;
 * `options` says that the option set of the policy holds values.
 */
export function actionWords(action: PolicyAction | undefined, context: { zoneName?: (id: string) => string | undefined; options?: boolean } = {}): string {
  const parts: string[] = [];
  if (action?.range) parts.push(t("dhcp.action.range", { first: action.range.first, last: action.range.last }));
  if (action?.lease) parts.push(t("dhcp.action.lease", { lease: leaseWords(action.lease) }));
  if (action?.ddns) {
    const id = action.ddns.forward_zone;
    const zone = id ? (context.zoneName?.(id) ?? id) : undefined;
    parts.push(!action.ddns.enabled ? t("dhcp.action.ddns_off") : zone ? t("dhcp.action.ddns_on_zone", { zone }) : t("dhcp.action.ddns_on"));
  }
  if (context.options) parts.push(t("dhcp.action.options"));
  return parts.length > 0 ? parts.join("; ") : t("dhcp.action.none");
}

/** DDNS settings in words: `DDNS is on with forward zone example.test, PTR records and TTL 300 s`. */
export function ddnsWords(ddns: DdnsPolicy | null | undefined, zoneName: (id: string) => string | undefined = () => undefined): string {
  const d = normalizedDdns(ddns);
  if (!d.enabled) return t("dhcp.ddns.words.off");
  const zone = d.forward_zone ? (zoneName(d.forward_zone) ?? d.forward_zone) : undefined;
  const parts = [
    zone ? t("dhcp.ddns.words.zone", { zone }) : t("dhcp.ddns.words.zone_domain"),
    d.reverse ? t("dhcp.ddns.words.reverse_on") : t("dhcp.ddns.words.reverse_off"),
    d.ttl ? t("dhcp.ddns.words.ttl", { seconds: d.ttl }) : t("dhcp.ddns.words.ttl_third"),
    d.conflict === "replace" ? t("dhcp.ddns.words.replace") : t("dhcp.ddns.words.protect"),
    ...(d.client_may_update_a ? [t("dhcp.ddns.words.client_a")] : []),
    d.legacy_clients ? t("dhcp.ddns.words.legacy_on") : t("dhcp.ddns.words.legacy_off"),
    ...(d.refuse_foreign ? [t("dhcp.ddns.words.foreign")] : []),
  ];
  return t("dhcp.ddns.words.on", { parts: formatList(parts, "conjunction") });
}
