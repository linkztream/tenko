// The words for the DHCP objects: a match, a condition, an action and lease times as a sentence in
// the language of the UI. The pure helpers they build on are in model.ts.
import { formatDuration, formatList, t } from "../i18n";
import { matchKind } from "./model";
import type { Condition, LeaseTimes, Match, OptionKind, PolicyAction, Term } from "./types";

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
  if ("architecture" in match) return t("dhcp.match.architecture", { value: match.architecture.code });
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

/** The type of an option in words: `IPv4 address, list`. */
export function kindWords(kind: OptionKind, array: boolean | undefined): string {
  const name = t(`dhcp.optset.kind.${kind}`);
  return array ? t("dhcp.optset.kind_list", { kind: name }) : name;
}

/** What a policy does, in words. */
export function actionWords(action: PolicyAction | undefined): string {
  const parts: string[] = [];
  if (action?.range) parts.push(t("dhcp.action.range", { first: action.range.first, last: action.range.last }));
  if (action?.lease) parts.push(t("dhcp.action.lease", { lease: leaseWords(action.lease) }));
  if (action?.ddns) parts.push(t("dhcp.action.ddns"));
  return parts.length > 0 ? parts.join("; ") : t("dhcp.action.none");
}
