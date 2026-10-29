// The reconciliation view (GET /api/v1/ipam/reconcile): the types of its rows and the words
// for the kinds, the truths and the rules that decide who wins.
import type { components } from "../../api/generated/schema";
import type { MessageKey } from "../../i18n";

type S = components["schemas"];

export type ReconcilePage = S["ReconcilePage"];
export type ReconcileRow = S["ReconcileRow"];
export type ReconcileKind = S["ReconcileKind"];
export type HostTruths = S["HostTruths"];
export type OsField = S["OsField"];
export type Truth = S["Truth"];
export type WinRule = S["WinRule"];

/** The kinds in the order of the page: what needs a person first. */
export const KINDS: readonly ReconcileKind[] = ["conflict", "ghost", "rogue", "orphan", "ptr_mismatch"];

/** The four truths in the order of the columns. */
export const TRUTHS: readonly Truth[] = ["intent", "lease", "dns", "scan"];

export const KIND_TITLE: Record<ReconcileKind, MessageKey> = {
  conflict: "ipam.reconcile.kind.conflict",
  ghost: "ipam.reconcile.kind.ghost",
  rogue: "ipam.reconcile.kind.rogue",
  orphan: "ipam.reconcile.kind.orphan",
  ptr_mismatch: "ipam.reconcile.kind.ptr_mismatch",
};

export const KIND_HELP: Record<ReconcileKind, MessageKey> = {
  conflict: "ipam.reconcile.kind_help.conflict",
  ghost: "ipam.reconcile.kind_help.ghost",
  rogue: "ipam.reconcile.kind_help.rogue",
  orphan: "ipam.reconcile.kind_help.orphan",
  ptr_mismatch: "ipam.reconcile.kind_help.ptr_mismatch",
};

/** What a group of the kind means, in one short line on its group row. */
export const KIND_NOTE: Record<ReconcileKind, MessageKey> = {
  conflict: "ipam.reconcile.note.conflict",
  ghost: "ipam.reconcile.note.ghost",
  rogue: "ipam.reconcile.note.rogue",
  orphan: "ipam.reconcile.note.orphan",
  ptr_mismatch: "ipam.reconcile.note.ptr_mismatch",
};

export const TRUTH_WORD: Record<Truth, MessageKey> = {
  intent: "ipam.reconcile.truth.intent",
  lease: "ipam.reconcile.truth.lease",
  dns: "ipam.reconcile.truth.dns",
  scan: "ipam.reconcile.truth.scan",
};

/** The text of a rule; the server's English `rule` is not shown. */
export const RULE_TEXT: Record<WinRule, MessageKey> = {
  intent_managed: "ipam.reconcile.rule.intent_managed",
  lease_dynamic: "ipam.reconcile.rule.lease_dynamic",
  newest_sighting: "ipam.reconcile.rule.newest_sighting",
  never_automatic: "ipam.reconcile.rule.never_automatic",
  orphan_rule: "ipam.reconcile.rule.orphan_rule",
  manual_record: "ipam.reconcile.rule.manual_record",
  forward_record: "ipam.reconcile.rule.forward_record",
};

export function isKind(value: string | undefined): value is ReconcileKind {
  return value !== undefined && (KINDS as readonly string[]).includes(value);
}
