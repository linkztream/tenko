// The live policy checklist of the administrator step: the four things the server judges about
// a password, as rows with a state. The server answers (POST /auth/password/check); this
// module only arranges the answer, so the rules stay in one place.
import type { PasswordCheckResult, PolicyViolation } from "../api/types";
import { t } from "../i18n";

export type ItemState = "idle" | "ok" | "bad" | "off" | "pending";

export type ChecklistId = "rule" | "trivial" | "context" | "breach";

export interface ChecklistItem {
  id: ChecklistId;
  state: ItemState;
  /** The violations that make this row fail, for the explanation under it. */
  violations: PolicyViolation[];
}

const RULE_KINDS: readonly PolicyViolation["kind"][] = [
  "too_short",
  "too_long",
  "pin_digits_only",
  "pattern_mismatch",
  "invalid_characters",
];

export interface ChecklistInput {
  hasPassword: boolean;
  /** An answer for the current password is on its way. */
  pending: boolean;
  /** The answer for the current password, when there is one. */
  result: PasswordCheckResult | null;
  /** The profile switches the breached-password check off (known before any answer). */
  breachOff: boolean;
}

export function buildChecklist(input: ChecklistInput): ChecklistItem[] {
  const { hasPassword, pending, result, breachOff } = input;
  const ids: ChecklistId[] = ["rule", "trivial", "context", "breach"];
  return ids.map((id): ChecklistItem => {
    if (!hasPassword) return { id, state: id === "breach" && breachOff ? "off" : "idle", violations: [] };
    if (pending) return { id, state: id === "breach" && breachOff ? "off" : "pending", violations: [] };
    if (!result) return { id, state: id === "breach" && breachOff ? "off" : "idle", violations: [] };

    const violations = result.violations;
    switch (id) {
      case "rule": {
        const own = violations.filter((v) => RULE_KINDS.includes(v.kind));
        return { id, state: own.length > 0 ? "bad" : "ok", violations: own };
      }
      case "trivial": {
        const own = violations.filter((v) => v.kind === "trivial");
        return { id, state: own.length > 0 ? "bad" : "ok", violations: own };
      }
      case "context": {
        const own = violations.filter((v) => v.kind === "context_specific");
        return { id, state: own.length > 0 ? "bad" : "ok", violations: own };
      }
      case "breach": {
        const own = violations.filter((v) => v.kind === "breached");
        switch (result.breach_check) {
          case "clean":
            return { id, state: "ok", violations: [] };
          case "breached":
            return { id, state: "bad", violations: own };
          default:
            // "off" (the profile) and "unavailable" (the lookup failed): not a failure, but not a pass.
            return { id, state: "off", violations: [] };
        }
      }
    }
  });
}

/** The explanation of one violation, in the words of the error catalog. */
export function violationMessage(v: PolicyViolation): string {
  switch (v.kind) {
    case "too_short":
      return t("errors.auth.password.too_short", { min: v.min });
    case "too_long":
      return t("errors.auth.password.too_long", { max: v.max });
    case "pin_digits_only":
      return t("errors.auth.password.pin_digits_only");
    case "trivial":
      return t("errors.auth.password.trivial");
    case "context_specific":
      return t("errors.auth.password.context_specific");
    case "pattern_mismatch":
      return t("errors.auth.password.pattern_mismatch");
    case "breached":
      return t("errors.auth.password.breached");
    case "invalid_characters":
      return t("errors.auth.password.invalid_characters");
  }
}
