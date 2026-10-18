// Password checking the way the backend does it (crates/tenko-auth/src/password/policy.rs):
// length by preset, trivial patterns, context-specific words, then the breached-password
// check. There are no composition rules. Lengths count Unicode scalar values after NFKC
// normalization, and every comparison is case-insensitive.
import type {
  BreachMode,
  BreachStatus,
  PasswordCheckResult,
  PasswordPolicy,
  PolicyViolation,
} from "../types";
import { BREACHED_PASSWORDS } from "./fixtures";
import { policyMaxLength, policyMinLength } from "./profiles";

/** Words of the product itself; a password containing one is context-specific. */
const PRODUCT_WORDS = ["tenko"];

/** Shortest user name, host name and host label that count as context. */
const MIN_SHORT_CONTEXT_CHARS = 3;
/** Shortest display name and display name part that count as context. */
const MIN_DISPLAY_CONTEXT_CHARS = 4;
/** Longest unit of a repeated pattern such as `abcabc`. */
const MAX_REPEATED_UNIT = 3;

export interface PasswordContext {
  userName?: string | null | undefined;
  displayName?: string | null | undefined;
  hostName?: string | null | undefined;
}

export interface PasswordCheckInput extends PasswordContext {
  policy: PasswordPolicy;
  breach: BreachMode;
}

const BREACHED = new Set(BREACHED_PASSWORDS);

/** NFKC, the form that is checked and hashed. */
export function normalizePassword(password: string): string {
  return password.normalize("NFKC");
}

function chars(text: string): string[] {
  return Array.from(text);
}

function fold(text: string): string {
  return chars(text)
    .map((c) => c.toLowerCase())
    .join("");
}

function isRepeatedUnit(folded: string): boolean {
  const points = chars(folded);
  for (let unit = 1; unit <= MAX_REPEATED_UNIT; unit += 1) {
    if (points.length < 2 * unit || points.length % unit !== 0) continue;
    if (points.every((c, i) => c === points[i % unit])) return true;
  }
  return false;
}

function isRun(folded: string): boolean {
  const points = chars(folded).map((c) => c.codePointAt(0) ?? 0);
  if (points.length < 2) return false;
  let ascending = true;
  let descending = true;
  for (let i = 1; i < points.length; i += 1) {
    const previous = points[i - 1] ?? 0;
    const current = points[i] ?? 0;
    ascending &&= current === previous + 1;
    descending &&= previous === current + 1;
    if (!ascending && !descending) return false;
  }
  return true;
}

/** A repeated or sequential pattern such as `0000`, `1234`, `abcd` or `aaaaaaaaaaaa`. */
export function isTrivial(password: string): boolean {
  const folded = fold(password);
  return isRepeatedUnit(folded) || isRun(folded);
}

function needle(raw: string | null | undefined, minChars: number): string | null {
  if (!raw) return null;
  const folded = fold(normalizePassword(raw.trim()));
  return chars(folded).length >= minChars ? folded : null;
}

function contextNeedles(kind: "user_name" | "display_name" | "host_name" | "product", c: PasswordContext): string[] {
  const out: (string | null)[] = [];
  switch (kind) {
    case "user_name":
      out.push(needle(c.userName, MIN_SHORT_CONTEXT_CHARS));
      break;
    case "display_name":
      if (c.displayName) {
        out.push(needle(c.displayName, MIN_DISPLAY_CONTEXT_CHARS));
        for (const part of c.displayName.split(/\s+/)) out.push(needle(part, MIN_DISPLAY_CONTEXT_CHARS));
      }
      break;
    case "host_name":
      if (c.hostName) {
        const host = c.hostName.trim().replace(/\.+$/, "");
        out.push(needle(host, MIN_SHORT_CONTEXT_CHARS));
        out.push(needle(host.split(".")[0], MIN_SHORT_CONTEXT_CHARS));
      }
      break;
    case "product":
      for (const word of PRODUCT_WORDS) out.push(needle(word, 1));
      break;
  }
  return out.filter((n): n is string => n !== null);
}

function matchesPattern(pattern: string, text: string): boolean {
  try {
    return new RegExp(`^(?:${pattern})$`, "u").test(text);
  } catch {
    // A pattern that does not compile matches nothing: the check fails closed.
    return false;
  }
}

/**
 * The violations of a password against a policy, in the order of the backend: invalid
 * characters, digits only, too short, too long, trivial, one context-specific entry per
 * matching word (user name, display name, host name, product) and the custom pattern.
 */
export function policyViolations(
  password: string,
  policy: PasswordPolicy,
  context: PasswordContext = {},
): PolicyViolation[] {
  const text = normalizePassword(password);
  const violations: PolicyViolation[] = [];

  if (/\p{Cc}/u.test(text)) violations.push({ kind: "invalid_characters" });
  if (policy.preset === "pin" && !/^[0-9]*$/.test(text)) violations.push({ kind: "pin_digits_only" });
  const length = chars(text).length;
  if (length < policyMinLength(policy)) violations.push({ kind: "too_short", min: policyMinLength(policy) });
  if (length > policyMaxLength(policy)) violations.push({ kind: "too_long", max: policyMaxLength(policy) });
  if (isTrivial(text)) violations.push({ kind: "trivial" });

  const folded = fold(text);
  for (const kind of ["user_name", "display_name", "host_name", "product"] as const) {
    if (contextNeedles(kind, context).some((n) => folded.includes(n))) {
      violations.push({ kind: "context_specific", context: kind });
    }
  }
  if (policy.preset === "custom" && policy.pattern && !matchesPattern(policy.pattern, text)) {
    violations.push({ kind: "pattern_mismatch" });
  }
  return violations;
}

/** A PIN in substance: digits only and under 12 characters (the server's rule, IAM-07). */
export function isPinLike(normalized: string): boolean {
  return normalized.length > 0 && normalized.length < 12 && /^[0-9]+$/.test(normalized);
}

/** Whether the breached-password corpus holds the password. */
export function isBreached(password: string): boolean {
  return BREACHED.has(password) || BREACHED.has(normalizePassword(password));
}

/** Checks a candidate the way `POST /auth/password/check` answers. */
export function checkPassword(password: string, input: PasswordCheckInput): PasswordCheckResult {
  const violations = policyViolations(password, input.policy, input);
  let breachCheck: BreachStatus = "off";
  if (input.breach !== "off") {
    if (isPinLike(normalizePassword(password)) && input.policy.preset === "pin") {
      // As the server: every short numeric code is in the corpus, so a PIN is not looked up.
      breachCheck = "not_applicable";
    } else if (isBreached(password)) {
      breachCheck = "breached";
      violations.push({ kind: "breached" });
    } else {
      breachCheck = "clean";
    }
  }
  return {
    acceptable: violations.length === 0,
    violations,
    breach_check: breachCheck,
    policy: structuredClone(input.policy),
  };
}

/** The stable code of a violation: `auth.password.<kind>`. */
export function violationCode(violation: PolicyViolation): string {
  return `auth.password.${violation.kind}`;
}

/** The named parameters of a violation's message (all strings, like the API's `params`). */
export function violationParams(violation: PolicyViolation): Record<string, string> {
  switch (violation.kind) {
    case "too_short":
      return { min: String(violation.min) };
    case "too_long":
      return { max: String(violation.max) };
    case "context_specific":
      return { context: violation.context };
    case "breached":
      return violation.count === undefined ? {} : { count: String(violation.count) };
    default:
      return {};
  }
}
