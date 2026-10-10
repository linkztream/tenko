// What the page needs to know about profiles beyond what the server reports: the toggle
// values of every profile, so that the profile dialog can preview a switch before it is
// made. The server reports the defaults of the selected profile only (`profile_default`),
// so this table mirrors docs/SECURITY-PROFILES.md and crates/tenko-auth/src/settings.rs.
// The server stays the authority: the preview is a preview, and the saved result always
// comes from the server's answer.
import type { MfaRequirement, PasswordPolicy, Profile, SecuritySettings, SecuritySettingsView } from "../api/types";
import {
  REVEAL_DEFAULT,
  revealOf,
  TOGGLES,
  UPDATES_DEFAULT,
  updatesOf,
  weakerThan,
  type ToggleDef,
  type ToggleSetting,
} from "./toggles";

const HOUR = 3_600;
const DAY = 86_400;

export const PROFILE_DEFAULTS: Readonly<Record<Profile, SecuritySettings>> = {
  home: {
    profile: "home",
    password_policy: { preset: "pin" },
    mfa: "optional",
    passkey_for_admins: false,
    session: { absolute_secs: 30 * DAY, idle_secs: 7 * DAY },
    token_max_days: 365,
    breach_check: "online",
    lockout: "progressive_delay",
    updates: UPDATES_DEFAULT.home,
    secret_reveal: REVEAL_DEFAULT.home,
  },
  standard: {
    profile: "standard",
    password_policy: { preset: "standard" },
    mfa: "administrators",
    passkey_for_admins: false,
    session: { absolute_secs: 12 * HOUR, idle_secs: HOUR },
    token_max_days: 90,
    breach_check: "online",
    lockout: "delay_then_temporary_lock",
    updates: UPDATES_DEFAULT.standard,
    secret_reveal: REVEAL_DEFAULT.standard,
  },
  hardened: {
    profile: "hardened",
    password_policy: { preset: "hardened" },
    mfa: "everyone",
    passkey_for_admins: true,
    session: { absolute_secs: 8 * HOUR, idle_secs: 15 * 60 },
    token_max_days: 30,
    breach_check: "offline_preferred",
    lockout: "lock_until_unlock",
    updates: UPDATES_DEFAULT.hardened,
    secret_reveal: REVEAL_DEFAULT.hardened,
  },
  lab: {
    profile: "lab",
    password_policy: { preset: "pin" },
    mfa: "optional",
    passkey_for_admins: false,
    session: { absolute_secs: 30 * DAY, idle_secs: 7 * DAY },
    token_max_days: null,
    breach_check: "off",
    lockout: "off",
    updates: UPDATES_DEFAULT.lab,
    secret_reveal: REVEAL_DEFAULT.lab,
  },
};

/** The value of one setting the way a toggle reports it (`null` for no token maximum). */
export function valueOf(settings: SecuritySettings, setting: ToggleSetting): unknown {
  if (setting === "updates") return updatesOf(settings);
  if (setting === "secret_reveal") return revealOf(settings);
  return setting === "token_max_days" ? (settings.token_max_days ?? null) : settings[setting];
}

/** The Home value of a setting: the baseline for "weaker than Home". */
export function homeValue(setting: ToggleSetting): unknown {
  return valueOf(PROFILE_DEFAULTS.home, setting);
}

/** A value with sorted keys and without empty members, so equal settings compare equal. */
function normalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      const member = record[key];
      if (member !== null && member !== undefined) out[key] = normalize(member);
    }
    return out;
  }
  return value === undefined ? null : value;
}

/** Whether two setting values are the same value as far as the API is concerned. */
export function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
}

/** One setting that a switch to a profile would change. */
export interface PlannedChange {
  def: ToggleDef;
  from: unknown;
  to: unknown;
  /** Whether the new value is weaker than Home. */
  weaker: boolean;
}

/**
 * The settings that change when `target` is selected: every setting whose value is not the
 * target's value. Selecting the current profile resets the settings that deviate from it.
 */
export function planProfileChange(view: SecuritySettingsView, target: Profile): PlannedChange[] {
  const out: PlannedChange[] = [];
  for (const def of TOGGLES) {
    const state = view.toggles.find((s) => s.id === def.id);
    if (!state) continue;
    // For the current profile the server's own default is the truth.
    const to = target === view.settings.profile ? state.profile_default : valueOf(PROFILE_DEFAULTS[target], def.setting);
    if (sameValue(state.value, to)) continue;
    out.push({ def, from: state.value, to, weaker: weakerThan(def.setting, to, homeValue(def.setting)) });
  }
  return out;
}

/** The settings of `target` that are weaker than Home. */
export function weakerSettings(target: Profile): ToggleDef[] {
  return TOGGLES.filter((def) => weakerThan(def.setting, valueOf(PROFILE_DEFAULTS[target], def.setting), homeValue(def.setting)));
}

/** Digits-only secrets shorter than this count as PINs whatever the preset (IAM-07). */
const PIN_LIKE_BELOW = 12;

/** The longest password a Custom policy accepts when it sets no maximum. */
const DEFAULT_MAX_LENGTH = 256;

/**
 * Whether a password policy lets a PIN stand alone: the PIN preset, or a Custom preset that
 * accepts a digits-only secret shorter than 12 characters (`admits_pin` in
 * crates/tenko-auth/src/service/account.rs). The server tries a non-trivial digit string of
 * length `max(min_length, 4)`; such a string passes every other check of a policy, so only
 * the length limits and the pattern decide. A pattern is matched against the whole string,
 * as the server does. A pattern that is not a valid JavaScript expression (the server speaks
 * Rust regex syntax) answers false: the server still refuses what it must, and the dialog
 * then shows its error.
 */
export function admitsPin(policy: PasswordPolicy): boolean {
  if (policy.preset === "pin") return true;
  if (policy.preset !== "custom") return false;
  const length = Math.max(policy.min_length, 4);
  if (length >= PIN_LIKE_BELOW || length > (policy.max_length ?? DEFAULT_MAX_LENGTH)) return false;
  const pattern = policy.pattern;
  if (pattern === undefined || pattern === null) return true;
  if (pattern === "") return false;
  try {
    return new RegExp(`^(?:${pattern})$`, "u").test("7391586240".repeat(2).slice(0, length));
  } catch {
    return false;
  }
}

/** Whether two policies are the same one for the server (an absent maximum is 256). */
function samePolicy(a: PasswordPolicy, b: PasswordPolicy): boolean {
  if (a.preset !== "custom" || b.preset !== "custom") return a.preset === b.preset;
  return (
    a.min_length === b.min_length &&
    (a.max_length ?? DEFAULT_MAX_LENGTH) === (b.max_length ?? DEFAULT_MAX_LENGTH) &&
    (a.pattern ?? null) === (b.pattern ?? null)
  );
}

/**
 * Whether the server would refuse a change of the security settings because of the PIN
 * coupling rule (IAM-07, `settings.pin_coupling`). `next` holds the password policy and the
 * MFA requirement the settings would have after the change. The change is refused exactly
 * when the vault holds an operator secret, the result lets a PIN stand alone (a policy that
 * admits a PIN with MFA optional) and the change touches what decides it (the policy or the
 * MFA requirement differs from the current one). Any other change passes, also under Home
 * and Lab, which have exactly that combination.
 */
export function pinCoupled(
  view: SecuritySettingsView,
  next: { password_policy: PasswordPolicy; mfa: MfaRequirement },
): boolean {
  if (!view.vault_has_operator_secrets) return false;
  if (next.mfa !== "optional" || !admitsPin(next.password_policy)) return false;
  const { password_policy, mfa } = view.settings;
  return mfa !== next.mfa || !samePolicy(password_policy, next.password_policy);
}
