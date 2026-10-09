// What the page needs to know about profiles beyond what the server reports: the toggle
// values of every profile, so that the profile dialog can preview a switch before it is
// made. The server reports the defaults of the selected profile only (`profile_default`),
// so this table mirrors docs/SECURITY-PROFILES.md and crates/tenko-auth/src/settings.rs.
// The server stays the authority: the preview is a preview, and the saved result always
// comes from the server's answer.
import type { PasswordPolicy, Profile, SecuritySettings, SecuritySettingsView } from "../api/types";
import { TOGGLES, weakerThan, type ToggleDef, type ToggleSetting } from "./toggles";

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
  },
};

/** The value of one setting the way a toggle reports it (`null` for no token maximum). */
export function valueOf(settings: SecuritySettings, setting: ToggleSetting): unknown {
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

/**
 * Whether the server would refuse `next` because of the PIN coupling rule (IAM-07): the PIN
 * preset cannot be selected while the vault holds secrets.
 */
export function pinBlocked(view: SecuritySettingsView, next: PasswordPolicy): boolean {
  return next.preset === "pin" && view.settings.password_policy.preset !== "pin" && view.vault_has_operator_secrets;
}
