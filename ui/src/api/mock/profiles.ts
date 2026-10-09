// The toggle matrix TGL-01 to TGL-07 of the four security profiles (docs/SECURITY-PROFILES.md)
// and the rules that turn a set of settings into toggle states and a banner. They mirror
// crates/tenko-auth/src/settings.rs.
import type {
  Banner,
  BreachMode,
  LockoutMode,
  MfaRequirement,
  PasswordPolicy,
  Profile,
  SecuritySettings,
  ToggleState,
} from "../types";

const DAY = 86_400;
const HOUR = 3_600;

/** The toggle values of each profile. */
export const PROFILE_MATRIX: Readonly<Record<Profile, SecuritySettings>> = {
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

/** A fresh copy of the settings a profile sets. */
export function profileSettings(profile: Profile): SecuritySettings {
  return structuredClone(PROFILE_MATRIX[profile]);
}

/** The toggle id of each setting. */
export const TOGGLE_IDS = {
  password_policy: "TGL-01",
  mfa: "TGL-02",
  passkey_for_admins: "TGL-03",
  session: "TGL-04",
  token_max_days: "TGL-05",
  breach_check: "TGL-06",
  lockout: "TGL-07",
} as const;

type ToggleSetting = keyof typeof TOGGLE_IDS;

const MFA_RANK: Record<MfaRequirement, number> = { optional: 0, administrators: 1, everyone: 2 };
const BREACH_RANK: Record<BreachMode, number> = { off: 0, online: 1, offline: 1, offline_preferred: 1 };
const LOCKOUT_RANK: Record<LockoutMode, number> = {
  off: 0,
  progressive_delay: 1,
  delay_then_temporary_lock: 2,
  lock_until_unlock: 3,
};

/** The minimum length a policy asks for; the presets order as pin < standard < hardened. */
export function policyMinLength(policy: PasswordPolicy): number {
  switch (policy.preset) {
    case "pin":
      return 4;
    case "standard":
      return 12;
    case "hardened":
      return 16;
    case "custom":
      return policy.min_length;
  }
}

/** The longest password a policy accepts. */
export function policyMaxLength(policy: PasswordPolicy): number {
  switch (policy.preset) {
    case "pin":
      return 64;
    case "standard":
    case "hardened":
      return 256;
    case "custom":
      return policy.max_length ?? 256;
  }
}

const HOME = PROFILE_MATRIX.home;

/** Whether the value of one setting is strictly weaker than the Home value. */
export function isWeakerThanHome(setting: ToggleSetting, settings: SecuritySettings): boolean {
  switch (setting) {
    case "password_policy":
      return policyMinLength(settings.password_policy) < policyMinLength(HOME.password_policy);
    case "mfa":
      return MFA_RANK[settings.mfa] < MFA_RANK[HOME.mfa];
    case "passkey_for_admins":
      return !settings.passkey_for_admins && HOME.passkey_for_admins;
    case "session":
      // A longer lifetime, absolute or idle, is weaker.
      return (
        settings.session.absolute_secs > HOME.session.absolute_secs ||
        settings.session.idle_secs > HOME.session.idle_secs
      );
    case "token_max_days": {
      const days = settings.token_max_days ?? null;
      const home = HOME.token_max_days ?? null;
      if (days === null) return home !== null;
      return home !== null && days > home;
    }
    case "breach_check":
      return BREACH_RANK[settings.breach_check] < BREACH_RANK[HOME.breach_check];
    case "lockout":
      return LOCKOUT_RANK[settings.lockout] < LOCKOUT_RANK[HOME.lockout];
  }
}

/** JSON text with sorted keys, for comparing values the way the API reports them. */
function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

/** The value of a setting as the toggle list reports it (JSON, `null` for no maximum). */
function toggleValue(setting: ToggleSetting, settings: SecuritySettings): unknown {
  return setting === "token_max_days" ? (settings.token_max_days ?? null) : structuredClone(settings[setting]);
}

/** TGL-01 to TGL-07 with their profile defaults, deviation and weakness markers. */
export function toggleStates(settings: SecuritySettings): ToggleState[] {
  const profile = PROFILE_MATRIX[settings.profile];
  return (Object.keys(TOGGLE_IDS) as ToggleSetting[]).map((setting) => {
    const value = toggleValue(setting, settings);
    const profileDefault = toggleValue(setting, profile);
    return {
      id: TOGGLE_IDS[setting],
      setting,
      value,
      profile_default: profileDefault,
      deviates: stable(value) !== stable(profileDefault),
      weaker_than_home: isWeakerThanHome(setting, settings),
    };
  });
}

/** The warning banner: the Lab profile, or any toggle weaker than Home. */
export function banner(settings: SecuritySettings): Banner {
  const toggles = toggleStates(settings);
  return {
    lab: settings.profile === "lab",
    weaker_than_home: toggles.some((t) => t.weaker_than_home),
    deviations: toggles.filter((t) => t.deviates).map((t) => t.id),
  };
}
