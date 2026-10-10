// The security toggles of Slice 1 (TGL-01 to TGL-07, TGL-23 and TGL-24, docs/SECURITY-PROFILES.md): their
// names, how a value reads in the UI, and whether a value is weaker than the Home profile.
// Shared by the first-run wizard (profile preview) and the security settings page.
import type {
  BreachMode,
  LockoutMode,
  MfaRequirement,
  PasswordPolicy,
  Profile,
  SecuritySettings,
  SessionLifetime,
} from "../api/types";
import { formatDuration, t, type MessageKey } from "../i18n";

export type ToggleSetting =
  | "password_policy"
  | "mfa"
  | "passkey_for_admins"
  | "session"
  | "token_max_days"
  | "breach_check"
  | "lockout"
  | "updates"
  | "secret_reveal";

export interface ToggleDef {
  id: string;
  setting: ToggleSetting;
  name: MessageKey;
}

export const TOGGLES: readonly ToggleDef[] = [
  { id: "TGL-01", setting: "password_policy", name: "toggles.password_policy.name" },
  { id: "TGL-02", setting: "mfa", name: "toggles.mfa.name" },
  { id: "TGL-03", setting: "passkey_for_admins", name: "toggles.passkey_for_admins.name" },
  { id: "TGL-04", setting: "session", name: "toggles.session.name" },
  { id: "TGL-05", setting: "token_max_days", name: "toggles.token_max_days.name" },
  { id: "TGL-06", setting: "breach_check", name: "toggles.breach_check.name" },
  { id: "TGL-07", setting: "lockout", name: "toggles.lockout.name" },
  { id: "TGL-23", setting: "updates", name: "toggles.updates.name" },
  { id: "TGL-24", setting: "secret_reveal", name: "toggles.secret_reveal.name" },
];

/** The total number of toggles in the profile matrix; later ones arrive with their features. */
export const TOGGLE_TOTAL = 24;

export function toggleById(id: string): ToggleDef | undefined {
  return TOGGLES.find((x) => x.id === id);
}

export function toggleBySetting(setting: string): ToggleDef | undefined {
  return TOGGLES.find((x) => x.setting === setting);
}

/** TGL-23 (OPS-24): the daily update check and who may install a new version. */
export type UpdatesPolicy = NonNullable<SecuritySettings["updates"]>;
export type UpdatesInstall = UpdatesPolicy["install"];
export const UPDATES_INSTALL: readonly UpdatesInstall[] = ["ui", "ui_step_up", "upload_only"];

/** The value of TGL-23 in each profile (docs/SECURITY-PROFILES.md): the daily check is on in all of them. */
export const UPDATES_DEFAULT: Readonly<Record<Profile, UpdatesPolicy>> = {
  home: { check: true, install: "ui" },
  standard: { check: true, install: "ui_step_up" },
  hardened: { check: true, install: "upload_only" },
  lab: { check: true, install: "ui" },
};

/** The updates policy of a settings object; one without it (an older answer) follows its profile. */
export function updatesOf(settings: SecuritySettings): UpdatesPolicy {
  return settings.updates ?? UPDATES_DEFAULT[settings.profile];
}

export function formatUpdates(value: unknown): string {
  const policy = (value ?? UPDATES_DEFAULT.home) as UpdatesPolicy;
  return t("toggles.updates.value", {
    check: t(policy.check ? "toggles.updates.check_on" : "toggles.updates.check_off"),
    install: t(`toggles.updates.install.${policy.install}`),
  });
}

/** TGL-24 (IAM-16, API-11): what revealing an operator secret takes. */
export type RevealPolicy = NonNullable<SecuritySettings["secret_reveal"]>;
export type RevealStepUp = RevealPolicy["step_up"];
/** The step-up values from the weakest to the strongest. */
export const REVEAL_STEP_UP: readonly RevealStepUp[] = ["session", "fresh", "passkey"];

/**
 * The value of TGL-24 in each profile (docs/SECURITY-PROFILES.md). No value is weaker than Home.
 * The PIN coupling rule holds on top of every value: a PIN-strength session never reveals, and
 * personal API tokens never reveal.
 */
export const REVEAL_DEFAULT: Readonly<Record<Profile, RevealPolicy>> = {
  home: { step_up: "session", bound_host_only: false },
  standard: { step_up: "fresh", bound_host_only: false },
  hardened: { step_up: "passkey", bound_host_only: true },
  lab: { step_up: "session", bound_host_only: false },
};

/** The reveal policy of a settings object; one without it (an older answer) follows its profile. */
export function revealOf(settings: SecuritySettings): RevealPolicy {
  return settings.secret_reveal ?? REVEAL_DEFAULT[settings.profile];
}

export function formatReveal(value: unknown): string {
  const policy = (value ?? REVEAL_DEFAULT.home) as RevealPolicy;
  return t("toggles.secret_reveal.value", {
    step_up: t(`toggles.secret_reveal.step_up.${policy.step_up}`),
    bound: policy.bound_host_only ? "yes" : "no",
  });
}

export function formatPolicy(p: PasswordPolicy): string {
  switch (p.preset) {
    case "pin":
      return t("toggles.password_policy.pin");
    case "standard":
      return t("toggles.password_policy.standard");
    case "hardened":
      return t("toggles.password_policy.hardened");
    case "custom":
      return t("toggles.password_policy.custom", { min: p.min_length });
  }
}

export function formatSession(s: SessionLifetime): string {
  return t("toggles.session.value", { absolute: formatDuration(s.absolute_secs), idle: formatDuration(s.idle_secs) });
}

/** How the value of a setting reads, for example "12 h / 1 h" or "Required for administrators". */
export function formatToggle(setting: string, value: unknown): string {
  switch (setting) {
    case "password_policy":
      return formatPolicy(value as PasswordPolicy);
    case "mfa":
      return t(`toggles.mfa.${value as MfaRequirement}`);
    case "passkey_for_admins":
      return value ? t("common.yes") : t("common.no");
    case "session":
      return formatSession(value as SessionLifetime);
    case "token_max_days":
      return value === null || value === undefined
        ? t("toggles.token_max_days.unlimited")
        : t("toggles.token_max_days.days", { days: value as number });
    case "breach_check":
      return t(`toggles.breach_check.${value as BreachMode}`);
    case "lockout":
      return t(`toggles.lockout.${value as LockoutMode}`);
    case "updates":
      return formatUpdates(value);
    case "secret_reveal":
      return formatReveal(value);
    default:
      return typeof value === "string" ? value : JSON.stringify(value);
  }
}

const POLICY_RANK: Record<PasswordPolicy["preset"], number> = { pin: 0, standard: 2, hardened: 3, custom: 1 };
const MFA_RANK: Record<MfaRequirement, number> = { optional: 0, administrators: 1, everyone: 2 };
const LOCKOUT_RANK: Record<LockoutMode, number> = {
  off: 0,
  progressive_delay: 1,
  delay_then_temporary_lock: 2,
  lock_until_unlock: 3,
};

function policyStrength(p: PasswordPolicy): number {
  if (p.preset === "custom") return p.min_length >= 16 ? 3 : p.min_length >= 12 ? 2 : 1;
  return POLICY_RANK[p.preset];
}

/**
 * Whether `value` is strictly weaker than `home` for a setting: the rule behind the
 * "weaker than Home" marker and the warning banner. The server reports this for the
 * current settings; the wizard uses it to preview a profile.
 */
export function weakerThan(setting: string, value: unknown, home: unknown): boolean {
  switch (setting) {
    case "password_policy":
      return policyStrength(value as PasswordPolicy) < policyStrength(home as PasswordPolicy);
    case "mfa":
      return MFA_RANK[value as MfaRequirement] < MFA_RANK[home as MfaRequirement];
    case "passkey_for_admins":
      return !value && !!home;
    case "session": {
      const v = value as SessionLifetime;
      const h = home as SessionLifetime;
      return v.absolute_secs > h.absolute_secs || v.idle_secs > h.idle_secs;
    }
    case "token_max_days": {
      const v = value as number | null | undefined;
      const h = home as number | null | undefined;
      if (v === null || v === undefined) return h !== null && h !== undefined;
      return h !== null && h !== undefined && v > h;
    }
    case "breach_check":
      return value === "off" && home !== "off";
    case "lockout":
      return LOCKOUT_RANK[value as LockoutMode] < LOCKOUT_RANK[home as LockoutMode];
    case "updates":
      // Not looking for new versions is weaker than Home; who installs them is a matter of taste.
      return (value as UpdatesPolicy).check === false && (home as UpdatesPolicy).check === true;
    case "secret_reveal":
      // Home asks for the least that TGL-24 allows (a signed-in session), so no value is weaker.
      return false;
    default:
      return false;
  }
}

/** The value of a toggle in a settings object. */
export function settingValue(settings: SecuritySettings, setting: ToggleSetting): unknown {
  if (setting === "updates") return updatesOf(settings);
  return setting === "secret_reveal" ? revealOf(settings) : settings[setting];
}
