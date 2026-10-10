// TGL-24, the reveal policy of operator secrets, as the mock settings carry it: the value of
// the settings when someone set it, else the default of the profile (SECURITY-PROFILES.md).
// Shared by the settings decoration (routes-reveal-policy.ts) and the reveal of the secrets
// mock (routes-secrets.ts).
import type { components } from "../generated/schema";
import type { SecuritySettings } from "../types";
import { db } from "./db";

type RevealPolicy = components["schemas"]["RevealPolicy"];

export const REVEAL_DEFAULT: Readonly<Record<SecuritySettings["profile"], RevealPolicy>> = {
  home: { step_up: "session", bound_host_only: false },
  standard: { step_up: "fresh", bound_host_only: false },
  hardened: { step_up: "passkey", bound_host_only: true },
  lab: { step_up: "session", bound_host_only: false },
};

/** TGL-24 of a settings object: its own value, or the default of its profile. */
export function revealPolicy(settings: SecuritySettings = db.settings): RevealPolicy {
  return settings.secret_reveal ?? REVEAL_DEFAULT[settings.profile];
}
