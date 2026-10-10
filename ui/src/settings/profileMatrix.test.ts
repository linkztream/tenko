import { describe, expect, it } from "vitest";
import { profileSettings, toggleStates } from "../api/mock/profiles";
import type { MfaRequirement, PasswordPolicy, SecuritySettingsView } from "../api/types";
import { admitsPin, PROFILE_DEFAULTS, pinCoupled, planProfileChange, valueOf, weakerSettings } from "./profileMatrix";
import { TOGGLES } from "./toggles";

const custom = (min_length: number, extra: { max_length?: number; pattern?: string } = {}): PasswordPolicy => ({
  preset: "custom",
  min_length,
  ...extra,
});

describe("admitsPin", () => {
  it("admits the PIN preset and no other preset", () => {
    expect(admitsPin({ preset: "pin" })).toBe(true);
    expect(admitsPin({ preset: "standard" })).toBe(false);
    expect(admitsPin({ preset: "hardened" })).toBe(false);
  });

  it("admits a Custom policy whose shortest password is shorter than 12 characters", () => {
    expect(admitsPin(custom(4))).toBe(true);
    expect(admitsPin(custom(8))).toBe(true);
    expect(admitsPin(custom(11))).toBe(true);
    expect(admitsPin(custom(12))).toBe(false);
    expect(admitsPin(custom(16, { max_length: 128 }))).toBe(false);
    // The server counts at least four characters whatever the minimum says.
    expect(admitsPin(custom(2))).toBe(true);
  });

  it("matches the pattern against the whole digit string of the shortest length", () => {
    expect(admitsPin(custom(8, { pattern: "[0-9]+" }))).toBe(true);
    expect(admitsPin(custom(8, { pattern: "\\d{8}" }))).toBe(true);
    expect(admitsPin(custom(8, { pattern: "\\d{4,8}" }))).toBe(true);
    // Anchored at both ends: a pattern for 9 digits does not match 8, and 4 digits do not match all 8.
    expect(admitsPin(custom(8, { pattern: "\\d{9}" }))).toBe(false);
    expect(admitsPin(custom(8, { pattern: "\\d{4}" }))).toBe(false);
    expect(admitsPin(custom(8, { pattern: "[a-z]+" }))).toBe(false);
    expect(admitsPin(custom(8, { pattern: "[a-z]+|[0-9]+" }))).toBe(true);
  });

  it("answers false for a pattern it cannot read", () => {
    expect(admitsPin(custom(8, { pattern: "(" }))).toBe(false);
    expect(admitsPin(custom(8, { pattern: "(?i)[0-9]+" }))).toBe(false);
    expect(admitsPin(custom(8, { pattern: "" }))).toBe(false);
  });

  it("refuses a policy whose maximum is below its shortest length", () => {
    expect(admitsPin(custom(8, { max_length: 6 }))).toBe(false);
  });
});

describe("pinCoupled", () => {
  /** The view of the settings of `profile` with `secrets` in the vault, and the given deviations. */
  function view(
    profile: "home" | "standard",
    secrets: boolean,
    changes: { mfa?: MfaRequirement; password_policy?: PasswordPolicy } = {},
  ): SecuritySettingsView {
    return {
      settings: { ...profileSettings(profile), ...changes },
      toggles: [],
      banner: { lab: false, weaker_than_home: false, deviations: [] },
      vault_has_operator_secrets: secrets,
      revision: 1,
    };
  }
  const PIN: PasswordPolicy = { preset: "pin" };
  const STANDARD: PasswordPolicy = { preset: "standard" };

  it("refuses a change that lets a PIN stand alone while the vault holds a secret", () => {
    // Standard to the PIN preset with MFA optional.
    expect(pinCoupled(view("standard", true), { password_policy: PIN, mfa: "optional" })).toBe(true);
    expect(pinCoupled(view("standard", true), { password_policy: custom(8), mfa: "optional" })).toBe(true);
    // Standard with MFA optional: the PIN preset alone is enough.
    expect(pinCoupled(view("standard", true, { mfa: "optional" }), { password_policy: PIN, mfa: "optional" })).toBe(true);
    // Home with MFA for everyone: MFA back to optional.
    expect(pinCoupled(view("home", true, { mfa: "everyone" }), { password_policy: PIN, mfa: "optional" })).toBe(true);
    // Home: a different policy that still admits a PIN.
    expect(pinCoupled(view("home", true), { password_policy: custom(6), mfa: "optional" })).toBe(true);
  });

  it("passes whatever does not let a PIN stand alone", () => {
    expect(pinCoupled(view("standard", true), { password_policy: PIN, mfa: "administrators" })).toBe(false);
    expect(pinCoupled(view("standard", true), { password_policy: PIN, mfa: "everyone" })).toBe(false);
    expect(pinCoupled(view("standard", true), { password_policy: STANDARD, mfa: "optional" })).toBe(false);
    expect(pinCoupled(view("standard", true), { password_policy: custom(12), mfa: "optional" })).toBe(false);
  });

  it("passes a change that leaves the password policy and MFA as they are, also under Home", () => {
    expect(pinCoupled(view("home", true), { password_policy: PIN, mfa: "optional" })).toBe(false);
    expect(pinCoupled(view("home", true, { password_policy: custom(8) }), { password_policy: custom(8, { max_length: 256 }), mfa: "optional" })).toBe(false);
    expect(pinCoupled(view("home", true, { password_policy: custom(8, { max_length: 128 }) }), { password_policy: custom(8, { max_length: 128 }), mfa: "optional" })).toBe(false);
  });

  it("passes everything while the vault holds no secret", () => {
    expect(pinCoupled(view("standard", false), { password_policy: PIN, mfa: "optional" })).toBe(false);
    expect(pinCoupled(view("home", false, { mfa: "everyone" }), { password_policy: PIN, mfa: "optional" })).toBe(false);
  });
});

describe("the toggle table", () => {
  it("lists the toggles by id, with TGL-21 before TGL-23", () => {
    const ids = TOGGLES.map((def) => def.id);
    expect(ids).toEqual([...ids].sort());
    expect(ids.indexOf("TGL-21")).toBe(ids.indexOf("TGL-07") + 1);
    expect(ids.indexOf("TGL-23")).toBe(ids.indexOf("TGL-21") + 1);
    expect(TOGGLES.find((def) => def.id === "TGL-21")?.setting).toBe("audit_export");
    // Every toggle of the table has a value in every profile.
    for (const profile of ["home", "standard", "hardened", "lab"] as const) {
      for (const def of TOGGLES) expect(valueOf(PROFILE_DEFAULTS[profile], def.setting), `${profile} ${def.id}`).not.toBeUndefined();
    }
  });

  it("plans a switch of profile with the audit export, and never finds it weaker than Home", () => {
    const standard = PROFILE_DEFAULTS.standard;
    const states = toggleStates(standard);
    const view = {
      settings: standard,
      toggles: TOGGLES.map((def) => {
        const state = states.find((s) => s.id === def.id);
        const value = state?.value ?? valueOf(standard, def.setting);
        return { id: def.id, setting: def.setting, value, profile_default: value, deviates: false, weaker_than_home: false };
      }),
      banner: { lab: false, weaker_than_home: false, deviations: [] },
      vault_has_operator_secrets: false,
      revision: 1,
    } as SecuritySettingsView;

    const hardened = planProfileChange(view, "hardened").find((change) => change.def.id === "TGL-21");
    expect(hardened).toMatchObject({ from: "optional", to: "required", weaker: false });
    const lab = planProfileChange(view, "lab").find((change) => change.def.id === "TGL-21");
    expect(lab).toMatchObject({ from: "optional", to: "local", weaker: false });
    expect(planProfileChange(view, "standard").some((change) => change.def.id === "TGL-21")).toBe(false);

    for (const profile of ["home", "standard", "hardened", "lab"] as const) {
      expect(weakerSettings(profile).map((def) => def.id)).not.toContain("TGL-21");
    }
  });
});
