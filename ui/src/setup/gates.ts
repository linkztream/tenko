// Why Continue is blocked on a step, and which control fixes it. Pure functions of plain
// data, so the logic is tested without rendering (the mockup's `gate()`).
import type { DataDirFacts, NodeRole, Profile, TlsMode } from "../api/types";
import { isValidUserName, parseProxyList, validateHostName } from "./validate";

export const STEP_IDS = ["welcome", "profile", "admin", "host", "disk", "roles", "done"] as const;
export type StepId = (typeof STEP_IDS)[number];
export const STEP_COUNT = STEP_IDS.length;
export const LAST_STEP = STEP_COUNT - 1;

export function stepIndex(id: StepId): number {
  return STEP_IDS.indexOf(id);
}

/** DOM ids of the controls a gate points at. */
export const FOCUS = {
  token: "wz-token",
  labAck: "wz-lab-ack",
  userName: "wz-user",
  displayName: "wz-name",
  password: "wz-pw",
  hostName: "wz-host",
  proxies: "wz-proxies",
  diskOverride: "wz-disk-override",
  roleController: "wz-role-controller",
  roleProbe: "wz-role-probe",
  tlsPlain: "wz-tls-plain",
  firstNetwork: "wz-net-first",
  passkey: "wz-passkey",
  codesAck: "wz-codes",
} as const;

/** Where the password check stands for the current password, user name and profile. */
export type PasswordCheckStatus = "idle" | "pending" | "ok" | "bad" | "error";

/** The words for a gate; none of them takes arguments. */
export type GateMessage =
  | "setup.gate.token"
  | "setup.gate.lab_ack"
  | "setup.gate.user_name"
  | "setup.gate.display_name"
  | "setup.gate.password.pin"
  | "setup.gate.password.password"
  | "setup.gate.password.passphrase"
  | "setup.gate.password_pending"
  | "setup.gate.password_error"
  | "setup.gate.password_policy"
  | "setup.gate.tls_plain"
  | "setup.gate.host_empty"
  | "setup.gate.host_invalid"
  | "setup.gate.proxies_empty"
  | "setup.gate.proxies_invalid"
  | "setup.gate.disk"
  | "setup.gate.roles_none"
  | "setup.gate.roles_controller"
  | "setup.gate.probe_networks"
  | "setup.gate.codes_loading"
  | "setup.gate.codes_ack"
  | "setup.gate.passkey_waiting"
  | "setup.gate.passkey_required";

export interface Gate {
  message: GateMessage;
  /** The id of the control that fixes it. */
  focus: string;
  /** Waiting for something to finish rather than for the operator to act. */
  soft?: boolean;
}

export interface GateInput {
  token: string;
  profile: Profile;
  labAck: boolean;
  userName: string;
  displayName: string;
  password: string;
  /** "PIN", "password" or "passphrase", from the preset of the chosen profile. */
  passwordKind: "pin" | "password" | "passphrase";
  passwordCheck: PasswordCheckStatus;
  hostName: string;
  tlsMode: TlsMode;
  proxies: string;
  diskRisk: boolean;
  acceptSlowDisk: boolean;
  roles: Record<NodeRole, boolean>;
  /** The probe networks that are ticked. */
  probeNetworks: readonly string[];
  /** Whether the node reported any networks to probe. */
  hasNetworks: boolean;
}

export function rolesSelected(roles: Record<NodeRole, boolean>): number {
  return Object.values(roles).filter(Boolean).length;
}

const PASSWORD_MESSAGE = {
  pin: "setup.gate.password.pin",
  password: "setup.gate.password.password",
  passphrase: "setup.gate.password.passphrase",
} as const satisfies Record<GateInput["passwordKind"], GateMessage>;

/** The reason step `step` (0-based) cannot be left, or null. */
export function gateFor(step: number, g: GateInput): Gate | null {
  switch (STEP_IDS[step]) {
    case "welcome":
      if (g.token.trim() === "") return { message: "setup.gate.token", focus: FOCUS.token };
      return null;
    case "profile":
      if (g.profile === "lab" && !g.labAck) return { message: "setup.gate.lab_ack", focus: FOCUS.labAck };
      return null;
    case "admin":
      if (!isValidUserName(g.userName)) return { message: "setup.gate.user_name", focus: FOCUS.userName };
      if (g.displayName.trim() === "") return { message: "setup.gate.display_name", focus: FOCUS.displayName };
      if (g.password === "") return { message: PASSWORD_MESSAGE[g.passwordKind], focus: FOCUS.password };
      if (g.passwordCheck === "pending") return { message: "setup.gate.password_pending", focus: FOCUS.password, soft: true };
      if (g.passwordCheck === "error") return { message: "setup.gate.password_error", focus: FOCUS.password };
      if (g.passwordCheck !== "ok") return { message: "setup.gate.password_policy", focus: FOCUS.password };
      return null;
    case "host": {
      if (g.tlsMode === "plain" && g.profile !== "lab") return { message: "setup.gate.tls_plain", focus: FOCUS.tlsPlain };
      if (g.hostName.trim() === "") return { message: "setup.gate.host_empty", focus: FOCUS.hostName };
      if (!validateHostName(g.hostName).ok) return { message: "setup.gate.host_invalid", focus: FOCUS.hostName };
      if (g.tlsMode === "reverse_proxy") {
        const list = parseProxyList(g.proxies);
        if (list.entries.length === 0) return { message: "setup.gate.proxies_empty", focus: FOCUS.proxies };
        if (list.invalid.length > 0) return { message: "setup.gate.proxies_invalid", focus: FOCUS.proxies };
      }
      return null;
    }
    case "disk":
      if (g.diskRisk && !g.acceptSlowDisk) return { message: "setup.gate.disk", focus: FOCUS.diskOverride };
      return null;
    case "roles":
      if (rolesSelected(g.roles) === 0) return { message: "setup.gate.roles_none", focus: FOCUS.roleController };
      if (!g.roles.controller) return { message: "setup.gate.roles_controller", focus: FOCUS.roleController };
      if (g.roles.probe && g.probeNetworks.length === 0) {
        return { message: "setup.gate.probe_networks", focus: g.hasNetworks ? FOCUS.firstNetwork : FOCUS.roleProbe };
      }
      return null;
    default:
      return null;
  }
}

/** The first step before `before` (exclusive) that is blocked, or null. */
export function firstBlockedStep(g: GateInput, before: number = LAST_STEP): number | null {
  for (let i = 0; i < before; i += 1) if (gateFor(i, g) !== null) return i;
  return null;
}

export type DiskRisk = "rotating" | "slow";

/** The slowest median fsync a data disk may have (µs): a healthy SSD stays far below it. */
export const FSYNC_LIMIT_MICROS = 10_000;

/** Why the data disk is not supported, or null when it is fine (OPS-19). */
export function diskRisk(facts: DataDirFacts | null | undefined): DiskRisk | null {
  if (!facts) return null;
  if (facts.media === "hdd" || facts.media === "smr") return "rotating";
  if ((facts.fsync_p50_micros ?? 0) > FSYNC_LIMIT_MICROS) return "slow";
  return null;
}
