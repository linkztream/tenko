// Why Continue is blocked on a step, and which control fixes it. Pure functions of plain
// data, so the logic is tested without rendering (the mockup's `gate()`).
import type { DataDirFacts, NodeRole, Profile, TlsMode } from "../api/types";
import type { ForwardTransport } from "../dns/forwarders/model";
import { dnsStepProblem, isValidUserName, parseProxyList, validateHostName } from "./validate";
// WP8.6: the checks of the DHCP step.
import { dhcpStepProblem, type DhcpStepProblem, type DhcpStepState } from "./dhcp";

/**
 * The steps in order. The DNS step (P2-Q5) is always in the list; when the DNS module or the
 * `dns` role is not chosen it says so and has nothing to set.
 */
export const STEP_IDS = ["welcome", "profile", "admin", "host", "disk", "roles", "dns", "dhcp", "done"] as const;
// WP8.6: the DHCP step (after the DNS step) asks for the first scope while the `dhcp` role and
// the DHCP module are chosen; otherwise it says so and has nothing to set.
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
  dnsUpstreams: "wz-dns-upstreams",
  dnsTlsName: "wz-dns-tls",
  dnsEntries: "wz-dns-entries",
  // WP8.6: the controls of the DHCP step.
  dhcpMode: "wz-dhcp-mode",
  dhcpNetwork: "wz-dhcp-network",
  dhcpPoolFirst: "wz-dhcp-pool-first",
  dhcpPoolLast: "wz-dhcp-pool-last",
  dhcpRouter: "wz-dhcp-router",
  dhcpDns: "wz-dhcp-dns",
  dhcpLease: "wz-dhcp-lease",
  dhcpAddress: "wz-dhcp-address",
  dhcpIface: "wz-dhcp-iface",
  dhcpOthersOff: "wz-dhcp-others-off",
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
  | "setup.gate.dns_upstreams"
  | "setup.gate.dns_tls_name"
  | "setup.gate.dns_entries"
  // WP8.6: the DHCP step.
  | `setup.gate.dhcp.${DhcpStepProblem}`
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
  /** The DNS step: whether it applies (the module and the role are chosen) and what it holds. */
  dns: {
    wanted: boolean;
    // WP10.4: resolve names yourself or forward them.
    resolve?: "recurse" | "forward";
    upstreams: string;
    transport: ForwardTransport;
    tlsName: string;
    cache: boolean;
    cacheEntries: string;
  };
  // WP8.6: the DHCP step: whether it applies (the module and the role are chosen) and what it holds.
  dhcp?: { wanted: boolean; state: DhcpStepState };
}

// WP8.6: the control that fixes each problem of the DHCP step.
const DHCP_FOCUS: Readonly<Record<DhcpStepProblem, string>> = {
  network: FOCUS.dhcpNetwork,
  pool_first: FOCUS.dhcpPoolFirst,
  pool_last: FOCUS.dhcpPoolLast,
  pool_order: FOCUS.dhcpPoolFirst,
  router: FOCUS.dhcpRouter,
  router_in_pool: FOCUS.dhcpRouter,
  dns: FOCUS.dhcpDns,
  lease: FOCUS.dhcpLease,
  address: FOCUS.dhcpAddress,
  iface: FOCUS.dhcpIface,
  others_off: FOCUS.dhcpOthersOff,
};

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
    case "dns": {
      if (!g.dns.wanted) return null;
      switch (dnsStepProblem(g.dns)) {
        case "upstreams":
          return { message: "setup.gate.dns_upstreams", focus: FOCUS.dnsUpstreams };
        case "tls_name":
          return { message: "setup.gate.dns_tls_name", focus: FOCUS.dnsTlsName };
        case "entries":
          return { message: "setup.gate.dns_entries", focus: FOCUS.dnsEntries };
        default:
          return null;
      }
    }
    // WP8.6: the DHCP step.
    case "dhcp": {
      if (!g.dhcp) return null;
      const problem = dhcpStepProblem(g.dhcp.state, g.dhcp.wanted);
      return problem === null ? null : { message: `setup.gate.dhcp.${problem}`, focus: DHCP_FOCUS[problem] };
    }
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
