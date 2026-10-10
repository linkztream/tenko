// The L2 step of the mock moves (IPAM-19 step 4, WP2.8): where the mock network controller sees
// the devices of the IPAM seed, and what the move job does for each, following the rules of
// crates/tenko-ipam/src/moves/l2.rs. The controller is the one of the topology and VLAN mocks
// (`mockVlanController`): `present = false` means no network controller, `enabled = false` a
// disabled one, `writes_enabled = false` writes off (TGL-20). The attachment table is fixed and
// describes the lab before the IoT move: the IoT devices are still in the LAN (VLAN 10).
import type { MoveItem, MoveL2, MoveL2Output, MoveTarget } from "../moves";
import { encodeMoveL2Output } from "../moves";
import type { PlanWarning } from "../types";
import type { MockMoveL2 } from "./job-store";
import { controllerInfo, mockVlanController } from "./topology-store";

/** Codes of the L2 step (crates/tenko-ipam/src/moves/mod.rs, `codes`). */
export const L2_CODES = {
  refusedWarning: "ipam.move.l2_refused",
  unavailableWarning: "ipam.move.controller_unavailable",
  planChanged: "ipam.move.plan_changed",
  noVlan: "ipam.move.l2.no_vlan",
  noController: "ipam.move.l2.no_controller",
  noMac: "ipam.move.l2.no_mac",
  notSeen: "ipam.move.l2.not_seen",
  noNetwork: "ipam.move.l2.no_network",
  noProfile: "ipam.move.l2.no_profile",
  sharedPort: "ipam.move.l2.shared_port",
  joinSsid: "ipam.move.l2.join_ssid",
  readOnly: "ipam.move.l2.read_only",
  refused: "ipam.move.l2.refused",
  alreadyThere: "ipam.move.l2.already_there",
  sameInterface: "ipam.move.l2.same_interface",
} as const;

interface Port {
  device: string;
  deviceName: string;
  index: number;
  name: string;
  profile: string | null;
  uplink?: boolean;
  management?: boolean;
  /** Other clients on the port. */
  others?: number;
}

interface Wireless {
  device: string;
  deviceName: string;
  ssid: string;
  /** Whether the access point carries VLAN 30. */
  carries: boolean;
}

interface Client {
  vlan: number;
  network: string;
  networkName: string;
  wired?: Port;
  wireless?: Wireless;
  management?: boolean;
}

const SW_CORE = { device: "00:00:5e:00:53:02", deviceName: "sw-core" };
const SW_DESK = { device: "00:00:5e:00:53:03", deviceName: "sw-desk" };
const AP_HALL = { device: "00:00:5e:00:53:04", deviceName: "ap-hall" };
const AP_GARAGE = { device: "00:00:5e:00:53:05", deviceName: "ap-garage" };
const AP_ATTIC = { device: "5c:a1:ab:1e:0a:01", deviceName: "ap-attic" };

const LAN = { vlan: 10, network: "net-lan", networkName: "LAN" };
const PROFILES: Readonly<Record<string, string>> = { "prof-lan": "LAN", "prof-iot": "IoT" };

/** Where the controller sees each MAC address of the IPAM seed, by its last byte. */
const CLIENTS: Readonly<Record<string, Client>> = {
  // Wireless IoT devices on access points that carry the IoT VLAN.
  "29": { ...LAN, wireless: { ...AP_HALL, ssid: "home.example.test", carries: true } },
  "2a": { ...LAN, wireless: { ...AP_GARAGE, ssid: "home.example.test", carries: true } },
  // A wired camera on its own port.
  "2b": { ...LAN, wired: { ...SW_DESK, index: 7, name: "Port 7", profile: "prof-lan" } },
  // A speaker behind a small switch: the port serves another device too.
  "2c": { ...LAN, wired: { ...SW_DESK, index: 8, name: "Port 8", profile: "prof-lan", others: 1 } },
  // A printer the controller sees on an uplink (behind an unmanaged switch).
  "1e": { ...LAN, wired: { ...SW_CORE, index: 1, name: "Uplink", profile: "prof-lan", uplink: true } },
  // A laptop on an access point that does not carry the IoT VLAN.
  "14": { ...LAN, wireless: { ...AP_ATTIC, ssid: "home.example.test", carries: false } },
  // Tenko's own host.
  "0d": { ...LAN, wired: { ...SW_CORE, index: 2, name: "Port 2", profile: "prof-lan", management: true }, management: true },
};

const IOT_SSID = "iot.example.test";

function lastByte(mac: string): string {
  return mac.toLowerCase().replace(/-/g, ":").split(":").pop() ?? "";
}

function manual(reason: string, extra: Partial<MoveL2> = {}): MoveL2 {
  return { action: "manual", reason, ...extra };
}

/** What the mock decides for each item, plus the warnings it raises (a refusal needs an acknowledgement). */
export interface MockL2Decision {
  items: MoveL2[];
  warnings: PlanWarning[];
  controllers: ReturnType<typeof controllerInfo>[];
}

export function decideL2(items: readonly MoveItem[], target: MoveTarget): MockL2Decision {
  const controller = mockVlanController.present && mockVlanController.enabled;
  const vid = target.vid ?? null;
  const first = new Map<string, string>();
  const warnings: PlanWarning[] = [];
  const decided = items.map((item): MoveL2 => {
    if (item.interface) {
      const with_ = first.get(item.interface);
      if (with_) return { action: "shared", reason: L2_CODES.sameInterface, with: with_ };
      first.set(item.interface, item.object.id);
    }
    if (vid === null) return manual(L2_CODES.noVlan);
    if (!controller) return manual(L2_CODES.noController);
    if (!item.mac) return manual(L2_CODES.noMac, { ssids: [IOT_SSID] });
    const client = CLIENTS[lastByte(item.mac)];
    if (!client) return manual(L2_CODES.notSeen, { ssids: [IOT_SSID] });
    const l2 = decideClient(item, client, vid);
    if (l2.reason === L2_CODES.refused) {
      const who = item.host_name ?? item.old_ip;
      warnings.push({
        code: L2_CODES.refusedWarning,
        message: `a guardrail refuses the network change of ${who} (${l2.problem?.code ?? ""}); a person moves it, if that is intended`,
        object: item.object,
        params: { host: who, rule: l2.problem?.code ?? "" },
        requires_ack: true,
        acknowledged: false,
      });
    }
    return l2;
  });
  return { items: decided, warnings, controllers: controller ? [controllerInfo()] : [] };
}

function decideClient(item: MoveItem, client: Client, vid: number): MoveL2 {
  const now = new Date().toISOString();
  const network = mockVlanController.networks.find((n) => n.vlan === vid && !n.management);
  const base: MoveL2 = {
    action: "manual",
    connector: controllerInfo(),
    read_at: now,
    ssids: vid === 30 ? [IOT_SSID] : [],
    attachment: client.wired
      ? {
          medium: "wired",
          device: client.wired.device,
          device_name: client.wired.deviceName,
          port: client.wired.index,
          port_name: client.wired.name,
          profile: client.wired.profile,
          profile_name: client.wired.profile ? (PROFILES[client.wired.profile] ?? client.wired.profile) : null,
          network: client.network,
          network_name: client.networkName,
          vlan: client.vlan,
        }
      : {
          medium: "wireless",
          device: client.wireless?.device ?? "",
          device_name: client.wireless?.deviceName ?? "",
          ssid: client.wireless?.ssid ?? null,
          network: client.network,
          network_name: client.networkName,
          vlan: client.vlan,
        },
  };
  if (client.vlan === vid) return { ...base, action: "unchanged", reason: L2_CODES.alreadyThere };
  if (!network) return { ...base, action: "manual", reason: L2_CODES.noNetwork };
  const named = { ...base, network_name: network.name };
  const refuse = (code: string, detail: string): MoveL2 => ({
    ...named,
    action: "manual",
    reason: L2_CODES.refused,
    problem: { code, detail },
  });
  if (client.management) return refuse("connect.guardrail.management_client", `${item.mac ?? ""} is the controller or Tenko's host`);
  let l2: MoveL2;
  if (client.wired) {
    const port = client.wired;
    if (port.uplink) return refuse("connect.guardrail.uplink", `port ${port.index} of ${port.deviceName} is an uplink`);
    if (port.management) return refuse("connect.guardrail.management_port", `Tenko or the controller is reached through port ${port.index} of ${port.deviceName}`);
    if (port.others) return { ...named, action: "manual", reason: L2_CODES.sharedPort, others_on_port: port.others };
    const notes = ["ipam.move.l2.note.link_flap"];
    if (!port.profile) notes.push("ipam.move.l2.note.no_undo");
    l2 = {
      ...named,
      action: "port_profile",
      change: { type: "set_port_profile", data: { device: port.device, port: port.index, profile: "prof-iot" } },
      profile_name: "IoT",
      diff: [
        {
          path: `devices/${port.device}/ports/${port.index}/profile`,
          before: port.profile ? (PROFILES[port.profile] ?? port.profile) : null,
          after: "IoT",
        },
      ],
      notes,
    };
  } else {
    if (!client.wireless?.carries) return { ...named, action: "manual", reason: L2_CODES.joinSsid };
    l2 = {
      ...named,
      action: "client_vlan",
      change: { type: "set_client_vlan", data: { mac: item.mac ?? "", network: network.id } },
      diff: [{ path: `clients/${item.mac ?? ""}/network`, before: client.networkName, after: network.name }],
      notes: ["ipam.move.l2.note.reconnect"],
    };
  }
  if (!mockVlanController.writes_enabled) return { ...l2, action: "manual", reason: L2_CODES.readOnly };
  return l2;
}

/** The message key of the manual task of an L2 step (crates/tenko-ipam/src/moves/l2.rs, `instruction`). */
export function l2Instruction(l2: MoveL2): string {
  switch (l2.reason) {
    case L2_CODES.noVlan:
      return "ipam.move.task.l2";
    case L2_CODES.readOnly:
      return l2.change?.type === "set_port_profile" ? "ipam.move.task.l2_port" : "ipam.move.task.l2_client";
    case L2_CODES.noProfile:
      return "ipam.move.task.l2_port_vlan";
    case L2_CODES.sharedPort:
      return "ipam.move.task.l2_shared_port";
    case L2_CODES.joinSsid:
      return "ipam.move.task.l2_ssid";
    case L2_CODES.noNetwork:
      return "ipam.move.task.l2_network";
    case L2_CODES.refused:
      return "ipam.move.task.l2_refused";
    default:
      return "ipam.move.task.l2_vlan";
  }
}

/** The message arguments of an L2 step on top of the base arguments (`args` of l2.rs). */
export function l2Args(l2: MoveL2): Record<string, string> {
  const out: Record<string, string> = { action: l2.action };
  const put = (key: string, value: string | number | null | undefined) => {
    if (value !== null && value !== undefined && value !== "") out[key] = String(value);
  };
  put("reason", l2.reason);
  put("connector", l2.connector?.name);
  put("device", l2.attachment?.device_name);
  put("port", l2.attachment?.port);
  put("port_name", l2.attachment?.port_name);
  put("ssid", l2.reason === L2_CODES.joinSsid ? l2.ssids?.[0] : l2.attachment?.ssid);
  put("current_profile", l2.attachment?.profile_name);
  put("current_network", l2.attachment?.network_name);
  put("profile", l2.profile_name);
  put("network", l2.network_name);
  put("count", l2.others_on_port);
  put("rule", l2.problem?.code);
  if (l2.ssids?.length) put("ssids", l2.ssids.join(", "));
  const line = l2.diff?.[0];
  if (line) {
    put("path", line.path);
    put("before", line.before);
    put("after", line.after);
  }
  return out;
}

/** The L2 step of the mock job of an item, with the output the controller step keeps. */
export function l2Step(item: MoveItem): MockMoveL2 | null {
  const l2 = item.l2;
  if (!l2) return null;
  if (l2.action === "unchanged" || l2.action === "shared") return { action: l2.action };
  if (l2.action === "manual") return { action: "manual", key: l2Instruction(l2), args: l2Args(l2) };
  const now = new Date().toISOString();
  const connector = l2.connector?.id ?? "";
  const output: MoveL2Output = {
    connector,
    change: l2.change ?? { type: "clear_client_vlan", data: { mac: item.mac ?? "" } },
    diff: l2.diff ?? [],
    warnings: l2.action === "port_profile" ? ["the device on port loses its link for a moment while the switch applies the profile"] : [],
    read_at: now,
    unchanged: false,
    unknown_write: false,
    receipt: { connector, dry_run: false, applied_at: now, verified: true, undo_steps: 1, token: "00" },
  };
  const args: Record<string, string> = { ...l2Args(l2), mac: item.mac ?? "" };
  return {
    action: l2.action,
    args,
    output: encodeMoveL2Output(output),
    changes: connector ? [{ kind: "connector", id: connector }] : [],
  };
}

/** A fingerprint of what a move would run: the addresses, the steps and the L2 decisions. */
export function fingerprintOf(items: readonly MoveItem[], target: string): string {
  const text = JSON.stringify([
    target,
    items.map((item) => [item.object.id, item.new_ip, item.steps.map((s) => s.step_kind), item.l2?.action, item.l2?.reason ?? null, item.l2?.change ?? null]),
  ]);
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0").repeat(4);
}
