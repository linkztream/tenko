import { describe, expect, it } from "vitest";
import type { MoveItem, MoveL2, MovePreview, MoveStepPreview } from "../../api/moves";
import { l2DiffText, l2Headline, l2NoteText, l2ReasonText, l2SsidsText, l2TaskKey, l2TaskText, problemText, stepText } from "./moveText";

const preview = {
  target: { prefix: "p", cidr: "198.51.100.0/24", vrf: "v", vlan: "l", vid: 30, lease_secs: null },
  timeout_secs: 3600,
  timeout_source: "default",
  parallelism: 2,
  base_revision: 0,
  items: [],
  warnings: [],
  unacknowledged: [],
} as MovePreview;

const noVlan = { ...preview, target: { ...preview.target, vid: null } } as MovePreview;

function item(l2: MoveL2 | undefined, extra: Partial<MoveItem> = {}): MoveItem {
  return {
    object: { kind: "address", id: "a1" },
    requested: { kind: "host", id: "h1" },
    host_name: "cam-door",
    mac: "00:00:5e:00:53:2b",
    new_address: "a2",
    old_ip: "192.0.2.43",
    new_ip: "198.51.100.43",
    same_host_part: true,
    steps: [],
    ...(l2 ? { l2 } : {}),
    ...extra,
  };
}

function step(kind: string, params: Record<string, string> = {}, automatic = false): MoveStepPreview {
  return { kind, step_kind: `ipam.move.${kind}`, automatic, text: `The server's text of ${kind}`, params };
}

const readOnlyPort: MoveL2 = {
  action: "manual",
  reason: "ipam.move.l2.read_only",
  change: { type: "set_port_profile", data: { device: "sw", port: 7, profile: "prof" } },
};

describe("the task of a manual network step", () => {
  it("chooses the message like the server", () => {
    const key = (l2: Partial<MoveL2>) => l2TaskKey({ action: "manual", ...l2 });
    expect(key({ reason: "ipam.move.l2.no_vlan" })).toBe("ipam.move.task.l2");
    expect(key(readOnlyPort)).toBe("ipam.move.task.l2_port");
    expect(key({ reason: "ipam.move.l2.read_only", change: { type: "set_client_vlan", data: { mac: "00:00:5e:00:53:2b", network: "n" } } })).toBe(
      "ipam.move.task.l2_client",
    );
    expect(key({ reason: "ipam.move.l2.read_only" })).toBe("ipam.move.task.l2_client");
    expect(key({ reason: "ipam.move.l2.no_profile" })).toBe("ipam.move.task.l2_port_vlan");
    expect(key({ reason: "ipam.move.l2.shared_port" })).toBe("ipam.move.task.l2_shared_port");
    expect(key({ reason: "ipam.move.l2.join_ssid" })).toBe("ipam.move.task.l2_ssid");
    expect(key({ reason: "ipam.move.l2.no_network" })).toBe("ipam.move.task.l2_network");
    expect(key({ reason: "ipam.move.l2.refused" })).toBe("ipam.move.task.l2_refused");
    // Every other reason is the general task.
    for (const reason of ["ipam.move.l2.no_controller", "ipam.move.l2.no_mac", "ipam.move.l2.not_seen", "ipam.move.l2.controller_ambiguous", undefined]) {
      expect(key({ reason: reason ?? null })).toBe("ipam.move.task.l2_vlan");
    }
  });

  it("uses the arguments of the step and fills in the VLAN and the MAC address", () => {
    const params = { connector: "unifi.example.test", device: "sw-desk", port: "7", profile: "IoT" };
    const text = l2TaskText(step("l2.move", params), item(readOnlyPort), preview);
    expect(text).toBe("On unifi.example.test, give port 7 of sw-desk the port profile IoT (VLAN 30 untagged); writes through this connector are off.");
    // The arguments of the step win over the ones the item knows.
    expect(l2TaskText(step("l2.move", { ...params, vid: "31" }), item(readOnlyPort), preview)).toContain("VLAN 31 untagged");
    // The count is a number, so the plural rule applies.
    const shared: MoveL2 = { action: "manual", reason: "ipam.move.l2.shared_port" };
    expect(l2TaskText(step("l2.move", { device: "sw-desk", port: "8", count: "2" }), item(shared), preview)).toBe(
      "Move the device to VLAN 30 by hand: port 8 of sw-desk also serves 2 other devices, and a profile change would move them too.",
    );
    expect(l2TaskText(step("l2.move", { device: "sw-desk", port: "8", count: "1" }), item(shared), preview)).toContain("also serves 1 other device,");
  });

  it("says nothing exact when the step lacks an argument the message needs", () => {
    expect(l2TaskText(step("l2.move", { connector: "unifi.example.test", port: "7", profile: "IoT" }), item(readOnlyPort), preview)).toBeUndefined();
    expect(l2TaskText(step("l2.move", {}), item(readOnlyPort), preview)).toBeUndefined();
    // No VLAN on the target: only the general task about the network needs no VLAN.
    expect(l2TaskText(step("l2.move"), item({ action: "manual", reason: "ipam.move.l2.not_seen" }), noVlan)).toBeUndefined();
    expect(l2TaskText(step("l2.move"), item({ action: "manual", reason: "ipam.move.l2.no_vlan" }), noVlan)).toBe(
      "Move the device to the network 198.51.100.0/24.",
    );
    // An item without a decision, or with an automatic one, has no manual task.
    expect(l2TaskText(step("l2.move", { device: "sw" }), item(undefined), preview)).toBeUndefined();
    expect(l2TaskText(step("l2.move"), item({ action: "port_profile" }), preview)).toBeUndefined();
  });

  it("falls back to the old text of the step", () => {
    expect(stepText(step("l2.move"), item(readOnlyPort), preview)).toBe("Move cam-door to VLAN 30 (switch port or wireless network).");
    expect(stepText(step("l2.move"), item(undefined), noVlan)).toBe("Connect cam-door to the network 198.51.100.0/24.");
    expect(stepText(step("l2.move", { connector: "c", device: "d", port: "1", profile: "p" }), item(readOnlyPort), preview)).toContain("give port 1 of d the port profile p");
  });

  it("words the controller step and leaves unknown steps to the server", () => {
    const text = stepText(step("l2.controller", { connector: "unifi.example.test" }, true), item({ action: "port_profile" }), preview);
    expect(text).toBe("Move cam-door to VLAN 30 through unifi.example.test: dry run, write, read back and compare.");
    // The connector may come from the decision instead of the step.
    const decided = item({ action: "client_vlan", connector: { id: "c", name: "unifi.example.test", plugin: "unifi", enabled: true, writes_enabled: true } });
    expect(stepText(step("l2.controller", {}, true), decided, preview)).toContain("through unifi.example.test:");
    // Without it, the server's text stands.
    expect(stepText(step("l2.controller", {}, true), item(undefined), preview)).toBe("The server's text of l2.controller");
    expect(stepText(step("future.kind"), item(undefined), preview)).toBe("The server's text of future.kind");
  });
});

describe("the words of the network column", () => {
  it("gives a reason for every manual case and the code itself when it has no words or lacks an argument", () => {
    const reason = (l2: Partial<MoveL2>) => l2ReasonText({ action: "manual", ...l2 }, preview);
    expect(reason({ reason: "ipam.move.l2.no_mac" })).toBe("The device has no MAC address in IPAM.");
    expect(reason({ reason: "ipam.move.l2.no_network" })).toBe("The network controller has no network for VLAN 30.");
    expect(reason({ reason: "ipam.move.l2.join_ssid", ssids: ["iot.example.test"] })).toBe(
      "Its access point does not carry VLAN 30: the device must join iot.example.test.",
    );
    expect(reason({ reason: "ipam.move.l2.read_only", connector: { id: "c", name: "unifi.example.test", plugin: "unifi", enabled: true, writes_enabled: false } })).toBe(
      "Writes through unifi.example.test are off (TGL-20).",
    );
    expect(reason({ reason: "ipam.move.l2.shared_port", others_on_port: 3 })).toBe("3 other devices are on the same switch port.");
    // The name of the SSID is missing, the reason of a future server has no words yet.
    expect(reason({ reason: "ipam.move.l2.join_ssid" })).toBe("ipam.move.l2.join_ssid");
    expect(reason({ reason: "ipam.move.l2.something_new" })).toBe("ipam.move.l2.something_new");
    expect(reason({})).toBeUndefined();
  });

  it("translates the guardrail of a refusal and keeps the server's detail for a code it does not know", () => {
    expect(problemText({ code: "connect.guardrail.uplink", detail: "port 1 is an uplink" })).toBe("This switch port is an uplink; Tenko never changes it.");
    expect(problemText({ code: "connect.guardrail.future", detail: "port 1 is special" })).toBe("port 1 is special");
    const refused: MoveL2 = { action: "manual", reason: "ipam.move.l2.refused", problem: { code: "connect.guardrail.management_port", detail: "d" } };
    expect(l2ReasonText(refused, preview)).toBe(
      "Refused by a guardrail: Tenko or the network controller is reached through this switch port; Tenko never changes it.",
    );
  });

  it("heads each action", () => {
    const wired: MoveL2 = {
      action: "port_profile",
      profile_name: "IoT",
      attachment: { medium: "wired", device: "d", device_name: "sw-desk", port: 7 },
    };
    expect(l2Headline(wired, preview)).toBe("Port profile IoT on sw-desk port 7");
    expect(l2Headline({ ...wired, action: "client_vlan", attachment: { medium: "wireless", device: "d", device_name: "ap-hall" } }, preview)).toBe(
      "VLAN override on ap-hall",
    );
    expect(l2Headline({ ...wired, action: "client_vlan", attachment: { medium: "wireless", device: "d", device_name: "ap-hall", ssid: "home.example.test" } }, preview)).toBe(
      "VLAN override on ap-hall (SSID home.example.test)",
    );
    expect(l2Headline({ action: "unchanged", reason: "ipam.move.l2.already_there" }, preview)).toBe("In VLAN 30 already");
    expect(l2Headline({ action: "shared", reason: "ipam.move.l2.same_interface", with: "a0" }, preview, "192.0.2.41")).toBe("Moves with 192.0.2.41");
    // The item it moves with is not in the batch: the reason says why there is no step.
    expect(l2Headline({ action: "shared", reason: "ipam.move.l2.same_interface", with: "a0" }, preview)).toBe("Another address of the same interface moves the device.");
    expect(l2Headline({ action: "manual", reason: "ipam.move.l2.not_seen" }, preview)).toBe("By hand");
  });

  it("words the notes, the diff and the SSID alternative", () => {
    expect(l2NoteText("ipam.move.l2.note.reconnect", preview)).toBe("The device moves when it reconnects.");
    expect(l2NoteText("ipam.move.l2.note.carry_unknown", preview)).toBe("Tenko cannot tell whether the access point carries VLAN 30.");
    expect(l2NoteText("ipam.move.l2.note.carry_unknown", noVlan)).toBe("ipam.move.l2.note.carry_unknown");
    expect(l2NoteText("ipam.move.l2.note.future", preview)).toBe("ipam.move.l2.note.future");
    expect(l2DiffText("LAN", "IoT")).toBe("LAN → IoT");
    expect(l2DiffText(null, "IoT")).toBe("none → IoT");
    expect(l2DiffText("LAN", undefined)).toBe("LAN → none");
    expect(l2SsidsText({ action: "port_profile", ssids: ["a.example.test", "b.example.test"] }, preview)).toBe(
      "Or join a wireless network that carries VLAN 30: a.example.test, b.example.test.",
    );
    expect(l2SsidsText({ action: "manual", ssids: [] }, preview)).toBeUndefined();
    expect(l2SsidsText({ action: "manual", reason: "ipam.move.l2.join_ssid", ssids: ["a.example.test"] }, preview)).toBeUndefined();
  });
});
