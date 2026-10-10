import { describe, expect, it } from "vitest";
import type { PlanWarning } from "../../api/types";
import type { VlanStepPreview } from "./api";
import {
  buildRequest,
  confirmKey,
  emptyForm,
  isNetworkWarning,
  MAX_NETWORK_NAME,
  MAX_RELAYS,
  modeHint,
  modeWord,
  networkWarningText,
  parseRelays,
  problemText,
  reasonText,
  splitWarnings,
  stepText,
  validateForm,
  type ProvisionForm,
} from "./model";

const filled = (changes: Partial<ProvisionForm> = {}): ProvisionForm => ({
  ...emptyForm(),
  vid: "60",
  name: "Guests",
  ...changes,
});

const warning = (code: string, params: Record<string, string> = {}, requires_ack = true): PlanWarning => ({
  code,
  message: `English text of ${code}`,
  params,
  requires_ack,
  acknowledged: false,
});

const step = (kind: string, params: Record<string, string>, automatic = true): VlanStepPreview => ({
  kind,
  step_kind: `ipam.vlan.${kind}`,
  automatic,
  text: `English text of ${kind}`,
  params,
});

describe("emptyForm", () => {
  it("starts a new VLAN with the controller as the way to the network", () => {
    expect(emptyForm()).toMatchObject({ vlanId: "", vid: "", name: "", withPrefix: false, controller: "auto", connector: "" });
  });

  it("carries the id and the name of an existing VLAN", () => {
    expect(emptyForm({ id: "abc", vid: 30, name: "IoT" })).toMatchObject({ vlanId: "abc", vid: "30", name: "IoT" });
  });
});

describe("parseRelays", () => {
  it("splits on commas, semicolons and white space", () => {
    expect(parseRelays("192.0.2.53, 192.0.2.54;192.0.2.55\n192.0.2.56").addresses).toEqual([
      "192.0.2.53",
      "192.0.2.54",
      "192.0.2.55",
      "192.0.2.56",
    ]);
    expect(parseRelays("")).toEqual({ addresses: [], invalid: [] });
    expect(parseRelays(" , ; ").addresses).toEqual([]);
  });

  it("writes IPv6 addresses in their canonical form and keeps each address once", () => {
    expect(parseRelays("2001:DB8:0:0:0:0:0:53 2001:db8::53 192.0.2.1 192.0.2.1").addresses).toEqual(["2001:db8::53", "192.0.2.1"]);
  });

  it("lists what is not an address", () => {
    const list = parseRelays("192.0.2.53 dhcp.example.test 192.0.2.256 2001:db8::53");
    expect(list.addresses).toEqual(["192.0.2.53", "2001:db8::53"]);
    expect(list.invalid).toEqual(["dhcp.example.test", "192.0.2.256"]);
  });
});

describe("validateForm", () => {
  it("accepts a VLAN with a network and a few relays", () => {
    expect(
      validateForm(filled({ withPrefix: true, cidr: "203.0.113.208/28", dhcpRelay: "192.0.2.53, 2001:db8::53", vni: "5000", networkName: "Visitors" })),
    ).toEqual({});
  });

  it("wants a VLAN id from 1 to 4094 and a name", () => {
    expect(validateForm(filled({ vid: "", name: "" }))).toEqual({ vid: { code: "vid_invalid" }, name: { code: "name_required" } });
    for (const vid of ["0", "4095", "-1", "1.5", "ten", "1e2"]) expect(validateForm(filled({ vid })).vid, vid).toEqual({ code: "vid_invalid" });
    for (const vid of ["1", "4094", " 60 "]) expect(validateForm(filled({ vid })).vid, vid).toBeUndefined();
    expect(validateForm(filled({ name: "   " })).name).toEqual({ code: "name_required" });
  });

  it("checks the VNI only when there is one", () => {
    expect(validateForm(filled({ vni: "" })).vni).toBeUndefined();
    expect(validateForm(filled({ vni: "0" })).vni).toBeUndefined();
    expect(validateForm(filled({ vni: "16777215" })).vni).toBeUndefined();
    for (const vni of ["16777216", "-1", "1.5", "vx"]) expect(validateForm(filled({ vni })).vni, vni).toEqual({ code: "vni_invalid" });
  });

  it("does not check the id and the name of an existing VLAN", () => {
    expect(validateForm({ ...emptyForm({ id: "abc", vid: 30, name: "" }) })).toEqual({});
  });

  it("wants a CIDR without host bits and with a length when a network is asked for", () => {
    expect(validateForm(filled({ withPrefix: true })).cidr).toEqual({ code: "cidr_required" });
    for (const cidr of ["203.0.113.208", "203.0.113.209/28", "203.0.113.0/33", "lan", "2001:db8::1/64"]) {
      expect(validateForm(filled({ withPrefix: true, cidr })).cidr, cidr).toEqual({ code: "cidr_invalid" });
    }
    expect(validateForm(filled({ withPrefix: true, cidr: "2001:db8:0:60::/64" })).cidr).toBeUndefined();
    // Not asked for: whatever is typed is ignored.
    expect(validateForm(filled({ withPrefix: false, cidr: "nonsense" })).cidr).toBeUndefined();
  });

  it("limits the network name to 64 characters", () => {
    expect(validateForm(filled({ networkName: "x".repeat(MAX_NETWORK_NAME) }))["network-name"]).toBeUndefined();
    expect(validateForm(filled({ networkName: "x".repeat(MAX_NETWORK_NAME + 1) }))["network-name"]).toEqual({ code: "network_name_long" });
    // Characters, not bytes.
    expect(validateForm(filled({ networkName: "å".repeat(MAX_NETWORK_NAME) }))["network-name"]).toBeUndefined();
  });

  it("names the first relay that is not an address, and refuses more than eight", () => {
    expect(validateForm(filled({ dhcpRelay: "192.0.2.53 dhcp 192.0.2.999" }))["dhcp-relay"]).toEqual({ code: "relay_invalid", address: "dhcp" });
    const many = (count: number) => Array.from({ length: count }, (_, i) => `192.0.2.${50 + i}`).join(" ");
    expect(validateForm(filled({ dhcpRelay: many(MAX_RELAYS) }))["dhcp-relay"]).toBeUndefined();
    expect(validateForm(filled({ dhcpRelay: many(MAX_RELAYS + 1) }))["dhcp-relay"]).toEqual({ code: "relay_too_many" });
    // The same address twice is one address.
    expect(validateForm(filled({ dhcpRelay: `${many(MAX_RELAYS)} 192.0.2.50` }))["dhcp-relay"]).toBeUndefined();
  });

  it("does not check relays that a network made by hand will not use", () => {
    expect(validateForm(filled({ controller: "manual", dhcpRelay: "dhcp" }))["dhcp-relay"]).toBeUndefined();
  });
});

describe("problemText", () => {
  it("words every problem", () => {
    expect(problemText({ code: "vid_invalid" })).toBe("Enter a VLAN id from 1 to 4094.");
    expect(problemText({ code: "name_required" })).toBe("Enter a name.");
    expect(problemText({ code: "vni_invalid" })).toBe("Enter a VNI from 0 to 16777215.");
    expect(problemText({ code: "cidr_required" })).toBe("Enter the network.");
    expect(problemText({ code: "cidr_invalid" })).toMatch(/CIDR form/);
    expect(problemText({ code: "network_name_long" })).toBe("Use at most 64 characters.");
    expect(problemText({ code: "relay_invalid", address: "dhcp" })).toBe("dhcp is not a valid IPv4 or IPv6 address.");
    expect(problemText({ code: "relay_too_many" })).toBe("Enter at most 8 relay addresses.");
  });
});

describe("buildRequest", () => {
  it("builds the request of a new VLAN with only what was entered", () => {
    expect(buildRequest(filled())).toEqual({ create: { vid: 60, name: "Guests" } });
    expect(
      buildRequest(
        filled({
          name: "  Guests ",
          site: "site-1",
          vni: "5000",
          description: " Visitors ",
          withPrefix: true,
          cidr: " 203.0.113.208/28 ",
          vrf: "vrf-1",
          networkName: " Visitors ",
          dhcpRelay: "192.0.2.53, 2001:DB8::53",
        }),
      ),
    ).toEqual({
      create: { vid: 60, name: "Guests", site: "site-1", vni: 5000, description: "Visitors" },
      prefix: { cidr: "203.0.113.208/28", vrf: "vrf-1" },
      network_name: "Visitors",
      dhcp_relay: ["192.0.2.53", "2001:db8::53"],
    });
  });

  it("leaves the VRF out for the default VRF and the prefix out without a network", () => {
    expect(buildRequest(filled({ withPrefix: true, cidr: "203.0.113.208/28" })).prefix).toEqual({ cidr: "203.0.113.208/28" });
    expect(buildRequest(filled({ withPrefix: false, cidr: "203.0.113.208/28", vrf: "vrf-1" })).prefix).toBeUndefined();
  });

  it("names the existing VLAN instead of creating one", () => {
    const request = buildRequest({ ...emptyForm({ id: "vlan-30", vid: 30, name: "IoT" }), site: "ignored", vni: "1" });
    expect(request).toEqual({ vlan: "vlan-30" });
  });

  it("names the chosen connector", () => {
    expect(buildRequest(filled({ connector: "conn-1" })).connector).toBe("conn-1");
    expect(buildRequest(filled()).connector).toBeUndefined();
  });

  it("asks for a network by hand without a connector and without relays", () => {
    const request = buildRequest(filled({ controller: "manual", connector: "conn-1", dhcpRelay: "192.0.2.53", networkName: "Visitors" }));
    expect(request).toEqual({ create: { vid: 60, name: "Guests" }, manual: true, network_name: "Visitors" });
  });

  it("lists the acknowledged warning codes", () => {
    expect(buildRequest(filled(), ["ipam.vlan.network_changes"]).acknowledge).toEqual(["ipam.vlan.network_changes"]);
    expect(buildRequest(filled(), []).acknowledge).toBeUndefined();
  });
});

describe("confirmKey", () => {
  it("keeps the key for the same request and takes a new one when the request changes", () => {
    let made = 0;
    const make = () => `key-${++made}`;
    const first = confirmKey(null, buildRequest(filled()), make);
    expect(first.key).toBe("key-1");
    expect(confirmKey(first, buildRequest(filled()), make)).toBe(first);
    expect(made).toBe(1);
    const acknowledged = confirmKey(first, buildRequest(filled(), ["ipam.vlan.network_changes"]), make);
    expect(acknowledged.key).toBe("key-2");
    expect(confirmKey(acknowledged, buildRequest(filled(), ["ipam.vlan.network_changes"]), make)).toBe(acknowledged);
    expect(confirmKey(acknowledged, buildRequest(filled({ name: "Visitors" }), ["ipam.vlan.network_changes"]), make).key).toBe("key-3");
  });
});

describe("the words of the network step", () => {
  it("words each reason of a manual step, and an unknown one in general terms", () => {
    expect(reasonText("ipam.vlan.no_controller")).toMatch(/No network controller is configured/);
    expect(reasonText("ipam.vlan.manual_requested")).toMatch(/by hand/);
    expect(reasonText("ipam.vlan.controller_ambiguous")).toMatch(/Several network controllers/);
    expect(reasonText("ipam.vlan.controller_read_only")).toMatch(/switched off/);
    expect(reasonText("ipam.vlan.something_new")).toBe("A person creates the network.");
    expect(reasonText(null)).toBe("A person creates the network.");
    expect(reasonText(undefined)).toBe("A person creates the network.");
  });

  it("words each mode with a sentence", () => {
    expect([modeWord("automatic"), modeWord("unchanged"), modeWord("manual")]).toEqual(["Automatic", "Unchanged", "By hand"]);
    expect(modeHint("automatic")).toMatch(/reads it back/);
    expect(modeHint("unchanged")).toMatch(/already has the network/);
    expect(modeHint("manual")).toMatch(/person creates/);
  });
});

describe("stepText", () => {
  const vlan = { vid: 60, name: "Guests" };

  it("words the intent step of a new VLAN with and without a network", () => {
    const context = { vlan, existing: false, mode: "automatic" as const };
    expect(stepText(step("ipam.intent", { vid: "60", name: "Visitors", cidr: "203.0.113.208/28" }), context)).toBe(
      "Create VLAN 60 (Guests) and the network 203.0.113.208/28 in IPAM as planned.",
    );
    expect(stepText(step("ipam.intent", { vid: "60", name: "Visitors" }), context)).toBe("Create VLAN 60 (Guests) in IPAM as planned.");
  });

  it("words the intent step of an existing VLAN as the network it gets", () => {
    const context = { vlan: { vid: 20, name: "Lab" }, existing: true, mode: "automatic" as const };
    expect(stepText(step("ipam.intent", { vid: "20", name: "Lab", cidr: "203.0.113.208/28" }), context)).toBe(
      "Create the network 203.0.113.208/28 for VLAN 20 (Lab) in IPAM as planned.",
    );
  });

  it("words the network step with the network name of the step, not the VLAN name", () => {
    const params = { vid: "60", name: "Visitors", connector: "unifi.example.test" };
    expect(stepText(step("l2.network", params), { vlan, existing: false, mode: "automatic" })).toBe(
      "Create the network Visitors on VLAN 60 through unifi.example.test: dry run, write, read back and compare.",
    );
    expect(stepText(step("l2.network", params), { vlan, existing: false, mode: "unchanged" })).toBe(
      "Check that unifi.example.test has the network Visitors on VLAN 60.",
    );
  });

  it("words the manual step and the activation", () => {
    const context = { vlan, existing: false, mode: "manual" as const };
    expect(stepText(step("l2.manual", { vid: "60", name: "Guests" }, false), context)).toBe(
      "Create the network Guests on VLAN 60 on the switches and access points, then mark the step done.",
    );
    expect(stepText(step("activate", { vid: "60", name: "Guests" }), context)).toBe("Make VLAN 60 and its network active.");
  });

  it("falls back to the server text for a kind it does not know and for a step without its values", () => {
    const context = { vlan, existing: false, mode: "automatic" as const };
    expect(stepText(step("dns.manual", {}), context)).toBe("English text of dns.manual");
    expect(stepText(step("l2.network", { vid: "60", name: "Guests" }), context)).toBe("English text of l2.network");
    expect(stepText(step("l2.manual", {}, false), context)).toBe("English text of l2.manual");
    expect(stepText(step("ipam.intent", { vid: "20" }), { vlan, existing: true, mode: "automatic" })).toBe("English text of ipam.intent");
  });
});

describe("the warnings of the network step", () => {
  it("tells the warnings of the network step from those of the IPAM plan", () => {
    const warnings = [
      warning("ipam.prefix.nibble_boundary"),
      warning("ipam.vlan.controller_read_only", { connector: "unifi.example.test" }),
      warning("ipam.vlan.network_changes", { vid: "30" }),
      warning("ipam.vlan.controller_ambiguous", { count: "2" }),
    ];
    expect(isNetworkWarning(warnings[0] as PlanWarning)).toBe(false);
    expect(isNetworkWarning(warnings[1] as PlanWarning)).toBe(true);
    const split = splitWarnings(warnings);
    expect(split.plan.map((w) => w.code)).toEqual(["ipam.prefix.nibble_boundary"]);
    expect(split.network.map((w) => w.code)).toEqual(["ipam.vlan.controller_read_only", "ipam.vlan.network_changes", "ipam.vlan.controller_ambiguous"]);
  });

  it("words each warning from its own values", () => {
    expect(networkWarningText(warning("ipam.vlan.controller_read_only", { connector: "unifi.example.test" }))).toBe(
      "Writes through unifi.example.test are switched off. The network step is left to a person, who makes the changes shown above.",
    );
    expect(networkWarningText(warning("ipam.vlan.network_changes", { vid: "30" }))).toBe(
      "The controller already has a network on VLAN 30. The write changes it as shown above.",
    );
    expect(networkWarningText(warning("ipam.vlan.controller_ambiguous", { count: "2" }))).toMatch(/Several network controllers are configured/);
  });

  it("reads as the server's English when a value is missing, and for a warning of another kind", () => {
    expect(networkWarningText(warning("ipam.vlan.network_changes"))).toBe("English text of ipam.vlan.network_changes");
    expect(networkWarningText(warning("ipam.example.unknown"))).toBe("English text of ipam.example.unknown");
    // A warning of the IPAM plan reads as everywhere else: the translated text of its code.
    expect(networkWarningText(warning("ipam.prefix.nibble_boundary"))).toMatch(/nibble boundary/);
  });
});
