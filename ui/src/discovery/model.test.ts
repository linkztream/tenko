import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiEvent } from "../api/events";
import { formatDateTime, setLocale } from "../i18n";
import type { NameSource, ObservationSource, Observed, ObservedFact, Proposal } from "./api";
import {
  canApprove,
  factTypeWord,
  isCurrent,
  isOpen,
  isProposalEvent,
  kindClass,
  kindIcon,
  kindWord,
  lastSeenOf,
  lookupSubject,
  choiceText,
  choicesLine,
  nameRuleWord,
  nameSourceWord,
  observedParts,
  placeholderName,
  splitNames,
  NO_NAMES,
  kindSummary,
  observedText,
  probeMethodWord,
  ruleName,
  ruleText,
  severityIcon,
  severityWord,
  sourceKeyText,
  sourceText,
  stateWord,
  subjectKind,
  subjectLabel,
  subjectValue,
  type SourceNames,
} from "./model";

beforeEach(async () => {
  await setLocale("en");
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** A proposal with the members the words depend on; the summary is the server's English text. */
function ruled(rule: string, params: Record<string, string>, summary = "the English summary of the server"): Pick<Proposal, "rule" | "params" | "summary"> {
  return { rule, params, summary };
}

const text = (rule: string, params: Record<string, string>) => ruleText(ruled(rule, params));

const NAMES: SourceNames = {
  connector: (id) => ({ "0190d1c2-0000-7000-8000-00000c000001": "Lab inventory", "0190d1c2-0000-7000-8000-00000c000002": "Home network" })[id],
  node: (id) => ({ 1001: "probe-dmz" })[id],
};
const INVENTORY = "0190d1c2-0000-7000-8000-00000c000001";
const CONTROLLER = "0190d1c2-0000-7000-8000-00000c000002";

function fact(observed: Observed, expires_at?: string | null): ObservedFact {
  return {
    source: { type: "inventory", connector: INVENTORY },
    source_key: `inventory:${INVENTORY}`,
    subject: { type: "host", data: { external_id: "vm-1" } },
    subject_key: "host:vm-1",
    observed,
    observation: "0190d1c2-0000-7000-8000-00000e000001",
    first_seen: "2026-10-01T00:00:00Z",
    last_seen: "2026-10-01T00:00:00Z",
    received_at: "2026-10-01T00:00:00Z",
    expires_at,
    revision: 1,
  } as ObservedFact;
}

describe("the words of a proposal", () => {
  it("has a word, a glyph and a class for every kind", () => {
    expect(kindWord("discovered_host")).toBe("Discovered host");
    expect(kindWord("address_mismatch")).toBe("Address differs");
    expect(kindWord("conflict")).toBe("Conflict");
    expect(kindWord("outside_prefixes")).toBe("Outside known networks");
    expect(kindWord("orphaned_intent")).toBe("Not seen any more");
    expect(kindWord("vlan_discovered")).toBe("VLAN discovered");
    expect(kindWord("prefix_vlan_mismatch")).toBe("Prefix VLAN differs");
    expect(kindWord("host_name")).toBe("Host name");

    expect(kindIcon("discovered_host")).toBe("proposal");
    expect(kindIcon("conflict")).toBe("conflict");
    expect(kindIcon("address_mismatch")).toBe("alert");
    expect(kindIcon("outside_prefixes")).toBe("layers");
    expect(kindIcon("orphaned_intent")).toBe("clock");
    expect(kindIcon("vlan_discovered")).toBe("cable");
    expect(kindIcon("prefix_vlan_mismatch")).toBe("link");
    expect(kindIcon("host_name")).toBe("server");
    expect(kindClass("host_name")).toBe("proposal");
    expect(kindClass("vlan_discovered")).toBe("proposal");
    expect(kindClass("prefix_vlan_mismatch")).toBe("discrepancy");

    // Magenta for proposals, red for conflicts, amber for differences.
    expect(kindClass("discovered_host")).toBe("proposal");
    expect(kindClass("outside_prefixes")).toBe("proposal");
    expect(kindClass("conflict")).toBe("conflict");
    expect(kindClass("address_mismatch")).toBe("discrepancy");
    expect(kindClass("orphaned_intent")).toBe("discrepancy");
  });

  it("has a word and a glyph for every severity and a word for every state", () => {
    expect(severityWord("critical")).toBe("Critical");
    expect(severityWord("warning")).toBe("Warning");
    expect(severityWord("info")).toBe("Info");
    expect(severityIcon("critical")).toBe("conflict");
    expect(severityIcon("warning")).toBe("alert");
    expect(severityIcon("info")).toBe("info");
    expect(["open", "accepted", "rejected", "expired", "superseded"].map((s) => stateWord(s as Proposal["state"]))).toEqual([
      "Open",
      "Accepted",
      "Rejected",
      "Expired",
      "Superseded",
    ]);
  });
});

describe("what can be decided", () => {
  const commands = [{ op: "create_host", args: {} }] as unknown as Proposal["commands"];

  it("lets only an open proposal be decided", () => {
    expect(isOpen({ state: "open" })).toBe(true);
    for (const state of ["accepted", "rejected", "expired", "superseded"] as const) expect(isOpen({ state })).toBe(false);
  });

  it("lets an open proposal with commands be approved", () => {
    expect(canApprove({ state: "open", kind: "discovered_host", commands })).toBe(true);
    expect(canApprove({ state: "open", kind: "address_mismatch", commands })).toBe(true);
    expect(canApprove({ state: "open", kind: "outside_prefixes", commands })).toBe(true);
    expect(canApprove({ state: "open", kind: "orphaned_intent", commands })).toBe(true);
  });

  it("refuses a conflict, a decided proposal and one without commands", () => {
    expect(canApprove({ state: "open", kind: "conflict", commands })).toBe(false);
    for (const state of ["accepted", "rejected", "expired", "superseded"] as const) {
      expect(canApprove({ state, kind: "discovered_host", commands })).toBe(false);
    }
    expect(canApprove({ state: "open", kind: "discovered_host", commands: [] })).toBe(false);
    expect(canApprove({ state: "open", kind: "address_mismatch", commands: undefined })).toBe(false);
  });
});

describe("the events that concern proposals", () => {
  const event = (change: Partial<ApiEvent>): ApiEvent => ({ topic: "ipam", type: "ipam", objects: [], deleted: [], revision: 7, data: {}, ...change });

  it("accepts an event that names a proposal, changed or removed", () => {
    expect(isProposalEvent(event({ objects: [{ kind: "host", id: "h" }, { kind: "proposal", id: "p" }] }))).toBe(true);
    expect(isProposalEvent(event({ deleted: [{ kind: "proposal", id: "p" }] }))).toBe(true);
  });

  it("accepts an event that names the table of proposals", () => {
    expect(isProposalEvent(event({ data: { tables: ["ipam.hosts", "ipam.proposals"] } }))).toBe(true);
  });

  it("refuses the rest", () => {
    expect(isProposalEvent(event({}))).toBe(false);
    expect(isProposalEvent(event({ objects: [{ kind: "host", id: "h" }], deleted: [{ kind: "address", id: "a" }] }))).toBe(false);
    expect(isProposalEvent(event({ data: { tables: ["ipam.hosts", "ipam.adoption"] } }))).toBe(false);
    expect(isProposalEvent(event({ data: { tables: "ipam.proposals" } }))).toBe(false);
    expect(isProposalEvent(event({ data: { tables: null } }))).toBe(false);
  });
});

describe("the text of a rule", () => {
  it("takes the last part of a rule code as its name", () => {
    expect(ruleName("ipam.reconcile.discovered_mac")).toBe("discovered_mac");
    expect(ruleName("discovered_mac")).toBe("discovered_mac");
    expect(ruleName("a.b.c.d")).toBe("d");
    expect(ruleName("")).toBe("");
  });

  describe("discovered_mac and discovered_address (section 4.5)", () => {
    it("names the device, its addresses and its sources", () => {
      expect(text("ipam.reconcile.discovered_mac", { name: "media-pc", sources: "1", mac: "00:00:5e:00:53:d1", ips: "192.0.2.150" })).toBe(
        "Unknown device 00:00:5e:00:53:d1 (media-pc) seen at 192.0.2.150 by one source; adopt it as host media-pc",
      );
      expect(text("ipam.reconcile.discovered_mac", { name: "media-pc", sources: "3", mac: "00:00:5e:00:53:d1", ips: "192.0.2.150, 192.0.2.151" })).toBe(
        "Unknown device 00:00:5e:00:53:d1 (media-pc) seen at 192.0.2.150, 192.0.2.151 by 3 sources; adopt it as host media-pc",
      );
    });

    it("leaves out the addresses of a device that was seen without one", () => {
      expect(text("ipam.reconcile.discovered_mac", { name: "host-00005e0053d2", sources: "2", mac: "00:00:5e:00:53:d2" })).toBe(
        "Unknown device 00:00:5e:00:53:d2 (host-00005e0053d2) seen by 2 sources; adopt it as host host-00005e0053d2",
      );
    });

    it("leaves out the MAC address of a device that was seen without one", () => {
      expect(text("ipam.reconcile.discovered_address", { name: "host-198-51-100-77", sources: "1", ips: "198.51.100.77" })).toBe(
        "Unknown device (host-198-51-100-77) seen at 198.51.100.77 by one source; adopt it as host host-198-51-100-77",
      );
    });

    it("reads an empty parameter as an absent one", () => {
      expect(text("ipam.reconcile.discovered_address", { name: "a", sources: "1", mac: "", ips: "" })).toBe(
        "Unknown device (a) seen by one source; adopt it as host a",
      );
    });

    it("keeps a name that is made of digits as it is", () => {
      expect(text("ipam.reconcile.discovered_address", { name: "123", sources: "1", ips: "192.0.2.9" })).toBe(
        "Unknown device (123) seen at 192.0.2.9 by one source; adopt it as host 123",
      );
    });
  });

  describe("address_unrecorded and address_mismatch (section 4.6)", () => {
    it("says that the intent does not list the address", () => {
      expect(text("ipam.reconcile.address_unrecorded", { host: "thermostat-1", ip: "192.0.2.49" })).toBe(
        "thermostat-1 is seen at 192.0.2.49, which its intent does not list; record it",
      );
    });

    it("says which address a host was expected at", () => {
      expect(text("ipam.reconcile.address_mismatch", { host: "thermostat-1", ip: "192.0.2.49", intended: "192.0.2.41" })).toBe(
        "thermostat-1 is seen at 192.0.2.49, not at its intended 192.0.2.41",
      );
      // The server joins several intended addresses with a comma.
      expect(text("ipam.reconcile.address_mismatch", { host: "nas", ip: "2001:db8::5", intended: "2001:db8::1, 2001:db8::2" })).toBe(
        "nas is seen at 2001:db8::5, not at its intended 2001:db8::1, 2001:db8::2",
      );
    });
  });

  describe("orphaned_address (section 4.7)", () => {
    const seen = "2026-09-20T08:15:00+00:00";

    it("names the address, its host and when it was seen last", () => {
      const when = formatDateTime(Date.parse(seen));
      expect(text("ipam.reconcile.orphaned_address", { ip: "192.0.2.60", host: "doorbell", last_seen: seen, source: `probe:1:arp` })).toBe(
        `192.0.2.60 (doorbell) has not been seen since ${when}; deprecate the address`,
      );
    });

    it("names an address without a host by itself", () => {
      const when = formatDateTime(Date.parse(seen));
      expect(text("ipam.reconcile.orphaned_address", { ip: "192.0.2.61", last_seen: seen, source: "probe:1:arp" })).toBe(
        `192.0.2.61 has not been seen since ${when}; deprecate the address`,
      );
    });

    it("shows a time it cannot read as it is", () => {
      expect(text("ipam.reconcile.orphaned_address", { ip: "192.0.2.61", last_seen: "last week", source: "x" })).toBe(
        "192.0.2.61 has not been seen since last week; deprecate the address",
      );
    });
  });

  describe("conflicts (section 4.8)", () => {
    it("counts the devices that share an address", () => {
      expect(text("ipam.reconcile.conflict_shared_address", { ip: "192.0.2.30", macs: "00:00:5e:00:53:b0, 00:00:5e:00:53:b1", count: "2" })).toBe(
        "192.0.2.30 is used by 2 devices: 00:00:5e:00:53:b0, 00:00:5e:00:53:b1",
      );
      expect(text("ipam.reconcile.conflict_shared_address", { ip: "192.0.2.30", macs: "00:00:5e:00:53:b0", count: "1" })).toBe(
        "192.0.2.30 is used by 1 device: 00:00:5e:00:53:b0",
      );
    });

    it("counts the networks a device is seen in", () => {
      expect(text("ipam.reconcile.conflict_networks", { mac: "00:00:5e:00:53:d1", networks: "192.0.2.0/24, 198.51.100.0/24", count: "2" })).toBe(
        "00:00:5e:00:53:d1 is seen in 2 networks: 192.0.2.0/24, 198.51.100.0/24",
      );
      expect(text("ipam.reconcile.conflict_networks", { mac: "00:00:5e:00:53:d1", networks: "192.0.2.0/24", count: "1" })).toBe(
        "00:00:5e:00:53:d1 is seen in 1 network: 192.0.2.0/24",
      );
    });

    it("names the host an address is intended for and the devices that use it", () => {
      expect(
        text("ipam.reconcile.conflict_address_taken", { ip: "192.0.2.30", host: "printer-1", intended_mac: "00:00:5e:00:53:1e", macs: "00:00:5e:00:53:b0" }),
      ).toBe("192.0.2.30 is intended for printer-1 (00:00:5e:00:53:1e) but used by 00:00:5e:00:53:b0");
    });
  });

  describe("the VLANs of controller networks", () => {
    it("counts them in the phrase of a batch decision", () => {
      expect(kindSummary([{ kind: "vlan_discovered" }, { kind: "prefix_vlan_mismatch" }, { kind: "prefix_vlan_mismatch" }])).toBe(
        "1 discovered VLAN and 2 prefixes on another VLAN",
      );
    });

    it("names the VLAN to create and the prefix to link", () => {
      expect(text("ipam.reconcile.vlan_discovered", { vid: "30", name: "IoT", cidr: "198.51.100.0/24" })).toBe(
        "The network controller carries VLAN 30 (IoT), which IPAM does not know; create the VLAN",
      );
      expect(text("ipam.reconcile.prefix_vlan_unset", { cidr: "198.51.100.0/24", vid: "30", name: "IoT" })).toBe(
        "The network controller carries 198.51.100.0/24 on VLAN 30 (IoT); link the prefix to that VLAN",
      );
      expect(text("ipam.reconcile.prefix_vlan_differs", { cidr: "198.51.100.0/24", vid: "30", name: "IoT", current: "20" })).toBe(
        "The network controller carries 198.51.100.0/24 on VLAN 30 (IoT), but the prefix is linked to VLAN 20; link it to VLAN 30",
      );
    });
  });

  describe("outside_prefixes (section 4.9)", () => {
    it("counts the addresses and names the network to create", () => {
      expect(text("ipam.reconcile.outside_prefixes", { cidr: "203.0.113.224/27", count: "1", ips: "203.0.113.230" })).toBe(
        "1 address seen outside every known network; create the network 203.0.113.224/27",
      );
      expect(text("ipam.reconcile.outside_prefixes", { cidr: "203.0.113.0/24", count: "3", ips: "203.0.113.5, 203.0.113.6, 203.0.113.7" })).toBe(
        "3 addresses seen outside every known network; create the network 203.0.113.0/24",
      );
      expect(text("ipam.reconcile.outside_prefixes", { cidr: "2001:db8:0:77::/64", count: "2", ips: "2001:db8:0:77::1, 2001:db8:0:77::2" })).toBe(
        "2 addresses seen outside every known network; create the network 2001:db8:0:77::/64",
      );
    });
  });

  describe("the fallback to the summary of the server", () => {
    it("is the text of a rule this UI does not know", () => {
      expect(ruleText(ruled("ipam.reconcile.a_rule_of_a_newer_server", { ip: "192.0.2.1" }, "A newer rule says this."))).toBe("A newer rule says this.");
      expect(ruleText(ruled("", {}, "No rule."))).toBe("No rule.");
    });

    it("is the text of a rule whose parameters do not fit its message", () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
      // The message needs the host, the address and the intended address.
      expect(ruleText(ruled("ipam.reconcile.address_mismatch", { host: "thermostat-1" }, "The summary instead."))).toBe("The summary instead.");
      // Without the count no plural form can be chosen.
      expect(ruleText(ruled("ipam.reconcile.outside_prefixes", { cidr: "203.0.113.0/24" }, "Several addresses are outside."))).toBe("Several addresses are outside.");
      expect(warn).toHaveBeenCalled();
    });

    it("is the text of a rule without parameters at all", () => {
      vi.spyOn(console, "warn").mockImplementation(() => undefined);
      const bare = { rule: "ipam.reconcile.conflict_networks", summary: "No parameters here." } as Pick<Proposal, "rule" | "params" | "summary">;
      expect(ruleText(bare)).toBe("No parameters here.");
    });

    it("finds the message of a rule by its last part, whatever the prefix", () => {
      expect(text("custom.address_unrecorded", { host: "a", ip: "192.0.2.1" })).toBe("a is seen at 192.0.2.1, which its intent does not list; record it");
    });
  });
});

describe("the names of a device", () => {
  it("has a word for every kind of source and keeps a kind it does not know", () => {
    const words = ["proxmox", "home_assistant", "windows", "dns", "mdns", "llmnr", "unifi", "scan", "dhcp", "other"].map((s) => nameSourceWord(s));
    expect(words).toEqual(["Proxmox VE", "Home Assistant", "Windows", "DNS", "mDNS", "LLMNR", "UniFi", "Scan", "DHCP", "Other connector"]);
    expect(nameSourceWord("newsource")).toBe("newsource");
  });

  it("says in words what decided a name", () => {
    expect(nameRuleWord("default")).toBe("by the default name authority");
    expect(nameRuleWord("global")).toBe("by the global name authority");
    expect(nameRuleWord("site:0190d1c2-0000-7000-8000-000000030001")).toBe("by the name authority of the site");
    expect(nameRuleWord("host")).toBe("by the preferred source of the host");
    expect(nameRuleWord("elsewhere")).toBe("elsewhere");
  });

  describe("the rules that rename a host", () => {
    const params = { host: "host-192-0-2-16", name: "postgresql", name_source: "proxmox", name_rule: "default" };

    it("names the placeholder, the new name, the source and what decided", () => {
      expect(text("ipam.reconcile.placeholder_name", params)).toBe(
        "Host host-192-0-2-16 has a placeholder name; rename it to postgresql (Proxmox VE, by the default name authority)",
      );
      expect(text("ipam.reconcile.placeholder_name", { ...params, name_rule: "global", other_names: "db, sql" })).toBe(
        "Host host-192-0-2-16 has a placeholder name; rename it to postgresql (Proxmox VE, by the global name authority); also named db, sql",
      );
    });

    it("names the preferred source of a host", () => {
      expect(text("ipam.reconcile.preferred_name", { ...params, host: "db", name_source: "unifi", name_rule: "host" })).toBe(
        "Host db follows its preferred source, UniFi, which names it postgresql; rename it to postgresql",
      );
    });

    it("tells that the sources disagree and which one decided", () => {
      expect(text("ipam.reconcile.name_conflict", { ...params, host: "db", name_rule: "site:0190d1c2-0000-7000-8000-000000030001", other_names: "sql" })).toBe(
        "The sources name host db differently; rename it to postgresql (Proxmox VE, by the name authority of the site); also named sql",
      );
    });

    it("reads the rules in Swedish", async () => {
      await setLocale("sv");
      expect(text("ipam.reconcile.placeholder_name", params)).toBe(
        "Värden host-192-0-2-16 har ett låtsasnamn; döp om den till postgresql (Proxmox VE, enligt standardordningen för namnauktoritet)",
      );
    });

    it("counts the renames in the phrase of a batch decision", () => {
      expect(kindSummary([{ kind: "host_name" }, { kind: "host_name" }, { kind: "discovered_host" }])).toBe("1 discovered host and 2 host renames");
    });
  });

  describe("the candidates of a proposal", () => {
    const sources = (...list: [NameSource, string][]) =>
      list.map(([source, given]) => ({ source, source_key: `${source}:x`, given, last_seen: "2026-10-01T00:00:00Z" }));
    const choices: Proposal["choices"] = [
      { name: "postgresql", proposed: true, sources: sources(["proxmox", "postgresql"], ["dns", "postgresql"]), last_seen: "2026-10-01T00:00:00Z" },
      { name: "db", proposed: false, sources: sources(["unifi", "DB"]), last_seen: "2026-10-01T00:00:00Z" },
    ];

    it("writes a candidate with the kinds of source that give it, each once", () => {
      expect(choiceText(choices![0]!)).toBe("postgresql · Proxmox VE and DNS");
      expect(choiceText(choices![1]!)).toBe("db · UniFi");
      expect(choiceText({ name: "x", proposed: false, sources: [], last_seen: "2026-10-01T00:00:00Z" })).toBe("x");
    });

    it("writes every candidate in one line, the proposed one first", () => {
      expect(choicesLine({ choices })).toBe("postgresql · Proxmox VE and DNS, db · UniFi");
      expect(choicesLine({})).toBe("");
    });
  });

  describe("a name that a source made up", () => {
    const host = (data: object) => ({ type: "host", data: { external_id: "client-1", macs: ["00:00:5e:00:53:10"], ips: ["192.0.2.16"], ...data } }) as Observed;

    it("reads no name, and leaves the original to the tooltip", () => {
      const placeholder = host({ name: "host-192-0-2-16", name_placeholder: true });
      expect(placeholderName(placeholder)).toBe("host-192-0-2-16");
      expect(observedText(placeholder)).toBe("no name · 00:00:5e:00:53:10 · 192.0.2.16");
      expect(observedParts(placeholder)).toEqual({ before: "", placeholder: "host-192-0-2-16", after: " · 00:00:5e:00:53:10 · 192.0.2.16" });
    });

    it("leaves a real name as it is", () => {
      const real = host({ name: "postgresql" });
      expect(placeholderName(real)).toBeNull();
      expect(observedText(real)).toBe("postgresql · 00:00:5e:00:53:10 · 192.0.2.16");
      expect(observedParts(real)).toEqual({ before: "postgresql · 00:00:5e:00:53:10 · 192.0.2.16", placeholder: null, after: "" });
    });

    it("reads no name for the name a probe found, when it is a placeholder", () => {
      const found = { type: "name", data: { ip: "192.0.2.16", name: "host-192-0-2-16", placeholder: true } } as Observed;
      expect(observedText(found)).toBe("192.0.2.16 is called no name");
      expect(observedParts(found).placeholder).toBe("host-192-0-2-16");
      expect(observedText({ type: "name", data: { ip: "192.0.2.16", name: "gw" } })).toBe("192.0.2.16 is called gw");
    });

    it("reads it in Swedish", async () => {
      await setLocale("sv");
      expect(observedText(host({ name: "host-192-0-2-16", name_placeholder: true }))).toBe("inget namn · 00:00:5e:00:53:10 · 192.0.2.16");
    });

    it("is no subject to look up", () => {
      expect(lookupSubject(fact({ type: "host", data: { external_id: "x", name: "host-192-0-2-16", name_placeholder: true } }))).toBeNull();
      expect(lookupSubject(fact(host({ name: "host-192-0-2-16", name_placeholder: true })))).toBe("00:00:5e:00:53:10");
    });

    it("is kept out of the names of a subject unless a real fact gives the same name", () => {
      const facts = [fact(host({ name: "host-192-0-2-16", name_placeholder: true })), fact(host({ name: "postgresql" }))];
      expect(splitNames(["host-192-0-2-16", "postgresql"], facts)).toEqual({ names: ["postgresql"], placeholders: ["host-192-0-2-16"] });
      expect(splitNames(["host-192-0-2-16"], [facts[0]!])).toEqual({ names: [], placeholders: ["host-192-0-2-16"] });
      expect(splitNames(["host-192-0-2-16"], [fact(host({ name: "host-192-0-2-16" })), facts[0]!])).toEqual({ names: ["host-192-0-2-16"], placeholders: [] });
    });
  });
});

describe("the subject of a proposal", () => {
  it("is labelled by its name, its MAC address, its address or its network, in that order", () => {
    expect(subjectLabel({ subject: { name: "media-pc", mac: "00:00:5e:00:53:d1", ip: "192.0.2.150", cidr: "192.0.2.0/24", objects: [] } })).toBe("media-pc");
    expect(subjectLabel({ subject: { mac: "00:00:5e:00:53:d1", ip: "192.0.2.150", objects: [] } })).toBe("00:00:5e:00:53:d1");
    expect(subjectLabel({ subject: { ip: "192.0.2.150", cidr: "192.0.2.0/24", objects: [] } })).toBe("192.0.2.150");
    expect(subjectLabel({ subject: { cidr: "203.0.113.224/27", objects: [] } })).toBe("203.0.113.224/27");
    expect(subjectLabel({ subject: { objects: [] } })).toBe("–");
  });

  it("names the newest last sighting among the evidence", () => {
    const evidence = (last_seen: string) => ({ last_seen }) as Proposal["evidence"][number];
    expect(lastSeenOf({ evidence: [] })).toBeNull();
    expect(lastSeenOf({ evidence: [evidence("2026-10-01T10:00:00Z")] })).toBe("2026-10-01T10:00:00Z");
    expect(lastSeenOf({ evidence: [evidence("2026-10-01T10:00:00Z"), evidence("2026-10-03T08:00:00Z"), evidence("2026-10-02T09:00:00Z")] })).toBe(
      "2026-10-03T08:00:00Z",
    );
  });
});

describe("sources", () => {
  const sources: [string, ObservationSource, string][] = [
    ["an inventory", { type: "inventory", connector: INVENTORY }, "Lab inventory (inventory)"],
    ["a network controller", { type: "network_controller", connector: CONTROLLER }, "Home network (network controller)"],
    ["a probe", { type: "probe", node: 1001, method: "arp" }, "Probe probe-dmz, ARP"],
    ["a probe with a method of a newer server", { type: "probe", node: 1001, method: "ble_scan" } as unknown as ObservationSource, "Probe probe-dmz, ble_scan"],
    ["a DNS zone", { type: "dns_record", zone: "example.test" }, "DNS zone example.test"],
    ["the DHCP server of a node", { type: "dhcp_lease", node: 1001 }, "DHCP on node probe-dmz"],
  ];

  it.each(sources)("tells %s in words", (_what, source, words) => {
    expect(sourceText(source, NAMES)).toBe(words);
  });

  it("falls back to the start of an id, or to the number of a node, that has no name", () => {
    expect(sourceText({ type: "inventory", connector: INVENTORY })).toBe("0190d1c2 (inventory)");
    expect(sourceText({ type: "network_controller", connector: CONTROLLER }, NO_NAMES)).toBe("0190d1c2 (network controller)");
    expect(sourceText({ type: "probe", node: 7, method: "icmp" }, NO_NAMES)).toBe("Probe 7, ping");
    expect(sourceText({ type: "dhcp_lease", node: 7 }, NO_NAMES)).toBe("DHCP on node 7");
    expect(sourceText({ type: "inventory", connector: "unknown-id-of-a-connector" }, NAMES)).toBe("unknown- (inventory)");
  });

  it("shows the type of a source of a newer server, and nothing for a source without one", () => {
    expect(sourceText({ type: "mqtt_broker" } as unknown as ObservationSource, NAMES)).toBe("mqtt_broker");
    expect(sourceText({} as unknown as ObservationSource, NAMES)).toBe("");
  });

  it("has a word for every probe method and keeps one it does not know", () => {
    expect(["arp", "nd", "mdns", "lldp", "icmp", "tcp_syn", "os_fingerprint", "snmp", "tcp_connect", "reverse_dns", "llmnr", "arp_sweep", "dhcp_snoop"].map(probeMethodWord)).toEqual([
      "ARP",
      "neighbour discovery",
      "mDNS",
      "LLDP",
      "ping",
      "port scan",
      "OS fingerprint",
      "SNMP",
      "TCP connect",
      "reverse DNS",
      "LLMNR",
      "ARP sweep",
      "DHCP snoop",
    ]);
    expect(probeMethodWord("ble_scan")).toBe("ble_scan");
  });

  describe("source keys", () => {
    it.each([
      [`inventory:${INVENTORY}`, "Lab inventory (inventory)"],
      [`network_controller:${CONTROLLER}`, "Home network (network controller)"],
      ["probe:1001:arp", "Probe probe-dmz, ARP"],
      ["probe:1001:os_fingerprint", "Probe probe-dmz, OS fingerprint"],
      ["dhcp:1001", "DHCP on node probe-dmz"],
      ["dns:example.test", "DNS zone example.test"],
      ["dns:2.0.192.in-addr.arpa", "DNS zone 2.0.192.in-addr.arpa"],
    ])("tells %s in words", (key, words) => {
      expect(sourceKeyText(key, NAMES)).toBe(words);
    });

    it("falls back to the start of an id or the number of a node without a name", () => {
      expect(sourceKeyText(`inventory:${INVENTORY}`)).toBe("0190d1c2 (inventory)");
      expect(sourceKeyText("probe:42:icmp")).toBe("Probe 42, ping");
      expect(sourceKeyText("dhcp:42")).toBe("DHCP on node 42");
    });

    it("keeps a key it cannot read as it is", () => {
      for (const key of ["", "inventory", "inventory:", "probe:1001", "probe:abc:arp", "probe::arp", "dhcp:abc", "dhcp", "dns", "dns:", "mdns:example", "x:y:z"]) {
        expect(sourceKeyText(key, NAMES)).toBe(key);
      }
    });
  });
});

describe("facts", () => {
  it("has a word for every type of fact and keeps a type it does not know", () => {
    expect(["host", "address", "attachment", "services", "os", "link", "name", "vendor"].map(factTypeWord)).toEqual([
      "Host",
      "Address",
      "Attachment",
      "Open ports",
      "Operating system",
      "Link",
      "Name",
      "Vendor",
    ]);
    expect(factTypeWord("thermal_image")).toBe("thermal_image");
  });

  describe("whether a fact is current", () => {
    const now = Date.parse("2026-10-10T12:00:00Z");

    it("is current without an expiry and until the expiry", () => {
      expect(isCurrent({}, now)).toBe(true);
      expect(isCurrent({ expires_at: null }, now)).toBe(true);
      expect(isCurrent({ expires_at: "2026-10-10T12:00:01Z" }, now)).toBe(true);
    });

    it("is not current at its expiry or after it", () => {
      expect(isCurrent({ expires_at: "2026-10-10T12:00:00Z" }, now)).toBe(false);
      expect(isCurrent({ expires_at: "2026-10-09T12:00:00Z" }, now)).toBe(false);
    });

    it("reads the clock when no time is given", () => {
      expect(isCurrent({ expires_at: new Date(Date.now() + 60_000).toISOString() })).toBe(true);
      expect(isCurrent({ expires_at: new Date(Date.now() - 60_000).toISOString() })).toBe(false);
    });
  });

  describe("a network of a controller", () => {
    it("says its name, VLAN and subnet, and names no subject to look up", () => {
      const tagged = { type: "network" as const, data: { controller: "net-iot", name: "IoT", vlan: 30, subnet: "198.51.100.0/24", dhcp: "relay" as const } };
      expect(observedText(tagged)).toBe("IoT: VLAN 30, 198.51.100.0/24");
      expect(observedText({ type: "network", data: { controller: "net-default", name: "Default" } })).toBe("Default: untagged");
    });
  });

  describe("what a fact says (observedText)", () => {
    it("tells a host with everything a source knows about it", () => {
      expect(
        observedText({
          type: "host",
          data: { external_id: "vm-104", name: "media-pc", macs: ["00:00:5e:00:53:d1", "00:00:5e:00:53:d9"], ips: ["192.0.2.150"], os: "Debian 12", platform: "qemu", parent: "pve1", tags: ["media"] },
        }),
      ).toBe("media-pc · 00:00:5e:00:53:d1 and 00:00:5e:00:53:d9 · 192.0.2.150 · Debian 12 · qemu · on pve1");
    });

    it("names a host by its id in the source when it has no name, and leaves out what is empty", () => {
      expect(observedText({ type: "host", data: { external_id: "vm-200", macs: [], ips: [] } })).toBe("vm-200");
      expect(observedText({ type: "host", data: { external_id: "vm-201", name: "old-test", macs: ["00:00:5e:00:53:c4"], ips: [], platform: "lxc" } })).toBe(
        "old-test · 00:00:5e:00:53:c4 · lxc",
      );
    });

    it("tells an address with and without the MAC address behind it", () => {
      expect(observedText({ type: "address", data: { ip: "192.0.2.49", mac: "00:00:5e:00:53:29" } } as Observed)).toBe("192.0.2.49 from 00:00:5e:00:53:29");
      expect(observedText({ type: "address", data: { ip: "198.51.100.77", mac: null } } as Observed)).toBe("198.51.100.77");
      expect(observedText({ type: "address", data: { ip: "2001:db8::7" } } as Observed)).toBe("2001:db8::7");
    });

    it("tells open ports, or that there is none", () => {
      expect(observedText({ type: "services", data: { ip: "192.0.2.150", open_tcp: [22, 8096] } })).toBe("192.0.2.150: TCP 22, 8096");
      expect(observedText({ type: "services", data: { ip: "192.0.2.151", open_tcp: [] } })).toBe("192.0.2.151: no open TCP port");
    });

    it("adds the ports that answered a TLS handshake, for a server that reports them", () => {
      const services = (extra: object) => ({ type: "services", data: { ip: "192.0.2.150", open_tcp: [22, 443], ...extra } }) as Observed;
      expect(observedText(services({ tls_tcp: [443] }))).toBe("192.0.2.150: TCP 22, 443 · TLS on 443");
      expect(observedText(services({ tls_tcp: [443, 8443] }))).toBe("192.0.2.150: TCP 22, 443 · TLS on 443, 8443");
      // Nothing to add for an empty list or a member of another shape.
      expect(observedText(services({ tls_tcp: [] }))).toBe("192.0.2.150: TCP 22, 443");
      expect(observedText(services({ tls_tcp: "443" }))).toBe("192.0.2.150: TCP 22, 443");
    });

    it("tells a guess of the operating system with its confidence", () => {
      expect(observedText({ type: "os", data: { ip: "192.0.2.150", guess: "Linux 6.x", confidence: 90 } })).toBe("192.0.2.150: Linux 6.x, 90 %");
    });

    it("tells where a device is attached, with the parts a controller gave", () => {
      expect(observedText({ type: "attachment", data: { mac: "00:00:5e:00:53:d2", device: "switch-hall", port: "7", vlan: 10 } })).toBe(
        "00:00:5e:00:53:d2 at switch-hall, port 7, VLAN 10",
      );
      expect(observedText({ type: "attachment", data: { mac: "00:00:5e:00:53:29", device: "ap-garage", ssid: "iot", vlan: 30 } })).toBe(
        "00:00:5e:00:53:29 at ap-garage, wireless network iot, VLAN 30",
      );
      expect(observedText({ type: "attachment", data: { mac: "00:00:5e:00:53:c3", device: "ap-hall" } } as Observed)).toBe("00:00:5e:00:53:c3 at ap-hall");
      // VLAN 0 is a VLAN; only a missing one is left out.
      expect(observedText({ type: "attachment", data: { mac: "00:00:5e:00:53:c3", device: "ap-hall", vlan: 0 } })).toBe("00:00:5e:00:53:c3 at ap-hall, VLAN 0");
      expect(observedText({ type: "attachment", data: { mac: "00:00:5e:00:53:c3", device: "ap-hall", vlan: null } } as Observed)).toBe("00:00:5e:00:53:c3 at ap-hall");
    });

    it("tells a link between two devices, with or without ports", () => {
      expect(
        observedText({ type: "link", data: { a: { device: "switch-hall", port: "24" }, b: { device: "switch-den", port: "1" }, kind: "lldp" } } as Observed),
      ).toBe("switch-hall 24 to switch-den 1 (lldp)");
      expect(observedText({ type: "link", data: { a: { device: "switch-hall" }, b: { device: "ap-garage", port: null }, kind: "wired" } } as Observed)).toBe(
        "switch-hall to ap-garage (wired)",
      );
    });

    it("tells the name a probe found for an address", () => {
      expect(observedText({ type: "name", data: { ip: "192.0.2.44", name: "speaker-den.example.test" } })).toBe("192.0.2.44 is called speaker-den.example.test");
      expect(observedText({ type: "name", data: { ip: "2001:db8::7", name: "gw" } })).toBe("2001:db8::7 is called gw");
    });

    it("tells the vendor of a MAC address", () => {
      expect(observedText({ type: "vendor", data: { mac: "00:00:5e:00:53:d5", vendor: "ICANN, IANA Department" } })).toBe(
        "00:00:5e:00:53:d5 is made by ICANN, IANA Department",
      );
    });

    it("tells the name and the vendor in Swedish", async () => {
      await setLocale("sv");
      expect(observedText({ type: "name", data: { ip: "192.0.2.44", name: "speaker-den.example.test" } })).toBe("192.0.2.44 heter speaker-den.example.test");
      expect(observedText({ type: "vendor", data: { mac: "00:00:5e:00:53:d5", vendor: "ICANN, IANA Department" } })).toBe(
        "00:00:5e:00:53:d5 är tillverkad av ICANN, IANA Department",
      );
    });

    it("lists the members of a kind it cannot put in words", () => {
      // A name without its name, and a vendor without its vendor, are just members.
      expect(observedText({ type: "name", data: { ip: "192.0.2.1" } } as unknown as Observed)).toBe("ip 192.0.2.1");
      expect(observedText({ type: "vendor", data: { vendor: "Example Networks" } } as unknown as Observed)).toBe("vendor Example Networks");
      expect(observedText({ type: "thermal_image", data: { room: "den", rooms: ["a", "b"], size: 640, extra: { depth: 2 } } } as unknown as Observed)).toBe(
        'room den · rooms a, b · size 640 · extra {"depth":2}',
      );
      expect(observedText({ type: "thermal_image" } as unknown as Observed)).toBe("");
    });
  });

  describe("the subject to look up for a fact (lookupSubject)", () => {
    const lookup = (observed: Observed) => lookupSubject(fact(observed));

    it("is the first MAC address of a host, else its first address, else its name", () => {
      expect(lookup({ type: "host", data: { external_id: "x", name: "media-pc", macs: ["00:00:5e:00:53:d1", "00:00:5e:00:53:d9"], ips: ["192.0.2.150"] } })).toBe("00:00:5e:00:53:d1");
      expect(lookup({ type: "host", data: { external_id: "x", name: "media-pc", macs: [], ips: ["192.0.2.150", "192.0.2.151"] } })).toBe("192.0.2.150");
      expect(lookup({ type: "host", data: { external_id: "x", name: "media-pc" } })).toBe("media-pc");
      expect(lookup({ type: "host", data: { external_id: "x" } })).toBeNull();
    });

    it("is the MAC address of an address that has one, else the address", () => {
      expect(lookup({ type: "address", data: { ip: "192.0.2.49", mac: "00:00:5e:00:53:29" } } as Observed)).toBe("00:00:5e:00:53:29");
      expect(lookup({ type: "address", data: { ip: "198.51.100.77", mac: null } } as Observed)).toBe("198.51.100.77");
    });

    it("is the address of open ports and of a guess of the operating system", () => {
      expect(lookup({ type: "services", data: { ip: "192.0.2.150", open_tcp: [22] } })).toBe("192.0.2.150");
      expect(lookup({ type: "os", data: { ip: "192.0.2.150", guess: "Linux", confidence: 50 } })).toBe("192.0.2.150");
    });

    it("is the MAC address of an attachment", () => {
      expect(lookup({ type: "attachment", data: { mac: "00:00:5e:00:53:d2", device: "switch-hall" } })).toBe("00:00:5e:00:53:d2");
    });

    it("is nothing for a link, which has two devices and no subject", () => {
      expect(lookup({ type: "link", data: { a: { device: "a" }, b: { device: "b" }, kind: "lldp" } } as Observed)).toBeNull();
    });

    it("is the address of a name, which a probe found for that address", () => {
      expect(lookup({ type: "name", data: { ip: "192.0.2.44", name: "speaker-den.example.test" } })).toBe("192.0.2.44");
    });

    it("is the MAC address of a vendor, not a name or an address", () => {
      expect(lookup({ type: "vendor", data: { mac: "00:00:5e:00:53:d5", vendor: "ICANN, IANA Department" } })).toBe("00:00:5e:00:53:d5");
    });

    it("is the MAC address, else the address, else the name of a kind it does not know", () => {
      const other = (data: object) => lookup({ type: "thermal_image", data } as unknown as Observed);
      expect(other({ mac: "00:00:5e:00:53:01", ip: "192.0.2.1", name: "gw" })).toBe("00:00:5e:00:53:01");
      expect(other({ ip: "192.0.2.1", name: "gw" })).toBe("192.0.2.1");
      expect(other({ name: "gw" })).toBe("gw");
      expect(other({})).toBeNull();
      expect(other({ mac: 5 })).toBeNull();
      expect(lookup({ type: "thermal_image" } as unknown as Observed)).toBeNull();
    });
  });
});

describe("subjects", () => {
  it("knows a MAC address in either spelling, in either case", () => {
    for (const mac of ["00:00:5e:00:53:d1", "00-00-5E-00-53-D1", "00:00:5E:00:53:D1", " 00:00:5e:00:53:d1 "]) expect(subjectKind(mac)).toBe("mac");
  });

  it("does not take a MAC address with mixed separators, or too few or too many octets, for one", () => {
    for (const text of ["00:00:5e-00:53:d1", "00:00:5e:00:53", "00:00:5e:00:53:d1:ff", "00:00:5e:00:53:zz", "00005e0053d1", "0:0:5e:0:53:d1"]) {
      expect(subjectKind(text)).toBe("name");
    }
  });

  it("knows an IP address, v4 or v6", () => {
    for (const ip of ["192.0.2.150", "198.51.100.77", "2001:db8::1", "2001:db8:0:10::1", " 192.0.2.1 "]) expect(subjectKind(ip)).toBe("ip");
  });

  it("takes anything else for a name", () => {
    for (const name of ["media-pc", "media-pc.example.test", "192.0.2.256", "192.0.2", "", "   "]) expect(subjectKind(name)).toBe("name");
  });

  it("drops the prefix an API subject carries", () => {
    expect(subjectValue("mac:00:00:5e:00:53:d1")).toBe("00:00:5e:00:53:d1");
    expect(subjectValue("ip:192.0.2.150")).toBe("192.0.2.150");
    expect(subjectValue("ip:2001:db8::1")).toBe("2001:db8::1");
    expect(subjectValue("name:media-pc")).toBe("media-pc");
    expect(subjectValue("name:")).toBe("");
  });

  it("keeps a subject that has no such prefix", () => {
    expect(subjectValue("media-pc")).toBe("media-pc");
    expect(subjectValue("00:00:5e:00:53:d1")).toBe("00:00:5e:00:53:d1");
    expect(subjectValue("2001:db8::1")).toBe("2001:db8::1");
    expect(subjectValue("host:vm-1")).toBe("host:vm-1");
    expect(subjectValue(":x")).toBe(":x");
    expect(subjectValue("")).toBe("");
  });
});
