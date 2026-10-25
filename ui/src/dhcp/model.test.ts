// The pure helpers of the DHCP area: lease times in human units, option values to and from the
// typed data of the API, hexadecimal values, MAC patterns, the drafts of matches and terms, the
// local check of an exclusion, the order of policies, the words for matches, conditions and actions,
// and the helpers of a DHCPv6 scope (the preferred lifetime, the size of a large pool).
import { afterEach, describe, expect, it } from "vitest";
import { setLocale } from "../i18n";
import {
  ARCHITECTURES,
  architectureOfText,
  bitsOfSize,
  checkExclusion,
  checkMac,
  checkMacPattern,
  dataText,
  defaultPreferred,
  draftOfLease,
  draftOfMatch,
  draftOfTerm,
  emptyMatch,
  isKnownArchitecture,
  isV6,
  kindOfData,
  leaseOfDraft,
  matchKind,
  matchOfDraft,
  networkOf,
  parseHex,
  parseOptionText,
  percentOf,
  policyOrder,
  preferredOfText,
  rangeBits,
  sameLease,
  secsOf,
  spanOf,
  splitValues,
  termOfDraft,
  validDhcpName,
  type OptionShape,
} from "./model";
import type { Match, Policy, Term } from "./types";
import { actionWords, conditionWords, ddnsWords, kindWords, leaseWords, matchesWords, matchWords, poolCountWords } from "./words";

afterEach(async () => {
  await setLocale("en");
});

describe("lease times in human units", () => {
  it("shows seconds in the largest unit that divides them", () => {
    expect(spanOf(86_400)).toEqual({ value: "1", unit: "days" });
    expect(spanOf(172_800)).toEqual({ value: "2", unit: "days" });
    expect(spanOf(7200)).toEqual({ value: "2", unit: "hours" });
    expect(spanOf(5400)).toEqual({ value: "90", unit: "minutes" });
    expect(spanOf(90)).toEqual({ value: "1.5", unit: "minutes" });
  });

  it("reads a number with its unit as seconds, a comma as a decimal point", () => {
    expect(secsOf({ value: "2", unit: "hours" })).toBe(7200);
    expect(secsOf({ value: "1,5", unit: "hours" })).toBe(5400);
    expect(secsOf({ value: "0.5", unit: "minutes" })).toBe(30);
    expect(secsOf({ value: "0", unit: "days" })).toBeNull();
    expect(secsOf({ value: "-1", unit: "days" })).toBeNull();
    expect(secsOf({ value: "abc", unit: "days" })).toBeNull();
    expect(secsOf({ value: "", unit: "days" })).toBeNull();
  });

  it("builds lease times from a draft and checks 0 < min <= default <= max <= one year", () => {
    const draft = draftOfLease({ default_secs: 86_400, min_secs: 3600, max_secs: 604_800 });
    expect(leaseOfDraft(draft)).toEqual({ ok: true, lease: { default_secs: 86_400, min_secs: 3600, max_secs: 604_800 } });
    expect(leaseOfDraft({ ...draft, min: { value: "2", unit: "days" } })).toEqual({ ok: false, field: "min", problem: "order" });
    expect(leaseOfDraft({ ...draft, max: { value: "1", unit: "hours" } })).toEqual({ ok: false, field: "default", problem: "order" });
    expect(leaseOfDraft({ ...draft, max: { value: "366", unit: "days" } })).toEqual({ ok: false, field: "max", problem: "year" });
    expect(leaseOfDraft({ ...draft, max: { value: "365", unit: "days" } }).ok).toBe(true);
    expect(leaseOfDraft({ ...draft, default: { value: "x", unit: "days" } })).toEqual({ ok: false, field: "default", problem: "number" });
    expect(leaseOfDraft({ ...draft, min: { value: "0", unit: "hours" } })).toEqual({ ok: false, field: "min", problem: "number" });
  });

  it("keeps T1 and T2 while they still fit the default time and drops them otherwise", () => {
    const keep = { default_secs: 86_400, min_secs: 3600, max_secs: 604_800, t1_secs: 40_000, t2_secs: 70_000 };
    const same = leaseOfDraft(draftOfLease(keep), keep);
    expect(same.ok && same.lease).toEqual(keep);
    const shorter = leaseOfDraft({ ...draftOfLease(keep), default: { value: "12", unit: "hours" } }, keep);
    expect(shorter.ok && shorter.lease.t1_secs).toBeUndefined();
  });

  it("compares lease times", () => {
    const a = { default_secs: 1, min_secs: 1, max_secs: 1 };
    expect(sameLease(a, { ...a })).toBe(true);
    expect(sameLease(a, { ...a, t1_secs: 1 })).toBe(false);
    expect(sameLease(a, undefined)).toBe(false);
    expect(sameLease(undefined, null)).toBe(true);
  });
});

describe("names, hexadecimal values and MAC patterns", () => {
  it("accepts the names of the server's rule", () => {
    expect(validDhcpName("pxe-clients")).toBe(true);
    expect(validDhcpName("a".repeat(64))).toBe(true);
    expect(validDhcpName("a".repeat(65))).toBe(false);
    expect(validDhcpName("Upper")).toBe(false);
    expect(validDhcpName("with space")).toBe(false);
    expect(validDhcpName("")).toBe(false);
  });

  it("reads octets however they are typed", () => {
    expect(parseHex("c0ff")).toBe("c0ff");
    expect(parseHex("C0:FF")).toBe("c0ff");
    expect(parseHex("0xC0FF")).toBe("c0ff");
    expect(parseHex("c0 ff")).toBe("c0ff");
    expect(parseHex("c0f")).toBeNull();
    expect(parseHex("zz")).toBeNull();
    expect(parseHex("")).toBeNull();
    expect(parseHex("00".repeat(256))).toBeNull();
    expect(parseHex("00".repeat(255))).not.toBeNull();
  });

  it("writes a MAC pattern in its stored form: six positions, lowercase, colons", () => {
    expect(checkMacPattern("00:00:5E:00:53:01")).toBe("00:00:5e:00:53:01");
    expect(checkMacPattern("00-00-5e-00-53-01")).toBe("00:00:5e:00:53:01");
    expect(checkMacPattern("00:00:5e:00:53:*")).toBe("00:00:5e:00:53:*");
    expect(checkMacPattern("00:00:5e:*")).toBe("00:00:5e:*:*:*");
    expect(checkMacPattern("*")).toBe("*:*:*:*:*:*");
    expect(checkMacPattern("00:*:5e:00:53:01")).toBe("00:*:5e:00:53:01");
  });

  it("refuses what is not a pattern", () => {
    expect(checkMacPattern("00:00:5e")).toBeNull();
    expect(checkMacPattern("00:00:5e:00:53:01:02")).toBeNull();
    expect(checkMacPattern("00:00:5g:00:53:01")).toBeNull();
    expect(checkMacPattern("0:0:5e:00:53:01")).toBeNull();
    expect(checkMacPattern("")).toBeNull();
  });

  it("takes only a whole address where no wildcard is meant", () => {
    expect(checkMac("00:00:5E:00:53:01")).toBe("00:00:5e:00:53:01");
    expect(checkMac("00:00:5e:00:53:*")).toBeNull();
  });
});

describe("option values", () => {
  const shape = (kind: OptionShape["kind"], array = false): OptionShape => ({ kind, array });
  const typed = (s: OptionShape, text: string) => {
    const parsed = parseOptionText(s, text);
    return parsed.ok ? parsed.data : parsed.problem;
  };

  it("splits lists on commas, spaces, semicolons and lines", () => {
    expect(splitValues("192.0.2.1, 192.0.2.2\n192.0.2.3;192.0.2.4  ")).toEqual(["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]);
  });

  it("types addresses as the API sends them", () => {
    expect(typed(shape("ipv4_address", true), "192.0.2.53, 192.0.2.54")).toEqual({ ipv4: { values: ["192.0.2.53", "192.0.2.54"] } });
    expect(typed(shape("ipv4_address"), "192.0.2.1")).toEqual({ ipv4: { values: ["192.0.2.1"] } });
    expect(typed(shape("ipv4_address"), "192.0.2.1 192.0.2.2")).toBe("count");
    expect(typed(shape("ipv4_address", true), "192.0.2.1, 2001:db8::1")).toBe("ipv4");
    expect(typed(shape("ipv4_address", true), "")).toBe("empty");
    expect(typed(shape("ipv6_address", true), "2001:db8::53")).toEqual({ ipv6: { values: ["2001:db8::53"] } });
    expect(typed(shape("ipv6_address", true), "192.0.2.1")).toBe("ipv6");
    expect(typed(shape("ipv6_prefix", true), "2001:db8::/32")).toEqual({ ipv6_prefix: { values: ["2001:db8::/32"] } });
    expect(typed(shape("ipv6_prefix", true), "2001:db8::")).toBe("prefix");
  });

  it("types numbers within the width of the type", () => {
    expect(typed(shape("u16"), "1500")).toEqual({ unsigned: [1500] });
    expect(typed(shape("u8", true), "1, 2, 255")).toEqual({ unsigned: [1, 2, 255] });
    expect(typed(shape("u8"), "256")).toBe("range");
    expect(typed(shape("u16"), "-1")).toBe("number");
    expect(typed(shape("u32"), "4294967295")).toEqual({ unsigned: [4_294_967_295] });
    expect(typed(shape("u32"), "4294967296")).toBe("range");
    expect(typed(shape("i32"), "-3600")).toEqual({ signed: -3600 });
    expect(typed(shape("i32"), "2147483648")).toBe("range");
    expect(typed(shape("i32"), "1.5")).toBe("number");
  });

  it("types booleans, text, names and flags", () => {
    expect(typed(shape("bool"), "TRUE")).toEqual({ bool: [true] });
    expect(typed(shape("bool"), "yes")).toBe("bool");
    expect(typed(shape("string"), "example.test")).toEqual({ text: "example.test" });
    expect(typed(shape("string"), "  ")).toBe("empty");
    expect(typed(shape("fqdn", true), "Example.Test., lab.example.test")).toEqual({ names: ["example.test", "lab.example.test"] });
    expect(typed(shape("fqdn", true), "bad!name")).toBe("name");
    expect(typed(shape("empty"), "")).toBe("empty");
  });

  it("types classless routes from lines of destination via router", () => {
    expect(typed(shape("classless_routes"), "203.0.113.0/24 via 192.0.2.1\n198.51.100.0/25  VIA  192.0.2.2")).toEqual({
      routes: [
        { destination: "203.0.113.0/24", router: "192.0.2.1" },
        { destination: "198.51.100.0/25", router: "192.0.2.2" },
      ],
    });
    expect(typed(shape("classless_routes"), "203.0.113.0/24")).toBe("route");
    expect(typed(shape("classless_routes"), "203.0.113.1/24 via 192.0.2.1")).toBe("route");
    expect(typed(shape("classless_routes"), "203.0.113.0/24 via 2001:db8::1")).toBe("route");
    expect(typed(shape("classless_routes"), "")).toBe("empty");
  });

  it("types octets as hexadecimal", () => {
    expect(typed(shape("binary"), "C0:FF")).toEqual({ binary: "c0ff" });
    expect(typed(shape("binary"), "c0f")).toBe("hex");
  });

  it("shows typed data as text that types back to the same data", () => {
    const cases: [OptionShape, string][] = [
      [shape("ipv4_address", true), "192.0.2.53, 192.0.2.54"],
      [shape("ipv6_address", true), "2001:db8::53"],
      [shape("u16"), "1500"],
      [shape("i32"), "-3600"],
      [shape("bool"), "false"],
      [shape("string"), "example.test"],
      [shape("fqdn", true), "example.test, lab.example.test"],
      [shape("classless_routes"), "203.0.113.0/24 via 192.0.2.1\n198.51.100.0/25 via 192.0.2.2"],
      [shape("binary"), "c0ff"],
    ];
    for (const [s, text] of cases) {
      const data = parseOptionText(s, text);
      expect(data.ok, s.kind).toBe(true);
      if (data.ok) expect(dataText(data.data), s.kind).toBe(text);
    }
    expect(dataText("empty")).toBe("");
  });

  it("names the kind a typed value has", () => {
    expect(kindOfData({ ipv4: { values: [] } })).toBe("ipv4_address");
    expect(kindOfData({ unsigned: [1] })).toBe("u32");
    expect(kindOfData({ routes: [] })).toBe("classless_routes");
    expect(kindOfData("empty")).toBe("empty");
  });
});

describe("matches and terms", () => {
  const sample: Match[] = [
    { vendor_class: { value: "PXEClient", prefix: true } },
    { user_class: { value: "lab" } },
    { mac: { pattern: "00:00:5e:00:53:*" } },
    { client_id: { value: "01aabb" } },
    { circuit_id: { value: "0001" } },
    { remote_id: { value: "0a0b" } },
    { architecture: { code: 7 } },
    { host_name: { value: "printer", prefix: false } },
  ];

  it("round-trips every kind through its draft", () => {
    for (const match of sample) {
      const parsed = matchOfDraft(draftOfMatch(match));
      expect(parsed.ok && parsed.match).toEqual(match);
    }
    expect(sample.map(matchKind)).toEqual(["vendor_class", "user_class", "mac", "client_id", "circuit_id", "remote_id", "architecture", "host_name"]);
  });

  it("checks what the user typed", () => {
    expect(matchOfDraft({ ...emptyMatch("vendor_class"), value: "" })).toEqual({ ok: false, problem: "empty" });
    expect(matchOfDraft({ ...emptyMatch("vendor_class"), value: "x".repeat(256) })).toEqual({ ok: false, problem: "long" });
    expect(matchOfDraft({ ...emptyMatch("mac"), value: "00:00" })).toEqual({ ok: false, problem: "mac" });
    expect(matchOfDraft({ ...emptyMatch("client_id"), value: "zz" })).toEqual({ ok: false, problem: "hex" });
    expect(matchOfDraft({ ...emptyMatch("architecture"), value: "70000" })).toEqual({ ok: false, problem: "number" });
    const mac = matchOfDraft({ ...emptyMatch("mac"), value: "00:00:5E:*" });
    expect(mac.ok && mac.match).toEqual({ mac: { pattern: "00:00:5e:*:*:*" } });
    const client = matchOfDraft({ ...emptyMatch("client_id"), value: "01:AA:BB" });
    expect(client.ok && client.match).toEqual({ client_id: { value: "01aabb" } });
  });

  it("knows the client architectures and reads a number of 0 to 65535", () => {
    expect([...ARCHITECTURES]).toEqual([0, 6, 7, 9, 10, 11, 15, 16, 19]);
    expect([isKnownArchitecture(7), isKnownArchitecture(8), isKnownArchitecture(0)]).toEqual([true, false, true]);
    expect([architectureOfText("7"), architectureOfText(" 65535 "), architectureOfText("65536"), architectureOfText("-1"), architectureOfText("x"), architectureOfText("")]).toEqual([7, 65_535, null, null, null, null]);
  });

  it("round-trips the four kinds of term", () => {
    const terms: Term[] = [{ class: "c1" }, { not_class: "c2" }, { match: { host_name: { value: "pr", prefix: true } } }, { not_match: { architecture: { code: 0 } } }];
    for (const term of terms) {
      const parsed = termOfDraft(draftOfTerm(term));
      expect(parsed.ok && parsed.term).toEqual(term);
    }
    expect(termOfDraft({ kind: "class", class_id: "", match: emptyMatch() })).toEqual({ ok: false, problem: "class" });
    expect(termOfDraft({ kind: "match", class_id: "", match: emptyMatch() })).toEqual({ ok: false, problem: "empty" });
  });
});

describe("words", () => {
  it("says a match, the matches of a class and a condition in English", () => {
    expect(matchWords({ vendor_class: { value: "MSFT", prefix: true } })).toBe('vendor class starting with "MSFT"');
    expect(matchWords({ vendor_class: { value: "MSFT" } })).toBe('vendor class "MSFT"');
    expect(matchWords({ mac: { pattern: "00:00:5e:*:*:*" } })).toBe("MAC address 00:00:5e:*:*:*");
    // WP8.6: a known architecture shows its name; any other number stays a number.
    expect(matchWords({ architecture: { code: 7 } })).toBe("client architecture UEFI x64 (7)");
    expect(matchWords({ architecture: { code: 0 } })).toBe("client architecture BIOS x86 (0)");
    expect(matchWords({ architecture: { code: 33 } })).toBe("client architecture 33");
    expect(matchesWords([{ user_class: { value: "a" } }, { host_name: { value: "b", prefix: true } }])).toBe('user class "a" or host name starting with "b"');
    const names = (id: string) => (id === "c1" ? "pxe-clients" : id);
    expect(conditionWords({ join: "and", terms: [{ class: "c1" }, { not_match: { host_name: { value: "x" } } }] }, names)).toBe('in class pxe-clients and not host name "x"');
    expect(conditionWords({ join: "or", terms: [{ not_class: "c1" }, { match: { user_class: { value: "y" } } }] }, names)).toBe('not in class pxe-clients or user class "y"');
  });

  it("says an action and lease times", () => {
    expect(actionWords(undefined)).toBe("no change");
    expect(actionWords({})).toBe("no change");
    expect(actionWords({ range: { first: "192.0.2.100", last: "192.0.2.119" } })).toBe("only addresses 192.0.2.100 to 192.0.2.119");
    const both = actionWords({ range: { first: "192.0.2.100", last: "192.0.2.119" }, lease: { default_secs: 3600, min_secs: 600, max_secs: 7200 } });
    expect(both).toBe("only addresses 192.0.2.100 to 192.0.2.119; lease time default 1 hr, between 10 min and 2 hr");
    expect(leaseWords({ default_secs: 86_400, min_secs: 3600, max_secs: 604_800 })).toContain("between");
    expect(kindWords("ipv4_address", true)).toBe("IPv4 address, list");
    expect(kindWords("u16", false)).toBe("Number (0 to 65535)");
  });

  it("says the DDNS action and options of a policy", () => {
    const zoneName = (id: string) => (id === "z1" ? "example.test" : undefined);
    expect(actionWords({ ddns: { enabled: false } })).toBe("DDNS off");
    expect(actionWords({ ddns: { enabled: true } })).toBe("DDNS on");
    expect(actionWords({ ddns: { enabled: true, forward_zone: "z1" } }, { zoneName })).toBe("DDNS on, zone example.test");
    expect(actionWords({ ddns: { enabled: true, forward_zone: "zz" } }, { zoneName })).toBe("DDNS on, zone zz");
    expect(actionWords({ lease: { default_secs: 3600, min_secs: 600, max_secs: 7200 }, ddns: { enabled: true } }, { options: true })).toBe(
      "lease time default 1 hr, between 10 min and 2 hr; DDNS on; options",
    );
    expect(actionWords({}, { options: true })).toBe("options");
  });

  it("says DDNS settings in words", () => {
    expect(ddnsWords(undefined)).toBe("DDNS is off");
    expect(ddnsWords({})).toBe("DDNS is off");
    expect(ddnsWords({ enabled: true })).toBe("DDNS is on with the zone of the domain name, PTR records, TTL a third of the lease time, names protected, and names for legacy clients");
    expect(ddnsWords({ enabled: true, forward_zone: "z1", reverse: false, ttl: 300, conflict: "replace", client_may_update_a: true, legacy_clients: false, refuse_foreign: true }, (id) => (id === "z1" ? "example.test" : undefined))).toBe(
      "DDNS is on with forward zone example.test, no PTR records, TTL 300 s, names replaced by the last client, clients may write their own A record, no names for legacy clients, and names outside the zone refused",
    );
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    expect(matchWords({ vendor_class: { value: "MSFT", prefix: true } })).toBe('tillverkarklass som börjar med "MSFT"');
    expect(conditionWords({ join: "and", terms: [{ class: "c1" }, { class: "c2" }] }, (id) => id)).toBe("i klassen c1 och i klassen c2");
    expect(actionWords({})).toBe("ingen ändring");
    expect(actionWords({ ddns: { enabled: true } }, { options: true })).toBe("DDNS på; alternativ");
    expect(matchWords({ architecture: { code: 7 } })).toBe("klientarkitektur UEFI x64 (7)");
  });
});

describe("exclusions and policies", () => {
  const net = networkOf("192.0.2.0/24");

  it("checks an exclusion locally: two IPv4 addresses, ordered, inside the network", () => {
    expect(checkExclusion("192.0.2.10", "192.0.2.19", net)).toBeNull();
    expect(checkExclusion("192.0.2.10", "192.0.2.10", net)).toBeNull();
    expect(checkExclusion("x", "192.0.2.19", net)).toBe("first");
    expect(checkExclusion("2001:db8::1", "192.0.2.19", net)).toBe("first");
    expect(checkExclusion("192.0.2.10", "", net)).toBe("last");
    expect(checkExclusion("192.0.2.20", "192.0.2.10", net)).toBe("order");
    expect(checkExclusion("192.0.2.250", "192.0.3.5", net)).toBe("outside");
    expect(checkExclusion("198.51.100.1", "198.51.100.9", net)).toBe("outside");
    expect(checkExclusion("198.51.100.1", "198.51.100.9", null)).toBeNull();
  });

  it("puts the policies of each scope first, by network and order, then the server's", () => {
    const policy = (name: string, scope: string | undefined, order: number): Policy =>
      ({ id: name, name, scope, order, enabled: true, condition: { join: "and", terms: [] }, action: {}, revision: 1 }) as unknown as Policy;
    const cidr = (scope: string) => (scope === "s1" ? "192.0.2.0/24" : "198.51.100.0/24");
    const ordered = policyOrder([policy("server-b", undefined, 1), policy("iot-b", "s2", 2), policy("lan-b", "s1", 5), policy("iot-a", "s2", 1), policy("lan-a", "s1", 1)], cidr);
    expect(ordered.map((p) => p.name)).toEqual(["lan-a", "lan-b", "iot-a", "iot-b", "server-b"]);
  });

  it("rounds the used share to a whole percent within 0 to 100", () => {
    expect([percentOf(0), percentOf(0.444), percentOf(0.445), percentOf(1.2), percentOf(-1)]).toEqual([0, 44, 45, 100, 0]);
  });
});

// WP9.4: the helpers of a DHCPv6 scope.
describe("DHCPv6 helpers", () => {
  it("tells the family of a scope from the family the API says", () => {
    expect(isV6({ family: "v6" })).toBe(true);
    expect([isV6({ family: "v4" }), isV6({}), isV6(undefined), isV6(null)]).toEqual([false, false, false, false]);
  });

  it("takes five eighths of the valid lifetime, in whole seconds, as the default preferred lifetime", () => {
    expect([defaultPreferred(86_400), defaultPreferred(3600), defaultPreferred(7200), defaultPreferred(100)]).toEqual([54_000, 2250, 4500, 62]);
  });

  it("reads the preferred lifetime: empty is the default, whole seconds up to the valid lifetime", () => {
    expect(preferredOfText("", 86_400)).toEqual({ ok: true, secs: null });
    expect(preferredOfText("  ", 86_400)).toEqual({ ok: true, secs: null });
    expect(preferredOfText("3600", 86_400)).toEqual({ ok: true, secs: 3600 });
    expect(preferredOfText(" 86400 ", 86_400)).toEqual({ ok: true, secs: 86_400 });
    expect(preferredOfText("86401", 86_400)).toEqual({ ok: false, problem: "above" });
    for (const text of ["0", "-1", "1.5", "1h", "soon", "12345678901"]) expect(preferredOfText(text, 86_400), text).toEqual({ ok: false, problem: "number" });
  });

  it("says the size of a range as a power of two from 2^32 up", () => {
    expect(bitsOfSize(4_294_967_295n)).toBeNull();
    expect(bitsOfSize(4_294_967_296n)).toBe(32);
    expect(bitsOfSize((1n << 64n) - 1n)).toBe(63);
    expect(bitsOfSize(1n << 64n)).toBe(64);
    expect(rangeBits("2001:db8::", "2001:db8::ffff:fffe")).toBeNull();
    expect(rangeBits("2001:db8::", "2001:db8::1:0:0")).toBe(32);
    expect(rangeBits("2001:db8:0:10::", "2001:db8:0:10:ffff:ffff:ffff:ffff")).toBe(64);
    expect(rangeBits("x", "2001:db8::")).toBeNull();
  });

  it("checks an exclusion of an IPv6 network with IPv6 addresses inside it", () => {
    const net6 = networkOf("2001:db8:0:10::/64");
    expect(checkExclusion("2001:db8:0:10::1", "2001:db8:0:10::ff", net6)).toBeNull();
    expect(checkExclusion("192.0.2.1", "2001:db8:0:10::ff", net6)).toBe("first");
    expect(checkExclusion("2001:db8:0:10::1", "192.0.2.9", net6)).toBe("last");
    expect(checkExclusion("2001:db8:0:10::ff", "2001:db8:0:10::1", net6)).toBe("order");
    expect(checkExclusion("2001:db8:0:11::1", "2001:db8:0:11::9", net6)).toBe("outside");
  });

  it("words the size of a large pool as a power of two", () => {
    expect(poolCountWords(256, null)).toBe("256");
    expect(poolCountWords(256, undefined)).toBe("256");
    expect(poolCountWords(18_446_744_073_709_552_000, 64)).toBe("At least 2^64");
  });
});
