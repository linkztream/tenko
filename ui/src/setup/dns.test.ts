// The DNS parts of the wizard as pure functions: the generated [dns] section, the step's problem,
// the checklist, the gate of the step, and the controller's helpers (the preset per profile and
// the choice as the configuration and the root rule take it).
import { describe, expect, it } from "vitest";
import type { NodeRole } from "../api/types";
import { dnsChecklist } from "./checklist";
import { dnsChoice, dnsPreset, profileCacheEntries, type DnsStepState } from "./controller";
import { FOCUS, firstBlockedStep, gateFor, stepIndex, type GateInput } from "./gates";
import { generateDnsConfig, type DnsChoice } from "./generate";
import { dnsStepProblem, MAX_CACHE_ENTRIES, type DnsStepInput } from "./validate";

function choice(extra: Partial<DnsChoice> = {}): DnsChoice {
  return { upstreams: [], transport: "plain", tlsName: null, cache: true, cacheEntries: null, dot: false, doh: false, log: false, ...extra };
}

describe("generateDnsConfig", () => {
  it("writes an empty forwarders list when no upstream was chosen", () => {
    const text = generateDnsConfig(choice());
    expect(text).toContain("forwarders = []");
    expect(text).not.toContain("transport");
    expect(text.startsWith("[dns]\n")).toBe(true);
  });

  it("writes plain upstreams without a transport key", () => {
    const text = generateDnsConfig(choice({ upstreams: [{ address: "192.0.2.1" }, { address: "2001:db8::53" }] }));
    expect(text).toContain("forwarders = [\n  { address = \"192.0.2.1\" },\n  { address = \"2001:db8::53\" },\n]");
    expect(text).not.toContain("transport");
    expect(text).not.toContain("tls_name");
  });

  it("writes DoT entries with the transport and the TLS name", () => {
    const text = generateDnsConfig(choice({ upstreams: [{ address: "192.0.2.1" }], transport: "dot", tlsName: "dns.example.test" }));
    expect(text).toContain('{ address = "192.0.2.1", transport = "dot", tls_name = "dns.example.test" },');
  });

  it("writes a port, and the path of a DoH upstream", () => {
    const text = generateDnsConfig(
      choice({ upstreams: [{ address: "192.0.2.80", port: 8443, path: "/dns-query" }], transport: "doh", tlsName: "doh.example.test" }),
    );
    expect(text).toContain('{ address = "192.0.2.80", port = 8443, transport = "doh", tls_name = "doh.example.test", path = "/dns-query" },');
  });

  it("writes a port of a plain upstream", () => {
    const text = generateDnsConfig(choice({ upstreams: [{ address: "192.0.2.1", port: 5353 }] }));
    expect(text).toContain('{ address = "192.0.2.1", port = 5353 },');
  });

  it("leaves out a TLS name that a plain transport does not take", () => {
    const text = generateDnsConfig(choice({ upstreams: [{ address: "192.0.2.1" }], tlsName: "dns.example.test" }));
    expect(text).not.toContain("tls_name");
  });

  it("writes the cache bound only when the choice sets one", () => {
    expect(generateDnsConfig(choice())).toContain("[dns.cache]\nenabled = true\n\n");
    expect(generateDnsConfig(choice())).not.toContain("entries");
    expect(generateDnsConfig(choice({ cacheEntries: 250_000 }))).toContain("[dns.cache]\nenabled = true\nentries = 250000\n");
    expect(generateDnsConfig(choice({ cache: false }))).toContain("[dns.cache]\nenabled = false\n");
  });

  it("writes the served transports and the query log", () => {
    const off = generateDnsConfig(choice());
    expect(off).toContain("[dns.tls]\ndot = false\ndoh = false\n");
    expect(off).toContain("[dns.log]\nenabled = false\n");
    const on = generateDnsConfig(choice({ dot: true, doh: true, log: true }));
    expect(on).toContain("[dns.tls]\ndot = true\ndoh = true\n");
    expect(on).toContain("[dns.log]\nenabled = true\n");
    expect(on.endsWith("\n")).toBe(true);
  });

  it("escapes a string the way TOML needs", () => {
    const text = generateDnsConfig(choice({ upstreams: [{ address: "192.0.2.1" }], transport: "dot", tlsName: 'a"b' }));
    expect(text).toContain('tls_name = "a\\"b"');
  });
});

function input(extra: Partial<DnsStepInput> = {}): DnsStepInput {
  return { upstreams: "", transport: "plain", tlsName: "", cache: true, cacheEntries: "", ...extra };
}

describe("dnsStepProblem", () => {
  it("allows no upstream at all", () => {
    expect(dnsStepProblem(input())).toBeNull();
    expect(dnsStepProblem(input({ upstreams: "  \n " }))).toBeNull();
  });

  it("allows good upstreams, with a port, and a DoH path", () => {
    expect(dnsStepProblem(input({ upstreams: "192.0.2.1\n[2001:db8::53]:5353, 198.51.100.7:53" }))).toBeNull();
    expect(dnsStepProblem(input({ upstreams: "192.0.2.80:443/dns-query", transport: "doh", tlsName: "doh.example.test" }))).toBeNull();
  });

  it("refuses an address that is none", () => {
    expect(dnsStepProblem(input({ upstreams: "dns.example.test" }))).toBe("upstreams");
    expect(dnsStepProblem(input({ upstreams: "192.0.2.1 999.1.1.1" }))).toBe("upstreams");
    expect(dnsStepProblem(input({ upstreams: "192.0.2.1:99999" }))).toBe("upstreams");
  });

  it("refuses a path on a transport other than DoH", () => {
    expect(dnsStepProblem(input({ upstreams: "192.0.2.80/dns-query" }))).toBe("upstreams");
  });

  it("refuses DoT and DoH without a TLS name", () => {
    expect(dnsStepProblem(input({ upstreams: "192.0.2.1", transport: "dot" }))).toBe("tls_name");
    expect(dnsStepProblem(input({ upstreams: "192.0.2.1", transport: "doh", tlsName: "  " }))).toBe("tls_name");
    expect(dnsStepProblem(input({ upstreams: "192.0.2.1", transport: "dot", tlsName: "dns.example.test" }))).toBeNull();
  });

  it("refuses a TLS name that is no name", () => {
    expect(dnsStepProblem(input({ upstreams: "192.0.2.1", transport: "dot", tlsName: "*.example.test" }))).toBe("tls_name");
    expect(dnsStepProblem(input({ transport: "dot", tlsName: "bad name" }))).toBe("tls_name");
  });

  it("does not insist on a TLS name while no upstream is typed", () => {
    expect(dnsStepProblem(input({ transport: "dot" }))).toBeNull();
  });

  it("keeps the upstream problem ahead of the TLS name problem", () => {
    expect(dnsStepProblem(input({ upstreams: "nope", transport: "dot" }))).toBe("upstreams");
  });

  it("refuses a cache bound out of range or not a number", () => {
    for (const bad of ["0", "-5", "abc", "1.5", "10000001", "1e3"]) {
      expect(dnsStepProblem(input({ cacheEntries: bad }))).toBe("entries");
    }
    expect(dnsStepProblem(input({ cacheEntries: "1" }))).toBeNull();
    expect(dnsStepProblem(input({ cacheEntries: String(MAX_CACHE_ENTRIES) }))).toBeNull();
    expect(dnsStepProblem(input({ cacheEntries: " 5000 " }))).toBeNull();
  });

  it("ignores the bound while the cache is off", () => {
    expect(dnsStepProblem(input({ cache: false, cacheEntries: "0" }))).toBeNull();
  });
});

describe("dnsChecklist", () => {
  it("lists the role, the port, the capability and the firewall", () => {
    expect(dnsChecklist({ dot: false, doh: false })).toEqual(["role", "port", "capability", "firewall"]);
  });

  it("adds the TLS ports when DoT or DoH is served", () => {
    const all = ["role", "port", "capability", "firewall", "tls_ports"];
    expect(dnsChecklist({ dot: true, doh: false })).toEqual(all);
    expect(dnsChecklist({ dot: false, doh: true })).toEqual(all);
    expect(dnsChecklist({ dot: true, doh: true })).toEqual(all);
  });
});

const ROLES: Record<NodeRole, boolean> = { controller: true, dns: true, dhcp: true, probe: false };

function gateInput(dns: Partial<GateInput["dns"]> = {}): GateInput {
  return {
    token: "token",
    profile: "home",
    labAck: false,
    userName: "admin1",
    displayName: "Admin One",
    password: "quiet-orchard-ember-17",
    passwordKind: "password",
    passwordCheck: "ok",
    hostName: "tenko1.example.test",
    tlsMode: "internal_ca",
    proxies: "",
    diskRisk: false,
    acceptSlowDisk: false,
    roles: ROLES,
    probeNetworks: [],
    hasNetworks: false,
    dns: { wanted: true, upstreams: "", transport: "plain", tlsName: "", cache: true, cacheEntries: "", ...dns },
  };
}

describe("the gate of the DNS step", () => {
  const step = stepIndex("dns");

  it("is the step after the roles", () => {
    expect(step).toBe(stepIndex("roles") + 1);
  });

  it("lets the step go while nothing is typed", () => {
    expect(gateFor(step, gateInput())).toBeNull();
  });

  it("has no gate when DNS is not wanted, whatever is typed", () => {
    expect(gateFor(step, gateInput({ wanted: false, upstreams: "not an address", cacheEntries: "0" }))).toBeNull();
  });

  it("points a bad upstream at the upstreams field", () => {
    expect(gateFor(step, gateInput({ upstreams: "nope" }))).toEqual({ message: "setup.gate.dns_upstreams", focus: FOCUS.dnsUpstreams });
  });

  it("points a missing TLS name at the TLS name field", () => {
    expect(gateFor(step, gateInput({ upstreams: "192.0.2.1", transport: "dot" }))).toEqual({
      message: "setup.gate.dns_tls_name",
      focus: FOCUS.dnsTlsName,
    });
  });

  it("points a cache bound out of range at the bound", () => {
    expect(gateFor(step, gateInput({ cacheEntries: "0" }))).toEqual({ message: "setup.gate.dns_entries", focus: FOCUS.dnsEntries });
  });

  it("blocks finishing on the DNS step and names it as the first blocked step", () => {
    expect(firstBlockedStep(gateInput({ upstreams: "nope" }))).toBe(step);
    expect(firstBlockedStep(gateInput({ wanted: false, upstreams: "nope" }))).toBeNull();
    expect(firstBlockedStep(gateInput())).toBeNull();
  });
});

describe("dnsPreset and profileCacheEntries", () => {
  it("sets the Home preset: cache on with 10,000, DoT and DoH off, the query log off", () => {
    expect(dnsPreset("home")).toEqual({ cache: true, cacheEntries: "10000", dot: false, doh: false, log: false });
    expect(profileCacheEntries("home")).toBe(10_000);
  });

  it("turns the query log on and takes 100,000 entries under the other profiles", () => {
    for (const profile of ["standard", "hardened", "lab"] as const) {
      expect(dnsPreset(profile)).toEqual({ cache: true, cacheEntries: "100000", dot: false, doh: false, log: true });
      expect(profileCacheEntries(profile)).toBe(100_000);
    }
  });
});

function state(extra: Partial<DnsStepState> = {}): DnsStepState {
  return { upstreams: "", transport: "plain", tlsName: "", ...dnsPreset("home"), touched: false, ...extra };
}

describe("dnsChoice", () => {
  it("keeps the profile's bound (null) when the entries equal it or are empty", () => {
    expect(dnsChoice(state(), "home").cacheEntries).toBeNull();
    expect(dnsChoice(state({ cacheEntries: "" }), "home").cacheEntries).toBeNull();
    expect(dnsChoice(state({ cacheEntries: "10000" }), "home").cacheEntries).toBeNull();
    expect(dnsChoice(state({ cacheEntries: "100000" }), "standard").cacheEntries).toBeNull();
  });

  it("carries a bound that differs from the profile's", () => {
    expect(dnsChoice(state({ cacheEntries: "20000" }), "home").cacheEntries).toBe(20_000);
    expect(dnsChoice(state({ cacheEntries: "10000" }), "standard").cacheEntries).toBe(10_000);
  });

  it("carries no bound while the cache is off", () => {
    expect(dnsChoice(state({ cache: false, cacheEntries: "20000" }), "home")).toMatchObject({ cache: false, cacheEntries: null });
  });

  it("parses the upstreams and the TLS name of a valid draft", () => {
    const got = dnsChoice(state({ upstreams: "9.9.9.9\n149.112.112.112:853", transport: "dot", tlsName: "DNS.Quad9.net." }), "home");
    expect(got.upstreams).toEqual([{ address: "9.9.9.9" }, { address: "149.112.112.112", port: 853 }]);
    expect(got.transport).toBe("dot");
    expect(got.tlsName).toBe("dns.quad9.net");
  });

  it("has no upstreams and no TLS name when the draft is invalid or empty", () => {
    expect(dnsChoice(state({ upstreams: "nope" }), "home")).toMatchObject({ upstreams: [], tlsName: null });
    expect(dnsChoice(state({ upstreams: "192.0.2.1", transport: "dot" }), "home")).toMatchObject({ upstreams: [], tlsName: null });
    expect(dnsChoice(state(), "home")).toMatchObject({ upstreams: [], tlsName: null });
  });

  it("carries the served transports and the log switch", () => {
    expect(dnsChoice(state({ dot: true, doh: true, log: true }), "home")).toMatchObject({ dot: true, doh: true, log: true });
    expect(dnsChoice(state(), "home")).toMatchObject({ dot: false, doh: false, log: false });
  });

  it("feeds the generated configuration", () => {
    const text = generateDnsConfig(dnsChoice(state({ upstreams: "9.9.9.9", transport: "dot", tlsName: "dns.quad9.net", dot: true }), "home"));
    expect(text).toContain('{ address = "9.9.9.9", transport = "dot", tls_name = "dns.quad9.net" },');
    expect(text).toContain("[dns.tls]\ndot = true\ndoh = false\n");
    expect(text).not.toContain("entries");
  });
});
