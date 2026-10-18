// The pure helpers of the forwarding rules: the typed form of an upstream, the local checks of
// a rule, the order of the rules and the well-known public resolvers.
import { describe, expect, it } from "vitest";
import {
  checkRule,
  knownResolver,
  parseUpstream,
  ruleOrder,
  upstreamEndpoint,
  upstreamText,
  type ForwardTransport,
  type RuleDraft,
  type RuleProblem,
} from "./model";

describe("parseUpstream", () => {
  it("reads an IPv4 address with and without a port", () => {
    expect(parseUpstream("192.0.2.1", "plain")).toEqual({ ok: true, upstream: { address: "192.0.2.1" } });
    expect(parseUpstream(" 192.0.2.1:5353 ", "plain")).toEqual({ ok: true, upstream: { address: "192.0.2.1", port: 5353 } });
  });

  it("reads an IPv6 address bare or in brackets with a port", () => {
    expect(parseUpstream("2001:db8::53", "plain")).toEqual({ ok: true, upstream: { address: "2001:db8::53" } });
    expect(parseUpstream("[2001:db8::53]", "plain")).toEqual({ ok: true, upstream: { address: "2001:db8::53" } });
    expect(parseUpstream("[2001:DB8::53]:853", "dot")).toEqual({ ok: true, upstream: { address: "2001:db8::53", port: 853 } });
  });

  it("refuses a port of 0, above 65535 or not a number", () => {
    for (const raw of ["192.0.2.1:0", "192.0.2.1:65536", "192.0.2.1:abc", "192.0.2.1:", "[2001:db8::53]:0", "[2001:db8::53]:65536"]) {
      expect(parseUpstream(raw, "plain"), raw).toEqual({ ok: false, problem: "port" });
    }
    expect(parseUpstream("192.0.2.1:65535", "plain")).toEqual({ ok: true, upstream: { address: "192.0.2.1", port: 65_535 } });
    expect(parseUpstream("192.0.2.1:1", "plain")).toEqual({ ok: true, upstream: { address: "192.0.2.1", port: 1 } });
  });

  it("refuses what is not an IP address", () => {
    for (const raw of ["", "example.test", "192.0.2.256", "[192.0.2.1", "dns.example.test:53"]) {
      expect(parseUpstream(raw, "plain"), raw).toEqual({ ok: false, problem: "address" });
    }
  });

  it("takes a path only for DNS over HTTPS", () => {
    expect(parseUpstream("192.0.2.80:443/dns-query", "doh")).toEqual({ ok: true, upstream: { address: "192.0.2.80", port: 443, path: "/dns-query" } });
    expect(parseUpstream("192.0.2.80/dns-query", "doh")).toEqual({ ok: true, upstream: { address: "192.0.2.80", path: "/dns-query" } });
    expect(parseUpstream("[2001:db8::80]:443/dns-query", "doh")).toEqual({ ok: true, upstream: { address: "2001:db8::80", port: 443, path: "/dns-query" } });
    for (const transport of ["plain", "dot"] as ForwardTransport[]) {
      expect(parseUpstream("192.0.2.80/dns-query", transport), transport).toEqual({ ok: false, problem: "path_transport" });
    }
  });

  it("refuses a path with a space and a path glued on without its slash", () => {
    expect(parseUpstream("192.0.2.80/dns query", "doh")).toEqual({ ok: false, problem: "path" });
    // Without the leading slash the text is read as a port (or an address), never as a path.
    expect(parseUpstream("192.0.2.80:443dns-query", "doh")).toEqual({ ok: false, problem: "port" });
    expect(parseUpstream("192.0.2.80dns-query", "doh")).toEqual({ ok: false, problem: "address" });
  });
});

describe("upstreamText", () => {
  it("brackets an IPv6 address only when it has a port", () => {
    expect(upstreamText({ address: "2001:db8::53" })).toBe("2001:db8::53");
    expect(upstreamText({ address: "2001:db8::53", port: 853 })).toBe("[2001:db8::53]:853");
    expect(upstreamText({ address: "192.0.2.1", port: 5353 })).toBe("192.0.2.1:5353");
    expect(upstreamText({ address: "192.0.2.80", port: 443, path: "/dns-query" })).toBe("192.0.2.80:443/dns-query");
  });

  it("reads back what parseUpstream read", () => {
    for (const raw of ["192.0.2.1", "192.0.2.1:5353", "2001:db8::53", "[2001:db8::53]:853", "192.0.2.80:443/dns-query", "[2001:db8::80]:443/dns-query", "192.0.2.80/x"]) {
      const parsed = parseUpstream(raw, "doh");
      if (!parsed.ok) throw new Error(`${raw} did not parse`);
      const text = upstreamText(parsed.upstream);
      expect(parseUpstream(text, "doh"), raw).toEqual(parsed);
    }
  });
});

describe("upstreamEndpoint", () => {
  it("uses the default port of the transport when the upstream names none", () => {
    expect(upstreamEndpoint({ address: "192.0.2.1" }, "plain")).toBe("192.0.2.1:53");
    expect(upstreamEndpoint({ address: "192.0.2.1" }, "dot")).toBe("192.0.2.1:853");
    expect(upstreamEndpoint({ address: "192.0.2.1" }, "doh")).toBe("192.0.2.1:443");
  });

  it("keeps a given port and brackets IPv6", () => {
    expect(upstreamEndpoint({ address: "192.0.2.1", port: 5353 }, "dot")).toBe("192.0.2.1:5353");
    expect(upstreamEndpoint({ address: "2001:db8::53" }, "dot")).toBe("[2001:db8::53]:853");
    expect(upstreamEndpoint({ address: "2001:db8::53", port: 5353 }, "plain")).toBe("[2001:db8::53]:5353");
  });
});

describe("checkRule", () => {
  const draft = (over: Partial<RuleDraft> = {}): RuleDraft => ({
    suffix: "corp.example.test",
    upstreams: "192.0.2.10\n192.0.2.11",
    transport: "plain",
    tlsName: "",
    ...over,
  });
  const problems = (over: Partial<RuleDraft>, options?: { suffix?: boolean }): RuleProblem[] => {
    const checked = checkRule(draft(over), options);
    if (checked.ok) throw new Error("expected problems");
    return checked.problems;
  };

  it("accepts a plain rule and returns its parts", () => {
    expect(checkRule(draft())).toEqual({
      ok: true,
      suffix: "corp.example.test",
      upstreams: [{ address: "192.0.2.10" }, { address: "192.0.2.11" }],
      transport: "plain",
      tlsName: null,
    });
  });

  it("separates upstreams by lines, commas, spaces and semicolons", () => {
    const checked = checkRule(draft({ upstreams: "192.0.2.10, 192.0.2.11;192.0.2.12 192.0.2.13" }));
    expect(checked.ok && checked.upstreams).toHaveLength(4);
  });

  it("asks for at least one upstream", () => {
    expect(problems({ upstreams: "  \n " })).toEqual([{ field: "upstreams", problem: "none" }]);
  });

  it("refuses more than 16 upstreams and accepts 16", () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => `192.0.2.${i + 1}`).join("\n");
    expect(problems({ upstreams: many(17) })).toEqual([{ field: "upstreams", problem: "too_many" }]);
    expect(checkRule(draft({ upstreams: many(16) })).ok).toBe(true);
  });

  it("refuses an upstream listed twice, also with the default port written out", () => {
    expect(problems({ upstreams: "192.0.2.10\n192.0.2.10" })).toEqual([{ field: "upstreams", problem: "duplicate" }]);
    expect(problems({ upstreams: "192.0.2.10\n192.0.2.10:53" })).toEqual([{ field: "upstreams", problem: "duplicate" }]);
    expect(problems({ upstreams: "2001:db8::53\n[2001:db8::53]:53" })).toEqual([{ field: "upstreams", problem: "duplicate" }]);
  });

  it("tells two DoH paths on one address apart", () => {
    const checked = checkRule(draft({ transport: "doh", tlsName: "dns.example.test", upstreams: "192.0.2.80/a\n192.0.2.80/b" }));
    expect(checked.ok).toBe(true);
  });

  it("names the entry of an upstream it cannot read and stops there", () => {
    expect(problems({ upstreams: "192.0.2.10\nnot-an-ip\n192.0.2.10:0" })).toEqual([{ field: "upstreams", problem: "address", entry: "not-an-ip" }]);
    expect(problems({ upstreams: "192.0.2.10:0" })).toEqual([{ field: "upstreams", problem: "port", entry: "192.0.2.10:0" }]);
    expect(problems({ upstreams: "192.0.2.10/dns-query" })).toEqual([{ field: "upstreams", problem: "path_transport", entry: "192.0.2.10/dns-query" }]);
  });

  it("asks DNS over TLS and DNS over HTTPS for the TLS name", () => {
    expect(problems({ transport: "dot" })).toEqual([{ field: "tls_name", problem: "required" }]);
    expect(problems({ transport: "doh", tlsName: "  " })).toEqual([{ field: "tls_name", problem: "required" }]);
    const ok = checkRule(draft({ transport: "dot", tlsName: "DNS.Example.Test." }));
    expect(ok.ok && ok.tlsName).toBe("dns.example.test");
  });

  it("takes an IP address as the TLS name, and refuses a wildcard or a bad name", () => {
    const ip = checkRule(draft({ transport: "dot", tlsName: "192.0.2.53" }));
    expect(ip.ok && ip.tlsName).toBe("192.0.2.53");
    expect(problems({ transport: "dot", tlsName: "*.example.test" })).toEqual([{ field: "tls_name", problem: "name" }]);
    expect(problems({ transport: "dot", tlsName: "not a name" })).toEqual([{ field: "tls_name", problem: "name" }]);
  });

  it("does not ask a plain rule for a TLS name, but checks one that is typed", () => {
    expect(checkRule(draft({ tlsName: "" })).ok).toBe(true);
    expect(problems({ tlsName: "not a name" })).toEqual([{ field: "tls_name", problem: "name" }]);
  });

  it("refuses a suffix that is not a DNS name or has a wildcard", () => {
    expect(problems({ suffix: "not a name" })).toEqual([{ field: "suffix", problem: "name" }]);
    expect(problems({ suffix: "*.example.test" })).toEqual([{ field: "suffix", problem: "name" }]);
  });

  it("reads . and an empty suffix as the root", () => {
    for (const suffix of [".", "", "  "]) {
      const checked = checkRule(draft({ suffix }));
      expect(checked.ok && checked.suffix, JSON.stringify(suffix)).toBe(".");
    }
  });

  it("writes the suffix in its canonical form", () => {
    const checked = checkRule(draft({ suffix: "Corp.Example.Test." }));
    expect(checked.ok && checked.suffix).toBe("corp.example.test");
  });

  it("leaves the suffix unchecked when the caller says so", () => {
    expect(checkRule(draft({ suffix: "not a name" }), { suffix: false }).ok).toBe(true);
  });

  it("reports the problems of several fields together", () => {
    expect(problems({ suffix: "not a name", upstreams: "", transport: "dot" }).map((p) => p.field)).toEqual(["suffix", "upstreams", "tls_name"]);
  });
});

describe("ruleOrder", () => {
  const order = (suffixes: string[]) => suffixes.map((suffix) => ({ suffix })).sort(ruleOrder).map((r) => r.suffix);

  it("puts the root first, then goes from the root down", () => {
    expect(order(["corp.example.test", "example.test", ".", "a.test", "example.org"])).toEqual([".", "example.org", "a.test", "example.test", "corp.example.test"]);
  });

  it("does not depend on the order it is given", () => {
    const rules = [".", "example.test", "corp.example.test", "lab.example.test"];
    expect(order([...rules].reverse())).toEqual(order(rules));
    expect(order(rules)).toEqual([".", "example.test", "corp.example.test", "lab.example.test"]);
  });

  it("keeps two equal suffixes together", () => {
    expect(ruleOrder({ suffix: "example.test" }, { suffix: "example.test" })).toBe(0);
    expect(ruleOrder({ suffix: "." }, { suffix: "." })).toBe(0);
  });
});

describe("knownResolver", () => {
  it("recognises Quad9 by every one of its addresses", () => {
    for (const address of ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]) {
      expect(knownResolver([address])?.tlsName, address).toBe("dns.quad9.net");
    }
    expect(knownResolver(["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"])?.name).toBe("Quad9");
  });

  it("recognises the other resolvers of the docs", () => {
    expect(knownResolver(["1.1.1.1", "1.0.0.1"])?.tlsName).toBe("cloudflare-dns.com");
    expect(knownResolver(["8.8.8.8", "2001:4860:4860::8844"])?.tlsName).toBe("dns.google");
  });

  it("still matches addresses typed with a port, in brackets or in other letter case", () => {
    expect(knownResolver(["9.9.9.9:53", "[2620:FE::fe]:53"])?.tlsName).toBe("dns.quad9.net");
    expect(knownResolver(["[2620:fe::9]"])?.tlsName).toBe("dns.quad9.net");
  });

  it("offers nothing for a mix of providers", () => {
    expect(knownResolver(["9.9.9.9", "1.1.1.1"])).toBeUndefined();
  });

  it("offers nothing when one address is unknown, unreadable or none is typed", () => {
    expect(knownResolver(["9.9.9.9", "192.0.2.53"])).toBeUndefined();
    expect(knownResolver(["192.0.2.53"])).toBeUndefined();
    expect(knownResolver(["9.9.9.9", "not-an-ip"])).toBeUndefined();
    expect(knownResolver([])).toBeUndefined();
  });
});
