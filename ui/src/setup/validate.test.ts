import { describe, expect, it } from "vitest";
import { isAddressOrPrefix, isIPv4, isIPv6, isValidUserName, parseProxyList, validateHostName } from "./validate";

describe("isIPv4", () => {
  it("accepts dotted quads of the documentation ranges", () => {
    expect(isIPv4("192.0.2.13")).toBe(true);
    expect(isIPv4("198.51.100.0")).toBe(true);
    expect(isIPv4("203.0.113.255")).toBe(true);
  });

  it("rejects out-of-range octets, leading zeros and short forms", () => {
    expect(isIPv4("192.0.2.256")).toBe(false);
    expect(isIPv4("192.0.02.1")).toBe(false);
    expect(isIPv4("192.0.2")).toBe(false);
    expect(isIPv4("192.0.2.1.5")).toBe(false);
    expect(isIPv4("tenko1.example.test")).toBe(false);
  });
});

describe("isIPv6", () => {
  it("accepts the text forms of 2001:db8::/32", () => {
    expect(isIPv6("2001:db8::1")).toBe(true);
    expect(isIPv6("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe(true);
    expect(isIPv6("2001:db8::")).toBe(true);
    expect(isIPv6("::1")).toBe(true);
    expect(isIPv6("::")).toBe(true);
    expect(isIPv6("::ffff:192.0.2.1")).toBe(true);
  });

  it("rejects malformed addresses", () => {
    expect(isIPv6("2001:db8:::1")).toBe(false);
    expect(isIPv6("2001:db8::1::2")).toBe(false);
    expect(isIPv6("2001:db8")).toBe(false);
    expect(isIPv6("2001:db8:0:0:0:0:0:0:1")).toBe(false);
    expect(isIPv6("2001:db8::g")).toBe(false);
    expect(isIPv6("12345::1")).toBe(false);
    expect(isIPv6("192.0.2.13")).toBe(false);
  });
});

describe("isAddressOrPrefix", () => {
  it("takes addresses and prefixes of both families", () => {
    expect(isAddressOrPrefix("192.0.2.10")).toBe(true);
    expect(isAddressOrPrefix("198.51.100.0/24")).toBe(true);
    expect(isAddressOrPrefix("203.0.113.0/32")).toBe(true);
    expect(isAddressOrPrefix("2001:db8::/32")).toBe(true);
    expect(isAddressOrPrefix("2001:db8::1/128")).toBe(true);
  });

  it("rejects bad lengths and names", () => {
    expect(isAddressOrPrefix("198.51.100.0/33")).toBe(false);
    expect(isAddressOrPrefix("2001:db8::/129")).toBe(false);
    expect(isAddressOrPrefix("198.51.100.0/")).toBe(false);
    expect(isAddressOrPrefix("198.51.100.0/-1")).toBe(false);
    expect(isAddressOrPrefix("proxy.example.test")).toBe(false);
    expect(isAddressOrPrefix("")).toBe(false);
  });
});

describe("validateHostName", () => {
  it("accepts DNS names and returns them normalized", () => {
    expect(validateHostName("tenko1.example.test")).toEqual({ ok: true, name: "tenko1.example.test" });
    expect(validateHostName("  Tenko1.Example.TEST.  ")).toEqual({ ok: true, name: "tenko1.example.test" });
    expect(validateHostName("localhost")).toEqual({ ok: true, name: "localhost" });
    expect(validateHostName("a-b.c1.example.test")).toEqual({ ok: true, name: "a-b.c1.example.test" });
  });

  it("rejects IPv4 and IPv6 addresses", () => {
    expect(validateHostName("192.0.2.13")).toEqual({ ok: false, problem: "address" });
    expect(validateHostName("2001:db8::1")).toEqual({ ok: false, problem: "address" });
    expect(validateHostName("[2001:db8::1]")).toEqual({ ok: false, problem: "address" });
    expect(validateHostName("203.0.113.9.")).toEqual({ ok: false, problem: "address" });
  });

  it("rejects names that are numbers only", () => {
    expect(validateHostName("1234")).toEqual({ ok: false, problem: "address" });
  });

  it("rejects bad characters and labels", () => {
    expect(validateHostName("tenko_1.example.test")).toEqual({ ok: false, problem: "chars" });
    expect(validateHostName("-tenko.example.test")).toEqual({ ok: false, problem: "chars" });
    expect(validateHostName("tenko-.example.test")).toEqual({ ok: false, problem: "chars" });
    expect(validateHostName("tenko..example.test")).toEqual({ ok: false, problem: "chars" });
    expect(validateHostName("tenko 1.example.test")).toEqual({ ok: false, problem: "chars" });
    expect(validateHostName("tenko.example.test/path")).toEqual({ ok: false, problem: "chars" });
  });

  it("rejects empty and too long names", () => {
    expect(validateHostName("")).toEqual({ ok: false, problem: "empty" });
    expect(validateHostName("   ")).toEqual({ ok: false, problem: "empty" });
    expect(validateHostName(".")).toEqual({ ok: false, problem: "empty" });
    expect(validateHostName(`${"a".repeat(64)}.example.test`)).toEqual({ ok: false, problem: "length" });
    expect(validateHostName(`${Array.from({ length: 30 }, () => "abcdefgh").join(".")}.example.test`)).toEqual({
      ok: false,
      problem: "length",
    });
  });
});

describe("parseProxyList", () => {
  it("splits on new lines, spaces and commas, and drops duplicates", () => {
    const list = parseProxyList("192.0.2.10\n198.51.100.0/24, 2001:db8::/32\n\n192.0.2.10 \n");
    expect(list.entries).toEqual(["192.0.2.10", "198.51.100.0/24", "2001:db8::/32"]);
    expect(list.invalid).toEqual([]);
  });

  it("reports the entries that are not addresses or prefixes", () => {
    const list = parseProxyList("192.0.2.10\nproxy.example.test\n198.51.100.0/40");
    expect(list.entries).toHaveLength(3);
    expect(list.invalid).toEqual(["proxy.example.test", "198.51.100.0/40"]);
  });

  it("is empty for blank text", () => {
    expect(parseProxyList("  \n ")).toEqual({ entries: [], invalid: [] });
  });
});

describe("isValidUserName", () => {
  it("follows the rule of the mockup: 3 to 31 characters, lowercase letter first", () => {
    expect(isValidUserName("alex")).toBe(true);
    expect(isValidUserName(" alex ")).toBe(true);
    expect(isValidUserName("a.b-c_d9")).toBe(true);
    expect(isValidUserName("al")).toBe(false);
    expect(isValidUserName("Alex")).toBe(false);
    expect(isValidUserName("1alex")).toBe(false);
    expect(isValidUserName("alex smith")).toBe(false);
    expect(isValidUserName("a".repeat(32))).toBe(false);
    expect(isValidUserName("a".repeat(31))).toBe(true);
  });
});
