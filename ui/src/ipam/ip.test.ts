import { describe, expect, it } from "vitest";
import {
  addToIp,
  bitsOf,
  cidrOf,
  compareCidr,
  compareIp,
  containsCidr,
  containsIp,
  firstOf,
  formatCidr,
  formatIp,
  freeSubnets,
  hostPart,
  ipSortKey,
  isNibbleAligned,
  lastOf,
  normalizeCidr,
  normalizeIp,
  overlaps,
  parseCidr,
  parseIp,
  rangeSize,
  sizeOf,
  usableCount,
  usableRange,
  withHostPart,
  type Cidr,
  type Ip,
} from "./ip";

function ip(text: string): Ip {
  const parsed = parseIp(text);
  if (parsed === null) throw new Error(`not an address: ${text}`);
  return parsed;
}

function cidr(text: string): Cidr {
  const parsed = parseCidr(text);
  if (parsed === null) throw new Error(`not a prefix: ${text}`);
  return parsed;
}

function take(generator: Generator<Cidr>, count: number): string[] {
  const out: string[] = [];
  for (const item of generator) {
    out.push(formatCidr(item));
    if (out.length >= count) break;
  }
  return out;
}

describe("bitsOf", () => {
  it("returns the address width", () => {
    expect(bitsOf(4)).toBe(32);
    expect(bitsOf(6)).toBe(128);
  });
});

describe("parseIp and formatIp", () => {
  it("round-trips IPv4 addresses", () => {
    for (const text of ["0.0.0.0", "192.0.2.1", "198.51.100.254", "203.0.113.0", "255.255.255.255"]) {
      const parsed = ip(text);
      expect(parsed.version).toBe(4);
      expect(formatIp(parsed)).toBe(text);
    }
  });

  it("parses IPv4 values", () => {
    expect(ip("192.0.2.1").value).toBe(0xc0000201n);
    expect(ip("0.0.0.0").value).toBe(0n);
    expect(ip("255.255.255.255").value).toBe(0xffffffffn);
  });

  it("round-trips canonical IPv6 addresses", () => {
    for (const text of ["2001:db8::", "2001:db8::1", "::", "::1", "2001:db8:0:1:1:1:1:1", "2001:db8::1:0:0:1"]) {
      const parsed = ip(text);
      expect(parsed.version).toBe(6);
      expect(formatIp(parsed)).toBe(text);
    }
  });

  it("compresses the longest zero run, the first one on a tie", () => {
    expect(formatIp(ip("2001:db8:0:0:1:0:0:1"))).toBe("2001:db8::1:0:0:1");
    expect(formatIp(ip("2001:0:0:1:0:0:0:1"))).toBe("2001:0:0:1::1");
    expect(formatIp(ip("1:0:0:2:3:0:0:4"))).toBe("1::2:3:0:0:4");
  });

  it("normalizes full-form addresses", () => {
    expect(formatIp(ip("2001:0db8:0000:0000:0000:0000:0000:0001"))).toBe("2001:db8::1");
    expect(formatIp(ip("2001:DB8::ABCD"))).toBe("2001:db8::abcd");
  });

  it("does not compress a single zero group", () => {
    expect(formatIp(ip("2001:db8:0:1:1:1:1:1"))).toBe("2001:db8:0:1:1:1:1:1");
    expect(formatIp(ip("1:2:3:4:5:6:7:0"))).toBe("1:2:3:4:5:6:7:0");
    expect(formatIp(ip("0:1:2:3:4:5:6:7"))).toBe("0:1:2:3:4:5:6:7");
  });

  it("compresses a run at the start or the end", () => {
    expect(formatIp(ip("0:0:0:0:0:0:0:1"))).toBe("::1");
    expect(formatIp(ip("1:0:0:0:0:0:0:0"))).toBe("1::");
    expect(formatIp(ip("1:2:3:4:5:6:0:0"))).toBe("1:2:3:4:5:6::");
  });

  it("parses an embedded IPv4 tail and formats without it", () => {
    const parsed = ip("::ffff:192.0.2.1");
    expect(parsed.version).toBe(6);
    expect(parsed.value).toBe(0xffffc0000201n);
    expect(formatIp(parsed)).toBe("::ffff:c000:201");
    expect(ip("64:ff9b::198.51.100.7").value).toBe(ip("64:ff9b::c633:6407").value);
    expect(ip("1:2:3:4:5:6:192.0.2.1").value).toBe(ip("1:2:3:4:5:6:c000:201").value);
  });

  it("accepts the full width and all-ones value", () => {
    expect(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").value).toBe((1n << 128n) - 1n);
    expect(formatIp(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))).toBe("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
  });

  it("trims surrounding spaces", () => {
    expect(formatIp(ip("  192.0.2.1 "))).toBe("192.0.2.1");
    expect(formatIp(ip(" 2001:DB8::1 "))).toBe("2001:db8::1");
  });

  it("rejects malformed IPv4 addresses", () => {
    for (const text of [
      "",
      " ",
      "192.0.2.256",
      "192.0.2",
      "192.0.02.1",
      "192.0.2.1.5",
      "192.0.2.",
      ".192.0.2.1",
      "192.0.2.-1",
      "192.0.2.1/24",
      "192.0.2.a",
      "1234.0.0.1",
      "192,0,2,1",
      "0x7f.0.0.1",
    ]) {
      expect(parseIp(text), text).toBeNull();
    }
  });

  it("rejects malformed IPv6 addresses", () => {
    for (const text of [
      "2001:db8:::1",
      "2001:db8::1::2",
      "1:2:3:4:5:6:7:8:9",
      "1:2:3:4:5:6:7",
      "1:2:3:4:5:6:7::8:9",
      "1:2:3:4:5:6:7:8::",
      "fe80::1%eth0",
      "[2001:db8::1]",
      "2001:db8::g",
      "12345::1",
      ":1:2:3:4:5:6:7",
      "1:2:3:4:5:6:7:",
      ":",
      ":::",
      "::ffff:192.0.2.256",
      "::ffff:192.0.2",
      "1.2.3.4::",
      "::1.2.3.4:5",
      "1:2:3:4:5:6:7:1.2.3.4",
    ]) {
      expect(parseIp(text), text).toBeNull();
    }
  });
});

describe("parseCidr and formatCidr", () => {
  it("parses and formats prefixes", () => {
    expect(formatCidr(cidr("192.0.2.0/24"))).toBe("192.0.2.0/24");
    expect(formatCidr(cidr("2001:db8::/32"))).toBe("2001:db8::/32");
    expect(formatCidr(cidr("2001:0DB8:0:0:0:0:0:0/32"))).toBe("2001:db8::/32");
    expect(formatCidr(cidr("0.0.0.0/0"))).toBe("0.0.0.0/0");
    expect(formatCidr(cidr("::/0"))).toBe("::/0");
  });

  it("treats a missing length as a host prefix", () => {
    expect(cidr("192.0.2.7").length).toBe(32);
    expect(cidr("2001:db8::7").length).toBe(128);
    expect(formatCidr(cidr("192.0.2.7"))).toBe("192.0.2.7/32");
  });

  it("is strict about host bits by default", () => {
    expect(parseCidr("192.0.2.1/24")).toBeNull();
    expect(parseCidr("192.0.2.1/24", { strict: true })).toBeNull();
    expect(parseCidr("2001:db8::1/64")).toBeNull();
  });

  it("masks host bits when not strict", () => {
    const relaxed = parseCidr("192.0.2.1/24", { strict: false });
    expect(relaxed).not.toBeNull();
    expect(formatCidr(relaxed as Cidr)).toBe("192.0.2.0/24");
    expect(formatCidr(parseCidr("2001:db8:5:1:abcd::1/48", { strict: false }) as Cidr)).toBe("2001:db8:5::/48");
    expect(parseCidr("192.0.2.1/24", {})).toBeNull();
  });

  it("rejects lengths out of range and malformed lengths", () => {
    expect(parseCidr("192.0.2.0/33")).toBeNull();
    expect(parseCidr("192.0.2.0/33", { strict: false })).toBeNull();
    expect(parseCidr("2001:db8::/129")).toBeNull();
    expect(parseCidr("192.0.2.0/-1")).toBeNull();
    expect(parseCidr("192.0.2.0/")).toBeNull();
    expect(parseCidr("192.0.2.0/24/8")).toBeNull();
    expect(parseCidr("192.0.2.0/ab")).toBeNull();
    expect(parseCidr("192.0.2.0/024")).toBeNull();
    expect(parseCidr("192.0.2.0/2.5")).toBeNull();
    expect(parseCidr("/24")).toBeNull();
    expect(parseCidr("")).toBeNull();
  });

  it("accepts the extreme lengths", () => {
    expect(parseCidr("192.0.2.0/32")).not.toBeNull();
    expect(parseCidr("2001:db8::/128")).not.toBeNull();
    expect(parseCidr("0.0.0.0/0")).not.toBeNull();
    expect(parseCidr("2001:db8::/0")).toBeNull();
    expect(parseCidr("2001:db8::/0", { strict: false })?.network).toBe(0n);
  });
});

describe("cidrOf", () => {
  it("masks the host bits", () => {
    expect(formatCidr(cidrOf(ip("192.0.2.77"), 24))).toBe("192.0.2.0/24");
    expect(formatCidr(cidrOf(ip("2001:db8:1:2:3:4:5:6"), 48))).toBe("2001:db8:1::/48");
    expect(formatCidr(cidrOf(ip("192.0.2.77"), 32))).toBe("192.0.2.77/32");
    expect(formatCidr(cidrOf(ip("192.0.2.77"), 0))).toBe("0.0.0.0/0");
  });

  it("throws for a length outside the address width", () => {
    expect(() => cidrOf(ip("192.0.2.1"), 33)).toThrow(RangeError);
    expect(() => cidrOf(ip("192.0.2.1"), -1)).toThrow(RangeError);
    expect(() => cidrOf(ip("2001:db8::1"), 129)).toThrow(RangeError);
    expect(() => cidrOf(ip("192.0.2.1"), 24.5)).toThrow(RangeError);
  });
});

describe("sizes and bounds", () => {
  it("computes size, first and last", () => {
    const c = cidr("192.0.2.0/24");
    expect(sizeOf(c)).toBe(256n);
    expect(formatIp(firstOf(c))).toBe("192.0.2.0");
    expect(formatIp(lastOf(c))).toBe("192.0.2.255");
    expect(sizeOf(cidr("192.0.2.5/32"))).toBe(1n);
    expect(sizeOf(cidr("0.0.0.0/0"))).toBe(1n << 32n);
    expect(sizeOf(cidr("2001:db8::/64"))).toBe(1n << 64n);
    expect(sizeOf(cidr("::/0"))).toBe(1n << 128n);
    expect(formatIp(lastOf(cidr("2001:db8::/32")))).toBe("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff");
    expect(formatIp(lastOf(cidr("::/0")))).toBe("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
  });
});

describe("usableRange and usableCount", () => {
  it("excludes network and broadcast in an IPv4 /24", () => {
    const c = cidr("192.0.2.0/24");
    const range = usableRange(c);
    expect(formatIp(range.first)).toBe("192.0.2.1");
    expect(formatIp(range.last)).toBe("192.0.2.254");
    expect(usableCount(c)).toBe(254n);
  });

  it("excludes network and broadcast in an IPv4 /30", () => {
    const c = cidr("198.51.100.4/30");
    const range = usableRange(c);
    expect(formatIp(range.first)).toBe("198.51.100.5");
    expect(formatIp(range.last)).toBe("198.51.100.6");
    expect(usableCount(c)).toBe(2n);
  });

  it("uses both addresses of an IPv4 /31", () => {
    const c = cidr("198.51.100.4/31");
    const range = usableRange(c);
    expect(formatIp(range.first)).toBe("198.51.100.4");
    expect(formatIp(range.last)).toBe("198.51.100.5");
    expect(usableCount(c)).toBe(2n);
  });

  it("uses the single address of an IPv4 /32", () => {
    const c = cidr("203.0.113.9/32");
    const range = usableRange(c);
    expect(formatIp(range.first)).toBe("203.0.113.9");
    expect(formatIp(range.last)).toBe("203.0.113.9");
    expect(usableCount(c)).toBe(1n);
  });

  it("uses every address of an IPv6 prefix", () => {
    const c = cidr("2001:db8:0:1::/64");
    const range = usableRange(c);
    expect(formatIp(range.first)).toBe("2001:db8:0:1::");
    expect(formatIp(range.last)).toBe("2001:db8:0:1:ffff:ffff:ffff:ffff");
    expect(usableCount(c)).toBe(1n << 64n);
    expect(usableCount(cidr("2001:db8::1/128"))).toBe(1n);
  });
});

describe("containment and overlap", () => {
  const net = cidr("192.0.2.0/24");

  it("tests whether a prefix contains an address", () => {
    expect(containsIp(net, ip("192.0.2.0"))).toBe(true);
    expect(containsIp(net, ip("192.0.2.255"))).toBe(true);
    expect(containsIp(net, ip("192.0.3.0"))).toBe(false);
    expect(containsIp(net, ip("192.0.1.255"))).toBe(false);
  });

  it("is false across versions", () => {
    expect(containsIp(net, ip("::c000:200"))).toBe(false);
    expect(containsIp(cidr("::/0"), ip("192.0.2.1"))).toBe(false);
    expect(containsIp(cidr("0.0.0.0/0"), ip("2001:db8::1"))).toBe(false);
    expect(containsCidr(cidr("0.0.0.0/0"), cidr("2001:db8::/32"))).toBe(false);
    expect(overlaps(cidr("0.0.0.0/0"), cidr("::/0"))).toBe(false);
  });

  it("tests whether a prefix contains another prefix", () => {
    expect(containsCidr(net, net)).toBe(true);
    expect(containsCidr(net, cidr("192.0.2.128/25"))).toBe(true);
    expect(containsCidr(net, cidr("192.0.2.77/32"))).toBe(true);
    expect(containsCidr(net, cidr("192.0.0.0/16"))).toBe(false);
    expect(containsCidr(net, cidr("192.0.3.0/24"))).toBe(false);
    expect(containsCidr(cidr("192.0.0.0/16"), net)).toBe(true);
    expect(containsCidr(cidr("2001:db8::/32"), cidr("2001:db8:0:5::/64"))).toBe(true);
    expect(containsCidr(cidr("2001:db8:0:5::/64"), cidr("2001:db8::/32"))).toBe(false);
  });

  it("detects overlap", () => {
    expect(overlaps(net, cidr("192.0.2.128/25"))).toBe(true);
    expect(overlaps(cidr("192.0.2.128/25"), net)).toBe(true);
    expect(overlaps(net, net)).toBe(true);
    expect(overlaps(net, cidr("192.0.0.0/16"))).toBe(true);
    expect(overlaps(net, cidr("198.51.100.0/24"))).toBe(false);
    expect(overlaps(cidr("192.0.2.0/25"), cidr("192.0.2.128/25"))).toBe(false);
    expect(overlaps(cidr("2001:db8::/32"), cidr("2001:db8:1::/48"))).toBe(true);
    expect(overlaps(cidr("2001:db8::/32"), cidr("2001:db9::/32"))).toBe(false);
  });
});

describe("compareIp and compareCidr", () => {
  it("orders addresses, IPv4 before IPv6", () => {
    expect(compareIp(ip("192.0.2.1"), ip("192.0.2.2"))).toBe(-1);
    expect(compareIp(ip("192.0.2.2"), ip("192.0.2.1"))).toBe(1);
    expect(compareIp(ip("192.0.2.1"), ip("192.0.2.1"))).toBe(0);
    expect(compareIp(ip("255.255.255.255"), ip("::"))).toBe(-1);
    expect(compareIp(ip("::"), ip("255.255.255.255"))).toBe(1);
    expect(compareIp(ip("2001:db8::1"), ip("2001:db8::2"))).toBe(-1);
  });

  it("orders prefixes by version, network, then shorter length first", () => {
    expect(compareCidr(cidr("192.0.2.0/24"), cidr("198.51.100.0/24"))).toBe(-1);
    expect(compareCidr(cidr("198.51.100.0/24"), cidr("192.0.2.0/24"))).toBe(1);
    expect(compareCidr(cidr("192.0.2.0/24"), cidr("192.0.2.0/25"))).toBe(-1);
    expect(compareCidr(cidr("192.0.2.0/25"), cidr("192.0.2.0/24"))).toBe(1);
    expect(compareCidr(cidr("192.0.2.0/24"), cidr("192.0.2.0/24"))).toBe(0);
    expect(compareCidr(cidr("255.0.0.0/8"), cidr("::/0"))).toBe(-1);
    const sorted = ["2001:db8::/48", "192.0.2.0/25", "2001:db8::/32", "192.0.2.0/24", "10.0.0.0/8"]
      .map(cidr)
      .sort(compareCidr)
      .map(formatCidr);
    expect(sorted).toEqual(["10.0.0.0/8", "192.0.2.0/24", "192.0.2.0/25", "2001:db8::/32", "2001:db8::/48"]);
  });
});

describe("addToIp", () => {
  it("moves forward and backward", () => {
    expect(formatIp(addToIp(ip("192.0.2.255"), 1n) as Ip)).toBe("192.0.3.0");
    expect(formatIp(addToIp(ip("192.0.3.0"), -1n) as Ip)).toBe("192.0.2.255");
    expect(formatIp(addToIp(ip("2001:db8::ffff"), 1n) as Ip)).toBe("2001:db8::1:0");
    expect(formatIp(addToIp(ip("192.0.2.1"), 0n) as Ip)).toBe("192.0.2.1");
  });

  it("returns null when leaving the address space", () => {
    expect(addToIp(ip("255.255.255.255"), 1n)).toBeNull();
    expect(addToIp(ip("0.0.0.0"), -1n)).toBeNull();
    expect(addToIp(ip("::"), -1n)).toBeNull();
    expect(addToIp(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 1n)).toBeNull();
    expect(addToIp(ip("192.0.2.1"), 1n << 40n)).toBeNull();
    expect(addToIp(ip("255.255.255.254"), 1n)).not.toBeNull();
  });
});

describe("hostPart and withHostPart", () => {
  const a = cidr("192.0.2.0/24");
  const b = cidr("198.51.100.0/24");

  it("maps the same host part between two prefixes", () => {
    const offset = hostPart(a, ip("192.0.2.41"));
    expect(offset).toBe(41n);
    expect(formatIp(withHostPart(b, offset as bigint) as Ip)).toBe("198.51.100.41");
  });

  it("returns null outside the prefix", () => {
    expect(hostPart(a, ip("198.51.100.41"))).toBeNull();
    expect(hostPart(a, ip("2001:db8::29"))).toBeNull();
    expect(withHostPart(a, 256n)).toBeNull();
    expect(withHostPart(a, -1n)).toBeNull();
  });

  it("covers the first and last offsets", () => {
    expect(formatIp(withHostPart(a, 0n) as Ip)).toBe("192.0.2.0");
    expect(formatIp(withHostPart(a, 255n) as Ip)).toBe("192.0.2.255");
    expect(hostPart(a, ip("192.0.2.0"))).toBe(0n);
    expect(hostPart(a, ip("192.0.2.255"))).toBe(255n);
    const v6 = cidr("2001:db8:0:1::/64");
    expect(formatIp(withHostPart(v6, 0x1234n) as Ip)).toBe("2001:db8:0:1::1234");
    expect(withHostPart(v6, 1n << 64n)).toBeNull();
  });
});

describe("rangeSize", () => {
  it("counts addresses inclusively", () => {
    expect(rangeSize(ip("192.0.2.10"), ip("192.0.2.10"))).toBe(1n);
    expect(rangeSize(ip("192.0.2.10"), ip("192.0.2.19"))).toBe(10n);
    expect(rangeSize(ip("2001:db8::"), ip("2001:db8::ffff"))).toBe(0x10000n);
  });

  it("is zero for an empty or mixed range", () => {
    expect(rangeSize(ip("192.0.2.19"), ip("192.0.2.10"))).toBe(0n);
    expect(rangeSize(ip("192.0.2.1"), ip("::2"))).toBe(0n);
  });
});

describe("isNibbleAligned", () => {
  it("accepts IPv6 lengths that are a multiple of 4", () => {
    expect(isNibbleAligned(cidr("2001:db8::/48"))).toBe(true);
    expect(isNibbleAligned(cidr("2001:db8::/32"))).toBe(true);
    expect(isNibbleAligned(cidr("2001:db8::/64"))).toBe(true);
    expect(isNibbleAligned(cidr("2001:db8::/128"))).toBe(true);
  });

  it("rejects other IPv6 lengths", () => {
    expect(isNibbleAligned(cidr("2001:db8::/50"))).toBe(false);
    expect(isNibbleAligned(cidr("2001:db8::/47"))).toBe(false);
    expect(isNibbleAligned(cidr("2001:db8::/33"))).toBe(false);
  });

  it("is always true for IPv4", () => {
    expect(isNibbleAligned(cidr("192.0.2.0/24"))).toBe(true);
    expect(isNibbleAligned(cidr("192.0.2.0/25"))).toBe(true);
    expect(isNibbleAligned(cidr("192.0.2.1/32"))).toBe(true);
  });
});

describe("ipSortKey", () => {
  it("sorts with plain string comparison", () => {
    const texts = ["2001:db8::1", "10.0.0.2", "192.0.2.10", "::1", "192.0.2.9", "255.255.255.255", "2001:db8::", "0.0.0.0"];
    const bySortKey = [...texts].sort((a, b) => {
      const ka = ipSortKey(ip(a));
      const kb = ipSortKey(ip(b));
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    const byCompare = [...texts].sort((a, b) => compareIp(ip(a), ip(b)));
    expect(bySortKey).toEqual(byCompare);
    expect(bySortKey[0]).toBe("0.0.0.0");
    expect(bySortKey[bySortKey.length - 1]).toBe("2001:db8::1");
  });

  it("uses a version prefix and fixed-width lowercase hex", () => {
    expect(ipSortKey(ip("192.0.2.1"))).toBe("4:c0000201");
    expect(ipSortKey(ip("0.0.0.0"))).toBe("4:00000000");
    expect(ipSortKey(ip("::1"))).toBe(`6:${"0".repeat(31)}1`);
    expect(ipSortKey(ip("2001:DB8::A"))).toBe("6:20010db800000000000000000000000a");
  });
});

describe("freeSubnets", () => {
  it("finds the next free /26 around a taken /25", () => {
    const parent = cidr("203.0.113.0/24");
    const taken = [cidr("203.0.113.0/25")];
    expect(take(freeSubnets(parent, 26, taken), 1)).toEqual(["203.0.113.128/26"]);
    expect(take(freeSubnets(parent, 26, taken), 10)).toEqual(["203.0.113.128/26", "203.0.113.192/26"]);
  });

  it("searches from the highest end", () => {
    const parent = cidr("203.0.113.0/24");
    const taken = [cidr("203.0.113.0/25")];
    expect(take(freeSubnets(parent, 26, taken, "highest"), 1)).toEqual(["203.0.113.192/26"]);
    expect(take(freeSubnets(parent, 26, taken, "highest"), 10)).toEqual(["203.0.113.192/26", "203.0.113.128/26"]);
    expect(take(freeSubnets(parent, 26, [cidr("203.0.113.192/27")], "highest"), 2)).toEqual([
      "203.0.113.128/26",
      "203.0.113.64/26",
    ]);
  });

  it("yields every child of an empty parent in order", () => {
    const parent = cidr("203.0.113.0/24");
    expect(take(freeSubnets(parent, 26, []), 10)).toEqual([
      "203.0.113.0/26",
      "203.0.113.64/26",
      "203.0.113.128/26",
      "203.0.113.192/26",
    ]);
    expect(take(freeSubnets(parent, 26, [], "highest"), 10)).toEqual([
      "203.0.113.192/26",
      "203.0.113.128/26",
      "203.0.113.64/26",
      "203.0.113.0/26",
    ]);
    expect(take(freeSubnets(parent, 24, []), 10)).toEqual(["203.0.113.0/24"]);
    expect(take(freeSubnets(parent, 24, [], "highest"), 10)).toEqual(["203.0.113.0/24"]);
  });

  it("skips blocks that only partly overlap a taken prefix", () => {
    const parent = cidr("203.0.113.0/24");
    const taken = [cidr("203.0.113.70/32"), cidr("203.0.113.130/31")];
    expect(take(freeSubnets(parent, 26, taken), 10)).toEqual(["203.0.113.0/26", "203.0.113.192/26"]);
    expect(take(freeSubnets(parent, 26, taken, "highest"), 10)).toEqual(["203.0.113.192/26", "203.0.113.0/26"]);
  });

  it("yields nothing when the parent is full", () => {
    const parent = cidr("203.0.113.0/24");
    expect(take(freeSubnets(parent, 26, [parent]), 10)).toEqual([]);
    expect(take(freeSubnets(parent, 26, [cidr("203.0.0.0/16")], "highest"), 10)).toEqual([]);
    expect(take(freeSubnets(parent, 26, [cidr("203.0.113.0/25"), cidr("203.0.113.128/25")]), 10)).toEqual([]);
    expect(take(freeSubnets(parent, 26, [cidr("203.0.113.0/25"), cidr("203.0.113.128/25")], "highest"), 10)).toEqual([]);
  });

  it("yields nothing for an impossible length", () => {
    const parent = cidr("203.0.113.0/24");
    expect(take(freeSubnets(parent, 23, []), 10)).toEqual([]);
    expect(take(freeSubnets(parent, 33, []), 10)).toEqual([]);
    expect(take(freeSubnets(parent, 26.5, []), 10)).toEqual([]);
    expect(take(freeSubnets(cidr("2001:db8::/32"), 129, [], "highest"), 10)).toEqual([]);
  });

  it("ignores taken prefixes of the other version or outside the parent", () => {
    const parent = cidr("203.0.113.0/24");
    const taken = [cidr("2001:db8::/32"), cidr("198.51.100.0/24"), cidr("203.0.114.0/25")];
    expect(take(freeSubnets(parent, 25, taken), 10)).toEqual(["203.0.113.0/25", "203.0.113.128/25"]);
  });

  it("sorts and merges unsorted, duplicate and nested taken prefixes", () => {
    const parent = cidr("203.0.113.0/24");
    const taken = [
      cidr("203.0.113.128/26"),
      cidr("203.0.113.0/25"),
      cidr("203.0.113.0/26"),
      cidr("203.0.113.128/26"),
      cidr("203.0.113.64/27"),
    ];
    expect(take(freeSubnets(parent, 26, taken), 10)).toEqual(["203.0.113.192/26"]);
    expect(take(freeSubnets(parent, 26, taken, "highest"), 10)).toEqual(["203.0.113.192/26"]);
  });

  it("works from the very start and end of the IPv4 space", () => {
    const all = cidr("0.0.0.0/0");
    expect(take(freeSubnets(all, 8, []), 2)).toEqual(["0.0.0.0/8", "1.0.0.0/8"]);
    expect(take(freeSubnets(all, 8, [], "highest"), 2)).toEqual(["255.0.0.0/8", "254.0.0.0/8"]);
    expect(take(freeSubnets(all, 8, [cidr("0.0.0.0/7")]), 1)).toEqual(["2.0.0.0/8"]);
    expect(take(freeSubnets(all, 8, [cidr("254.0.0.0/7")], "highest"), 1)).toEqual(["253.0.0.0/8"]);
  });

  it("steps over taken ranges in a large IPv6 space without enumerating it", () => {
    const parent = cidr("2001:db8::/32");
    const taken = [cidr("2001:db8::/64"), cidr("2001:db8:0:1::/64")];
    const started = performance.now();
    expect(take(freeSubnets(parent, 64, taken), 3)).toEqual([
      "2001:db8:0:2::/64",
      "2001:db8:0:3::/64",
      "2001:db8:0:4::/64",
    ]);
    expect(performance.now() - started).toBeLessThan(500);
  });

  it("searches the highest end of a large IPv6 space", () => {
    const parent = cidr("2001:db8::/32");
    const taken = [cidr("2001:db8:ffff:ffff::/64"), cidr("2001:db8:ffff:fffe::/63")];
    const started = performance.now();
    expect(take(freeSubnets(parent, 64, taken, "highest"), 2)).toEqual([
      "2001:db8:ffff:fffd::/64",
      "2001:db8:ffff:fffc::/64",
    ]);
    expect(performance.now() - started).toBeLessThan(500);
  });

  it("jumps over a huge taken prefix in a large IPv6 space", () => {
    const parent = cidr("2001:db8::/32");
    const taken = [cidr("2001:db8::/33")];
    const started = performance.now();
    expect(take(freeSubnets(parent, 64, taken), 1)).toEqual(["2001:db8:8000::/64"]);
    expect(take(freeSubnets(parent, 64, [cidr("2001:db8:8000::/33")], "highest"), 1)).toEqual([
      "2001:db8:7fff:ffff::/64",
    ]);
    expect(performance.now() - started).toBeLessThan(500);
  });

  it("is lazy", () => {
    const generator = freeSubnets(cidr("2001:db8::/32"), 64, []);
    expect(generator.next().value).toEqual(cidr("2001:db8::/64"));
    expect(generator.next().value).toEqual(cidr("2001:db8:0:1::/64"));
  });
});

describe("normalizeIp and normalizeCidr", () => {
  it("normalizes valid input", () => {
    expect(normalizeIp("2001:0DB8:0:0:0:0:0:1")).toBe("2001:db8::1");
    expect(normalizeIp(" 192.0.2.1 ")).toBe("192.0.2.1");
    expect(normalizeCidr("2001:0DB8:0:0:0:0:0:0/32")).toBe("2001:db8::/32");
    expect(normalizeCidr("192.0.2.0/24")).toBe("192.0.2.0/24");
    expect(normalizeCidr("192.0.2.7")).toBe("192.0.2.7/32");
  });

  it("returns invalid input unchanged", () => {
    expect(normalizeIp("192.0.2.256")).toBe("192.0.2.256");
    expect(normalizeIp("")).toBe("");
    expect(normalizeIp("host.example.com")).toBe("host.example.com");
    expect(normalizeCidr("192.0.2.1/24")).toBe("192.0.2.1/24");
    expect(normalizeCidr("192.0.2.0/33")).toBe("192.0.2.0/33");
    expect(normalizeCidr("not a prefix")).toBe("not a prefix");
  });
});
