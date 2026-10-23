// The pure parts of the trust anchors and the negative trust anchors on the recursion page
// (WP10.4): the path segment of a zone, the order of the zones, the zone a form sends, the key
// counts of an anchor, the shape of a typed DS or DNSKEY, the lifetime of a negative trust
// anchor as people write it, and when one has expired.
import { describe, expect, it } from "vitest";
import {
  ANCHOR_STATES,
  isRootZone,
  keyCounts,
  keyShape,
  NTA_MAX_SECONDS,
  ntaExpired,
  parseLifetime,
  zoneInput,
  zoneOrder,
  zoneSegment,
  type AnchorKey,
  type TrustAnchorItem,
} from "./anchors";

function key(tag: number, state: AnchorKey["state"]): AnchorKey {
  return {
    key_tag: tag,
    algorithm: 8,
    digest_type: 2,
    data: { kind: "ds", rdata: `${tag} 8 2 AB` },
    state,
    state_since: "2026-10-01T00:00:00Z",
    source: { kind: "operator" },
    added_at: "2026-10-01T00:00:00Z",
    last_seen: null,
  };
}

function anchor(zone: string, keys: AnchorKey[]): TrustAnchorItem {
  return { zone, keys, last_query: null, next_query: null, revision: 1 };
}

describe("zoneSegment", () => {
  it("writes the root as root, because a URL turns the segment . into a dot segment", () => {
    expect(zoneSegment(".")).toBe("root");
    expect(zoneSegment("")).toBe("root");
  });

  it("writes a zone named root with a trailing dot, so that it differs from the root", () => {
    expect(zoneSegment("root")).toBe("root.");
    expect(zoneSegment("Root.")).toBe("root.");
  });

  it("writes any other zone in canonical form", () => {
    expect(zoneSegment("Corp.Example.Test.")).toBe("corp.example.test");
    expect(zoneSegment("example.test")).toBe("example.test");
  });
});

describe("isRootZone", () => {
  it("knows the root by its two spellings", () => {
    expect(isRootZone(".")).toBe(true);
    expect(isRootZone("")).toBe(true);
    expect(isRootZone("example.test")).toBe(false);
    expect(isRootZone("root")).toBe(false);
  });
});

describe("zoneOrder", () => {
  it("puts the root first and then the zones label by label from the root", () => {
    const zones = ["sub.example.test", "example.org", ".", "test", "example.test", "corp.example.test"];
    expect([...zones].sort(zoneOrder)).toEqual([".", "example.org", "test", "example.test", "corp.example.test", "sub.example.test"]);
  });

  it("puts a zone before the zones under it and keeps equal zones equal", () => {
    expect(zoneOrder("example.test", "www.example.test")).toBeLessThan(0);
    expect(zoneOrder("www.example.test", "example.test")).toBeGreaterThan(0);
    expect(zoneOrder("example.test", "Example.Test.")).toBe(0);
    expect(zoneOrder(".", ".")).toBe(0);
    expect(zoneOrder(".", "test")).toBeLessThan(0);
    expect(zoneOrder("test", ".")).toBeGreaterThan(0);
  });
});

describe("zoneInput", () => {
  it("takes nothing, a dot or the root as the root", () => {
    expect(zoneInput("")).toBe(".");
    expect(zoneInput("  ")).toBe(".");
    expect(zoneInput(".")).toBe(".");
  });

  it("takes a name in canonical form", () => {
    expect(zoneInput(" Corp.Example.Test. ")).toBe("corp.example.test");
    expect(zoneInput("example.test")).toBe("example.test");
  });

  it("refuses what is not a name and a wildcard", () => {
    expect(zoneInput("not a name")).toBeNull();
    expect(zoneInput("a..b")).toBeNull();
    expect(zoneInput("*.example.test")).toBeNull();
  });
});

describe("keyCounts", () => {
  it("counts the keys that are trusted and those that wait", () => {
    const a = anchor(".", [key(1, "valid"), key(2, "valid"), key(3, "add_pend"), key(4, "revoked"), key(5, "missing")]);
    expect(keyCounts(a)).toEqual({ valid: 2, pending: 1 });
    expect(keyCounts(anchor("example.test", []))).toEqual({ valid: 0, pending: 0 });
  });

  it("lists the states in the order a key goes through them", () => {
    expect(ANCHOR_STATES).toEqual(["start", "add_pend", "valid", "missing", "revoked", "removed"]);
  });
});

describe("keyShape", () => {
  const digest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

  it("accepts a DS record: key tag, algorithm, digest type and a hexadecimal digest", () => {
    expect(keyShape("ds", `20326 8 2 ${digest}`)).toBe(true);
    expect(keyShape("ds", `  20326   8 2 ${digest.toLowerCase()}  `)).toBe(true);
    // The digest may be written in groups, as dig prints it.
    expect(keyShape("ds", "20326 8 2 E06D44B8 0B8F1D39")).toBe(true);
  });

  it("refuses a malformed DS record", () => {
    expect(keyShape("ds", "")).toBe(false);
    expect(keyShape("ds", "20326 8 2")).toBe(false);
    expect(keyShape("ds", `x 8 2 ${digest}`)).toBe(false);
    expect(keyShape("ds", `20326 8 two ${digest}`)).toBe(false);
    expect(keyShape("ds", "20326 8 2 not-hex")).toBe(false);
    // An odd number of hexadecimal digits is not a digest.
    expect(keyShape("ds", "20326 8 2 ABC")).toBe(false);
    expect(keyShape("ds", `123456 8 2 ${digest}`)).toBe(false);
  });

  it("accepts a DNSKEY record: flags, protocol, algorithm and a Base64 key", () => {
    expect(keyShape("dnskey", "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")).toBe(true);
    expect(keyShape("dnskey", "257 3 8 AwEAAa Zm9v YmFy")).toBe(true);
  });

  it("refuses a malformed DNSKEY record", () => {
    expect(keyShape("dnskey", "")).toBe(false);
    expect(keyShape("dnskey", "257 3 15")).toBe(false);
    expect(keyShape("dnskey", "257 three 15 AAAA")).toBe(false);
    expect(keyShape("dnskey", "257 3 15 not*base64")).toBe(false);
  });

  it("does not take one kind of record for the other", () => {
    expect(keyShape("dnskey", `20326 8 2 ${digest}`)).toBe(true);
    expect(keyShape("ds", "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")).toBe(false);
  });
});

describe("parseLifetime", () => {
  it("reads minutes, hours, days and seconds", () => {
    expect(parseLifetime("30m")).toBe(1_800);
    expect(parseLifetime("12h")).toBe(43_200);
    expect(parseLifetime("2d")).toBe(172_800);
    expect(parseLifetime("90s")).toBe(90);
  });

  it("adds the parts of a lifetime written in several units, in any case and with space around", () => {
    expect(parseLifetime("1d12h")).toBe(129_600);
    expect(parseLifetime(" 1D6H30M ")).toBe(86_400 + 6 * 3_600 + 1_800);
  });

  it("takes seven days exactly and no more", () => {
    expect(parseLifetime("7d")).toBe(NTA_MAX_SECONDS);
    expect(parseLifetime("168h")).toBe(NTA_MAX_SECONDS);
    expect(parseLifetime("6d23h59m59s")).toBe(NTA_MAX_SECONDS - 1);
    expect(parseLifetime("8d")).toBeNull();
    expect(parseLifetime("7d1s")).toBeNull();
  });

  it("refuses a lifetime of nothing and what is not a lifetime", () => {
    expect(parseLifetime("0s")).toBeNull();
    expect(parseLifetime("0d0h")).toBeNull();
    expect(parseLifetime("x")).toBeNull();
    expect(parseLifetime("")).toBeNull();
    expect(parseLifetime("12")).toBeNull();
    expect(parseLifetime("h12")).toBeNull();
    expect(parseLifetime("1 d")).toBeNull();
    expect(parseLifetime("-1d")).toBeNull();
    expect(parseLifetime("1.5h")).toBeNull();
  });
});

describe("ntaExpired", () => {
  const at = Date.parse("2026-10-17T12:00:00Z");

  it("has expired from the moment of its expiry on", () => {
    expect(ntaExpired({ expires_at: "2026-10-17T12:00:00Z" }, at)).toBe(true);
    expect(ntaExpired({ expires_at: "2026-10-17T11:59:59Z" }, at)).toBe(true);
    expect(ntaExpired({ expires_at: "2026-10-17T12:00:01Z" }, at)).toBe(false);
    expect(ntaExpired({ expires_at: "2026-10-24T12:00:00Z" }, at)).toBe(false);
  });
});
