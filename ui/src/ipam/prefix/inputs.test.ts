import { describe, expect, it } from "vitest";
import { parseCidr } from "../ip";
import { addressIn, checkAlarm, checkNetwork, networkHint } from "./inputs";

describe("checkNetwork", () => {
  it("accepts IPv4 and IPv6 networks in CIDR form", () => {
    expect(checkNetwork("192.0.2.0/24")).toMatchObject({ ok: true, cidr: { version: 4, length: 24 } });
    expect(checkNetwork(" 2001:db8:0:40::/62 ")).toMatchObject({ ok: true, cidr: { version: 6, length: 62 } });
  });
  it("asks for the network when there is no text", () => {
    expect(checkNetwork("")).toEqual({ ok: false, reason: "empty" });
    expect(checkNetwork("   ")).toEqual({ ok: false, reason: "empty" });
  });
  it("refuses what is not CIDR, also an address without a length", () => {
    for (const text of ["192.0.2.0", "192.0.2.0/33", "192.0.2/24", "nonsense", "2001:db8::/129", "192.0.2.0/24/1"]) {
      expect(checkNetwork(text)).toEqual({ ok: false, reason: "invalid" });
    }
  });
  it("names the network when host bits are set", () => {
    expect(checkNetwork("198.51.100.77/26")).toEqual({ ok: false, reason: "host_bits", given: "198.51.100.77/26", network: "198.51.100.64/26" });
    expect(checkNetwork("2001:db8:0:41::/62")).toEqual({ ok: false, reason: "host_bits", given: "2001:db8:0:41::/62", network: "2001:db8:0:40::/62" });
  });
});

describe("networkHint", () => {
  it("is the part of the parent that every child shares, up to a group boundary", () => {
    expect(networkHint("203.0.113.0/24")).toBe("203.0.113.");
    expect(networkHint("10.0.0.0/8")).toBe("10.");
    expect(networkHint("192.0.2.0/23")).toBe("192.0.");
    expect(networkHint("2001:db8::/32")).toBe("2001:db8:");
    expect(networkHint("2001:db8:0:10::/60")).toBe("2001:db8:0:");
  });
  it("is empty without a parent, for a parent too short to say anything and for text that is no network", () => {
    expect(networkHint(undefined)).toBe("");
    expect(networkHint("")).toBe("");
    expect(networkHint("0.0.0.0/0")).toBe("");
    expect(networkHint("::/8")).toBe("");
    expect(networkHint("nonsense")).toBe("");
  });
});

describe("checkAlarm", () => {
  it("is no alarm when both thresholds are empty", () => {
    expect(checkAlarm("", "")).toEqual({ ok: true, alarm: null });
    expect(checkAlarm(" ", " ")).toEqual({ ok: true, alarm: null });
  });
  it("takes two percentages with the warning below the critical one", () => {
    expect(checkAlarm("80", "95")).toEqual({ ok: true, alarm: { warn_pct: 80, crit_pct: 95 } });
    expect(checkAlarm("1", "100")).toEqual({ ok: true, alarm: { warn_pct: 1, crit_pct: 100 } });
  });
  it("wants both, in range, in order", () => {
    expect(checkAlarm("80", "")).toEqual({ ok: false, crit: "required" });
    expect(checkAlarm("", "90")).toEqual({ ok: false, warn: "required" });
    expect(checkAlarm("0", "50")).toEqual({ ok: false, warn: "range" });
    expect(checkAlarm("50", "101")).toEqual({ ok: false, crit: "range" });
    expect(checkAlarm("5.5", "x")).toEqual({ ok: false, warn: "range", crit: "range" });
    expect(checkAlarm("90", "90")).toEqual({ ok: false, crit: "order" });
    expect(checkAlarm("95", "80")).toEqual({ ok: false, crit: "order" });
  });
});

describe("addressIn", () => {
  const net = parseCidr("192.0.2.0/24");
  if (!net) throw new Error("the test network does not parse");
  it("tells an address inside from one outside and from text that is no address", () => {
    expect(addressIn(net, "192.0.2.77")).toBe("ok");
    expect(addressIn(net, "192.0.2.255")).toBe("ok");
    expect(addressIn(net, "192.0.3.1")).toBe("outside");
    expect(addressIn(net, "2001:db8::1")).toBe("outside");
    expect(addressIn(net, "192.0.2.300")).toBe("invalid");
    expect(addressIn(net, "")).toBe("invalid");
  });
});
