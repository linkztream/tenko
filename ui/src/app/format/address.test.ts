import { describe, expect, it } from "vitest";
import { splitAddress, splitMac } from "./address";

describe("splitAddress", () => {
  it("splits IPv4 at the /24 boundary by default", () => {
    expect(splitAddress("192.0.2.41")).toEqual({ net: "192.0.2.", host: "41", len: "" });
  });
  it("follows the prefix length of the text or the argument", () => {
    expect(splitAddress("198.51.100.0/24")).toEqual({ net: "198.51.100.", host: "0", len: "/24" });
    expect(splitAddress("203.0.113.130", 16)).toEqual({ net: "203.0.", host: "113.130", len: "" });
    expect(splitAddress("203.0.113.128/26")).toEqual({ net: "203.0.113.", host: "128", len: "/26" });
  });
  it("splits IPv6 at the compressed zeros or after 64 bits", () => {
    expect(splitAddress("2001:db8::1")).toEqual({ net: "2001:db8::", host: "1", len: "" });
    expect(splitAddress("2001:db8:0:1:0:0:0:2a")).toEqual({ net: "2001:db8:0:1:", host: "0:0:0:2a", len: "" });
    expect(splitAddress("2001:db8::/32")).toEqual({ net: "2001:db8::", host: "", len: "/32" });
  });
  it("returns anything else as host", () => {
    expect(splitAddress("nas.example.test")).toEqual({ net: "", host: "nas.example.test", len: "" });
  });
});

describe("splitMac", () => {
  it("separates the vendor part", () => {
    expect(splitMac("00-00-5E-00-53-29")).toEqual({ oui: "00-00-5E-", rest: "00-53-29" });
    expect(splitMac("00:00:5e:00:53:2a")).toEqual({ oui: "00:00:5e:", rest: "00:53:2a" });
  });
  it("leaves other text alone", () => {
    expect(splitMac("unknown")).toEqual({ oui: "", rest: "unknown" });
  });
});
