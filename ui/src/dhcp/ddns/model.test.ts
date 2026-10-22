// The pure helpers of the DDNS settings: the draft of a form and the settings it stands for, the
// comparison that finds nothing changed, the server's field errors, the forward zones and the rule
// of the security profile for a zone.
import { describe, expect, it } from "vitest";
import {
  ddnsFieldErrors,
  ddnsOfDraft,
  draftOfDdns,
  isForwardZone,
  namesDdns,
  normalizedDdns,
  profileOpensZones,
  sameDdns,
  TTL_MAX,
  zoneTakesDhcp,
} from "./model";

describe("the draft of DDNS settings", () => {
  it("reads absent fields as the defaults of the model", () => {
    expect(draftOfDdns(undefined)).toEqual({ enabled: false, zone: "", reverse: true, ttl: "", conflict: "protect", clientMayUpdateA: false, legacyClients: true, refuseForeign: false });
    expect(draftOfDdns({})).toEqual(draftOfDdns(null));
  });

  it("reads every field", () => {
    const draft = draftOfDdns({ enabled: true, forward_zone: "z1", reverse: false, ttl: 300, conflict: "replace", client_may_update_a: true, legacy_clients: false, refuse_foreign: true });
    expect(draft).toEqual({ enabled: true, zone: "z1", reverse: false, ttl: "300", conflict: "replace", clientMayUpdateA: true, legacyClients: false, refuseForeign: true });
  });

  it("writes every switch out, and the zone and the TTL only when they are set", () => {
    expect(ddnsOfDraft(draftOfDdns({ enabled: true }))).toEqual({
      ok: true,
      ddns: { enabled: true, reverse: true, conflict: "protect", client_may_update_a: false, legacy_clients: true, refuse_foreign: false },
    });
    const full = ddnsOfDraft({ ...draftOfDdns({ enabled: true }), zone: "z1", ttl: " 300 " });
    expect(full.ok && full.ddns).toMatchObject({ forward_zone: "z1", ttl: 300 });
  });

  it("checks the TTL: a whole number from 1 to 2147483647, or empty", () => {
    const base = draftOfDdns({ enabled: true });
    for (const bad of ["abc", "0", "-5", "1.5", "2147483648", "12345678901", "3 0"]) expect(ddnsOfDraft({ ...base, ttl: bad })).toEqual({ ok: false, field: "ttl", problem: "ttl" });
    for (const good of ["", "1", String(TTL_MAX), "604800"]) expect(ddnsOfDraft({ ...base, ttl: good }).ok).toBe(true);
  });
});

describe("comparing settings", () => {
  it("treats an absent field and its default as the same", () => {
    expect(sameDdns({}, undefined)).toBe(true);
    expect(sameDdns({}, { enabled: false, reverse: true, conflict: "protect", legacy_clients: true })).toBe(true);
    expect(sameDdns({ enabled: true }, { enabled: true, ttl: null, forward_zone: null })).toBe(true);
  });

  it("sees a change in any field", () => {
    const base = { enabled: true };
    for (const changed of [{ enabled: false }, { forward_zone: "z1" }, { reverse: false }, { ttl: 60 }, { conflict: "replace" as const }, { client_may_update_a: true }, { legacy_clients: false }, { refuse_foreign: true }]) {
      expect(sameDdns(base, { ...base, ...changed })).toBe(false);
    }
  });

  it("normalizes to every default written out", () => {
    expect(normalizedDdns(undefined)).toEqual({ enabled: false, reverse: true, conflict: "protect", client_may_update_a: false, legacy_clients: true, refuse_foreign: false });
  });
});

describe("the server's errors by field", () => {
  const fields = { "ddns.ttl": "too long", "ddns.conflict": "no", name: "x", ddns: "general" };

  it("names the fields under a prefix", () => {
    expect(ddnsFieldErrors(fields, "ddns")).toEqual({ ttl: "too long", conflict: "no" });
    expect(ddnsFieldErrors({ "action.ddns.ttl": "too long" }, "action.ddns")).toEqual({ ttl: "too long" });
    expect(ddnsFieldErrors({ name: "x" }, "ddns")).toEqual({});
  });

  it("tells whether a refusal names the settings", () => {
    expect(namesDdns(fields, "ddns")).toBe(true);
    expect(namesDdns({ name: "x" }, "ddns")).toBe(false);
    expect(namesDdns({ "action.range": "x" }, "action.ddns")).toBe(false);
  });
});

describe("zones and the profile", () => {
  it("takes the primary zones that are not reverse zones as forward zones", () => {
    expect(isForwardZone({ kind: "primary", name: "example.test" })).toBe(true);
    expect(isForwardZone({ kind: "primary", name: "2.0.192.in-addr.arpa" })).toBe(false);
    expect(isForwardZone({ kind: "primary", name: "8.b.d.0.1.0.0.2.ip6.arpa." })).toBe(false);
    expect(isForwardZone({ kind: "primary", name: "lan.example.test", reverse_of: "p1" })).toBe(false);
    expect(isForwardZone({ kind: "secondary", name: "lab.example.test" })).toBe(false);
    expect(isForwardZone({ kind: "forward", name: "corp.example.test" })).toBe(false);
  });

  it("lets Home and Lab take DHCP updates unless a zone says no, and Standard and Hardened only a zone that says yes", () => {
    expect([profileOpensZones("home"), profileOpensZones("lab"), profileOpensZones("standard"), profileOpensZones("hardened")]).toEqual([true, true, false, false]);
    expect(zoneTakesDhcp(undefined, "home")).toBe("profile_on");
    expect(zoneTakesDhcp({ dhcp: null }, "lab")).toBe("profile_on");
    expect(zoneTakesDhcp({}, "standard")).toBe("profile_off");
    expect(zoneTakesDhcp({ dhcp: true }, "hardened")).toBe("on");
    expect(zoneTakesDhcp({ dhcp: false }, "home")).toBe("off");
  });
});
