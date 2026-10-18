// The pure helpers of the views page: the rule drafts and their checks per test, the time of
// day, the scope map with its weights and shares, the whole-view check, the order and the
// positions a move or a drop asks for.
import { describe, expect, it } from "vitest";
import {
  checkView,
  draftOf,
  droppedAt,
  emptyDraft,
  minuteText,
  movedTo,
  parseMinute,
  parseRule,
  parseScopes,
  ruleValues,
  shares,
  viewOrder,
  type RuleDraft,
} from "./model";

const draft = (kind: RuleDraft["kind"], text: string): RuleDraft => ({ ...emptyDraft(kind), text });

describe("the rules", () => {
  it("reads every list test from its typed values", () => {
    expect(parseRule(draft("client_subnet", "192.0.2.0/24, 2001:DB8::/32\n192.0.2.0/24"))).toEqual({
      ok: true,
      rule: { test: "client_subnet", prefixes: ["192.0.2.0/24", "2001:db8::/32"] },
    });
    expect(parseRule(draft("interface", "192.0.2.53 2001:db8::53"))).toEqual({ ok: true, rule: { test: "interface", addresses: ["192.0.2.53", "2001:db8::53"] } });
    expect(parseRule(draft("qtype", "a aaaa TYPE65"))).toEqual({ ok: true, rule: { test: "qtype", types: ["A", "AAAA", "TYPE65"] } });
    expect(parseRule(draft("qname", "Example.Test. lab.example.test"))).toEqual({ ok: true, rule: { test: "qname", suffixes: ["example.test", "lab.example.test"] } });
  });

  it("names the first value a test refuses", () => {
    expect(parseRule(draft("client_subnet", "192.0.2.0/24 192.0.2.0/33"))).toEqual({ ok: false, problem: "prefix", entry: "192.0.2.0/33" });
    expect(parseRule(draft("interface", "host"))).toEqual({ ok: false, problem: "address", entry: "host" });
    expect(parseRule(draft("qtype", "A 1x"))).toEqual({ ok: false, problem: "type", entry: "1X" });
    expect(parseRule(draft("qname", "bad..name"))).toEqual({ ok: false, problem: "name", entry: "bad..name" });
    expect(parseRule(draft("qname", " "))).toEqual({ ok: false, problem: "empty" });
    expect(parseRule(draft("client_subnet", Array.from({ length: 1001 }, (_, i) => `198.51.${i >> 8}.${i & 255}/32`).join(" ")))).toEqual({ ok: false, problem: "too_many" });
  });

  it("keeps the transports in their order and refuses none", () => {
    expect(parseRule({ ...emptyDraft("transport"), transports: ["doh", "udp"] })).toEqual({ ok: true, rule: { test: "transport", transports: ["udp", "doh"] } });
    expect(parseRule({ ...emptyDraft("transport"), transports: [] })).toEqual({ ok: false, problem: "empty" });
    expect(emptyDraft("transport").transports).toEqual(["dot", "doh"]);
  });

  it("reads a time window, one that wraps midnight too", () => {
    expect(parseRule({ ...emptyDraft("time_of_day"), from: "22:00", to: "6:30" })).toEqual({ ok: true, rule: { test: "time_of_day", from_minute: 1320, to_minute: 390 } });
    expect(parseRule({ ...emptyDraft("time_of_day"), from: "24:00", to: "01:00" })).toEqual({ ok: false, problem: "time", entry: "24:00" });
    expect(parseMinute("23:59")).toBe(1439);
    expect(parseMinute("12:60")).toBeNull();
    expect(parseMinute("noon")).toBeNull();
    expect(minuteText(0)).toBe("00:00");
    expect(minuteText(1439)).toBe("23:59");
  });

  it("turns a rule back into its draft", () => {
    expect(draftOf({ test: "client_subnet", prefixes: ["192.0.2.0/24", "198.51.100.0/24"] }).text).toBe("192.0.2.0/24\n198.51.100.0/24");
    expect(draftOf({ test: "transport", transports: ["tcp"] }).transports).toEqual(["tcp"]);
    expect(draftOf({ test: "time_of_day", from_minute: 480, to_minute: 1020 })).toMatchObject({ from: "08:00", to: "17:00" });
    expect(ruleValues({ test: "time_of_day", from_minute: 1, to_minute: 2 })).toEqual([]);
  });
});

describe("the scope map", () => {
  it("reads zone, scope and weight and refuses a weight out of range or a scope twice", () => {
    expect(parseScopes([{ zone: "z1", scope: "internal", weight: " 700 " }, { zone: "z1", scope: "external", weight: "300" }])).toEqual({
      ok: true,
      map: [
        { zone: "z1", scope: "internal", weight: 700 },
        { zone: "z1", scope: "external", weight: 300 },
      ],
    });
    expect(parseScopes([{ zone: "z1", scope: "internal", weight: "0" }])).toEqual({ ok: false, index: 0, problem: "weight" });
    expect(parseScopes([{ zone: "z1", scope: "internal", weight: "1001" }])).toEqual({ ok: false, index: 0, problem: "weight" });
    expect(parseScopes([{ zone: "z1", scope: "internal", weight: "1.5" }])).toEqual({ ok: false, index: 0, problem: "weight" });
    expect(parseScopes([{ zone: "", scope: "", weight: "1" }])).toEqual({ ok: false, index: 0, problem: "zone" });
    expect(
      parseScopes([
        { zone: "z1", scope: "internal", weight: "1" },
        { zone: "z1", scope: "internal", weight: "2" },
      ]),
    ).toEqual({ ok: false, index: 1, problem: "twice" });
  });

  it("gives each weight its share among the scopes of its zone", () => {
    expect(
      shares([
        { zone: "z1", scope: "internal", weight: 700 },
        { zone: "z1", scope: "external", weight: 300 },
        { zone: "z2", scope: "default", weight: 5 },
      ]),
    ).toEqual([70, 30, 100]);
    expect(shares([])).toEqual([]);
  });
});

describe("a whole view", () => {
  it("passes a view without rules and scopes, trimmed", () => {
    expect(checkView({ name: "  everyone ", rules: [], scopes: [], description: " last " })).toEqual({ ok: true, name: "everyone", rules: [], scopeMap: [], description: "last" });
  });

  it("names the first problem of every field", () => {
    const checked = checkView({
      name: "",
      rules: [draft("client_subnet", "192.0.2.0/24"), draft("interface", "nope"), draft("qname", "")],
      scopes: [{ zone: "z1", scope: "internal", weight: "2000" }],
      description: "d".repeat(1001),
    });
    expect(checked.ok).toBe(false);
    if (checked.ok) return;
    expect(checked.problems).toEqual([
      { field: "name", problem: "required" },
      { field: "rules", index: 1, problem: "address", entry: "nope" },
      { field: "scope_map", index: 0, problem: "weight" },
      { field: "description", problem: "long" },
    ]);
    const long = checkView({ name: "x".repeat(65), rules: Array.from({ length: 33 }, () => draft("qtype", "A")), scopes: [], description: "" });
    expect(long.ok ? [] : long.problems.map((p) => [p.field, p.problem])).toEqual([
      ["name", "long"],
      ["rules", "too_many_rules"],
    ]);
  });
});

describe("the order", () => {
  const views = [
    { id: "b", order: 2 },
    { id: "a", order: 1 },
    { id: "c", order: 2 },
  ].sort(viewOrder);

  it("sorts by order, then identifier", () => {
    expect(views.map((v) => v.id)).toEqual(["a", "b", "c"]);
  });

  it("asks for the next position up or down, none past an end", () => {
    expect(movedTo(views, "b", -1)).toBe(1);
    expect(movedTo(views, "b", 1)).toBe(3);
    expect(movedTo(views, "a", -1)).toBeUndefined();
    expect(movedTo(views, "c", 1)).toBeUndefined();
    expect(movedTo(views, "x", 1)).toBeUndefined();
  });

  it("asks for the place of the view a drag ends on", () => {
    expect(droppedAt(views, "c", "a")).toBe(1);
    expect(droppedAt(views, "a", "c")).toBe(3);
    expect(droppedAt(views, "a", "a")).toBeUndefined();
  });
});
