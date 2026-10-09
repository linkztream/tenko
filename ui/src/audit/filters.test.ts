import { describe, expect, it } from "vitest";
import {
  checkAction,
  checkObject,
  checkPrincipal,
  checkTime,
  filterState,
  isSubject,
  readFilters,
  toLocalInput,
  toRfc3339,
} from "./filters";

const UUID = "0190d1c2-0000-7000-8000-00000000a001";

describe("reading the filters from the URL", () => {
  it("takes the first value of a repeated parameter and skips empty ones", () => {
    expect(readFilters({ action: ["ipam.", "auth."], outcome: "", order: "asc", other: "x" })).toEqual({
      action: "ipam.",
      order: "asc",
    });
  });
});

describe("action filter", () => {
  it("accepts a full action and a group that ends with a dot", () => {
    for (const ok of ["ipam.prefix.create", "auth.login.failure", "ipam.", "ipam.prefix.", "IPAM.Prefix."]) {
      expect(checkAction(ok), ok).toBeUndefined();
    }
  });

  it("refuses a single word, spaces and odd characters", () => {
    for (const bad of ["ipam", "", "ipam prefix", "ipam..", "ipam.pre fix", "ipam/prefix"]) {
      expect(checkAction(bad), bad).toBe("audit.filter.action_invalid");
    }
  });
});

describe("object filter", () => {
  it("accepts a kind and a kind with the full id", () => {
    expect(checkObject("prefix")).toBeUndefined();
    expect(checkObject("custom_field")).toBeUndefined();
    expect(checkObject(`host:${UUID}`)).toBeUndefined();
    expect(checkObject(`HOST:${UUID.toUpperCase()}`)).toBeUndefined();
  });

  it("refuses an unknown kind and a short or missing id", () => {
    expect(checkObject("printer")).toBe("audit.filter.object_invalid");
    expect(checkObject("host:0190d1c2")).toBe("audit.filter.object_invalid");
    expect(checkObject("host:")).toBe("audit.filter.object_invalid");
  });
});

describe("principal filter", () => {
  it("accepts the subjects of the API", () => {
    for (const ok of [`user:${UUID}`, `token:${UUID}`, "node:3", "system:ipam", "System:Jobs"]) {
      expect(isSubject(ok), ok).toBe(true);
      expect(checkPrincipal(ok), ok).toBeUndefined();
    }
  });

  it("refuses names, other components and short ids", () => {
    for (const bad of ["sam", "user:sam", "user:0190d1c2", "system:nothing", "node:x", "team:ipam"]) {
      expect(isSubject(bad), bad).toBe(false);
      expect(checkPrincipal(bad), bad).toBe("audit.filter.principal_invalid");
    }
  });
});

describe("time filter", () => {
  it("accepts RFC 3339 with a zone and refuses the rest", () => {
    expect(checkTime("2026-10-09T10:00:00Z")).toBeUndefined();
    expect(checkTime("2026-10-09T10:00:00.250+02:00")).toBeUndefined();
    expect(checkTime("2026-10-09T10:00")).toBe("audit.filter.time_invalid");
    expect(checkTime("yesterday")).toBe("audit.filter.time_invalid");
    expect(checkTime("2026-13-45T10:00:00Z")).toBe("audit.filter.time_invalid");
  });

  it("converts between the local input value and RFC 3339 in UTC", () => {
    const rfc = toRfc3339("2026-10-09T12:30");
    expect(rfc).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00Z$/);
    expect(new Date(rfc as string).getTime()).toBe(new Date("2026-10-09T12:30").getTime());
    // The way back shows the same local time whatever the zone of the machine is.
    expect(toLocalInput(rfc)).toBe("2026-10-09T12:30");
  });

  it("gives nothing for an empty or unreadable value", () => {
    expect(toRfc3339("")).toBeUndefined();
    expect(toRfc3339("not a time")).toBeUndefined();
    expect(toLocalInput(undefined)).toBe("");
    expect(toLocalInput("yesterday")).toBe("");
  });
});

describe("the state of the filters", () => {
  it("builds the query from the usable values in the form the API compares", () => {
    const state = filterState({
      from: "2026-10-09T10:00:00Z",
      action: " IPAM. ",
      object: `Host:${UUID}`,
      principal: "system:ipam",
      outcome: "Failed",
      order: "asc",
    });
    expect(state.query).toEqual({
      from: "2026-10-09T10:00:00Z",
      action: "ipam.",
      object: `host:${UUID}`,
      principal: "system:ipam",
      outcome: "failed",
      order: "asc",
    });
    expect(state.problems).toEqual({});
    expect(state.order).toBe("asc");
    expect(state.filtered).toBe(true);
  });

  it("leaves a value the server would refuse out of the query and reports it", () => {
    const state = filterState({ action: "nonsense", outcome: "maybe", from: "yesterday", order: "sideways" });
    expect(state.query).toEqual({});
    expect(state.problems).toEqual({
      action: "audit.filter.action_invalid",
      outcome: "audit.filter.value_invalid",
      from: "audit.filter.time_invalid",
      order: "audit.filter.value_invalid",
    });
    expect(state.filtered).toBe(false);
    expect(state.order).toBe("desc");
  });

  it("does not count the order as a filter, and notices an empty range", () => {
    expect(filterState({ order: "asc" }).filtered).toBe(false);
    const range = filterState({ from: "2026-10-09T10:00:00Z", to: "2026-10-09T09:00:00Z" });
    expect(range.emptyRange).toBe(true);
    expect(filterState({ from: "2026-10-09T09:00:00Z", to: "2026-10-09T10:00:00Z" }).emptyRange).toBe(false);
    // `to` is exclusive: the same instant selects nothing.
    expect(filterState({ from: "2026-10-09T09:00:00Z", to: "2026-10-09T09:00:00Z" }).emptyRange).toBe(true);
  });
});
