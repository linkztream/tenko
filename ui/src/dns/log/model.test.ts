// The pure parts of the query log page and the log of the mock: the filter checks, the query a
// form makes, the client kinds and RCODE names; the mock's reader with its cursor and filters.
import { describe, expect, it } from "vitest";
import { logStatus, readLog, seedDnsLog, switchLog, DnsLogFailure } from "../../api/mock/dns-log-model";
import { checkFilters, clientKind, NO_FILTERS, PAGE_SIZE, rcodeName, toQuery } from "./model";

describe("the filter form", () => {
  it("accepts names, pseudonyms and addresses and refuses the rest", () => {
    expect(checkFilters({ ...NO_FILTERS, qname: "example.test.", client: "p:3f2a9c0d81b7e645" })).toEqual([]);
    expect(checkFilters({ ...NO_FILTERS, client: "192.0.2.10" })).toEqual([]);
    expect(checkFilters({ ...NO_FILTERS, client: "2001:db8::20" })).toEqual([]);
    expect(checkFilters({ ...NO_FILTERS, client: "192.0.2.300" })).toEqual(["client"]);
    expect(checkFilters({ ...NO_FILTERS, client: "p:xyz" })).toEqual(["client"]);
    expect(checkFilters({ ...NO_FILTERS, qname: "two words" })).toEqual(["qname"]);
    expect(checkFilters({ ...NO_FILTERS, from: "2026-10-17T12:30", until: "2026-10-17T12:00" })).toEqual(["until"]);
  });

  it("sends only the fields that are set, the end of the window through its whole minute", () => {
    expect(toQuery(NO_FILTERS, undefined)).toEqual({ limit: PAGE_SIZE });
    const query = toQuery({ qname: " example.test ", client: "", rcode: "3", from: "2026-10-17T12:00", until: "2026-10-17T12:00" }, "m:10");
    expect(query.cursor).toBe("m:10");
    expect(query.qname).toBe("example.test");
    expect(query.rcode).toBe(3);
    expect(query.client).toBeUndefined();
    expect(Date.parse(query.until ?? "") - Date.parse(query.from ?? "")).toBe(59_999);
  });

  it("names RCODEs and client kinds", () => {
    expect(rcodeName(3)).toBe("NXDOMAIN");
    expect(rcodeName(23)).toBe("23");
    expect(clientKind({ client: "p:3f2a9c0d81b7e645" })).toBe("pseudonym");
    expect(clientKind({ client: "192.0.2.10" })).toBe("address");
    expect(clientKind({ client: null })).toBe("hidden");
    expect(clientKind({})).toBe("hidden");
  });
});

describe("the mock's query log", () => {
  it("reads newest first with a cursor to the end", () => {
    const state = seedDnsLog();
    const first = readLog(state, { limit: "25" }, true, 1);
    expect(first.items).toHaveLength(25);
    expect(first.items[0]?.at).toBe("2026-10-17T12:00:59.000Z");
    const second = readLog(state, { limit: "25", cursor: first.next_cursor }, true, 1);
    const third = readLog(state, { limit: "25", cursor: second.next_cursor }, true, 1);
    expect(third.items).toHaveLength(10);
    expect(third.next_cursor).toBeNull();
  });

  it("finds an address by its pseudonym, and by its address only for those who may update the node", () => {
    const state = seedDnsLog();
    const byPseudonym = readLog(state, { client: "p:3f2a9c0d81b7e645" }, false, 1);
    expect(byPseudonym.items).toHaveLength(20);
    expect(readLog(state, { client: "192.0.2.10" }, true, 1).items).toHaveLength(20);
    expect(() => readLog(state, { client: "192.0.2.10" }, false, 1)).toThrow(DnsLogFailure);
    state.client = "address";
    expect(readLog(state, { limit: "1" }, false, 1).items[0]?.client).toBeUndefined();
    expect(readLog(state, { limit: "1" }, true, 1).items[0]?.client).toBe("2001:db8::20");
  });

  it("switches and reports the log, and refuses everything while it is off", () => {
    const state = seedDnsLog();
    switchLog(state, true);
    expect(logStatus(state)?.state).toBe("stopped");
    state.mode = "off";
    expect(logStatus(state)).toBeUndefined();
    expect(() => readLog(state, {}, true, 1)).toThrow(DnsLogFailure);
    expect(() => switchLog(state, false)).toThrow(DnsLogFailure);
  });
});
