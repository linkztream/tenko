import { describe, expect, it } from "vitest";
import { clientKind, hourBars, listName, logIsShort, pauseEnded, pauseState, pct, secondsLeft, share, windowOf } from "./model";

describe("the window", () => {
  it("is 24 hours unless 7 days is asked for", () => {
    expect(windowOf(undefined)).toBe("24h");
    expect(windowOf("7d")).toBe("7d");
    expect(windowOf("1y")).toBe("24h");
    expect(windowOf(["7d"])).toBe("24h");
  });

  it("is short when the log keeps fewer days than the window covers", () => {
    expect(logIsShort("7d", 3)).toBe(true);
    expect(logIsShort("7d", 7)).toBe(false);
    expect(logIsShort("24h", 1)).toBe(false);
    expect(logIsShort("24h", 0)).toBe(true);
  });
});

describe("the pause", () => {
  const until = "2026-10-17T12:15:00Z";
  const at = (text: string) => Date.parse(text);

  it("is on, timed or until resumed", () => {
    expect(pauseState(null)).toBe("on");
    expect(pauseState(undefined)).toBe("on");
    expect(pauseState({ since: "2026-10-17T12:00:00Z", until })).toBe("timed");
    expect(pauseState({ since: "2026-10-17T12:00:00Z" })).toBe("open");
    expect(pauseState({ since: "2026-10-17T12:00:00Z", until: null })).toBe("open");
  });

  it("counts the seconds left and notices the end", () => {
    const pause = { since: "2026-10-17T12:00:00Z", until };
    expect(secondsLeft(pause, at("2026-10-17T12:10:00Z"))).toBe(300);
    expect(secondsLeft(pause, at("2026-10-17T12:14:59.5Z"))).toBe(1);
    expect(secondsLeft(pause, at("2026-10-17T12:20:00Z"))).toBe(0);
    expect(secondsLeft({ since: pause.since }, at(until))).toBeNull();
    expect(secondsLeft(null, 0)).toBeNull();
    expect(pauseEnded(pause, at("2026-10-17T12:14:59Z"))).toBe(false);
    expect(pauseEnded(pause, at(until))).toBe(true);
    expect(pauseEnded({ since: pause.since }, at(until))).toBe(false);
  });
});

describe("the bars of the hours", () => {
  it("scale to the busiest hour and keep the blocked part", () => {
    const bars = hourBars([
      { start: "2026-10-17T10:00:00Z", queries: 200, blocked: 50 },
      { start: "2026-10-17T11:00:00Z", queries: 100, blocked: 100 },
      { start: "2026-10-17T12:00:00Z", queries: 0, blocked: 0 },
    ]);
    expect(bars.map((b) => b.total)).toEqual([1, 0.5, 0]);
    expect(bars.map((b) => b.part)).toEqual([0.25, 1, 0]);
  });

  it("does not divide by zero for a window without queries", () => {
    expect(hourBars([{ start: "2026-10-17T10:00:00Z", queries: 0, blocked: 0 }])[0]).toMatchObject({ total: 0, part: 0 });
    expect(hourBars([])).toEqual([]);
  });

  it("writes a fraction as a percentage", () => {
    expect(pct(0.25)).toBe("25%");
    expect(pct(0.3333)).toBe("33.3%");
    expect(pct(2)).toBe("100%");
    expect(pct(-1)).toBe("0%");
  });
});

describe("clients and lists", () => {
  it("tells a pseudonym from an address and a withheld client", () => {
    expect(clientKind("p:3f2a9c0d81b7e645")).toBe("pseudonym");
    expect(clientKind("192.0.2.10")).toBe("address");
    expect(clientKind("2001:db8::20")).toBe("address");
    expect(clientKind(undefined)).toBe("withheld");
    expect(clientKind(null)).toBe("withheld");
    expect(clientKind("")).toBe("withheld");
  });

  it("names a list by its id, and not a deleted one", () => {
    const lists = [
      { list: "a", name: "Ads", blocked: 3 },
      { list: "b", blocked: 1 },
    ];
    expect(listName(lists, "a")).toBe("Ads");
    expect(listName(lists, "b")).toBeUndefined();
    expect(listName(lists, "c")).toBeUndefined();
    expect(listName(lists, null)).toBeUndefined();
  });

  it("computes a share", () => {
    expect(share(1, 4)).toBe(0.25);
    expect(share(1, 0)).toBe(0);
  });
});
