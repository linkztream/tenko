// The pure helpers of the block lists page: the local checks of a list, the URL rule, the draft
// of a seeded list and back, and the address of a redirect.
import { describe, expect, it } from "vitest";
import { checkList, DEFAULT_INTERVAL, draftOf, redirectOf, validUrl, type ListDraft } from "./model";

const draft = (over: Partial<ListDraft> = {}): ListDraft => ({ ...draftOf(), name: "Ads", url: "https://lists.example.test/ads.txt", ...over });

function problems(over: Partial<ListDraft>): string[] {
  const checked = checkList(draft(over));
  return checked.ok ? [] : checked.problems;
}

describe("checkList", () => {
  it("sends the body of a URL list", () => {
    expect(checkList(draft({ description: "  Ads and trackers " }))).toEqual({
      ok: true,
      body: {
        name: "Ads",
        source: { kind: "url", url: "https://lists.example.test/ads.txt" },
        format: "domains",
        action: { kind: "nxdomain" },
        enabled: true,
        interval_hours: 24,
        description: "Ads and trackers",
      },
    });
  });

  it("sends an uploaded list without an interval and a URL, whatever the fields hold", () => {
    expect(checkList(draft({ source: "upload", url: "not a url", interval: "zero", format: "hosts", enabled: false }))).toEqual({
      ok: true,
      body: { name: "Ads", source: { kind: "upload" }, format: "hosts", action: { kind: "nxdomain" }, enabled: false, interval_hours: null, description: null },
    });
  });

  it("sends each kind of action", () => {
    for (const kind of ["nxdomain", "nodata"] as const) {
      const checked = checkList(draft({ action: kind, redirect: "192.0.2.80" }));
      expect(checked.ok && checked.body.action).toEqual({ kind });
    }
    const redirect = checkList(draft({ action: "redirect", redirect: " 2001:DB8::80 " }));
    expect(redirect.ok && redirect.body.action).toEqual({ kind: "redirect", address: "2001:db8::80" });
  });

  it("checks the name", () => {
    for (const name of ["", "   ", "-ads", ".ads", "a/b", "a".repeat(65)]) expect(problems({ name }), JSON.stringify(name)).toEqual(["name"]);
    for (const name of ["a", "Ads 2", "ads_v1.2-x", "Blåbär", "a".repeat(64), "  Ads  "]) expect(problems({ name }), JSON.stringify(name)).toEqual([]);
  });

  it("trims the name it sends", () => {
    const checked = checkList(draft({ name: "  Ads  " }));
    expect(checked.ok && checked.body.name).toBe("Ads");
  });

  it("needs an https or http URL for a URL list", () => {
    for (const url of ["", "lists.example.test/ads.txt", "ftp://lists.example.test/ads.txt", "file:///etc/hosts", "https://", "http:// "]) {
      expect(problems({ url }), url).toEqual(["url"]);
    }
    expect(problems({ url: "http://lists.example.test/ads.txt" })).toEqual([]);
    expect(problems({ url: " HTTPS://lists.example.test/ads.txt " })).toEqual([]);
  });

  it("takes the interval from 1 to 168 hours for a URL list only", () => {
    for (const interval of ["", "0", "169", "-1", "1.5", "abc", "1e2", "0x10"]) expect(problems({ interval }), interval).toEqual(["interval"]);
    for (const interval of ["1", "24", "168", " 12 "]) expect(problems({ interval }), interval).toEqual([]);
    expect(problems({ source: "upload", interval: "999" })).toEqual([]);
  });

  it("needs an IP address for a redirect and nothing for the other actions", () => {
    for (const redirect of ["", "lists.example.test", "192.0.2", "192.0.2.256", "2001:db8::g"]) {
      expect(problems({ action: "redirect", redirect }), redirect).toEqual(["redirect"]);
    }
    expect(problems({ action: "redirect", redirect: "192.0.2.80" })).toEqual([]);
    expect(problems({ action: "nodata", redirect: "garbage" })).toEqual([]);
  });

  it("names every problem at once", () => {
    expect(problems({ name: "", url: "x", interval: "0", action: "redirect", redirect: "x" })).toEqual(["name", "url", "interval", "redirect"]);
  });
});

describe("validUrl", () => {
  it("accepts a host over http or https", () => {
    expect(validUrl("https://lists.example.test/ads.txt")).toBe(true);
    expect(validUrl("http://192.0.2.7:8080/list")).toBe(true);
    expect(validUrl("https://[2001:db8::1]/list")).toBe(true);
  });
  it("refuses other schemes, a missing host and plain text", () => {
    for (const text of ["", "ads.txt", "ftp://example.test/x", "javascript:alert(1)", "https://", "https://exa mple.test"]) {
      expect(validUrl(text), text).toBe(false);
    }
  });
});

describe("draftOf", () => {
  it("starts a new list as a URL list of domains that blocks with NXDOMAIN", () => {
    expect(draftOf()).toEqual({
      name: "",
      source: "url",
      url: "",
      format: "domains",
      interval: String(DEFAULT_INTERVAL),
      action: "nxdomain",
      redirect: "",
      enabled: true,
      description: "",
    });
  });

  it("round-trips the seeded URL list", () => {
    const ads = {
      name: "Ads",
      source: { kind: "url" as const, url: "https://lists.example.test/ads.txt" },
      format: "domains" as const,
      interval_hours: 24,
      action: { kind: "nxdomain" as const },
      enabled: true,
      description: null,
    };
    const d = draftOf(ads);
    expect(d).toEqual({ name: "Ads", source: "url", url: ads.source.url, format: "domains", interval: "24", action: "nxdomain", redirect: "", enabled: true, description: "" });
    const checked = checkList(d);
    expect(checked.ok && checked.body).toEqual({ ...ads, description: null });
  });

  it("round-trips the seeded uploaded list with its redirect, off, and the interval 0 of an upload", () => {
    const local = {
      name: "Local",
      source: { kind: "upload" as const },
      format: "hosts" as const,
      interval_hours: 0,
      action: { kind: "redirect" as const, address: "192.0.2.80" },
      enabled: false,
      description: "Names blocked by hand",
    };
    const d = draftOf(local);
    expect(d).toEqual({
      name: "Local",
      source: "upload",
      url: "",
      format: "hosts",
      interval: String(DEFAULT_INTERVAL),
      action: "redirect",
      redirect: "192.0.2.80",
      enabled: false,
      description: "Names blocked by hand",
    });
    const checked = checkList(d);
    expect(checked.ok && checked.body).toEqual({
      name: "Local",
      source: { kind: "upload" },
      format: "hosts",
      action: local.action,
      enabled: false,
      interval_hours: null,
      description: "Names blocked by hand",
    });
  });
});

describe("redirectOf", () => {
  it("gives the address of a redirect and nothing otherwise", () => {
    expect(redirectOf({ kind: "redirect", address: "192.0.2.80" })).toBe("192.0.2.80");
    expect(redirectOf({ kind: "nxdomain" })).toBeUndefined();
    expect(redirectOf({ kind: "nodata" })).toBeUndefined();
  });
});
