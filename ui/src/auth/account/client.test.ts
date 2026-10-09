import { describe, expect, it } from "vitest";
import { setLocale } from "../../i18n";
import { clientLabel, describeClient, lifetimeChoices, tokenMaxDays } from "./client";

const FIREFOX_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";
const FIREFOX_ANDROID = "Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0";
const CHROME_LINUX = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const EDGE_WINDOWS =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0";
const SAFARI_MAC =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
const SAFARI_IPHONE =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

describe("describeClient", () => {
  it("names the browser and the system", () => {
    expect(describeClient(FIREFOX_WINDOWS)).toEqual({ browser: "Firefox", os: "Windows" });
    expect(describeClient(FIREFOX_ANDROID)).toEqual({ browser: "Firefox", os: "Android" });
    expect(describeClient(CHROME_LINUX)).toEqual({ browser: "Chrome", os: "Linux" });
    expect(describeClient(SAFARI_MAC)).toEqual({ browser: "Safari", os: "macOS" });
  });

  it("does not mistake Edge for Chrome or an iPhone for a Mac", () => {
    expect(describeClient(EDGE_WINDOWS).browser).toBe("Edge");
    expect(describeClient(SAFARI_IPHONE)).toEqual({ browser: "Safari", os: "iOS" });
  });

  it("knows command-line tools by their product token", () => {
    expect(describeClient("curl/8.5.0")).toEqual({ browser: "curl", os: null });
  });

  it("copes with nothing to go on", () => {
    expect(describeClient(null)).toEqual({ browser: null, os: null });
    expect(describeClient("")).toEqual({ browser: null, os: null });
    expect(describeClient("Mozilla/5.0 (compatible)")).toEqual({ browser: null, os: null });
  });
});

describe("clientLabel", () => {
  it("reads as a phrase in the current language", async () => {
    await setLocale("en");
    expect(clientLabel(FIREFOX_WINDOWS)).toBe("Firefox on Windows");
    expect(clientLabel("curl/8.5.0")).toBe("curl");
    expect(clientLabel(null)).toBe("Unknown client");
    await setLocale("sv");
    expect(clientLabel(FIREFOX_WINDOWS)).toBe("Firefox på Windows");
    await setLocale("en");
  });
});

describe("token lifetimes", () => {
  it("follows the maximum of each profile (TGL-05)", () => {
    expect(tokenMaxDays("home")).toBe(365);
    expect(tokenMaxDays("standard")).toBe(90);
    expect(tokenMaxDays("hardened")).toBe(30);
    expect(tokenMaxDays("lab")).toBeNull();
  });

  it("offers only the choices within the maximum", () => {
    expect(lifetimeChoices(365)).toEqual([30, 90, 365]);
    expect(lifetimeChoices(90)).toEqual([30, 90]);
    expect(lifetimeChoices(30)).toEqual([30]);
    expect(lifetimeChoices(null)).toEqual([30, 90, 365]);
  });
});
