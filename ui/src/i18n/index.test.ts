import { afterEach, describe, expect, it } from "vitest";
import {
  formatDuration,
  formatList,
  formatNumber,
  formatRelative,
  hasMessage,
  locale,
  matchLocale,
  resolveLocale,
  setLocale,
  storedLocale,
  storeLocale,
  t,
  tDynamic,
  tx,
} from ".";

afterEach(async () => {
  await setLocale("en");
  storeLocale(null);
});

describe("language resolution (API-08)", () => {
  it("matches exact tags and primary subtags", () => {
    expect(matchLocale("sv")).toBe("sv");
    expect(matchLocale("sv-SE")).toBe("sv");
    expect(matchLocale("EN-gb")).toBe("en");
    expect(matchLocale("de-DE")).toBeUndefined();
    expect(matchLocale(null)).toBeUndefined();
  });

  it("prefers the account, then this browser's choice, then the browser, then the installation", () => {
    expect(resolveLocale({ user: "sv", stored: "en", browser: ["en"], installation: "en" })).toBe("sv");
    expect(resolveLocale({ user: null, stored: "sv", browser: ["en"] })).toBe("sv");
    expect(resolveLocale({ browser: ["de-DE", "sv-SE", "en"] })).toBe("sv");
    expect(resolveLocale({ browser: ["de-DE", "fr"], installation: "sv" })).toBe("sv");
  });

  it("falls back to English", () => {
    expect(resolveLocale({})).toBe("en");
    expect(resolveLocale({ browser: ["de"], installation: "fr" })).toBe("en");
  });

  it("remembers a choice made before sign-in", () => {
    storeLocale("sv");
    expect(storedLocale()).toBe("sv");
    storeLocale(null);
    expect(storedLocale()).toBeNull();
  });
});

describe("messages", () => {
  it("formats plain messages, arguments and plurals in English", () => {
    expect(t("common.action.cancel")).toBe("Cancel");
    expect(t("common.greeting", { name: "alex" })).toBe("Signed in as alex");
    expect(t("common.count.items", { count: 1 })).toBe("1 item");
    expect(t("common.count.items", { count: 1234 })).toBe("1,234 items");
  });

  it("switches to Swedish, loaded on demand, and back", async () => {
    await setLocale("sv");
    expect(locale()).toBe("sv");
    expect(document.documentElement.lang).toBe("sv");
    expect(t("common.action.cancel")).toBe("Avbryt");
    expect(t("shell.status.running", { count: 2 })).toBe("2 körs");
    expect(t("auth.signin.retry_in", { seconds: 1 })).toBe("Försök igen om 1 sekund.");
    await setLocale("en");
    expect(t("common.action.cancel")).toBe("Cancel");
  });

  it("treats an unknown language as English", async () => {
    await setLocale("xx");
    expect(locale()).toBe("en");
  });

  it("interpolates elements without turning text into markup", () => {
    // Only text: one string, with the markup-looking value kept as text.
    expect(tx("common.greeting", { name: "<b>alex</b>" })).toBe("Signed in as <b>alex</b>");
    const el = document.createElement("b");
    el.textContent = "alex";
    const mixed = tx("common.greeting", { name: el }) as unknown as unknown[];
    expect(mixed).toContain(el);
  });

  it("looks up keys built at run time", () => {
    expect(hasMessage("errors.auth.invalid_credentials")).toBe(true);
    expect(hasMessage("errors.no.such.code")).toBe(false);
    expect(tDynamic("errors.auth.throttled", { retry_after: 20 })).toBe("Too many attempts. Try again in 20 s.");
    expect(tDynamic("errors.no.such.code")).toBeUndefined();
  });
});

describe("numbers, dates and lists", () => {
  it("follow the current language", async () => {
    expect(formatNumber(48213)).toBe("48,213");
    expect(formatList(["DNS", "DHCP", "IPAM"])).toBe("DNS, DHCP, and IPAM");
    await setLocale("sv");
    expect(formatNumber(48213)).toBe("48 213");
    expect(formatList(["DNS", "DHCP", "IPAM"])).toBe("DNS, DHCP och IPAM");
  });

  it("formats relative times and durations", () => {
    const now = Date.UTC(2026, 9, 9, 12, 0, 0);
    expect(formatRelative(now - 4000, now)).toBe("4 seconds ago");
    expect(formatRelative(now + 2 * 86_400_000, now)).toBe("in 2 days");
    expect(formatDuration(12 * 3600)).toBe("12 hr");
    expect(formatDuration(300)).toBe("5 min");
    expect(formatDuration(45)).toBe("45 sec");
  });
});
