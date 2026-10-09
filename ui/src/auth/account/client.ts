// Small pure helpers of the account pages: a readable summary of a user agent and the
// token lifetime a profile allows (TGL-05).
import type { Profile } from "../../api/types";
import { t } from "../../i18n";

export interface ClientInfo {
  /** The browser or tool, for example "Firefox" or "curl"; null when nothing matched. */
  browser: string | null;
  /** The operating system, for example "Windows"; null when nothing matched. */
  os: string | null;
}

// Names of products are not translated. The order matters: Edge and Opera also say
// Chrome, and Chrome also says Safari.
const BROWSERS: readonly (readonly [RegExp, string])[] = [
  [/\bEdg(?:e|A|iOS)?\/\d/, "Edge"],
  [/\b(?:OPR|Opera)\/\d/, "Opera"],
  [/\bSamsungBrowser\/\d/, "Samsung Internet"],
  [/\bVivaldi\/\d/, "Vivaldi"],
  [/\b(?:Firefox|FxiOS)\/\d/, "Firefox"],
  [/\b(?:Chrome|CriOS|Chromium)\/\d/, "Chrome"],
  [/\bSafari\/\d/, "Safari"],
];

// iPhone and iPad also say "like Mac OS X", and Android also says Linux.
const SYSTEMS: readonly (readonly [RegExp, string])[] = [
  [/\b(?:iPhone|iPod)\b/, "iOS"],
  [/\biPad\b/, "iPadOS"],
  [/\bAndroid\b/, "Android"],
  [/\bCrOS\b/, "ChromeOS"],
  [/\bWindows\b/, "Windows"],
  [/\b(?:Mac OS X|Macintosh)\b/, "macOS"],
  [/\b(?:Linux|X11)\b/, "Linux"],
];

/** The browser and the operating system of a user agent, by simple matching. */
export function describeClient(userAgent: string | null | undefined): ClientInfo {
  const ua = (userAgent ?? "").trim();
  if (!ua) return { browser: null, os: null };
  let browser = BROWSERS.find(([re]) => re.test(ua))?.[1] ?? null;
  if (browser === null && !ua.startsWith("Mozilla/")) {
    // A command-line tool or a library: its own product token, "curl/8.5.0".
    const product = /^([A-Za-z][A-Za-z0-9._ -]{0,30}?)\/\d/.exec(ua);
    browser = product?.[1] ?? null;
  }
  const os = SYSTEMS.find(([re]) => re.test(ua))?.[1] ?? null;
  return { browser, os };
}

/** "Firefox on Windows", the browser alone, the system alone, or "Unknown client". */
export function clientLabel(userAgent: string | null | undefined): string {
  const { browser, os } = describeClient(userAgent);
  if (browser && os) return t("account.sessions.client", { browser, os });
  return browser ?? os ?? t("account.sessions.client_unknown");
}

/** The longest token lifetime in days the profile allows (TGL-05); null means no maximum. */
export function tokenMaxDays(profile: Profile): number | null {
  switch (profile) {
    case "home":
      return 365;
    case "standard":
      return 90;
    case "hardened":
      return 30;
    case "lab":
      return null;
  }
}

/** Lifetimes offered in days, in order; the ones above the maximum are left out. */
export const TOKEN_LIFETIMES: readonly number[] = [30, 90, 365];

export function lifetimeChoices(max: number | null): number[] {
  return TOKEN_LIFETIMES.filter((d) => max === null || d <= max);
}
