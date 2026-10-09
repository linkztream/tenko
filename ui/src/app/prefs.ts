// Per-browser display preferences: theme, row density and the "Emphasize host part"
// address treatment (design decisions 1 and 2). They live in localStorage under the same
// keys as the mockups and are mirrored on <html> as data attributes that tokens.css and
// design.css read. public/theme-init.js applies them before the first paint.
import { createSignal } from "solid-js";

export type ThemeChoice = "system" | "light" | "dark";
export type Density = "dense" | "compact" | "comfortable";

const THEME_KEY = "tenko-theme";
const DENSITY_KEY = "tenko-density";
const EMPHASIS_KEY = "tenko-emphasize";

export const THEMES: readonly ThemeChoice[] = ["system", "light", "dark"];
export const DENSITIES: readonly Density[] = ["dense", "compact", "comfortable"];

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string | null): void {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Storage unavailable: the choice lasts for this page only.
  }
}

function initialTheme(): ThemeChoice {
  const v = read(THEME_KEY);
  return v === "light" || v === "dark" ? v : "system";
}

function initialDensity(): Density {
  const v = read(DENSITY_KEY);
  return v === "dense" || v === "comfortable" ? v : "compact";
}

const [theme, setThemeSignal] = createSignal<ThemeChoice>(initialTheme());
const [density, setDensitySignal] = createSignal<Density>(initialDensity());
const [emphasizeHost, setEmphasisSignal] = createSignal<boolean>(read(EMPHASIS_KEY) === "host");

const darkQuery =
  typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : undefined;
const [systemDark, setSystemDark] = createSignal<boolean>(darkQuery?.matches ?? false);
darkQuery?.addEventListener("change", (e) => setSystemDark(e.matches));

/** The theme the user picked: system, light or dark. */
export { theme, density, emphasizeHost };

/** The theme in effect after resolving "system" against the operating system. */
export function effectiveTheme(): "light" | "dark" {
  const t = theme();
  if (t === "light" || t === "dark") return t;
  return systemDark() ? "dark" : "light";
}

function root(): HTMLElement {
  return document.documentElement;
}

export function setTheme(next: ThemeChoice): void {
  setThemeSignal(next);
  if (next === "system") {
    delete root().dataset.theme;
    write(THEME_KEY, null);
  } else {
    root().dataset.theme = next;
    write(THEME_KEY, next);
  }
}

/** System, then light, then dark (Shift+T and the theme button). */
export function cycleTheme(): void {
  const i = THEMES.indexOf(theme());
  setTheme(THEMES[(i + 1) % THEMES.length] ?? "system");
}

export function setDensity(next: Density): void {
  setDensitySignal(next);
  if (next === "compact") delete root().dataset.density;
  else root().dataset.density = next;
  write(DENSITY_KEY, next);
}

export function setEmphasizeHost(on: boolean): void {
  setEmphasisSignal(on);
  if (on) root().dataset.emphasize = "host";
  else delete root().dataset.emphasize;
  write(EMPHASIS_KEY, on ? "host" : null);
}

/** Re-applies every preference to <html> (after tests or a document swap). */
export function applyPrefs(): void {
  setTheme(theme());
  setDensity(density());
  setEmphasizeHost(emphasizeHost());
}
