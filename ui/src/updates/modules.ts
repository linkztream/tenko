// The product modules this installation runs (OPS-25): read once after sign-in, then the
// rail, the "go to" commands, the command palette, the dashboard and the router ask which
// areas to show. While the answer is unknown (not loaded yet, or the server has no module
// service) every module counts as running, so a slow or missing answer never hides anything.
import { createSignal } from "solid-js";
import type { Area } from "../shell/areas";
import { readModules, type ModuleName, type ModuleSettings } from "./api";

export type { ModuleName } from "./api";

export const MODULE_NAMES: readonly ModuleName[] = ["ipam", "dns", "dhcp", "discovery"];

const [settings, setSettings] = createSignal<ModuleSettings | null>(null);

/** What the server reported, or null while unknown. */
export { settings as moduleSettings };

/** Reads the module settings; a failed read leaves the modules unknown. */
export async function loadModules(): Promise<void> {
  try {
    setSettings(await readModules());
  } catch {
    setSettings(null);
  }
}

/** Forgets the answer (sign-out, tests). */
export function resetModules(): void {
  setSettings(null);
}

/** For tests: a known set of running modules. */
export function setModulesForTest(running: readonly ModuleName[] | null, extra: Partial<ModuleSettings> = {}): void {
  setSettings(
    running === null
      ? null
      : { running: [...running], configured: [...running], pinned: false, restart: "none", ...extra },
  );
}

/** Whether a module runs; true while unknown. */
export function moduleRunning(name: ModuleName): boolean {
  const s = settings();
  return s === null || s.running.includes(name);
}

/** The module a rail area belongs to; none for the dashboard, jobs, audit and settings. */
const AREA_MODULE: Partial<Record<Area["id"], ModuleName>> = {
  ipam: "ipam",
  dns: "dns",
  dhcp: "dhcp",
  discovery: "discovery",
  topology: "discovery",
};

/** Whether the area of the rail is shown. */
export function areaEnabled(id: Area["id"]): boolean {
  const name = AREA_MODULE[id];
  return name === undefined || moduleRunning(name);
}

/** The first path segment that belongs to a module (the search finds IPAM objects). */
const SEGMENT_MODULE: Readonly<Record<string, ModuleName>> = {
  ipam: "ipam",
  search: "ipam",
  dns: "dns",
  dhcp: "dhcp",
  discovery: "discovery",
  topology: "discovery",
};

/** The module an application path belongs to, or null for the paths every installation has. */
export function pathModule(pathname: string): ModuleName | null {
  const first = pathname.split("/").filter(Boolean)[0] ?? "";
  return SEGMENT_MODULE[first] ?? null;
}

/** The restart state of a pending module change (admins read it from the same answer). */
export function moduleRestart(): ModuleSettings["restart"] {
  return settings()?.restart ?? "none";
}

/** The status warning while a module change waits for a restart (params `configured`, `running`). */
export const RESTART_WARNING = "sys.modules.restart_required";

/** The module names in a list the server printed ("ipam, dns"); words that are no module are dropped. */
export function parseModuleList(text: string | undefined): ModuleName[] {
  const words = (text ?? "").split(/[\s,]+/).filter(Boolean);
  return MODULE_NAMES.filter((name) => words.includes(name));
}
