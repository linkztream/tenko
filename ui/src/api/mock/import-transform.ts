// Value transforms of the import (crates/tenko-ipam/src/import/transform.rs): host names from
// labels, enumerations in English and Swedish (written without diacritics, values are folded
// before the lookup), tags, interface lists and the formula escape of the export.
import { normalizeDnsName } from "./ipam/input";
import { fold } from "./import-vocab";
import { parseDuid, parseMac } from "./import-shape";

/**
 * A host name from a label: the label itself when it is valid (case does not count as a
 * change), else a normalized form (lowercase, spaces and other characters turned into `-`,
 * runs collapsed, accented letters folded to ASCII). `changed` says whether the name differs
 * from the label beyond case. Null when nothing usable is left.
 */
export function hostName(label: string): { name: string; changed: boolean } | null {
  const trimmed = label.trim();
  if (trimmed === "") return null;
  const valid = normalizeDnsName(trimmed, 1);
  if (valid !== null) return { name: valid, changed: false };
  let folded = "";
  for (const c of fold(trimmed)) folded += /[a-z0-9_.]/.test(c) ? c : "-";
  const labels = folded
    .split(".")
    .map((part) => part.replace(/-+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63).replace(/-+$/, ""))
    .filter((part) => part !== "");
  if (labels.length === 0) return null;
  const name = normalizeDnsName(labels.join("."), 1);
  return name === null ? null : { name, changed: true };
}

/**
 * Removes the formula escape the export adds: one leading `'` in front of quotes that stand
 * before `=`, `+`, `-`, `@`, a tab or a carriage return (`'=SUM(1)` is `=SUM(1)`).
 */
export function unescape(value: string): string {
  if (!value.startsWith("'")) return value;
  const rest = value.slice(1);
  return /^'*[=+\-@\t\r]/.test(rest) ? rest : value;
}

function lookup<T>(value: string, table: readonly (readonly [T, readonly string[]])[]): T | null {
  const key = fold(value.trim());
  return table.find(([, words]) => words.includes(key))?.[0] ?? null;
}

export type Status = "planned" | "active" | "reserved" | "deprecated";
export type Mode = "static" | "reserved" | "dynamic" | "unmanaged";
export type Role = "network" | "supernet";
export type Alloc = "lowest" | "highest";

export function status(value: string): Status | null {
  return lookup<Status>(value, [
    ["planned", ["planned", "planerad", "planerat"]],
    ["active", ["active", "aktiv", "aktivt", "in use", "used", "anvands"]],
    ["reserved", ["reserved", "reserverad", "reserverat"]],
    ["deprecated", ["deprecated", "utfasad", "utfasat"]],
  ]);
}

export function mode(value: string): Mode | null {
  return lookup<Mode>(value, [
    ["static", ["static", "statisk", "fast"]],
    ["reserved", ["reserved", "reservation", "reserverad"]],
    ["dynamic", ["dynamic", "dynamisk", "dhcp"]],
    ["unmanaged", ["unmanaged", "ohanterad"]],
  ]);
}

export function boolean(value: string): boolean | null {
  return lookup<boolean>(value, [
    [true, ["true", "yes", "y", "ja", "j", "1", "x", "sant"]],
    [false, ["false", "no", "n", "nej", "0", "falskt"]],
  ]);
}

export function role(value: string): Role | null {
  return lookup<Role>(value, [
    ["network", ["network", "nat", "natverk"]],
    ["supernet", ["supernet", "supernat", "container"]],
  ]);
}

export function alloc(value: string): Alloc | null {
  return lookup<Alloc>(value, [
    ["lowest", ["lowest", "lagsta"]],
    ["highest", ["highest", "hogsta"]],
  ]);
}

/** A percentage from 0 to 100 (`80`, `80%`). */
export function percent(value: string): number | null {
  const text = value.trim().replace(/%$/, "").trim();
  if (!/^[0-9]{1,3}$/.test(text)) return null;
  const n = Number(text);
  return n <= 100 ? n : null;
}

/** A VLAN id from 1 to 4094. */
export function vlan(value: string): number | null {
  const text = value.trim();
  if (!/^[0-9]{1,5}$/.test(text)) return null;
  const n = Number(text);
  return n >= 1 && n <= 4094 ? n : null;
}

/** Tags separated by `;`, empty parts dropped. */
export function tags(value: string): string[] {
  return value
    .split(";")
    .map((t) => t.trim())
    .filter((t) => t !== "");
}

/** A DHCPv4 client identifier in hexadecimal (`:` and `-` allowed) as lowercase hexadecimal. */
export function clientId(value: string): string | null {
  const hex = value.trim().replace(/[:-]/g, "");
  return hex !== "" && hex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hex) ? hex.toLowerCase() : null;
}

/** One entry of an `interfaces` cell: `name`, `name=mac`, `name=mac=duid` or `name==duid`. */
export interface InterfaceEntry {
  name: string;
  mac: string | null;
  duid: string | null;
}

/** Parses an `interfaces` cell; entries whose MAC or DUID does not parse come back as `bad`. */
export function interfaces(value: string): { entries: InterfaceEntry[]; bad: string[] } {
  const entries: InterfaceEntry[] = [];
  const bad: string[] = [];
  for (const part of value.split(";").map((p) => p.trim()).filter((p) => p !== "")) {
    const first = part.indexOf("=");
    const name = (first < 0 ? part : part.slice(0, first)).trim();
    const afterName = first < 0 ? null : part.slice(first + 1);
    const second = afterName === null ? -1 : afterName.indexOf("=");
    const macText = afterName === null ? "" : (second < 0 ? afterName : afterName.slice(0, second)).trim();
    const duidText = afterName === null || second < 0 ? "" : afterName.slice(second + 1).trim();
    const mac = macText === "" ? null : parseMac(macText);
    const duid = duidText === "" ? null : parseDuid(duidText);
    if (name === "" || (macText !== "" && mac === null) || (duidText !== "" && duid === null)) {
      bad.push(part);
      continue;
    }
    entries.push({ name, mac, duid });
  }
  return { entries, bad };
}
