// Number and text formatting for the wizard: sizes of memory and disks, the latency of a
// disk, and the fingerprint of the internal certificate authority.
import { formatNumber } from "../i18n";

const MIB = 1024 ** 2;
const GIB = 1024 ** 3;

function unit(value: number, name: "megabyte" | "gigabyte" | "terabyte" | "millisecond", digits: number): string {
  return formatNumber(value, { style: "unit", unit: name, unitDisplay: "short", maximumFractionDigits: digits });
}

/** Memory as the operating system reports it (binary units, shown as GB like the mockup): "8 GB". */
export function formatMemory(bytes: number): string {
  return bytes >= GIB ? unit(bytes / GIB, "gigabyte", 1) : unit(bytes / MIB, "megabyte", 0);
}

/** Free disk space (decimal units): "412 GB", "3.1 TB". */
export function formatDiskSize(bytes: number): string {
  if (bytes >= 1e12) return unit(bytes / 1e12, "terabyte", 1);
  if (bytes >= 1e9) return unit(bytes / 1e9, "gigabyte", 0);
  return unit(bytes / 1e6, "megabyte", 0);
}

/** An estimate in megabytes: "250 MB", "1.1 GB". */
export function formatMegabytes(mb: number): string {
  return mb >= 1000 ? unit(mb / 1000, "gigabyte", 1) : unit(mb, "megabyte", 0);
}

/** A latency given in microseconds, in milliseconds: "0.9 ms", "44.5 ms". */
export function formatMicros(micros: number): string {
  return unit(micros / 1000, "millisecond", 1);
}

/** The pairs of a hexadecimal fingerprint in upper case, split into rows of `perRow` pairs. */
export function fingerprintRows(hex: string, perRow = 16): string[][] {
  const pairs = (hex.replace(/[^0-9a-fA-F]/g, "").toUpperCase().match(/.{1,2}/g) ?? []) as string[];
  const rows: string[][] = [];
  for (let i = 0; i < pairs.length; i += perRow) rows.push(pairs.slice(i, i + perRow));
  return rows;
}

/** The fingerprint as it is copied: pairs separated by colons. */
export function fingerprintText(hex: string): string {
  return fingerprintRows(hex, Number.MAX_SAFE_INTEGER).flat().join(":");
}
