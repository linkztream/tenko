// A size in bytes in the current language with a decimal unit (B, kB, MB, GB), through
// Intl's unit formatting; at most three significant digits so a cell never grows.
import { formatNumber } from "../i18n";

const UNITS = ["byte", "kilobyte", "megabyte", "gigabyte"] as const;

export function formatBytes(bytes: number): string {
  let value = Math.max(0, bytes);
  let unit = 0;
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return formatNumber(value, { style: "unit", unit: UNITS[unit], unitDisplay: "short", maximumSignificantDigits: 3 });
}
