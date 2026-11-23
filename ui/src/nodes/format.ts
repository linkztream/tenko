// A size in bytes in the current language with a decimal unit (B, kB, MB, GB), through
// Intl's unit formatting; at most three significant digits so a cell never grows.
import { formatDuration, formatNumber, t } from "../i18n";

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

/** The health conditions of a data directory short of room, which are freed on the host. */
export const DISK_CODES: readonly string[] = ["node.disk.low", "sys.store.disk_reserve"];

/**
 * The text of a data directory short of room: for low disk space the sentence of the rule that
 * raised it (the hour's or the day's rate, the store's line, the file system's level), else the
 * server's summary; then what to free. Without a time to say (a rate that eased while its severity
 * clears) it says the store's line only while the free space is under the line's own clear line
 * (1.21 × the margin), else the file system's level. The time left: minutes under two hours, whole
 * hours under two days, else whole days.
 */
export function diskText(finding: { code: string; summary: string; params?: Record<string, string> | null }): string {
  const p = finding.params ?? {};
  const bytes = (name: string) => formatBytes(Number(p[name]));
  const left = Number(p.seconds_left);
  // About as long: whole days from two days, whole hours from two hours, else minutes.
  const unit = left >= 2 * 86_400 ? 86_400 : left >= 2 * 3_600 ? 3_600 : 60;
  const rate = { left: formatDuration(Math.max(unit, Math.round(left / unit) * unit)), rate: bytes("bytes"), free: bytes("free") };
  const cause = finding.code === "node.disk.low" ? p.cause : undefined;
  const near = cause !== "level" && Number(p.free) < Number(p.margin) * 1.21;
  const first =
    cause === "hour" && p.seconds_left
      ? t("finding.disk.rate_hour", rate)
      : cause === "day" && p.seconds_left
        ? t("finding.disk.rate_day", rate)
        : cause && near
          ? t("finding.disk.line", { free: bytes("free"), margin: bytes("margin") })
          : cause && p.available && p.total
            ? t("finding.disk.level", { free: bytes("available"), total: bytes("total") })
            : finding.summary;
  return `${first} ${t("finding.disk.next")}`;
}
