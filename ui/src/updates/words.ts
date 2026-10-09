// The words of the updates area as functions over `t`: why an install is not possible, why
// the check is off, what a failed check or a switched-back install says. Codes come from
// the server; a code this UI has no words for is shown as it is, which is readable enough
// to report.
import { formatDate, formatDateTime, formatNumber, t, tDynamic } from "../i18n";
import type { InstallBlock, UpdateCheck } from "./api";

/** Why an install cannot start from here, in a sentence. */
export function blockedText(reason: InstallBlock | string, platform?: string): string {
  switch (reason) {
    case "container":
      return t("updates.blocked.container");
    case "cluster":
      return t("updates.blocked.cluster");
    case "layout_missing":
      return t("updates.blocked.layout_missing");
    case "unsupervised":
      return t("updates.blocked.unsupervised");
    case "unsupported_platform":
      return t("updates.blocked.unsupported_platform", { platform: platform ?? "" });
    case "upload_only":
      return t("updates.blocked.upload_only");
    case "air_gapped":
      return t("updates.blocked.air_gapped");
    case "no_asset":
      return t("updates.blocked.no_asset");
    case "up_to_date":
      return t("updates.blocked.up_to_date");
    case "in_progress":
      return t("updates.blocked.in_progress");
    default:
      return t("updates.blocked.other", { reason });
  }
}

/** Why the scheduled check does not run. */
export function offReasonText(reason: NonNullable<UpdateCheck["off_reason"]> | null | undefined): string {
  return reason === "air_gapped" ? t("updates.check.off_air_gapped") : t("updates.check.off_setting");
}

/** A server code in words: the translation of `errors.<code>`, else the code itself. */
export function codeText(code: string): string {
  return tDynamic(`errors.${code}`) ?? t("updates.code_unknown", { code });
}

/** The size of a file in the largest fitting unit, for the upload section. */
export function formatFileSize(bytes: number): string {
  const units: readonly [string, number][] = [
    ["gigabyte", 1024 ** 3],
    ["megabyte", 1024 ** 2],
    ["kilobyte", 1024],
  ];
  for (const [unit, size] of units) {
    if (bytes >= size) {
      return formatNumber(bytes / size, { style: "unit", unit, unitDisplay: "short", maximumFractionDigits: 1 });
    }
  }
  return formatNumber(bytes, { style: "unit", unit: "byte", unitDisplay: "short" });
}

/** A date and time from the server, or a dash for none. */
export function whenText(at: string | null | undefined): string {
  return at ? formatDateTime(at) : "–";
}

/** The release date `YYYY-MM-DD` as a date in the current language. */
export function releaseDate(date: string): string {
  const parsed = new Date(`${date}T00:00:00Z`);
  return Number.isNaN(parsed.getTime()) ? date : formatDate(parsed, { dateStyle: "medium", timeZone: "UTC" });
}
