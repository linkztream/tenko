// Backups (OPS-07; docs/backup.md): the wire shapes are the generated ones of the OpenAPI
// document, and this file holds the words and rules the page puts over them: the status of the
// backups, "back up now", the interval schedule, and the command that restores one backup on a
// new host (Phase 1 restores only from the command line and offers no download).
import type { components } from "../../api/generated/schema";
import { formatNumber, t, tDynamic } from "../../i18n";

type S = components["schemas"];

/** `GET /system/backups`: the settings, the newest backups and the conditions to look at. */
export type BackupStatus = S["BackupStatusView"];
/** The stored settings, the same on every controller. */
export type BackupSettings = S["BackupSettingsView"];
/** `PUT /system/backups/settings`: all fields; the stored settings are replaced. */
export type BackupSettingsUpdate = S["BackupSettingsUpdate"];
/** One backup a controller wrote, or tried to. */
export type BackupRun = S["BackupRunView"];
/** `POST /system/backups`: an optional passphrase next to the configured recipient. */
export type BackupCreate = S["BackupCreateRequest"];
export type BackupOutcome = S["BackupOutcome"];
export type BackupReason = S["BackupReason"];
/** The restore this installation was started from. */
export type RestoreNotice = S["RestoreNoticeView"];
export type BackupWarning = S["StatusWarning"];

/** The shortest passphrase the dialog accepts; the server's Argon2id parameters do the rest. */
export const MIN_PASSPHRASE = 12;
export const MIN_INTERVAL_HOURS = 1;
export const MAX_INTERVAL_HOURS = 168;
export const MIN_KEEP = 1;
export const MAX_KEEP = 365;

/** A recipient is `tkbr1:` and 43 base64url characters (`tenko backup keygen` prints it). */
const RECIPIENT = /^tkbr1:[A-Za-z0-9_-]{43}$/;

export function validRecipient(value: string): boolean {
  return RECIPIENT.test(value.trim());
}

/** Whether a number is a whole number in `min..=max`. */
export function inRange(value: number, min: number, max: number): boolean {
  return Number.isInteger(value) && value >= min && value <= max;
}

/** Whether a directory is absolute on a POSIX host (`/…`) or a Windows one (`C:\…`, `\\…`). */
export function absoluteDir(value: string): boolean {
  return value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value) || value.startsWith("\\\\");
}

/** The form's fields as text and numbers; `settingsBody` turns them into the request body. */
export interface ScheduleDraft {
  enabled: boolean;
  intervalHours: number;
  keep: number;
  recipient: string;
  targetDir: string;
  includeConfig: boolean;
}

export function draftOf(settings: BackupSettings): ScheduleDraft {
  return {
    enabled: settings.enabled,
    intervalHours: settings.interval_hours,
    keep: settings.keep,
    recipient: settings.recipient ?? "",
    targetDir: settings.target_dir ?? "",
    includeConfig: settings.include_config,
  };
}

/** Empty text means "absent" for the recipient and the target directory. */
export function settingsBody(draft: ScheduleDraft): BackupSettingsUpdate {
  const recipient = draft.recipient.trim();
  const targetDir = draft.targetDir.trim();
  return {
    enabled: draft.enabled,
    include_config: draft.includeConfig,
    interval_hours: draft.intervalHours,
    keep: draft.keep,
    recipient: recipient === "" ? null : recipient,
    target_dir: targetDir === "" ? null : targetDir,
  };
}

/** The problems of a draft; a key is present only when that field is wrong. */
export interface DraftErrors {
  interval?: string;
  keep?: string;
  recipient?: string;
  targetDir?: string;
}

export function draftErrors(draft: ScheduleDraft): DraftErrors {
  const errors: DraftErrors = {};
  if (!inRange(draft.intervalHours, MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS)) {
    errors.interval = t("backup.schedule.error.interval", { min: MIN_INTERVAL_HOURS, max: MAX_INTERVAL_HOURS });
  }
  if (!inRange(draft.keep, MIN_KEEP, MAX_KEEP)) {
    errors.keep = t("backup.schedule.error.keep", { min: MIN_KEEP, max: MAX_KEEP });
  }
  const recipient = draft.recipient.trim();
  if (recipient !== "" && !validRecipient(recipient)) errors.recipient = t("backup.schedule.error.recipient");
  const dir = draft.targetDir.trim();
  if (dir !== "" && !absoluteDir(dir)) errors.targetDir = t("backup.schedule.error.target_dir");
  return errors;
}

/** Scheduled backups need a recipient: enabling the schedule without one is refused. */
export function needsRecipient(draft: Pick<ScheduleDraft, "enabled" | "recipient">): boolean {
  return draft.enabled && draft.recipient.trim() === "";
}

/** The schedule in words: "Off", "Every 24 h", "Every 5 days". */
export function scheduleText(settings: Pick<BackupSettings, "enabled" | "interval_hours">): string {
  if (!settings.enabled) return t("backup.schedule.off");
  return t("backup.schedule.every", { interval: intervalText(settings.interval_hours) });
}

/** Hours as whole days when they are, else as hours: "6 h", "2 d". */
export function intervalText(hours: number): string {
  const unit = (value: number, name: "day" | "hour") => formatNumber(value, { style: "unit", unit: name, unitDisplay: "short" });
  return hours >= 24 && hours % 24 === 0 ? unit(hours / 24, "day") : unit(hours, "hour");
}

/** The age the server counted, in its largest whole unit: "3 d", "5 h", "12 min", "30 s". */
export function ageText(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  const steps = [
    ["day", 86_400],
    ["hour", 3_600],
    ["minute", 60],
  ] as const;
  for (const [unit, size] of steps) {
    if (total >= size) return formatNumber(Math.floor(total / size), { style: "unit", unit, unitDisplay: "short" });
  }
  return formatNumber(total, { style: "unit", unit: "second", unitDisplay: "short" });
}

export function outcomeText(outcome: BackupOutcome): string {
  return outcome === "succeeded" ? t("backup.run.succeeded") : t("backup.run.failed");
}

export function reasonText(reason: BackupReason): string {
  return reason === "scheduled" ? t("backup.run.scheduled") : t("backup.run.manual");
}

/** What opens a backup: `passphrase`, `recipient`. */
export function slotsText(slots: readonly string[]): string {
  return slots
    .map((slot) => tDynamic(`backup.slot.${slot}`) ?? slot)
    .join(", ");
}

/** The words of a warning of the status: its translation with the parameters, else the detail. */
export function warningText(warning: BackupWarning): string {
  const key = `backup.warning.${warning.code.replace(/^backup\./, "").replace(/\./g, "_")}`;
  return tDynamic(key, warning.params ?? {}) ?? warning.detail;
}

/**
 * The command that restores a backup on a new host (restore is a command, not a button;
 * docs/backup.md, section 6). The file lies in the target directory of the controller that wrote it.
 */
export function restoreCommand(run: Pick<BackupRun, "file" | "target_dir">): string {
  const dir = run.target_dir;
  const sep = dir.includes("\\") && !dir.includes("/") ? "\\" : "/";
  const path = `${dir.replace(/[\\/]+$/, "")}${sep}${run.file ?? ""}`;
  return `tenko backup restore ${path} --config <tenko.toml of the new host>`;
}

/** Bytes as KiB, MiB or GiB with one decimal. */
export function sizeText(bytes: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
}
