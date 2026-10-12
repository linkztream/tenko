// Backups (OPS-07; slice-3 plan WP3.4b, S3-Q11): the status of the backups in the target
// directory, "back up now", the schedule and how many backups are kept, and the restore preview
// of one backup (its manifest and the command that restores it on a new host; Phase 1 restores
// only from the command line and offers no download).
//
// The routes belong to WP3.4b, which runs in parallel; until the API document describes them,
// they are typed here as pending operations (api/pending.ts). The shapes follow section 3 of the
// plan and are reconciled with the server at merge.
import { locale, t } from "../../i18n";

/** When scheduled backups run; off by default (S3-Q11). */
export interface BackupSchedule {
  kind: "off" | "daily" | "weekly";
  /** The local time of the controller, "HH:MM". */
  time: string;
  /** For weekly backups: 0 is Monday, 6 Sunday. */
  weekday?: number | null;
}

/** `GET` and `PUT /settings/backup`: the schedule and how many backups the target keeps. */
export interface BackupSettings {
  schedule: BackupSchedule;
  keep: number;
  revision: number;
}

export type BackupSettingsUpdate = Omit<BackupSettings, "revision">;

/** One part of a backup and its digest, as the manifest lists it. */
export interface BackupPart {
  name: string;
  size_bytes: number;
  sha256: string;
}

/** One backup file of the target directory, with its manifest. */
export interface BackupFile {
  file: string;
  created_at: string;
  size_bytes: number;
  tenko_version: string;
  data_format: number;
  revision: number;
  audit_head: number;
  ca_fingerprint: string;
  /** How the backup key is wrapped: a passphrase or the recipient key file. */
  key: "passphrase" | "recipient";
  /** Scheduled or made by a person. */
  trigger: "schedule" | "manual";
  parts: BackupPart[];
}

/** `GET /system/backups`: the target, the last attempts and the backups there. */
export interface BackupStatus {
  /** The target directory of the controller (`[backup] target_dir`). */
  target: string;
  /** Whether a recipient key file is configured; scheduled backups need one. */
  recipient: boolean;
  running: boolean;
  last_good_at?: string | null;
  last_attempt?: { at: string; ok: boolean; error?: string | null } | null;
  /** Standard and Hardened warn after 7 days without a good backup. */
  stale: boolean;
  next_at?: string | null;
  backups: BackupFile[];
}

/** `POST /system/backups`: a passphrase, or none to use the recipient key file. */
export interface BackupCreate {
  passphrase?: string | null;
}

/** The answer of `POST /system/backups`: the inline job that writes the backup. */
export interface BackupStarted {
  job: string;
}

// The document describes `get_backups`, `create_backup` and `update_backup_settings` now; the
// shapes above are the page's working model until WP3.11c moves it to the generated types, and
// `/settings/backup` has no server route (the settings live under `/system/backups/settings`).
declare module "../../api/pending" {
  interface PendingOperations {
    "get /api/v1/settings/backup": { response: BackupSettings };
    "put /api/v1/settings/backup": { response: BackupSettings; body: BackupSettingsUpdate };
  }
}

/** The shortest passphrase the dialog accepts; the server's Argon2id parameters do the rest. */
export const MIN_PASSPHRASE = 12;

/** Whether a time is "HH:MM" on a 24-hour clock. */
export function validTime(value: string): boolean {
  const m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(value);
  return m !== null;
}

/** The schedule in words: "Off", "Every day at 02:30", "Every Sunday at 03:00". */
export function scheduleText(schedule: BackupSchedule): string {
  switch (schedule.kind) {
    case "off":
      return t("backup.schedule.off");
    case "daily":
      return t("backup.schedule.daily_at", { time: schedule.time });
    case "weekly":
      return t("backup.schedule.weekly_at", { day: weekdayName(schedule.weekday ?? 6), time: schedule.time });
  }
}

/** The name of a weekday, 0 Monday to 6 Sunday, in the UI language. */
export function weekdayName(day: number): string {
  // 2024-01-01 was a Monday.
  return new Date(Date.UTC(2024, 0, 1 + day)).toLocaleDateString(locale(), { weekday: "long", timeZone: "UTC" });
}

/** The command that restores a backup on a new host (restore is a command, not a button). */
export function restoreCommand(file: BackupFile, target: string): string {
  const sep = target.includes("\\") ? "\\" : "/";
  return `tenko backup restore ${target.replace(/[\\/]$/, "")}${sep}${file.file} --data-dir <new data directory>`;
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
