// The newest good backup's age next to an install button ("Last backup 3 h ago", "No backup
// yet"), with a link to the Backup page. The age is the one the update status reported, aged
// by the time since it arrived.
import { A } from "@solidjs/router";
import { paths } from "../app/paths";
import { t } from "../i18n";
import { ageText } from "../settings/backup/model";
import type { UpdateStatus } from "./api";
import { backupAgeNow } from "./InstallConfirm";

export function BackupAge(props: { status: UpdateStatus; receivedAt: number }) {
  const text = () => {
    const seconds = backupAgeNow(props.status, props.receivedAt);
    return seconds === null ? t("updates.backup.none") : t("updates.backup.age", { age: ageText(seconds) });
  };
  return (
    <span class="muted" data-testid="updates-backup-age">
      {text()}{" "}
      <A href={paths.settings("backup")} data-testid="updates-backup-link">
        {t("updates.backup.link")}
      </A>
    </span>
  );
}
