// The settings page for Backup (WP3.11b): status, back up now, schedule and target.
// A placeholder until the page exists: a sub-page of Settings at /settings/backup for administrators.
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";

export default function BackupPage() {
  return (
    <div class="page" data-testid="page-backup">
      <PageHead title={t("backup.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted" data-testid="backup-placeholder">
          {t("backup.placeholder")}
        </p>
      </div>
    </div>
  );
}
