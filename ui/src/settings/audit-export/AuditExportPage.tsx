// The settings page for Audit export (WP3.11b): sinks, test and status.
// A placeholder until the page exists: a sub-page of Settings at /settings/audit-export for administrators.
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";

export default function AuditExportPage() {
  return (
    <div class="page" data-testid="page-audit-export">
      <PageHead title={t("audit_export.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted" data-testid="audit-export-placeholder">
          {t("audit_export.placeholder")}
        </p>
      </div>
    </div>
  );
}
