// The scans page (WP3.11a): a placeholder that says so until the page exists.
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";

export default function ScansPage() {
  return (
    <div class="page" data-testid="page-scans">
      <PageHead title={t("scans.title")} />
      <div class="page-body">
        <p class="muted" data-testid="scans-placeholder">
          {t("scans.placeholder")}
        </p>
      </div>
    </div>
  );
}
