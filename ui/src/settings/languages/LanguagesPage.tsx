// The settings page for Languages (WP3.7): language packs, upload, report, preview and activate.
// A placeholder until the page exists: a sub-page of Settings at /settings/languages for administrators.
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";

export default function LanguagesPage() {
  return (
    <div class="page" data-testid="page-languages">
      <PageHead title={t("languages.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted" data-testid="languages-placeholder">
          {t("languages.placeholder")}
        </p>
      </div>
    </div>
  );
}
