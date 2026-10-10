// The settings page for Access (WP3.11b): grants, service accounts and scoped tokens.
// A placeholder until the page exists: a sub-page of Settings at /settings/access for administrators.
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";

export default function AccessPage() {
  return (
    <div class="page" data-testid="page-access">
      <PageHead title={t("access.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted" data-testid="access-placeholder">
          {t("access.placeholder")}
        </p>
      </div>
    </div>
  );
}
