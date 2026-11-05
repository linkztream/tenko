// The directory mappings page under access (/settings/access/mappings; identity plan section
// 3.18, WP13.0): a table of group to role and scope per provider, with the users currently
// mapped and a dry run for a user name. The route and the page exist so that the area has its
// place; WP13.5 builds the table, the form and the dry run. Administrators only.
import { A } from "@solidjs/router";
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { paths } from "../../app/paths";
import { SettingsNav } from "../SettingsNav";
import "../settings.css";

export default function MappingsPage() {
  return (
    <div class="page" data-testid="page-access-mappings">
      <PageHead title={t("access.mappings.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("access.mappings.lede")}</p>
        <div class="empty" data-testid="access-mappings-coming">
          <h2>{t("access.mappings.coming.title")}</h2>
          <p>{t("access.mappings.coming.body")}</p>
          <A class="btn" href={paths.settings("access")} data-testid="access-mappings-back">
            {t("access.mappings.back")}
          </A>
        </div>
      </div>
    </div>
  );
}
