// The settings page for access (WP3.11b, IAM-01, IAM-06, IAM-10; docs/access.md): the roles and
// the sign-in requirement of each, every scoped grant with the scope picker, and the service
// accounts with their scoped tokens. Administrators only; the server decides every change.
import { latest } from "../../api/live";
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";
import { createScopeCatalog } from "./data";
import { GrantsSection } from "./Grants";
import { RolesSection } from "./RolePolicies";
import { ServiceAccountsSection } from "./ServiceAccounts";
import "../settings.css";
import "./access.css";

export default function AccessPage() {
  const catalog = createScopeCatalog();
  return (
    <div class="page" data-testid="page-access">
      <PageHead title={t("access.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("access.lede")}</p>
        <RolesSection />
        <GrantsSection catalog={latest(catalog)} headingId="access-grants-title" />
        <ServiceAccountsSection catalog={latest(catalog)} />
      </div>
    </div>
  );
}
