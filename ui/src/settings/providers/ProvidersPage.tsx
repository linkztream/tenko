// The settings page of the sign-in providers (/settings/providers; identity plan section 3.18,
// WP13.0): OpenID Connect, LDAP and Kerberos through the browser, each with its state, last
// success and last error. The route and the page exist so that the area has its place; WP13.5
// builds the OIDC provider form and the test sign-in, WP13.6 the LDAP form with the certificate
// setup (the chain import with its confirmation screen, the PEM paste or upload, the system
// trust store, the clear-text warning of plain LDAP under Lab) and the test dialog, WP13.7 the
// negotiate provider. Administrators only.
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";
import "../settings.css";

export default function ProvidersPage() {
  return (
    <div class="page" data-testid="page-providers">
      <PageHead title={t("settings.providers.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted">{t("settings.providers.lede")}</p>
        <div class="empty" data-testid="providers-coming">
          <h2>{t("settings.providers.coming.title")}</h2>
          <p>{t("settings.providers.coming.body")}</p>
        </div>
      </div>
    </div>
  );
}
