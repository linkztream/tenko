// The settings page for Vault (WP3.11b): the key-encryption keys, their status and online rotation.
// A placeholder until the page exists: a sub-page of Settings at /settings/vault for administrators.
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { SettingsNav } from "../SettingsNav";

export default function VaultPage() {
  return (
    <div class="page" data-testid="page-vault">
      <PageHead title={t("vault.title")} />
      <SettingsNav />
      <div class="page-body">
        <p class="muted" data-testid="vault-placeholder">
          {t("vault.placeholder")}
        </p>
      </div>
    </div>
  );
}
