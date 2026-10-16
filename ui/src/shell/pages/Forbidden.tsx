import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";

/** Shown instead of a page that needs a role the account does not have. */
export default function Forbidden() {
  return (
    <div class="page" data-testid="page-forbidden">
      <PageHead title={t("shell.forbidden.title")} />
      <div class="empty">
        <p>{t("shell.forbidden.body")}</p>
      </div>
    </div>
  );
}
