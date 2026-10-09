import { A, useLocation } from "@solidjs/router";
import { paths } from "../../app/paths";
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";

export default function NotFound() {
  const location = useLocation();
  return (
    <div class="page">
      <PageHead title={t("shell.notfound.title")} />
      <div class="empty">
        <p>{t("shell.notfound.body", { path: location.pathname })}</p>
        <A class="btn" href={paths.dashboard()}>
          {t("shell.notfound.home")}
        </A>
      </div>
    </div>
  );
}
