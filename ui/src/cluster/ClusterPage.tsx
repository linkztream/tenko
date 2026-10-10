// The cluster page (WP3.11a): a placeholder that says so until the page exists.
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";

export default function ClusterPage() {
  return (
    <div class="page" data-testid="page-cluster">
      <PageHead title={t("cluster.title")} />
      <div class="page-body">
        <p class="muted" data-testid="cluster-placeholder">
          {t("cluster.placeholder")}
        </p>
      </div>
    </div>
  );
}
