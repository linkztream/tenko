import { PageHead } from "../components/PageHead";
import { t } from "../i18n";

/** The DNS area until its views are built: what the module will hold. */
export default function DnsPage() {
  return (
    <div class="page" data-testid="page-dns">
      <PageHead title={t("dns.title")} />
      <div class="empty" data-testid="dns-coming">
        <h2>{t("dns.coming.title")}</h2>
        <p>{t("dns.coming.body")}</p>
      </div>
    </div>
  );
}
