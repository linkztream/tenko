import { A } from "@solidjs/router";
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";
import { DnsNav } from "./DnsNav";
import { dnsPaths } from "./paths";

/** Every DNS path no view claims yet (views, forwarders and block lists come in later slices). */
export default function DnsPage() {
  return (
    <div class="page" data-testid="page-dns-later">
      <DnsNav />
      <PageHead title={t("dns.title")} />
      <div class="empty" data-testid="dns-coming">
        <h2>{t("dns.coming.title")}</h2>
        <p>{t("dns.coming.body")}</p>
        <A class="btn" href={dnsPaths.zones()} data-testid="dns-coming-zones">
          {t("dns.coming.zones")}
        </A>
      </div>
    </div>
  );
}
