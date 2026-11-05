// The Kerberos section of the DNS area (/dns/kerberos; identity plan section 3.18, WP13.0): the
// account of secure dynamic updates, its wizard, its status and the zones of the realm. The
// route and the page exist so that the area has its place; WP13.3 builds the wizard (the
// realm and its KDCs, the account name with the PowerShell block for the administrator, the
// one-time password, the self-test with its findings, or the keytab upload) and the status
// (the key versions, the SPNs, the last rotation and self-test, the contexts and the refusals
// of the last hour), WP13.4 the zones of the realm with their modes.
import { A } from "@solidjs/router";
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { DnsNav } from "../DnsNav";
import { dnsPaths } from "../paths";
import "../dns.css";

export default function KerberosPage() {
  return (
    <div class="page" data-testid="page-dns-kerberos">
      <DnsNav />
      <PageHead title={t("dns.kerberos.title")} sub={t("dns.kerberos.sub")} />
      <div class="empty" data-testid="dns-kerberos-coming">
        <h2>{t("dns.kerberos.coming.title")}</h2>
        <p>{t("dns.kerberos.coming.body")}</p>
        <A class="btn" href={dnsPaths.zones()} data-testid="dns-kerberos-zones">
          {t("dns.coming.zones")}
        </A>
      </div>
    </div>
  );
}
