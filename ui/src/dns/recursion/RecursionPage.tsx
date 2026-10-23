// The recursion section of the DNS area (/dns/recursion): the recursive resolver of this server's
// node and what it validates with. WP10.1 placed the status block first (StatusBlock.tsx: the
// hints source and the last priming with the prime button, the root servers, the infrastructure
// cache's sizes, the counters; WP10.4 adds the validation counters to it). WP10.4 made the rest
// real: the trust anchors with their RFC 5011 states, the refresh, the add form and the remove
// action (AnchorsSection.tsx), and the negative trust anchors with their form, expiry and delete
// action (NtaSection.tsx). Both lists follow the `dns` topic.
import { PageHead } from "../../components/PageHead";
import { t } from "../../i18n";
import { DnsNav } from "../DnsNav";
import { AnchorsSection } from "./AnchorsSection";
import { NtaSection } from "./NtaSection";
import { RecursionStatusBlock } from "./StatusBlock";
import "../dns.css";

export default function RecursionPage() {
  return (
    <div class="page" data-testid="page-dns-recursion">
      <DnsNav />
      <PageHead title={t("dns.recursion.title")} sub={t("dns.recursion.sub")} />
      {/* WP10.1: the status block */}
      <RecursionStatusBlock />
      {/* WP10.1: end */}
      <AnchorsSection />
      <NtaSection />
    </div>
  );
}
