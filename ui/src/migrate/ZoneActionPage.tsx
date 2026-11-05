// The two zone actions of plan section 2.6 (/dns/zones/:id/flip and /dns/zones/:id/release):
// the flip of a secondary zone to primary with its SOA and NS form (and back), and the release
// of the frozen names of a primary zone. WP14.0 stubs both; WP14.2 builds them.
import { A, useParams } from "@solidjs/router";
import { decodeSegment } from "../app/paths";
import { PageHead } from "../components/PageHead";
import { dnsPaths } from "../dns/paths";
import { t } from "../i18n";

export type ZoneAction = "flip" | "release";

export function ZoneActionPage(props: { action: ZoneAction }) {
  const params = useParams<{ id: string }>();
  const id = () => decodeSegment(params.id);
  return (
    <div class="page" data-testid={`page-migrate-zone-${props.action}`} data-id={id()}>
      <PageHead crumbs={<A href={dnsPaths.zone(id())}>{t("dns.zones.title")}</A>} title={t(`migrate.${props.action}.title`)} sub={<span class="mono">{id()}</span>} />
      <div class="empty" data-testid="migrate-coming">
        <h2>{t("migrate.coming.title")}</h2>
        <p>{t(`migrate.${props.action}.body`)}</p>
        <A class="btn" href={dnsPaths.zone(id())} data-testid="migrate-coming-back">
          {t("migrate.coming.zone")}
        </A>
      </div>
    </div>
  );
}
