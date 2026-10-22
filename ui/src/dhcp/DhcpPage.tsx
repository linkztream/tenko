import { A, useLocation } from "@solidjs/router";
import { paths } from "../app/paths";
import { PageHead } from "../components/PageHead";
import { t, type MessageKey } from "../i18n";

/** The title of each DHCP section, by the segment after /dhcp; the scopes list has no segment. */
const TITLES: Readonly<Record<string, MessageKey>> = {
  scopes: "dhcp.scope.title",
  "shared-networks": "dhcp.shared_networks.title",
  options: "dhcp.options.title",
  classes: "dhcp.classes.title",
  policies: "dhcp.policies.title",
  filters: "dhcp.filters.title",
  leases: "dhcp.leases.title",
  history: "dhcp.history.title",
};

function titleOf(pathname: string): MessageKey {
  const segments = pathname.split("/").filter(Boolean);
  if (segments.length <= 1) return "dhcp.scopes.title";
  return TITLES[segments[1] ?? ""] ?? "dhcp.title";
}

/** The DHCP area until its views are built: every DHCP path says its part comes later. */
export default function DhcpPage() {
  const location = useLocation();
  return (
    <div class="page" data-testid="page-dhcp">
      <PageHead title={t(titleOf(location.pathname))} />
      <div class="empty" data-testid="dhcp-coming">
        <h2>{t("dhcp.coming.title")}</h2>
        <p>{t("dhcp.coming.body")}</p>
        <A class="btn" href={paths.dhcp()} data-testid="dhcp-coming-scopes">
          {t("dhcp.coming.scopes")}
        </A>
      </div>
    </div>
  );
}
