// The "Scanning" section of a node that runs the probe role: what it is and the link to its scan
// configuration (docs/scanning.md, section 7.5). The node panel shows it for an enrolled probe and
// the "This controller" section of the Nodes page for the controller's own probe role.
import { A } from "@solidjs/router";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import { nodeScanPath } from "../scans/model";

export function NodeScanPanel(props: { id: number | string; /** Inside a section that already is a landmark of its own: no landmark of its own, so two panels on a page stay distinguishable. */ bare?: boolean }) {
  return (
    <section class="section" aria-labelledby={!props.bare ? "node-scan" : undefined} data-testid="node-scan-panel">
      <h3 id={props.bare ? undefined : "node-scan"}>{t("nodes.scan.panel.title")}</h3>
      <p class="muted">{t("nodes.scan.panel.hint")}</p>
      <div class="row-actions">
        <A href={nodeScanPath(props.id)} class="btn" data-testid="node-scan-config">
          <Icon name="scan" />
          {t("nodes.scan.panel.link")}
        </A>
      </div>
    </section>
  );
}
