// What the IPAM view shows before a prefix is chosen: the top-level prefixes of the VRF in
// view with their utilization, so the busiest networks are one click away.
import { createMemo, Show } from "solid-js";
import type { TreeNode, TreeResponse } from "../../api/types";
import { Addr } from "../../components/Addr";
import { AlarmFlag, StatusBadge, UtilizationMeter } from "../../grid/cells";
import { DataGrid } from "../../grid/DataGrid";
import { t } from "../../i18n";
import type { Scope } from "../scope";
import { VlanRef } from "../vlan/VlanRef";
import type { VlanStyle } from "../vlan/palette";
import { prefixRoleWord } from "../words";

export function VrfOverview(props: {
  scope: Scope;
  tree: TreeResponse | undefined;
  vlanOf: (id: string) => { vid: number; name: string; style?: VlanStyle | undefined } | undefined;
  onOpen: (node: TreeNode) => void;
}) {
  const nodes = createMemo(() => props.tree?.nodes ?? []);
  const alarms = () => nodes().filter((n) => n.level !== "normal").length;
  return (
    <div class="vrf-overview" data-testid="vrf-overview">
      <div class="page-head">
        <div>
          <h1 tabIndex={-1}>
            {props.scope.vrf()?.name ?? ""}
            <span class="sub">
              {t("ipam.overview.sub", { tenant: props.scope.tenant()?.name ?? "", count: nodes().length, alarms: alarms() })}
            </span>
          </h1>
        </div>
      </div>
      <DataGrid
        id="vrf-prefixes"
        label={t("ipam.overview.grid", { vrf: props.scope.vrf()?.name ?? "" })}
        noSelection
        rows={nodes()}
        rowId={(n) => n.id}
        rowKey={(n) => n.cidr}
        initial={!props.tree}
        loading={!props.tree}
        onOpen={props.onOpen}
        columns={[
          {
            id: "cidr",
            header: () => t("ipam.col.prefix"),
            width: 220,
            fixed: true,
            text: (n: TreeNode) => n.cidr,
            render: (n) => (
              <span class="indent" style={{ "--depth": n.depth }}>
                <Addr value={n.cidr} />
              </span>
            ),
          },
          { id: "description", header: () => t("ipam.col.description"), render: (n) => n.description ?? "" },
          { id: "role", header: () => t("ipam.col.role"), width: 110, render: (n) => prefixRoleWord(n.role) },
          {
            id: "vlan",
            header: () => t("ipam.col.vlan"),
            width: 120,
            render: (n) => <VlanRef id={n.vlan} vlanOf={props.vlanOf} />,
          },
          { id: "status", header: () => t("ipam.col.status"), width: 110, render: (n) => <StatusBadge status={n.status} /> },
          {
            id: "use",
            header: () => t("ipam.col.utilization"),
            width: 190,
            render: (n) => (
              <>
                <UtilizationMeter percent={n.utilization.percent} level={n.level} used={n.utilization.used} capacity={n.utilization.capacity} />
                <Show when={n.level !== "normal"}>
                  {" "}
                  <AlarmFlag level={n.level} />
                </Show>
              </>
            ),
          },
        ]}
        empty={
          <div class="empty">
            <h3>{t("ipam.tree.empty")}</h3>
            <p>{t("ipam.overview.empty_hint")}</p>
          </div>
        }
      />
    </div>
  );
}
