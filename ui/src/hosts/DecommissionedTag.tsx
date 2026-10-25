// The badge of a decommissioned host, and the compact "when and by whom" of the hosts list.
import { Show } from "solid-js";
import type { Decommission } from "../api/types";
import { PrincipalLabel } from "../components/Principal";
import { TimeAgo } from "../grid/cells";
import { formatDateTime, t } from "../i18n";

/** The badge next to the name of a decommissioned host; nothing for an active one. */
export function DecommissionedTag(props: { decommissioned?: Decommission | null | undefined }) {
  return (
    <Show when={props.decommissioned}>
      {(d) => (
        <span class="tag decommissioned" data-testid="decommissioned-tag" title={formatDateTime(d().at)}>
          {t("hosts.decommissioned.tag")}
        </span>
      )}
    </Show>
  );
}

/** When a host was decommissioned and by whom: "3 days ago by Alex". */
export function DecommissionedBy(props: { decommissioned: Decommission }) {
  return (
    <span class="decommissioned-by">
      <TimeAgo at={props.decommissioned.at} /> {t("hosts.decommissioned.by")} <PrincipalLabel principal={props.decommissioned.by} />
    </span>
  );
}
