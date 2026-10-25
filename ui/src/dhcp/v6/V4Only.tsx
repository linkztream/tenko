// The line that stands where a DHCPv4-only part of the scope page would be for a DHCPv6 scope:
// the network boot tab, the admitted classes and the server identifier (docs/dhcp.md 19.2:
// classes, policies and network boot are DHCPv4 only; a DHCPv6 client is matched by its scope
// and its reservation).
import { t } from "../../i18n";

export function V4Only(props: { /** Which part is missing, for tests: `boot`, `classes`, `server_id`, `effective`. */ part: string; /** Replaces the general line with a specific one. */ text?: string | undefined }) {
  return (
    <p class="muted" data-testid="v4-only" data-key={props.part}>
      {props.text ?? t("dhcp.v6.v4_only")}
    </p>
  );
}
