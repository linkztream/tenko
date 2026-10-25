// The router advertisement panel of the leases page (DHCP-10, docs/dhcp.md 19.12): what the `dhcp`
// role hears of the IPv6 routers on its links, and whether their M and O flags fit the DHCPv6
// scopes. The check runs where a `probe` role is in the process: without one the panel says it is
// not checked, where the raw socket cannot be opened it says why, otherwise it lists the links
// heard in the last hour and the findings. A node that serves no DHCPv6 and does not check shows
// nothing. The panel is one line until it is opened (the state and the number of findings), so the
// lease list keeps its room; the findings are the Nodes page's health rows as well.
import { For, Match, Show, Switch } from "solid-js";
import { Notice } from "../../components/Notice";
import { TimeAgo } from "../../grid/cells";
import { t } from "../../i18n";
import type { NodeStatus } from "../leases/model";
import { hasV6 } from "../leases/overview";
import { raFindingKind, raFindingText } from "./raWords";

type Report = NonNullable<NodeStatus["ra"]>;
type Link = NonNullable<Report["links"]>[number];

/** A flag as a tag: yes or no, never colour alone. */
function Flag(props: { flag: "m" | "o"; on: boolean }) {
  return (
    <span class={props.on ? "tag ok" : "tag"} data-testid={`ra-flag-${props.flag}`} data-key={props.on ? "yes" : "no"}>
      {props.on ? t("common.yes") : t("common.no")}
    </span>
  );
}

function List(props: { items: readonly string[] }) {
  return (
    <Show when={props.items.length > 0} fallback={<span class="muted">–</span>}>
      <span class="mono dhcp-ra-list">{props.items.join(", ")}</span>
    </Show>
  );
}

export function RaPanel(props: { node: NodeStatus }) {
  const report = (): Report | undefined => props.node.ra;
  const shown = (): Report | undefined => {
    const ra = report();
    return ra !== undefined && (ra.check !== "off" || hasV6(props.node)) ? ra : undefined;
  };
  const links = (): Link[] => report()?.links ?? [];
  // The entries of the report carry no node; the health rows of the system status do, so the
  // sentences of both read alike.
  const findings = () =>
    (report()?.findings ?? [])
      .filter((f) => f.code !== "dhcp.ra.unchecked" || report()?.check !== "unavailable")
      .map((f) => ({
        ...f,
        params: { node: String(props.node.node), ...f.params },
      }));
  return (
    <Show when={shown()}>
      {(ra) => (
        <details class="dhcp-ra" data-testid="ra-panel" data-check={ra().check}>
          <summary class="dhcp-ra-title" data-testid="ra-summary">
            <span>{t("dhcp.ra.title")}</span>
            <Show when={ra().check === "watching"}>
              <span class="tag ok" data-testid="ra-state" data-key="watching">
                {t("dhcp.ra.state.watching")}
              </span>
            </Show>
            <Show when={findings().length > 0}>
              <span
                class={findings().some((f) => raFindingKind(f.code) === "warn") ? "tag conflict" : "tag"}
                data-testid="ra-finding-count"
                data-count={String(findings().length)}
              >
                {t("dhcp.ra.findings_count", { count: findings().length })}
              </span>
            </Show>
          </summary>
          <Switch>
            <Match when={ra().check === "off"}>
              <p class="muted" data-testid="ra-state" data-key="off">
                {t("dhcp.ra.state.off")}
              </p>
            </Match>
            <Match when={ra().check === "unavailable"}>
              <Notice kind="info" role="status" testid="ra-state">
                {t("dhcp.ra.state.unavailable", { reason: ra().reason ?? "" })}
              </Notice>
            </Match>
            <Match when={links().length === 0}>
              <p class="muted" data-testid="ra-none">
                {t("dhcp.ra.none")}
              </p>
            </Match>
            <Match when={true}>
              <div class="table-wrap">
                <table class="plain" aria-label={t("dhcp.ra.label")}>
                  <thead>
                    <tr>
                      <th scope="col">{t("dhcp.ra.col.interface")}</th>
                      <th scope="col">{t("dhcp.ra.col.routers")}</th>
                      <th scope="col" title={t("dhcp.ra.col.m_title")}>
                        {t("dhcp.ra.col.m")}
                      </th>
                      <th scope="col" title={t("dhcp.ra.col.o_title")}>
                        {t("dhcp.ra.col.o")}
                      </th>
                      <th scope="col">{t("dhcp.ra.col.prefixes")}</th>
                      <th scope="col">{t("dhcp.ra.col.scopes")}</th>
                      <th scope="col">{t("dhcp.ra.col.seen")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={links()}>
                      {(link) => (
                        <tr data-testid="ra-link" data-key={link.interface}>
                          <td class="mono">{link.interface}</td>
                          <td>
                            <List items={link.routers} />
                          </td>
                          <td>
                            <Flag flag="m" on={link.managed} />
                          </td>
                          <td>
                            <Flag flag="o" on={link.other} />
                          </td>
                          <td>
                            <List items={link.prefixes} />
                          </td>
                          <td>
                            <List items={link.scopes} />
                          </td>
                          <td>
                            <TimeAgo at={link.seen} />
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Match>
          </Switch>
          <Show when={findings().length > 0}>
            <div class="dhcp-ra-findings">
              <For each={findings()}>
                {(f) => (
                  <Notice kind={raFindingKind(f.code)} testid="ra-finding" code={f.code}>
                    {raFindingText(f)}
                  </Notice>
                )}
              </For>
            </div>
          </Show>
          <Show when={ra().check === "watching"}>
            <p class="muted dhcp-ra-note" data-testid="ra-default-route">
              {t("dhcp.ra.default_route")}
            </p>
          </Show>
        </details>
      )}
    </Show>
  );
}
