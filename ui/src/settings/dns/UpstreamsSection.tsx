// dns-visibility: the upstreams of the node's resolver (`upstreams` of `GET /nodes/{id}/dns`):
// per rule (the default forwarder of `[dns] forwarders`, the forwarding rules by suffix, the
// stub zones whose name servers were learnt) each upstream with its state, the last and the
// smoothed round-trip time, the median and the 99th percentile of the last minute, the answered
// and failed exchanges since the role started and the last error. The upstream the next query
// goes to is marked. A node that forwards nothing shows a line saying so.
import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import { formatDateTime, formatNumber, t } from "../../i18n";
import { figuresTitle, msText, stateDot, type UpstreamGroup } from "../../dns/forwarders/figures";
import { dnsPaths } from "../../dns/paths";

/** The configuration section of the default forwarder, beside the heading. */
const SECTION = "[dns] forwarders";

/** The heading of a rule's rows: the default forwarder, a stub zone, or the rule's suffix. */
function ruleText(group: UpstreamGroup): string {
  if (group.rule === undefined || group.rule === null) {
    if (group.stub !== undefined && group.stub !== null) return t("dns.upstream.rule.stub", { zone: group.label.replace(/^stub:/, "") });
    return t("dns.upstream.rule.default");
  }
  return group.label;
}

export function UpstreamsSection(props: { groups: UpstreamGroup[] }) {
  return (
    <section class="page-section dns-set-group" data-testid="dns-settings-upstreams" aria-labelledby="dns-upstreams-title">
      <h2 id="dns-upstreams-title">
        {t("dns.upstream.section.title")} <code class="dns-set-section">{SECTION}</code>
      </h2>
      <p class="muted dns-set-doc">
        {t("dns.upstream.section.doc")}{" "}
        <A href={dnsPaths.forwarders()} data-testid="dns-settings-upstreams-link">
          {t("dns.upstream.section.link")}
        </A>
      </p>
      <Show
        when={props.groups.length > 0}
        fallback={
          <p class="muted" data-testid="dns-settings-upstreams-empty">
            {t("dns.upstream.section.empty")}
          </p>
        }
      >
        <div class="table-wrap">
          <table class="plain">
            <caption class="sr-only">{t("dns.upstream.section.title")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("dns.upstream.col.rule")}</th>
                <th scope="col">{t("dns.upstream.col.upstream")}</th>
                <th scope="col">{t("dns.upstream.col.state")}</th>
                <th scope="col" class="r">
                  {t("dns.upstream.col.last")}
                </th>
                <th scope="col" class="r">
                  {t("dns.upstream.col.ewma")}
                </th>
                <th scope="col" class="r">
                  {t("dns.upstream.col.p50")}
                </th>
                <th scope="col" class="r">
                  {t("dns.upstream.col.p99")}
                </th>
                <th scope="col" class="r">
                  {t("dns.upstream.col.answered")}
                </th>
                <th scope="col" class="r">
                  {t("dns.upstream.col.failed")}
                </th>
                <th scope="col">{t("dns.upstream.col.error")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={props.groups}>
                {(group) => (
                  <For each={group.upstreams}>
                    {(u, i) => (
                      <tr data-testid="dns-settings-upstream" data-rule={group.label} data-key={u.upstream} data-state={u.state} data-chosen={u.chosen ? "true" : undefined} title={figuresTitle(u)}>
                        <td class="mono">{i() === 0 ? ruleText(group) : ""}</td>
                        <td class="mono">
                          {u.upstream}
                          <Show when={u.chosen}>
                            {" "}
                            <span class="tag accent" data-testid="upstream-chosen">
                              {t("dns.upstream.chosen")}
                            </span>
                          </Show>
                        </td>
                        <td>
                          <span class="up-badge">
                            <span class={stateDot(u.state)} aria-hidden="true" />
                            {t(`dns.upstream.state.${u.state}`)}
                          </span>
                        </td>
                        <td class="r mono">{msText(u.last_rtt_ms)}</td>
                        <td class="r mono">{msText(u.ewma_ms)}</td>
                        <td class="r mono" data-testid="dns-settings-upstream-p50">
                          {msText(u.p50_ms)}
                        </td>
                        <td class="r mono">{msText(u.p99_ms)}</td>
                        <td class="r">{formatNumber(u.answered)}</td>
                        <td class="r">{formatNumber(u.failed)}</td>
                        <td class="muted">
                          <Show when={u.last_error}>
                            {(error) => (
                              <span data-testid="dns-settings-upstream-error">
                                {u.last_error_at ? `${formatDateTime(u.last_error_at)}: ` : ""}
                                {error()}
                              </span>
                            )}
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </section>
  );
}
