// The status strip of the leases page (WP7.5): what this server's `dhcp` role does now: serving,
// accepting lease writes, conflict detection, listeners, scopes, leases by state, the last commit
// and the revision of the configuration image. A node that does not run the role says so; any other
// failure (no node, no permission, an older server) hides the strip, the page works without it.
import { createResource, For, Match, Show, Switch } from "solid-js";
import { ApiError } from "../../api/problem";
import { Notice } from "../../components/Notice";
import { formatNumber, t } from "../../i18n";
import { thisNodeDhcp } from "./api";

function notDhcp(err: unknown): boolean {
  return err instanceof ApiError && err.code === "dhcp.node.not_dhcp";
}

/** `version` changes when the strip is to be read again (the page's live refresh). */
export function NodeStrip(props: { version: () => number }) {
  // The source is an array, which is never falsy: a version of 0 would stop the first read.
  const [status] = createResource(() => [props.version()] as const, () => thisNodeDhcp());
  const shown = () => (status.error ? undefined : status.latest);
  return (
    <Switch>
      <Match when={status.error && notDhcp(status.error)}>
        <div class="dhcp-strip-note">
          <Notice kind="info" role="status" title={t("dhcp.strip.not_dhcp_title")} testid="dhcp-strip-not-dhcp">
            {t("dhcp.strip.not_dhcp_body")}
          </Notice>
        </div>
      </Match>
      <Match when={shown()}>
        {(node) => (
          <div class="dhcp-strip" role="group" aria-label={t("dhcp.strip.label")} data-testid="dhcp-strip" data-serving={String(node().serving)} data-accepting={String(node().accepting)}>
            <span class={node().serving ? "tag ok" : "tag conflict"} data-testid="strip-serving">
              {node().serving ? t("dhcp.strip.serving") : t("dhcp.strip.not_serving")}
            </span>
            <span class={node().accepting ? "tag" : "tag conflict"} data-testid="strip-accepting">
              {node().accepting ? t("dhcp.strip.accepting") : t("dhcp.strip.refusing")}
            </span>
            <span class="dhcp-fact" data-testid="strip-probe" data-key={String(node().probe)}>
              {node().probe ? t("dhcp.strip.probe_on") : t("dhcp.strip.probe_off")}
            </span>
            <span class="dhcp-fact" data-testid="strip-listeners">
              {t("dhcp.strip.listeners", { count: node().listeners.length })}
            </span>
            <span class="dhcp-fact" data-testid="strip-scopes">
              {t("dhcp.strip.scopes", { count: node().scopes })}
            </span>
            <For each={node().leases}>
              {(entry) => (
                <span class="dhcp-fact" data-testid="strip-leases" data-key={entry.state}>
                  {t(`dhcp.leases.state.${entry.state}`)} <b>{formatNumber(entry.count)}</b>
                </span>
              )}
            </For>
            <Show when={node().last_commit_ms !== null && node().last_commit_ms !== undefined}>
              <span class="dhcp-fact" data-testid="strip-commit">
                {t("dhcp.strip.commit", { ms: formatNumber(node().last_commit_ms ?? 0, { maximumFractionDigits: 1 }) })}
              </span>
            </Show>
            <span class="dhcp-fact" data-testid="strip-revision">
              {t("dhcp.strip.revision", { revision: formatNumber(node().revision) })}
            </span>
          </div>
        )}
      </Match>
    </Switch>
  );
}
