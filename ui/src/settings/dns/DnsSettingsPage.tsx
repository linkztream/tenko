// The DNS settings of a node (/settings/dns, administrators): read-only, what the node's DNS role
// runs with and its figures (`GET /nodes/{id}/dns`): the listeners with UDP, TCP, DoT and DoH,
// the workers, the upstreams with their round-trip times and states, the cache with its
// entries, octets and hit ratio, the TCP connections, the query
// log, and the problems the node reports. Each figure names the `tenko.toml` key that sets it
// and the section of the documentation; the settings are read at start, so they change in the
// file and with a restart. A node without the `dns` role, a switched-off module and a server
// without the route (501) each get their notice.
import { A } from "@solidjs/router";
import { createResource, For, Match, Show, Switch, type JSX } from "solid-js";
import { api } from "../../api/client";
import { ApiError } from "../../api/problem";
import { paths } from "../../app/paths";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { formatDateTime, formatNumber, t } from "../../i18n";
import { formatBytes } from "../../nodes/format";
import { nodeDns } from "../../dns/log/api";
import { moduleOff, notBuilt } from "../../dns/Parts";
import { dnsPaths } from "../../dns/paths";
import { SettingsNav } from "../SettingsNav";
// cache-browse: what the cache holds.
import { CacheSection } from "./CacheSection";
// dns-visibility: the upstreams with their times and states.
import { UpstreamsSection } from "./UpstreamsSection";
import { listenerDoc, listenerKey, serves, settingGroups, type DnsNodeStatus, type SettingRow } from "./model";
import "./dns-settings.css";

/** This server's node: its id (when it has one) and its roles. */
async function thisNode(): Promise<{ id: number | null; roles: string[] }> {
  const status = await api.get("/api/v1/system/status");
  const id = status.node.id;
  return { id: id === null || id === undefined ? null : Number(id), roles: status.node.roles };
}

function servedWord(on: boolean): string {
  return on ? t("dns.node.served") : t("dns.node.not_served");
}

function notDns(err: unknown): boolean {
  return err instanceof ApiError && err.code === "dns.node.not_dns";
}

function valueText(row: SettingRow): string {
  const v = row.value;
  if (v === null || v === undefined) return t("dns.node.unknown");
  switch (row.format) {
    case "bool":
      return v ? t("dns.node.yes") : t("dns.node.no");
    case "bytes":
      return formatBytes(Number(v));
    case "ratio":
      return formatNumber(Number(v), { style: "percent", maximumFractionDigits: 1 });
    case "time":
      return formatDateTime(String(v));
    case "word":
      return String(v);
    case "count":
      return formatNumber(Number(v));
  }
}

function Group(props: { title: string; section: string; doc: string; testid: string; children: JSX.Element }) {
  return (
    <section class="page-section dns-set-group" data-testid={props.testid}>
      <h2>
        {props.title} <code class="dns-set-section">{props.section}</code>
      </h2>
      <p class="muted dns-set-doc">
        {t("dns.node.doc")} <code data-testid="dns-setting-doc">{props.doc}</code>
      </p>
      {props.children}
    </section>
  );
}

function Status(props: { status: DnsNodeStatus }) {
  const groups = () => settingGroups(props.status);
  return (
    <>
      <Show when={(props.status.problems ?? []).length > 0}>
        <Notice kind="warn" role="status" title={t("dns.node.problems")} testid="dns-settings-problems">
          <ul class="dns-set-problems">
            <For each={props.status.problems}>{(p) => <li data-testid="dns-settings-problem">{p}</li>}</For>
          </ul>
        </Notice>
      </Show>
      <Show when={!props.status.query_log}>
        <p class="muted" data-testid="dns-settings-log-off">
          {t("dns.node.log_off")}
        </p>
      </Show>
      <Group title={t("dns.node.group.listeners")} section="[dns]" doc={listenerDoc("udp")} testid="dns-settings-listeners">
        <div class="table-wrap">
          <table class="plain">
            <caption class="sr-only">{t("dns.node.group.listeners")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("dns.node.col.address")}</th>
                <th scope="col">{t("dns.node.col.transport")}</th>
                <th scope="col" class="r">
                  {t("dns.node.col.workers")}
                </th>
                <th scope="col">{t("dns.node.col.key")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={props.status.listeners}>
                {(l, i) => (
                  <tr data-testid="dns-settings-listener" data-index={i()} data-key={l.address} data-kind={l.transport}>
                    <td class="mono">{l.address}</td>
                    <td>{t(`dns.log.transport.${l.transport}`)}</td>
                    <td class="r">{l.transport === "udp" ? formatNumber(l.workers) : ""}</td>
                    <td>
                      <code>{listenerKey(l.transport)}</code>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
        <p class="muted" data-testid="dns-settings-tls" data-dot={String(serves(props.status, "dot"))} data-doh={String(serves(props.status, "doh"))}>
          {t("dns.node.tls", { dot: servedWord(serves(props.status, "dot")), doh: servedWord(serves(props.status, "doh")) })}
        </p>
      </Group>
      {/* dns-visibility: the upstreams with their times and states. */}
      <UpstreamsSection groups={props.status.upstreams ?? []} />
      <For each={groups()}>
        {(group) => (
          <Group title={t(`dns.node.group.${group.id}`)} section={group.section} doc={group.doc} testid={`dns-settings-${group.id}`}>
            <dl class="kv dns-set-kv">
              <For each={group.rows}>
                {(row) => (
                  <>
                    <dt>{t(`dns.node.row.${row.id}`)}</dt>
                    <dd data-testid="dns-setting" data-key={row.id} data-value={row.value === null ? undefined : String(row.value)}>
                      <span class="mono">{valueText(row)}</span>
                      <Show when={row.key}>
                        {(key) => (
                          <>
                            {" "}
                            <code class="dns-set-key" data-testid="dns-setting-key">
                              {key()}
                            </code>
                          </>
                        )}
                      </Show>
                    </dd>
                  </>
                )}
              </For>
            </dl>
          </Group>
        )}
      </For>
    </>
  );
}

export default function DnsSettingsPage() {
  const [node] = createResource(thisNode);
  // `latest` throws the error of a failed read; these read it only when there is none.
  const here = () => (node.error ? undefined : node.latest);
  const id = () => here()?.id ?? undefined;
  const [status, { refetch }] = createResource(id, (n) => nodeDns(n));
  const current = () => (status.error ? undefined : status.latest);
  const roleMissing = () => !!here() && !here()?.roles.includes("dns");

  return (
    <div class="page" data-testid="page-dns-settings">
      <PageHead
        title={t("dns.node.title")}
        actions={
          <Show when={current()}>
            <button type="button" class="btn" data-testid="dns-settings-refresh" onClick={() => void refetch()}>
              {t("dns.node.refresh")}
            </button>
          </Show>
        }
      />
      <SettingsNav />
      <div class="page-body dns-set-body">
        <p class="muted">{t("dns.node.lede")}</p>
        <ErrorNotice error={node.error} />
        <Switch>
          <Match when={here()?.id === null}>
            <Notice kind="info" role="status" testid="dns-settings-no-node">
              {t("dns.node.no_node")}
            </Notice>
          </Match>
          <Match when={moduleOff(status.error)}>
            <Notice kind="warn" role="status" title={t("dns.state.off_title")} testid="dns-settings-off">
              {t("dns.node.off_body")}{" "}
              <A href={paths.settings()} data-testid="dns-modules-link">
                {t("dns.state.off_link")}
              </A>
            </Notice>
          </Match>
          <Match when={notBuilt(status.error)}>
            <Notice kind="info" role="status" title={t("dns.state.not_built_title")} testid="dns-not-built">
              {t("dns.state.not_built_body")}
            </Notice>
          </Match>
          <Match when={notDns(status.error) || (roleMissing() && status.error)}>
            <Notice kind="info" role="status" title={t("dns.node.no_role_title")} testid="dns-settings-no-role">
              {t("dns.node.no_role_body", { roles: "roles = \"controller,dns\"" })}
            </Notice>
          </Match>
          <Match when={status.error}>
            <ErrorNotice error={status.error} />
          </Match>
          <Match when={current()}>
            {(shown) => (
              <>
                <p class="muted">
                  {t("dns.node.forwarders_hint")}{" "}
                  <A href={dnsPaths.forwarders()} data-testid="dns-settings-forwarders">
                    {t("dns.node.forwarders_link")}
                  </A>
                </p>
                <Status status={shown()} />
                {/* cache-browse: what the cache holds. */}
                <CacheSection node={shown().node} />
              </>
            )}
          </Match>
        </Switch>
      </div>
    </div>
  );
}
