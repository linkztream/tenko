// The forwarding rules of the DNS area (/dns/forwarders, docs/dns-resolver.md section 2): the
// rules by suffix with the root rule (the default forwarder) first, their upstreams with the
// transport and the TLS name, and the view a rule applies in. Create, edit (with the rule's
// revision) and delete. Without a root rule the note says where the remaining names go: the
// configuration file's `[dns] forwarders`, which the node status does not list. Below the
// rules, who may recurse: the profile's default for the implicit default view, which is no
// row and so has nothing to edit (WP6.4: each view names its own recursion access list on the
// views page, linked here), and the problems the node reports for stub zones and recursion
// lists.
//
// dns-visibility: each upstream shows its state, its round-trip time on the node that answers
// (the median of the last minute) and the upstream the next query goes to (`upstream_status`).
import { A } from "@solidjs/router";
import { createResource, createSignal, For, Show } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { session } from "../../auth/session";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { DataGrid } from "../../grid/DataGrid";
import type { Column, RowAction } from "../../grid/types";
import { t } from "../../i18n";
import { mayWriteDns } from "../access";
import { DnsNav } from "../DnsNav";
import { logNodes, nodeDns } from "../log/api";
import { DnsProblem, unavailable } from "../Parts";
import { dnsPaths } from "../paths";
import { listForwarders, type ForwarderItem } from "./api";
import { DeleteForwarderDialog, ForwarderDialog } from "./ForwarderDialog";
import { isRoot, ruleOrder, upstreamEndpoint } from "./model";
// dns-visibility: the upstreams' figures.
import { UpstreamBadge } from "./figures";
import "../dns.css";

/** The problems the node reports for the resolver side; none while it cannot be read. */
async function nodeProblems(): Promise<string[]> {
  try {
    const [id] = await logNodes();
    if (id === undefined) return [];
    return (await nodeDns(id)).problems ?? [];
  } catch {
    return [];
  }
}

/** Who may recurse in the implicit default view, by the profile in force (section 2.3). */
function Recursion() {
  const profile = () => session()?.profile ?? "home";
  const rule = () => {
    const p = profile();
    return p === "hardened" ? "hardened" : p === "lab" ? "lab" : "known";
  };
  return (
    <section class="page-section dns-fwd-side" aria-labelledby="dns-recursion-title" data-testid="dns-recursion" data-state="default" data-key={profile()}>
      <h2 id="dns-recursion-title">{t("dns.fwd.recursion.title")}</h2>
      <p>{t(`dns.fwd.recursion.${rule()}`, { profile: t(`profile.${profile()}.name`) })}</p>
      <p class="muted">
        {t("dns.fwd.recursion.views")}{" "}
        {/* WP6.4: the recursion list of each view is edited on the views page. */}
        <A href={dnsPaths.views()} data-testid="fwd-views-link">
          {t("dns.fwd.recursion.views_link")}
        </A>
      </p>
    </section>
  );
}

export default function ForwardersPage() {
  const [dialog, setDialog] = createSignal<{ kind: "edit"; rule?: ForwarderItem } | { kind: "delete"; rule: ForwarderItem } | null>(null);
  const query = createLiveQuery({
    topics: ["dns"],
    fetch: async (signal) => {
      const page = await listForwarders(signal);
      return { value: [...page.items].sort(ruleOrder), revision: page.revision };
    },
  });
  const [problems] = createResource(nodeProblems);
  const blocked = () => unavailable(query.value.error);
  const rules = () => latest(query);
  const noRoot = () => {
    const list = rules();
    return list !== undefined && !list.some(isRoot);
  };
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };

  const columns: Column<ForwarderItem>[] = [
    {
      id: "suffix",
      header: () => t("dns.fwd.col.suffix"),
      width: 220,
      fixed: true,
      text: (r) => r.suffix,
      render: (r) => (
        <span class="dns-chips">
          <span class="mono">{r.suffix}</span>
          <Show when={isRoot(r)}>
            <span class="tag accent" data-testid="fwd-default">
              {t("dns.fwd.default")}
            </span>
          </Show>
        </span>
      ),
    },
    {
      id: "transport",
      header: () => t("dns.fwd.col.transport"),
      width: 150,
      text: (r) => t(`dns.fwd.transport.${r.transport ?? "plain"}`),
      render: (r) => (
        <span class="tag" data-testid="fwd-transport" data-kind={r.transport ?? "plain"}>
          {t(`dns.fwd.transport.${r.transport ?? "plain"}`)}
        </span>
      ),
    },
    {
      id: "upstreams",
      header: () => t("dns.fwd.col.upstreams"),
      text: (r) => (r.upstreams ?? []).map((u) => upstreamEndpoint(u, r.transport ?? "plain")).join(", "),
      render: (r) => (
        <span class="dns-chips">
          <For each={r.upstreams ?? []}>
            {(u, i) => (
              <span class="fwd-up" data-testid="fwd-upstream-cell" data-key={upstreamEndpoint(u, r.transport ?? "plain")}>
                <span class="tag mono" data-testid="fwd-upstream" data-key={upstreamEndpoint(u, r.transport ?? "plain")}>
                  {upstreamEndpoint(u, r.transport ?? "plain")}
                  {u.path ?? ""}
                </span>
                {/* The figures come in the rule's order of upstreams. */}
                <Show when={r.upstream_status?.[i()]}>{(figures) => <UpstreamBadge figures={figures()} />}</Show>
              </span>
            )}
          </For>
        </span>
      ),
    },
    { id: "tls_name", header: () => t("dns.fwd.col.tls_name"), width: 200, text: (r) => r.tls_name ?? "", render: (r) => <span class="mono">{r.tls_name ?? ""}</span> },
    {
      id: "view",
      header: () => t("dns.fwd.col.view"),
      width: 140,
      text: (r) => r.view ?? "",
      render: (r) => (
        <Show when={r.view} fallback={<span class="muted">{t("dns.fwd.all_views")}</span>}>
          <span class="mono">{r.view}</span>
        </Show>
      ),
    },
    { id: "description", header: () => t("dns.col.description"), width: 200, render: (r) => <span class="muted">{r.description ?? ""}</span> },
  ];
  const actions: RowAction<ForwarderItem>[] = [
    { id: "edit", label: () => t("dns.do.edit"), hidden: () => !mayWriteDns(), run: (r) => setDialog({ kind: "edit", rule: r }) },
    { id: "delete", label: () => t("dns.do.delete"), danger: true, hidden: () => !mayWriteDns(), run: (r) => setDialog({ kind: "delete", rule: r }) },
  ];

  return (
    <div class="page dns-page list-page" data-testid="page-dns-forwarders">
      <DnsNav />
      <PageHead
        title={t("dns.fwd.title")}
        sub={t("dns.fwd.sub")}
        actions={
          <Show when={mayWriteDns() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dns-forwarder-create" onClick={() => setDialog({ kind: "edit" })}>
              <Icon name="plus" />
              {t("dns.fwd.create")}
            </button>
          </Show>
        }
      />
      <Show when={!blocked()} fallback={<div class="page-body"><DnsProblem error={query.value.error} /></div>}>
        <Show when={noRoot() || (problems.latest ?? []).length > 0}>
          <div class="dns-fwd-notes">
            <Show when={noRoot()}>
              <Notice kind="info" role="status" title={t("dns.fwd.no_default_title")} testid="fwd-no-default">
                {t("dns.fwd.no_default_body")}{" "}
                <A href={dnsPaths.settings()} data-testid="fwd-settings-link">
                  {t("dns.fwd.no_default_link")}
                </A>
              </Notice>
            </Show>
            <Show when={(problems.latest ?? []).length > 0}>
              <Notice kind="warn" role="status" title={t("dns.fwd.problems_title")} testid="fwd-problems">
                <ul class="dns-fwd-problems">
                  <For each={problems.latest}>{(p) => <li data-testid="fwd-problem">{p}</li>}</For>
                </ul>
              </Notice>
            </Show>
          </div>
        </Show>
        <div class="dns-list-body">
          <DataGrid
            id="dns-forwarders"
            label={t("dns.fwd.title")}
            noSelection
            columns={columns}
            rows={rules() ?? []}
            rowId={(r) => r.id}
            rowKey={(r) => (r.view ? `${r.suffix}@${r.view}` : r.suffix)}
            rowLabel={(r) => r.suffix}
            loading={query.value.loading}
            initial={rules() === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(r) => (mayWriteDns() ? setDialog({ kind: "edit", rule: r }) : undefined)}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dns-forwarders-empty">
                <h3>{t("dns.fwd.empty")}</h3>
                <p>{t("dns.fwd.empty_body")}</p>
              </div>
            }
          />
        </div>
        <Recursion />
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "edit" ? (
            <ForwarderDialog rule={d.rule} onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <DeleteForwarderDialog rule={d.rule} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
