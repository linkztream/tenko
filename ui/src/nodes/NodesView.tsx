// The cluster nodes (/nodes, /nodes/<id>; OPS-04): the enrolled data-plane nodes with their
// roles, address, connection, versions, certificate expiry and last sighting, live on the
// `cluster` topic; the node in the URL docked beside the list. The cluster summary of the
// system status (the cluster port, the protocol majors, the versions of the connected nodes)
// and the warning of nodes that share no protocol major with this controller. Administrators
// manage the enrolment tokens: create one (shown once, with the command to run on the node),
// see their state, and delete them.
import { A, useNavigate, useParams } from "@solidjs/router";
import { createMemo, createSignal, For, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { deleteEnrolment, listEnrolments, type EnrolmentView, type NodeView } from "../api/nodes";
import { errorMessage } from "../api/problem";
import type { SystemStatus } from "../api/types";
import { paths } from "../app/paths";
import { isAdmin } from "../auth/session";
import { ConfirmDialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { DataGrid } from "../grid/DataGrid";
import { createColumnState } from "../grid/prefs";
import { createListSource } from "../grid/source";
import type { Column } from "../grid/types";
import { formatList, t } from "../i18n";
import { useCommands } from "../shell/commands";
import { EnrolDialog } from "./EnrolDialog";
import { linkState, linkWord, roleWord, tokenStateWord } from "./model";
import { CertificateText, LinkBadge, NodePanel } from "./NodePanel";
// node-roles: the roles of this controller.
import { RolesEditor } from "./RolesEditor";
import "./nodes.css";

/** The status warning of nodes with a refused handshake (docs/cluster.md, section 5). */
const MISMATCH_WARNING = "cluster.protocol.mismatch";

function nodeColumns(): Column<NodeView>[] {
  return [
    {
      id: "name",
      header: () => t("nodes.col.name"),
      width: 180,
      fixed: true,
      text: (n) => n.name,
      render: (n) => (
        <A href={paths.node(n.id)} class="mono node-name" tabIndex={-1}>
          {n.name}
        </A>
      ),
    },
    { id: "roles", header: () => t("nodes.col.roles"), width: 140, text: (n) => n.roles.map(roleWord).join(", "), render: (n) => n.roles.map(roleWord).join(", ") },
    { id: "address", header: () => t("nodes.col.address"), width: 160, render: (n) => <span class="mono">{n.address ?? "–"}</span> },
    {
      id: "link",
      header: () => t("nodes.col.connected"),
      width: 170,
      text: (n) => linkWord(linkState(n)),
      render: (n) => <LinkBadge node={n} />,
    },
    {
      id: "version",
      header: () => t("nodes.col.version"),
      width: 150,
      render: (n) => (
        <span class="mono">
          {n.version ?? "–"}
          <Show when={n.connection?.major ?? n.protocol.agreed}>{(major) => <span class="muted"> · {t("nodes.col.major", { major: major() })}</span>}</Show>
        </span>
      ),
    },
    { id: "certificate", header: () => t("nodes.col.certificate"), width: 150, render: (n) => <CertificateText node={n} /> },
    { id: "last_seen", header: () => t("nodes.col.last_seen"), width: 120, render: (n) => <TimeAgo at={n.last_seen} /> },
    { id: "id", header: () => t("nodes.col.id"), width: 80, hidden: true, align: "right", render: (n) => <span class="num">{n.id}</span> },
  ];
}

export default function NodesView() {
  const params = useParams<{ id?: string }>();
  const navigate = useNavigate();
  const admin = () => isAdmin();

  const source = createListSource<NodeView>({
    path: "/api/v1/nodes",
    query: () => ({}),
    rowId: (n) => String(n.id),
    topics: ["cluster"],
  });
  const status = createLiveQuery<SystemStatus>({
    topics: ["cluster"],
    debounceMs: 500,
    fetch: async (signal) => ({ value: await api.get("/api/v1/system/status", { signal }) }),
  });
  const tokens = createLiveQuery<EnrolmentView[] | null>({
    topics: ["cluster"],
    fetch: async (signal) => ({ value: admin() ? await listEnrolments(signal) : null }),
  });

  const columns = nodeColumns();
  const columnState = createColumnState("nodes", () => columns);
  const [enrolling, setEnrolling] = createSignal(false);
  const [withdrawing, setWithdrawing] = createSignal<EnrolmentView | null>(null);

  // Reading `latest` of a failed load throws the error at the reader, so a failed load reads as no
  // value (the token list shows its error).
  const system = () => (status.value.error ? undefined : status.value.latest);
  const tokenList = () => (tokens.value.error ? undefined : tokens.value.latest);
  const cluster = () => system()?.cluster ?? null;
  const mismatch = createMemo(() => system()?.warnings.find((w) => w.code === MISMATCH_WARNING));
  const mismatchNames = () => {
    const ids = (mismatch()?.params?.nodes ?? "").split(",").filter(Boolean);
    return ids.map((id) => source.rows().find((n) => String(n.id) === id)?.name ?? id);
  };
  const open = (n: NodeView) => navigate(paths.node(n.id));

  useCommands(() => [
    {
      id: "nodes.enrol",
      group: "actions",
      icon: "plus",
      label: () => t("nodes.action.enrol"),
      when: admin,
      run: () => setEnrolling(true),
    },
  ]);

  const onGridClick = (e: MouseEvent) => {
    const el = e.target as HTMLElement;
    if (el.closest("a, button, input, select, textarea")) return;
    const id = el.closest<HTMLElement>("tr[data-id]")?.dataset.id;
    if (id) navigate(paths.node(id));
  };

  const withdraw = async (token: EnrolmentView) => {
    try {
      await deleteEnrolment(token.id);
      toast({ kind: "ok", title: t("nodes.token.deleted") });
      tokens.refetch();
    } catch (err) {
      toast({ kind: "bad", title: t("nodes.token.delete_failed"), body: errorMessage(err) });
    }
  };

  const summary = () => {
    const c = cluster();
    if (!c) return undefined;
    return t("nodes.summary", { nodes: c.nodes, connected: c.connected });
  };

  return (
    <div class="page nodes-page" data-testid="page-nodes">
      <PageHead
        title={t("shell.nav.nodes")}
        sub={summary()}
        actions={
          <Show when={admin()}>
            <button type="button" class="btn primary" data-testid="nodes-enrol" onClick={() => setEnrolling(true)}>
              <Icon name="plus" />
              {t("nodes.action.enrol")}
            </button>
          </Show>
        }
      />
      <div class="nodes-notes">
        <Show when={mismatch()}>
          {(w) => (
            <Notice kind="bad" testid="nodes-version-mismatch" role="alert">
              {t("nodes.mismatch", { count: Number(w().params?.count ?? 1), names: formatList(mismatchNames()), majors: (cluster()?.majors ?? []).join(", ") })}
            </Notice>
          )}
        </Show>
        <Show when={cluster()}>
          {(c) => (
            <p class="muted nodes-cluster" data-testid="nodes-cluster">
              <Show when={c().listening.length > 0} fallback={t("nodes.port_closed")}>
                {t("nodes.port_open", { addresses: c().listening.join(", "), majors: c().majors.join(", ") })}
              </Show>
              <Show when={Object.keys(c().versions).length > 0}>
                {" · "}
                {t("nodes.versions", {
                  versions: Object.entries(c().versions)
                    .map(([v, n]) => t("nodes.version_count", { version: v, count: n }))
                    .join(", "),
                })}
              </Show>
            </p>
          )}
        </Show>
      </div>
      <div class="nodes-split" classList={{ "with-panel": !!params.id }}>
        <div class="nodes-main">
          <div class="nodes-grid" onClick={onGridClick}>
            <DataGrid
              id="nodes"
              label={t("nodes.grid.label")}
              columns={columns}
              columnState={columnState}
              rows={source.rows()}
              rowId={(n) => String(n.id)}
              rowKey={(n) => n.name}
              rowLabel={(n) => n.name}
              rowClass={(n) => (linkState(n) === "mismatch" ? "node-mismatch" : String(n.id) === params.id ? "current" : undefined)}
              noSelection
              loading={source.loading()}
              initial={source.initial()}
              hasMore={source.hasMore()}
              onLoadMore={source.loadMore}
              error={source.error()}
              onRetry={source.reload}
              flashed={source.flashed}
              onOpen={open}
              onDetails={open}
              onOpenPage={open}
              empty={
                <div class="empty" data-testid="nodes-empty">
                  <h3>{t("nodes.empty.title")}</h3>
                  <p>{t("nodes.empty.body")}</p>
                </div>
              }
            />
          </div>

          {/* node-roles: the roles of the controller that serves this page, which the node list does not show. */}
          <Show when={system()?.node.id}>
            {(id) => (
              <section class="page-section nodes-self" aria-labelledby="nodes-self" data-testid="nodes-self">
                <h2 id="nodes-self">
                  {t("nodes.roles.self_title")}
                  <span class="aside">{t("nodes.roles.self_hint", { id: id() })}</span>
                </h2>
                <RolesEditor id={id()} bare />
              </section>
            )}
          </Show>
          <Show when={admin()}>
            <section class="page-section nodes-tokens" aria-labelledby="nodes-tokens" data-testid="nodes-tokens">
              <h2 id="nodes-tokens">
                {t("nodes.token.title")}
                <span class="aside">{t("nodes.token.hint")}</span>
              </h2>
              <ErrorNotice error={tokens.value.error} />
              <Show
                when={(tokenList() ?? []).length > 0}
                fallback={
                  <Show when={!tokens.value.error}>
                    <p class="muted">{t("nodes.token.none")}</p>
                  </Show>
                }
              >
                <div class="table-wrap">
                  <table class="plain" aria-label={t("nodes.token.title")}>
                    <thead>
                      <tr>
                        <th scope="col">{t("nodes.token.col.state")}</th>
                        <th scope="col">{t("nodes.token.col.name")}</th>
                        <th scope="col">{t("nodes.token.col.roles")}</th>
                        <th scope="col">{t("nodes.token.col.created")}</th>
                        <th scope="col">{t("nodes.token.col.expires")}</th>
                        <th scope="col">{t("nodes.token.col.used")}</th>
                        <th scope="col" class="r">
                          <span class="sr-only">{t("nodes.token.col.actions")}</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={tokenList() ?? []}>
                        {(token) => (
                          <tr data-testid="enrolment" data-id={token.id} data-state={token.state}>
                            <td>
                              <span class={`tag token-state ${token.state}`}>{tokenStateWord(token.state)}</span>
                            </td>
                            <td class="mono">{token.name ?? t("nodes.token.any_name")}</td>
                            <td>{token.roles.map(roleWord).join(", ")}</td>
                            <td>
                              <TimeAgo at={token.created_at} />
                            </td>
                            <td>
                              <TimeAgo at={token.expires_at} />
                            </td>
                            <td>
                              <Show when={token.used} fallback={<span class="muted">–</span>}>
                                {(u) => (
                                  <A href={paths.node(u().node)} class="mono" data-testid="enrolment-node" data-id={u().node}>
                                    {source.rows().find((n) => n.id === u().node)?.name ?? t("nodes.panel.id", { id: u().node })}
                                  </A>
                                )}
                              </Show>
                            </td>
                            <td class="r">
                              <button
                                type="button"
                                class="btn sm"
                                data-testid="enrolment-delete"
                                aria-label={t("nodes.token.delete_named", { name: token.name ?? token.id.slice(0, 8) })}
                                onClick={() => setWithdrawing(token)}
                              >
                                <Icon name="trash" size="sm" />
                                {t("nodes.token.delete")}
                              </button>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
              </Show>
            </section>
          </Show>
        </div>
        <Show when={params.id} keyed>
          {(id) => (
            <NodePanel
              id={id}
              onClose={() => navigate(paths.nodes())}
              onRevoked={() => {
                navigate(paths.nodes());
                source.reload();
              }}
            />
          )}
        </Show>
      </div>

      <Show when={enrolling()}>
        <EnrolDialog onClose={() => setEnrolling(false)} onCreated={() => tokens.refetch()} />
      </Show>
      <Show when={withdrawing()} keyed>
        {(token) => (
          <ConfirmDialog
            title={t("nodes.token.delete_title")}
            body={<p>{token.state === "pending" ? t("nodes.token.delete_pending") : t("nodes.token.delete_done")}</p>}
            confirmLabel={t("nodes.token.delete")}
            cancelLabel={t("common.action.cancel")}
            danger
            onClose={() => setWithdrawing(null)}
            onConfirm={() => {
              setWithdrawing(null);
              void withdraw(token);
            }}
          />
        )}
      </Show>
    </div>
  );
}
