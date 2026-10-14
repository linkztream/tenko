// The cluster page (/cluster; OPS-03, OPS-26): the controllers of the installation with their
// role, health, replication lag and last contact, live on the `cluster` topic. Administrators
// promote a learner, remove a member, hand leadership over and add a controller (a join token,
// shown once); everyone can check that the members hold the same data. Each change shows its
// preview first (MemberDialogs.tsx) and the answer of the server replaces the table.
import { A, useNavigate } from "@solidjs/router";
import { createEffect, createSignal, For, on, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { paths } from "../app/paths";
import { isAdmin } from "../auth/session";
import { Icon, type IconName } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { formatDateTime, formatNumber, t } from "../i18n";
import { EnrolDialog } from "../nodes/EnrolDialog";
import { listMembers, systemStatus } from "./api";
import { DigestPanel } from "./DigestPanel";
import { FormatPanel } from "./FormatPanel";
import { PromoteDialog, RemoveDialog, StepDownDialog } from "./MemberDialogs";
import { compatParts, contactText, healthWord, memberHealth, memberName, quorumWord, roleWord, sortMembers, toleranceText, voters, type ClusterView, type MemberHealth, type MemberView, type StepDown, CLUSTER_QUEUE_PATH } from "./model";
import "./cluster.css";

const HEALTH_ICON: Record<MemberHealth, IconName> = {
  leader: "check",
  caught_up: "check",
  catching_up: "refresh",
  out_of_contact: "alert",
  unknown: "pause",
};

export default function ClusterPage() {
  const navigate = useNavigate();
  const admin = () => isAdmin();

  const live = createLiveQuery<ClusterView>({
    topics: ["cluster"],
    fetch: async (signal) => ({ value: await listMembers(signal) }),
  });
  // The data format and the warnings come from the status of this node.
  const status = createLiveQuery({
    topics: ["system", "cluster"],
    fetch: async (signal) => ({ value: await systemStatus(signal) }),
  });
  // The answer of a membership change is the new view; it stands until the next live read.
  const [answered, setAnswered] = createSignal<ClusterView | null>(null);
  createEffect(on(() => live.latest(), () => setAnswered(null), { defer: true }));
  const view = (): ClusterView | undefined => answered() ?? live.latest();

  const [promoting, setPromoting] = createSignal<MemberView | null>(null);
  const [removing, setRemoving] = createSignal<MemberView | null>(null);
  const [steppingDown, setSteppingDown] = createSignal(false);
  const [adding, setAdding] = createSignal(false);

  const members = () => sortMembers(view()?.members ?? []);
  const nameOfNode = (node: number | null | undefined): string | undefined => {
    const found = node == null ? undefined : view()?.members.find((m) => m.node === node);
    return found ? memberName(found) : undefined;
  };
  const leads = (v: ClusterView) => v.leader != null && v.leader === v.node && v.members.length > 1;

  const changed = (title: string, next: ClusterView) => {
    setAnswered(next);
    const job = next.job_id;
    toast({ kind: "ok", title, actions: job ? [{ label: t("cluster.done.open_job"), run: () => navigate(paths.job(job)) }] : [] });
  };

  const promoted = (member: MemberView, next: ClusterView) => {
    setPromoting(null);
    changed(t("cluster.done.promoted", { name: memberName(member) }), next);
  };
  const removed = (member: MemberView, next: ClusterView) => {
    setRemoving(null);
    changed(t("cluster.done.removed", { name: memberName(member) }), next);
  };
  const steppedDown = (answer: StepDown) => {
    setSteppingDown(false);
    live.refetch();
    toast({ kind: "ok", title: t("cluster.done.stepped_down", { name: nameOfNode(answer.leader) ?? t("cluster.member.unnamed", { id: answer.leader }), term: formatNumber(answer.term) }) });
  };

  return (
    <div class="page" data-testid="page-cluster">
      <PageHead
        title={t("cluster.title")}
        actions={
          <>
            <A href={CLUSTER_QUEUE_PATH} class="btn" data-testid="cluster-queue-link">
              {t("cluster.action.queue")}
            </A>
            <Show when={admin()}>
              <button type="button" class="btn primary" data-testid="cluster-add-controller" onClick={() => setAdding(true)}>
                <Icon name="plus" />
                {t("cluster.action.add")}
              </button>
            </Show>
          </>
        }
      />
      <div class="page-body">
        <ErrorNotice error={live.value.error} />
        <Show when={view()} fallback={<Show when={!live.value.error}><p class="muted" role="status">{t("common.loading")}</p></Show>}>
          {(v) => (
            <>
              <section class="cluster-summary" aria-label={t("cluster.summary.label")} data-testid="cluster-summary">
                <dl class="cluster-facts">
                  <div>
                    <dt>{t("cluster.summary.quorum")}</dt>
                    <dd data-testid="cluster-quorum" data-state={v().quorum.state}>
                      {quorumWord(v().quorum.state)}
                      <Show when={v().quorum.since}>{(since) => <span class="muted"> · {t("cluster.summary.since", { since: formatDateTime(since()) })}</span>}</Show>
                    </dd>
                  </div>
                  <div>
                    <dt>{t("cluster.summary.term")}</dt>
                    <dd class="num" data-testid="cluster-term">
                      {formatNumber(v().term)}
                    </dd>
                  </div>
                  <div>
                    <dt>{t("cluster.summary.leader")}</dt>
                    <dd data-testid="cluster-leader" data-node={v().leader ?? undefined}>
                      {nameOfNode(v().leader) ?? t("cluster.summary.no_leader")}
                    </dd>
                  </div>
                  <div>
                    <dt>{t("cluster.summary.voters")}</dt>
                    <dd data-testid="cluster-voters" data-count={voters(v()).length}>
                      {t("cluster.summary.voters_value", { count: voters(v()).length, tolerance: toleranceText(voters(v()).length) })}
                    </dd>
                  </div>
                  <div>
                    <dt>{t("cluster.summary.node")}</dt>
                    <dd data-testid="cluster-node" data-node={v().node}>
                      {nameOfNode(v().node) ?? t("cluster.member.unnamed", { id: v().node })}
                    </dd>
                  </div>
                </dl>
                <Show when={v().changing}>
                  <Notice kind="info" role="status" testid="cluster-changing">
                    {t("cluster.changing")}
                  </Notice>
                </Show>
                <Show when={admin() && leads(v())}>
                  <div class="cluster-actions">
                    <button type="button" class="btn" data-testid="cluster-step-down" onClick={() => setSteppingDown(true)}>
                      {t("cluster.action.step_down")}
                    </button>
                  </div>
                </Show>
              </section>

              <Show when={status.latest()}>{(st) => <FormatPanel status={st()} members={v().members} />}</Show>

              <section class="page-section" aria-labelledby="cluster-members-title">
                <h2 id="cluster-members-title">
                  {t("cluster.members.title")}
                  <span class="aside">{t("cluster.members.count", { count: v().members.length })}</span>
                </h2>
                <div class="table-wrap">
                  <table class="plain cluster-members" aria-label={t("cluster.members.title")} data-testid="cluster-members">
                    <thead>
                      <tr>
                        <th scope="col">{t("cluster.col.name")}</th>
                        <th scope="col">{t("cluster.col.address")}</th>
                        <th scope="col">{t("cluster.col.role")}</th>
                        <th scope="col">{t("cluster.col.health")}</th>
                        <th scope="col" class="r">
                          {t("cluster.col.lag")}
                        </th>
                        <th scope="col">{t("cluster.col.contact")}</th>
                        <th scope="col">{t("cluster.col.version")}</th>
                        <th scope="col">{t("cluster.col.compat")}</th>
                        <th scope="col">{t("cluster.col.joined")}</th>
                        <Show when={admin()}>
                          <th scope="col" class="r">
                            <span class="sr-only">{t("cluster.col.actions")}</span>
                          </th>
                        </Show>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={members()}>
                        {(m) => {
                          const health = () => memberHealth(m);
                          const name = () => memberName(m);
                          return (
                            <tr data-testid={`member-row-${m.node}`} data-id={m.node} data-state={health()} data-role={m.role} classList={{ leader: m.leader }}>
                              <td>
                                <span class="mono member-name">{name()}</span>
                                <Show when={m.leader}>
                                  <span class="member-leader" data-testid="member-leader" title={t("cluster.member.leader_marker")}>
                                    <Icon name="bolt" size="xs" />
                                  </span>
                                </Show>
                              </td>
                              <td class="mono">{m.address ?? "–"}</td>
                              <td>{roleWord(m.role)}</td>
                              <td>
                                <span class={`tag cluster-health ${health()}`} data-state={health()} data-testid="member-health">
                                  <Icon name={HEALTH_ICON[health()]} size="xs" />
                                  {healthWord(health())}
                                </span>
                              </td>
                              <td class="r num" data-testid="member-lag">
                                {m.lag_entries != null ? formatNumber(m.lag_entries) : "–"}
                              </td>
                              <td data-testid="member-contact">{contactText(m.last_contact_ms)}</td>
                              <td>
                                <span class="mono">{m.version ?? "–"}</span>
                                <Show when={m.data_format != null}>
                                  <span class="muted"> · {t("cluster.col.format", { format: m.data_format ?? 0 })}</span>
                                </Show>
                              </td>
                              <td data-testid={`member-compat-${m.node}`}>
                                {(() => {
                                  const c = compatParts(m);
                                  return (
                                    <span class="member-compat" title={t("cluster.compat.tooltip", c)}>
                                      <span data-testid="compat-majors">{c.majors}</span>
                                      <span class="muted"> · </span>
                                      <span class="mono" data-testid="compat-wire">{c.wire}</span>
                                      <span class="muted"> · </span>
                                      <span data-testid="compat-formats">{c.formats}</span>
                                    </span>
                                  );
                                })()}
                              </td>
                              <td>
                                <TimeAgo at={m.joined_at} />
                              </td>
                              <Show when={admin()}>
                                <td class="r">
                                  <div class="cluster-actions end">
                                    <Show when={m.role === "learner"}>
                                      <button
                                        type="button"
                                        class="btn sm"
                                        data-testid={`member-promote-${m.node}`}
                                        aria-label={t("cluster.action.promote_named", { name: name() })}
                                        onClick={() => setPromoting(m)}
                                      >
                                        {t("cluster.action.promote")}
                                      </button>
                                    </Show>
                                    <button
                                      type="button"
                                      class="btn sm"
                                      data-testid={`member-remove-${m.node}`}
                                      aria-label={t("cluster.action.remove_named", { name: name() })}
                                      onClick={() => setRemoving(m)}
                                    >
                                      <Icon name="trash" size="sm" />
                                      {t("cluster.action.remove")}
                                    </button>
                                  </div>
                                </td>
                              </Show>
                            </tr>
                          );
                        }}
                      </For>
                    </tbody>
                  </table>
                </div>
              </section>

              <DigestPanel members={() => v().members} />

              <Show when={promoting()} keyed>
                {(member) => <PromoteDialog view={() => v()} member={member} onDone={(next) => promoted(member, next)} onClose={() => setPromoting(null)} />}
              </Show>
              <Show when={removing()} keyed>
                {(member) => <RemoveDialog view={() => v()} member={member} onDone={(next) => removed(member, next)} onClose={() => setRemoving(null)} />}
              </Show>
              <Show when={steppingDown()}>
                <StepDownDialog view={() => v()} onDone={steppedDown} onClose={() => setSteppingDown(false)} />
              </Show>
            </>
          )}
        </Show>
      </div>
      <Show when={adding()}>
        <EnrolDialog
          roles={["controller"]}
          title={t("cluster.add.title")}
          intro={t("cluster.add.intro")}
          next={t("cluster.add.next")}
          onCreated={() => live.refetch()}
          onClose={() => setAdding(false)}
        />
      </Show>
    </div>
  );
}
