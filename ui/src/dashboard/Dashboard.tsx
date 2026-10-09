// The start page (decision 13): the node at a glance, the utilization of the networks per
// tenant and VRF, the active utilization alarms, the jobs that wait for a person, the most
// recent audit records, and the quick actions (claim the next free address, a new prefix,
// an import). Every number that can grow is an SI number with the exact value as tooltip;
// utilization is a bar, never a gauge.
import { A, useNavigate } from "@solidjs/router";
import { createMemo, createSignal, For, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { fetchAll } from "../api/paginate";
import type { AuditRecord, JobSummary, Range, Tenant, TreeNode, TreeResponse, Vrf } from "../api/types";
import { paths } from "../app/paths";
import { Addr } from "../components/Addr";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { PageHead } from "../components/PageHead";
import { PrincipalLabel } from "../components/Principal";
import { Si } from "../components/Si";
import { AlarmFlag, Count, TimeAgo, UtilizationMeter } from "../grid/cells";
import { formatDuration, t, type MessageKey } from "../i18n";
import { isAlarmEvent } from "../ipam/alarms";
import { MoveDialog } from "../ipam/move/MoveDialog";
import { NextFreeAddressDialog } from "../ipam/prefix/NextFreeDialogs";
import { PrefixForm } from "../ipam/prefix/PrefixForm";
import { useScope } from "../ipam/scope";
import { JobStateChip } from "../jobs/StateChip";
import { jobTitle } from "../jobs/words";
import { createShellStatus } from "../shell/status";
import { storeRoleLabel } from "../shell/TopBar";
import "./dashboard.css";

const ROLE: Record<string, MessageKey> = {
  controller: "node.role.controller",
  dns: "node.role.dns",
  dhcp: "node.role.dhcp",
  probe: "node.role.probe",
};

/** Networks shown per VRF; the busiest first. */
const NETWORKS_SHOWN = 8;

interface VrfUse {
  vrf: Vrf;
  tenant: Tenant | undefined;
  networks: TreeNode[];
  used: bigint;
  capacity: bigint;
}

function big(text: string): bigint {
  try {
    return BigInt(text);
  } catch {
    return 0n;
  }
}

/** Utilization of every VRF from its prefix tree (the networks only, so nothing counts twice). */
function useUtilization() {
  return createLiveQuery<VrfUse[]>({
    topics: ["ipam", "system"],
    relevant: (e) => isAlarmEvent(e) || e.objects.some((o) => o.kind === "prefix" || o.kind === "address" || o.kind === "range"),
    debounceMs: 500,
    fetch: async (signal) => {
      const [tenants, vrfs] = await Promise.all([
        fetchAll<Tenant>("/api/v1/tenants", { signal }),
        fetchAll<Vrf>("/api/v1/vrfs", { signal }),
      ]);
      const trees: TreeResponse[] = await Promise.all(
        vrfs.items.map((vrf) => api.get("/api/v1/prefixes/tree", { query: { vrf: vrf.id }, signal })),
      );
      const value = vrfs.items.map((vrf, i) => {
        const networks = (trees[i]?.nodes ?? []).filter((n) => n.role === "network");
        const used = networks.reduce((sum, n) => sum + big(n.utilization.used) + big(n.utilization.reserved), 0n);
        const capacity = networks.reduce((sum, n) => sum + big(n.utilization.capacity), 0n);
        return {
          vrf,
          tenant: tenants.items.find((tn) => tn.id === vrf.tenant),
          networks: [...networks].sort((a, b) => b.utilization.percent - a.utilization.percent),
          used,
          capacity,
        };
      });
      return { value, revision: vrfs.revision as number };
    },
  });
}

/** One decimal percent of two big counts. */
function percentOf(used: bigint, capacity: bigint): number {
  if (capacity === 0n) return 0;
  return Number((used * 1000n) / capacity) / 10;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const status = createShellStatus();
  const scope = useScope();
  const s = () => status.system();
  const use = useUtilization();
  const vrfs = () => use.value.latest ?? [];
  const alarms = createMemo(() =>
    vrfs()
      .flatMap((v) => v.networks.filter((n) => n.level !== "normal").map((node) => ({ vrf: v.vrf, node })))
      .sort((a, b) => (a.node.level === b.node.level ? b.node.utilization.percent - a.node.utilization.percent : a.node.level === "critical" ? -1 : 1)),
  );

  const waiting = createLiveQuery<JobSummary[]>({
    topics: ["jobs"],
    fetch: async (signal) => {
      const page = await api.get("/api/v1/jobs", { query: { state: ["waiting", "rolling_back"], limit: 100 }, signal });
      return { value: page.items.filter((j) => (j.manual_steps ?? []).length > 0), revision: page.revision };
    },
  });
  const audit = createLiveQuery<AuditRecord[]>({
    topics: ["audit"],
    fetch: async (signal) => {
      const page = await api.get("/api/v1/audit", { query: { order: "desc", limit: 8 }, signal });
      return { value: page.items, revision: page.revision };
    },
  });

  const [action, setAction] = createSignal<"claim" | "claim_in" | "prefix" | null>(null);
  const [claimIn, setClaimIn] = createSignal<TreeNode | null>(null);
  const defaultTree = (): TreeResponse | undefined => {
    const v = vrfs().find((x) => x.vrf.id === scope.vrf()?.id);
    return v ? { nodes: v.networks, revision: 0, vrf: v.vrf.id } : undefined;
  };

  return (
    <div class="page dashboard" data-testid="page-dashboard">
      <PageHead
        title={t("shell.nav.dashboard")}
        sub={t("shell.dashboard.sub")}
        actions={
          <>
            <button type="button" class="btn" data-testid="dashboard-claim" onClick={() => setAction("claim")} disabled={!scope.vrf()}>
              <Icon name="plus" />
              {t("dashboard.action.claim")}
            </button>
            <button type="button" class="btn" data-testid="dashboard-new-prefix" onClick={() => setAction("prefix")} disabled={!scope.vrf()}>
              <Icon name="layers" />
              {t("dashboard.action.prefix")}
            </button>
            <A class="btn" href={paths.imports()} data-testid="dashboard-import">
              <Icon name="export" />
              {t("dashboard.action.import")}
            </A>
          </>
        }
      />
      <div class="page-body wide dash-body">
        <div class="tiles">
          <section class="card tile">
            <h2>{t("shell.dashboard.node")}</h2>
            <div class="tile-value">{s() ? storeRoleLabel(s()?.store.role) : "–"}</div>
            <p class="muted">
              <For each={s()?.node.roles ?? []} fallback={t("shell.dashboard.no_roles")}>
                {(r, i) => (
                  <>
                    {i() > 0 ? ", " : ""}
                    {ROLE[r] ? t(ROLE[r]!) : r}
                  </>
                )}
              </For>
            </p>
          </section>
          <section class="card tile">
            <h2>{t("dashboard.tile.addresses")}</h2>
            <div class="tile-value">
              <Count value={vrfs().reduce((n, v) => n + v.used, 0n)} />
            </div>
            <p class="muted">
              {t("dashboard.tile.addresses_of")} <Count value={vrfs().reduce((n, v) => n + v.capacity, 0n)} />
            </p>
          </section>
          <section class="card tile">
            <h2>{t("dashboard.tile.alarms")}</h2>
            <div class="tile-value">
              <Si value={alarms().length} />
            </div>
            <p class="muted">{t("dashboard.tile.alarms_hint", { critical: alarms().filter((a) => a.node.level === "critical").length })}</p>
          </section>
          <section class="card tile">
            <h2>{t("shell.dashboard.jobs")}</h2>
            <div class="tile-value">
              <Si value={status.jobs() ? status.jobs()!.running + status.jobs()!.waiting : null} />
            </div>
            <p class="muted">{t("dashboard.tile.waiting_for_you", { count: waiting.value.latest?.length ?? 0 })}</p>
          </section>
          <section class="card tile">
            <h2>{t("shell.dashboard.uptime")}</h2>
            <div class="tile-value">{s() ? formatDuration(Math.floor((s()?.uptime_seconds ?? 0) / 60) * 60) : "–"}</div>
            <p class="muted">{s() ? t("shell.status.version", { version: s()!.version }) : ""}</p>
          </section>
        </div>

        <div class="dash-grid">
          <section class="card dash-card" id="alarms" aria-labelledby="dash-alarms" data-testid="dashboard-alarms">
            <h2 id="dash-alarms">{t("dashboard.alarms.title")}</h2>
            <Show when={alarms().length > 0} fallback={<p class="muted">{t("dashboard.alarms.none")}</p>}>
              <ul class="dash-list">
                <For each={alarms()}>
                  {(a) => (
                    <li data-key={a.node.cidr} data-level={a.node.level}>
                      <AlarmFlag level={a.node.level} />
                      <A href={paths.prefix(a.node.cidr, a.vrf.id)}>
                        <Addr value={a.node.cidr} />
                      </A>
                      <span class="muted">{a.node.description ?? a.vrf.name}</span>
                      <UtilizationMeter
                        percent={a.node.utilization.percent}
                        level={a.node.level}
                        used={a.node.utilization.used}
                        capacity={a.node.utilization.capacity}
                      />
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </section>

          <section class="card dash-card" aria-labelledby="dash-waiting" data-testid="dashboard-waiting">
            <h2 id="dash-waiting">
              {t("dashboard.waiting.title")}
              <A class="aside" href={paths.jobs({ state: "waiting" })}>
                {t("dashboard.waiting.all")}
              </A>
            </h2>
            <Show when={(waiting.value.latest?.length ?? 0) > 0} fallback={<p class="muted">{t("dashboard.waiting.none")}</p>}>
              <ul class="dash-list">
                <For each={waiting.value.latest ?? []}>
                  {(job) => (
                    <li data-id={job.id}>
                      <JobStateChip state={job.state} done={job.steps_done} total={job.step_count} />
                      <A href={paths.job(job.id)}>{jobTitle(job)}</A>
                      <span class="muted">{t("dashboard.waiting.step", { step: (job.current_step ?? 0) + 1, total: job.step_count })}</span>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </section>

          <section class="card dash-card" aria-labelledby="dash-audit" data-testid="dashboard-audit">
            <h2 id="dash-audit">
              {t("dashboard.audit.title")}
              <A class="aside" href={paths.audit()}>
                {t("dashboard.audit.all")}
              </A>
            </h2>
            <Show when={(audit.value.latest?.length ?? 0) > 0} fallback={<p class="muted">{t("dashboard.audit.none")}</p>}>
              <ul class="dash-list">
                <For each={audit.value.latest ?? []}>
                  {(r) => (
                    <li data-seq={r.seq}>
                      <A href={paths.auditRecord(r.seq)} class="mono">
                        {r.draft.action}
                      </A>
                      <PrincipalLabel principal={r.principal} />
                      <TimeAgo at={r.at} />
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </section>
        </div>

        <section class="dash-use" aria-labelledby="dash-use" data-testid="dashboard-utilization">
          <h2 id="dash-use">{t("dashboard.use.title")}</h2>
          <div class="dash-vrfs">
            <For each={vrfs()}>
              {(v) => (
                <section class="card dash-card" aria-label={t("dashboard.use.vrf", { tenant: v.tenant?.name ?? "", vrf: v.vrf.name })} data-vrf={v.vrf.id}>
                  <h3>
                    <span>{t("dashboard.use.vrf", { tenant: v.tenant?.name ?? "", vrf: v.vrf.name })}</span>
                    <span class="aside">
                      <Count value={v.used} /> {t("dashboard.use.of")} <Count value={v.capacity} />
                    </span>
                  </h3>
                  <UtilizationMeter percent={percentOf(v.used, v.capacity)} used={String(v.used)} capacity={String(v.capacity)} />
                  <Show when={v.networks.length > 0} fallback={<p class="muted">{t("dashboard.use.empty")}</p>}>
                    <table class="plain dash-nets" aria-label={t("dashboard.use.networks")}>
                      <tbody>
                        <For each={v.networks.slice(0, NETWORKS_SHOWN)}>
                          {(n) => (
                            <tr data-key={n.cidr}>
                              <td>
                                <A href={paths.prefix(n.cidr, v.vrf.id)}>
                                  <Addr value={n.cidr} />
                                </A>
                              </td>
                              <td class="muted">{n.description ?? ""}</td>
                              <td class="r">
                                <UtilizationMeter percent={n.utilization.percent} level={n.level} used={n.utilization.used} capacity={n.utilization.capacity} />
                              </td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                    <Show when={v.networks.length > NETWORKS_SHOWN}>
                      <A href={paths.ipam()} class="muted">
                        {t("dashboard.use.more", { count: v.networks.length - NETWORKS_SHOWN })}
                      </A>
                    </Show>
                  </Show>
                </section>
              )}
            </For>
          </div>
        </section>
        <p class="muted">
          <Kbd keys={["Ctrl", "K"]} /> {t("dashboard.palette_hint")}
        </p>
      </div>

      <Show when={action() === "claim"}>
        <MoveDialogPicker
          tree={defaultTree()}
          onPick={(n) => {
            setClaimIn(n);
            setAction("claim_in");
          }}
          onClose={() => setAction(null)}
        />
      </Show>
      <Show when={action() === "claim_in" && claimIn()}>
        {(n) => <ClaimIn node={n()} onClose={() => setAction(null)} onDone={(ip) => navigate(paths.address(ip))} />}
      </Show>
      <Show when={action() === "prefix" && scope.vrf()}>
        <PrefixForm
          vrf={scope.vrf()!}
          onClose={() => setAction(null)}
          onDone={(p) => {
            setAction(null);
            navigate(paths.prefix(p.cidr));
          }}
        />
      </Show>
    </div>
  );
}

/** Picks the network to claim in: the network list of the move dialog, reused. */
function MoveDialogPicker(props: { tree: TreeResponse | undefined; onPick: (n: TreeNode) => void; onClose: () => void }) {
  return <MoveDialog tree={props.tree} items={[]} onClose={props.onClose} onPick={props.onPick} title={t("dashboard.action.claim_where")} />;
}

/** The next free address dialog for a network of the tree (it needs the prefix and its ranges). */
function ClaimIn(props: { node: TreeNode; onClose: () => void; onDone: (ip: string) => void }) {
  const live = createLiveQuery({
    topics: [],
    fetch: async (signal) => {
      const [prefix, ranges] = await Promise.all([
        api.get("/api/v1/prefixes/{id}", { path: { id: props.node.id }, signal }),
        fetchAll<Range>("/api/v1/prefixes/{id}/ranges", { path: { id: props.node.id }, signal }),
      ]);
      return { value: { prefix, ranges: ranges.items } };
    },
  });
  return (
    <Show when={live.value.latest}>
      {(d) => <NextFreeAddressDialog prefix={d().prefix} ranges={d().ranges} onClose={props.onClose} onDone={(a) => props.onDone(a.ip)} />}
    </Show>
  );
}
