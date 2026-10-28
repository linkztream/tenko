// The start page (decision 13; U3, docs/plans/ui-plan.md section 5.1). It answers "Is anything
// wrong, and what?" in five seconds: five blocks in reading order inside the page header.
//
// 1. The header: the title, one subtitle line of facts (the node, its uptime as people say it,
//    the free disk of its total, the store's size, the version) and the primary actions (an import,
//    a new prefix, "Claim next free address" with its N key).
// 2. The needs-attention strip (Attention.tsx): the findings to act on with their default action,
//    one line for those to review, or one "All clear" line.
// 3. The health row (HealthRow.tsx): metric blocks for the addresses in use, the findings, the jobs
//    and connectors (Standard and Hardened) and the utilization alarms, each a link.
// 4. The service panels for DNS and DHCP (Services.tsx, for administrators, from the page's one
//    `metrics` stream), the system panel (SystemPanel.tsx: the host's CPU and memory when read, the
//    controller's metrics under Lab or with more than one node, the nodes connected), and under
//    Hardened the security panel (SecurityPanel.tsx).
// 5. The fullest prefixes per tenant and VRF (Prefixes.tsx) beside the recent changes (Changes.tsx).
//
// At the foot, the Hidden line names the metrics the page does not draw and why; "Show all
// metrics" draws every block and the live tiles of every metric (MetricsTiles.tsx, a lazy part)
// for the session. The profile chooses the set (ui-plan section 6, model.ts).
import { A, useNavigate } from "@solidjs/router";
import { createMemo, createSignal, lazy, onCleanup, onMount, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { fetchAll } from "../api/paginate";
import type { Range, TreeNode, TreeResponse } from "../api/types";
import { paths } from "../app/paths";
import { isAdmin, session } from "../auth/session";
import { HiddenLine, type HiddenItem } from "../components/HiddenLine";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { PageHeader } from "../components/PageHeader";
import { formatNumber, t, withPacks } from "../i18n";
import { MoveDialog } from "../ipam/move/MoveDialog";
import { NextFreeAddressDialog } from "../ipam/prefix/NextFreeDialogs";
import { PrefixForm } from "../ipam/prefix/PrefixForm";
import { useScope } from "../ipam/scope";
import { formatBytes } from "../nodes/format";
import { isCluster } from "../shell/cluster";
import { useFindingCounts } from "../shell/findings";
import { isTyping } from "../shell/keyboard";
import { trackLazyPart } from "../shell/lazyParts";
import { createShellStatus } from "../shell/status";
import { moduleRunning } from "../updates/modules";
import { Attention } from "./Attention";
import { Changes } from "./Changes";
import { HealthRow } from "./HealthRow";
import { createLiveMetrics, type LiveMetrics } from "./liveMetrics";
import { DISK_LOW_WARNING, GIB, LONG_HISTORY } from "./metrics";
import { dashboardSet, hiddenKeys, profileOf, type HiddenKey } from "./model";
import { Prefixes } from "./Prefixes";
import { SecurityPanel } from "./SecurityPanel";
import { DhcpPanel, DnsPanel } from "./Services";
import { SystemPanel, useClusterSummary } from "./SystemPanel";
import { useUtilization } from "./utilization";
import "./dashboard.css";

// The notices of the updates area: a newer release, and a module change that waits for a restart.
const UpdateCard = lazy(() => trackLazyPart(import("../updates/UpdateCard")));
const ModulesNotice = lazy(() => trackLazyPart(import("../updates/ModulesNotice")));
// Every metric as a tile, behind "Show all metrics", with its own chunk and message pack.
const MetricsTiles = lazy(withPacks(["metrics"], () => trackLazyPart(import("./MetricsTiles"))));

/** "Show all metrics" holds for the session, per tab. */
const SHOW_ALL_KEY = "tenko.dashboard.show-all";

function readShowAll(): boolean {
  try {
    return sessionStorage.getItem(SHOW_ALL_KEY) === "1";
  } catch {
    return false;
  }
}

function writeShowAll(value: boolean): void {
  try {
    if (value) sessionStorage.setItem(SHOW_ALL_KEY, "1");
    else sessionStorage.removeItem(SHOW_ALL_KEY);
  } catch {
    // Without session storage the choice holds for the page only.
  }
}

/** A duration as people say it: "17 h 17 min", "3 d 4 h", "5 min", "40 s". */
export function humanDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return t("dashboard.duration.days", { days: d, hours: h });
  if (h > 0) return t("dashboard.duration.hours", { hours: h, minutes: m });
  if (m > 0) return t("dashboard.duration.minutes", { minutes: m });
  return t("dashboard.duration.seconds", { seconds: s });
}

/** GiB with no decimal from ten up, one below. */
function gib(bytes: number): string {
  const value = bytes / GIB;
  return formatNumber(value, { maximumFractionDigits: value < 10 ? 1 : 0 });
}

/** Opens the page's `metrics` stream while it is mounted and hands it to the page. */
function MetricsSource(props: { onLive: (live: LiveMetrics | undefined) => void }) {
  const live = createLiveMetrics(undefined, LONG_HISTORY);
  onMount(() => props.onLive(live));
  onCleanup(() => props.onLive(undefined));
  return null;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const status = createShellStatus();
  const scope = useScope();
  const counts = useFindingCounts();
  const s = () => status.system();
  const use = useUtilization();
  const vrfs = () => use.latest();
  const admin = () => isAdmin();
  const profile = () => profileOf(session()?.profile);

  const [live, setLive] = createSignal<LiveMetrics>();
  const [showAll, setShowAll] = createSignal(readShowAll());
  // More than one node: a second controller, or an enrolled node (followed on the `cluster` topic).
  const clusterNodes = useClusterSummary(s);
  const multiNode = () => isCluster(s()) || (clusterNodes()?.nodes ?? 0) > 0;
  const set = createMemo(() => dashboardSet(profile(), multiNode(), showAll()));
  const sample = () => live()?.history().latest?.cluster ?? null;

  const hiddenText = (key: HiddenKey): string => {
    switch (key) {
      case "host":
        return t("dashboard.hidden.host");
      case "host-cpu":
        return t("dashboard.hidden.host_cpu");
      case "host-memory":
        return t("dashboard.hidden.host_memory");
      case "controller":
        return t("dashboard.hidden.controller");
      case "operations":
        return t("dashboard.hidden.operations", { profile: t(`profile.${profile()}.name`) });
      case "dns":
        return t("dashboard.hidden.dns");
      case "dhcp":
        return t("dashboard.hidden.dhcp");
      case "admin":
        return t("dashboard.hidden.admin");
    }
  };
  const hidden = createMemo((): HiddenItem[] => hiddenKeys({ set: set(), admin: admin(), sample: sample() }).map((key) => ({ key, text: hiddenText(key) })));

  const facts = () => {
    const status = s();
    if (!status) return "";
    const parts: string[] = [];
    if (status.node.name) parts.push(status.node.name);
    parts.push(t("dashboard.sub.uptime", { duration: humanDuration(status.uptime_seconds) }));
    const host = status.host;
    if (host?.disk_available != null && host.disk_total != null) {
      parts.push(t("dashboard.sub.disk", { free: gib(host.disk_available), total: gib(host.disk_total) }));
    }
    parts.push(t("dashboard.sub.store", { size: formatBytes(status.store.disk_bytes ?? status.store.data_bytes) }));
    parts.push(status.version);
    return parts.join(" · ");
  };
  const diskLow = () => s()?.warnings.some((w) => w.code === DISK_LOW_WARNING) ?? false;

  const [action, setAction] = createSignal<"claim" | "claim_in" | "prefix" | null>(null);
  const [claimIn, setClaimIn] = createSignal<TreeNode | null>(null);
  const defaultTree = (): TreeResponse | undefined => {
    const v = (vrfs() ?? []).find((x) => x.vrf.id === scope.vrf()?.id);
    return v ? { nodes: v.networks, revision: 0, vrf: v.vrf.id } : undefined;
  };
  const mayClaim = () => moduleRunning("ipam") && !!scope.vrf();

  // N claims the next free address, as on a network's page (the keyboard sheet lists it).
  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || isTyping(e) || e.ctrlKey || e.metaKey || e.altKey || action()) return;
      if (document.querySelector("[aria-modal='true']")) return;
      if (e.key === "n" && mayClaim()) {
        e.preventDefault();
        setAction("claim");
      }
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  return (
    <div class="page dashboard" data-testid="page-dashboard">
      <PageHeader
        title={t("shell.nav.dashboard")}
        sub={<span data-testid="dashboard-facts" data-disk-low={diskLow() ? "true" : undefined}>{facts()}</span>}
        actions={
          <Show when={moduleRunning("ipam")}>
            <A class="btn" href={paths.imports()} data-testid="dashboard-import">
              {t("dashboard.action.import")}
            </A>
            <button type="button" class="btn" data-testid="dashboard-new-prefix" onClick={() => setAction("prefix")} disabled={!scope.vrf()}>
              {t("dashboard.action.prefix")}
            </button>
            <button type="button" class="btn primary" data-testid="dashboard-claim" onClick={() => setAction("claim")} disabled={!scope.vrf()}>
              <Icon name="plus" />
              {t("dashboard.action.claim")}
              <Kbd keys={["N"]} />
            </button>
          </Show>
        }
      />
      <div class="page-body wide dash-body">
        <ModulesNotice warnings={s()?.warnings} />
        <UpdateCard />
        <Show when={admin()}>
          <MetricsSource onLive={setLive} />
        </Show>

        <Attention counts={counts()} />

        <HealthRow vrfs={vrfs()} counts={counts()} running={status.jobs()?.running ?? null} operations={set().operations} />

        <Show when={live()}>
          {(l) => (
            <div class="dash-row">
              <DnsPanel live={l()} counts={counts()} />
              <DhcpPanel live={l()} counts={counts()} />
            </div>
          )}
        </Show>

        <SystemPanel live={live()} nodes={clusterNodes()} controller={set().controller} cluster={set().cluster} />

        <Show when={set().security}>
          <SecurityPanel />
        </Show>

        <div class="dash-row">
          <Show when={moduleRunning("ipam") && vrfs()}>{(list) => <Prefixes vrfs={list()} />}</Show>
          <Changes systemDefault={set().systemActivity} />
        </div>

        <HiddenLine
          label={t("dashboard.hidden.label")}
          items={hidden()}
          show={t("dashboard.hidden.show")}
          hide={t("dashboard.hidden.hide")}
          shown={showAll()}
          onToggle={(value) => {
            setShowAll(value);
            writeShowAll(value);
          }}
        />

        <Show when={showAll() && live()}>
          {(l) => <MetricsTiles live={l()} diskLow={diskLow()} />}
        </Show>
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
