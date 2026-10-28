// The proposal inbox (/discovery, /discovery/<id>): what the reconciler suggests, open ones
// first (IPAM-15). A data grid over GET /proposals, filtered and sorted by the server (state,
// defaulting to open; kind; severity; prefix; subject), live on the `ipam` topic; the proposal
// in the URL is docked beside the grid with its evidence, the suggested change and the
// decision. "Reconcile now" runs the reconciler and shows what the run did.
//
// An administrator or operator selects rows with the grid's checkbox column (the loaded rows;
// the grid pages in more as it scrolls) and approves or rejects them in one go: one
// confirmation or one reason dialog, one request, one toast with the counts and, when the
// server skipped some, a panel with the reasons and a way to keep them selected.
//
// Filters live in the URL (`state`, `kind`, `severity`, `prefix`, `q`), so a link from the
// prefix pane or the dashboard opens the inbox already narrowed.
import { useLocation, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createResource, createSignal, For, on, onCleanup, Show } from "solid-js";
import { errorMessage } from "../api/problem";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { toast } from "../components/toast";
import { ActionBar, ActionButton } from "../grid/ActionBar";
import { createGridSelection, DataGrid } from "../grid/DataGrid";
import { FilterBar, ToggleChip } from "../grid/FilterBar";
import { createColumnState } from "../grid/prefs";
import { createListSource } from "../grid/source";
import { sortParam, type RowAction, type SortState } from "../grid/types";
import { t } from "../i18n";
import { useWriteToast } from "../ipam/plan/PlanDialog";
import { useCommands } from "../shell/commands";
import { approveProposals, PROPOSAL_KINDS, PROPOSAL_STATES, reconcileNow, rejectProposal, rejectProposals, SEVERITIES, type ApproveRequest, type BatchDecision, type Decision, type Proposal, type ProposalKind, type ProposalSeverity, type ProposalState, type ReconcileReport } from "./api";
import { proposalColumns } from "./columns";
import { ApproveDialog, ApproveManyDialog, ReconcileReportDialog, RejectDialog, SkippedDialog } from "./dialogs";
import { DiscoveryNav } from "./DiscoveryNav";
import { isDecider } from "./access";
import { canApprove, isOpen, isProposalEvent, kindIcon, kindWord, ruleText, severityIcon, severityWord, stateWord, subjectLabel } from "./model";
import { ProposalPanel } from "./ProposalPanel";
import { readPrefix, useSourceNames } from "./refs";
import "./discovery.css";

type StateFilter = ProposalState | "all";
const STATE_FILTERS: readonly StateFilter[] = [...PROPOSAL_STATES, "all"];

/** The severities of the findings model a link may filter the inbox by. */
type ProposalLevel = "act" | "review";
const LEVELS: readonly ProposalLevel[] = ["act", "review"];
const LEVEL_LABEL = { act: "discovery.filter.level_act", review: "discovery.filter.level_review" } as const;

/** The finding severity of an open proposal of this kind: a conflict is to act on, the rest to review. */
function levelOfKind(kind: ProposalKind): ProposalLevel {
  return kind === "conflict" ? "act" : "review";
}

/** A single value of a query parameter; a repeated parameter counts as absent. */
function one(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** The known values of a comma-separated query parameter. */
function listOf<T extends string>(value: string | string[] | undefined, known: readonly T[]): T[] {
  const text = one(value);
  if (!text) return [];
  return text.split(",").filter((v): v is T => (known as readonly string[]).includes(v));
}

export default function ProposalsView() {
  const params = useParams<{ id?: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const [search, setSearch] = useSearchParams();
  const names = useSourceNames();
  const writeToast = useWriteToast();

  const state = (): StateFilter => {
    const s = one(search.state);
    return s && (STATE_FILTERS as readonly string[]).includes(s) ? (s as StateFilter) : "open";
  };
  const kinds = () => listOf<ProposalKind>(search.kind, PROPOSAL_KINDS);
  const severities = () => listOf<ProposalSeverity>(search.severity, SEVERITIES);
  // The severity of the findings model (`?severity=act`, the links of the status bar): an open
  // conflict is to act on, every other open proposal to review (docs/reconciliation.md 12.2).
  const levels = () => listOf<ProposalLevel>(search.severity, LEVELS);
  const levelKinds = (): ProposalKind[] => {
    const wanted = levels();
    if (wanted.length === 0) return kinds();
    const byLevel = PROPOSAL_KINDS.filter((k) => wanted.includes(levelOfKind(k)));
    const chosen = kinds();
    return chosen.length === 0 ? byLevel : chosen.filter((k) => byLevel.includes(k));
  };
  const prefix = () => one(search.prefix);

  // The subject filter: typed here, sent to the server after a pause, kept in the URL.
  const [text, setText] = createSignal(one(search.q) ?? "");
  const [subject, setSubject] = createSignal(one(search.q) ?? "");
  let typing: ReturnType<typeof setTimeout> | undefined;
  createEffect(
    on(text, (value) => {
      clearTimeout(typing);
      typing = setTimeout(() => {
        setSubject(value.trim());
        setSearch({ q: value.trim() || undefined }, { replace: true });
      }, 300);
    }, { defer: true }),
  );
  onCleanup(() => clearTimeout(typing));

  const [sort, setSort] = createSignal<SortState | null>(null);
  const source = createListSource<Proposal>({
    path: "/api/v1/proposals",
    query: () => ({
      state: state() === "all" ? undefined : state(),
      kind: levelKinds(),
      severity: severities(),
      prefix: prefix(),
      subject: subject() || undefined,
      sort: sortParam(sort()),
    }),
    rowId: (p) => p.id,
    topics: ["ipam"],
    relevant: isProposalEvent,
  });

  const [prefixInfo] = createResource(prefix, (id) => readPrefix(id));

  const columns = proposalColumns(names);
  const columnState = createColumnState("proposals", () => columns);

  const [dialog, setDialog] = createSignal<
    | { kind: "approve"; proposal: Proposal; request?: ApproveRequest }
    | { kind: "reject"; proposal: Proposal }
    | { kind: "approve_many"; proposals: Proposal[] }
    | { kind: "reject_many"; proposals: Proposal[] }
    | null
  >(null);
  const [skipped, setSkipped] = createSignal<{ result: BatchDecision; labels: Map<string, string> } | null>(null);
  const [report, setReport] = createSignal<ReconcileReport | null>(null);
  const [running, setRunning] = createSignal(false);

  const withQuery = (path: string) => `${path}${location.search}`;
  const open = (p: Proposal) => navigate(withQuery(paths.proposal(p.id)));
  const close = () => navigate(withQuery(paths.discovery()));

  const toggleIn = <T extends string>(name: string, list: T[], value: T) => {
    const next = list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
    setSearch({ [name]: next.length ? next.join(",") : undefined });
  };

  const runReconcile = async () => {
    if (running()) return;
    setRunning(true);
    try {
      setReport(await reconcileNow());
      source.reload();
    } catch (err) {
      toast({ kind: "bad", title: t("discovery.reconcile.failed"), body: errorMessage(err) });
    } finally {
      setRunning(false);
    }
  };

  const decided = (title: string, decision: Decision) => {
    setDialog(null);
    writeToast(title, decision);
    source.reload();
  };

  useCommands(() => [
    {
      id: "discovery.reconcile",
      group: "actions",
      icon: "refresh",
      label: () => t("discovery.action.reconcile"),
      when: isDecider,
      run: () => void runReconcile(),
    },
    {
      id: "discovery.observations",
      group: "goto",
      icon: "search",
      label: () => t("discovery.nav.observations"),
      run: () => navigate(paths.observations()),
    },
  ]);

  // Only an administrator or operator decides, and only open proposals can be decided: the grid
  // offers its checkbox column to them. The selection covers the loaded rows.
  const selectable = (p: Proposal) => isDecider() && isOpen(p);
  // A severity of the findings model narrows on the client as well: the kinds it stands for may
  // not meet the kinds of the URL, and then nothing is shown.
  const rows = createMemo(() => {
    const wanted = levels();
    if (wanted.length === 0) return source.rows();
    const chosen = kinds();
    return source.rows().filter((p) => wanted.includes(levelOfKind(p.kind)) && (chosen.length === 0 || chosen.includes(p.kind)));
  });
  const selection = createGridSelection(rows, (p) => p.id, selectable);
  const selected = () => rows().filter((p) => selection.has(p.id));

  /** The toast of a batch, the selection cleared, and the panel of what was skipped. */
  const batchDone = (verb: "approved" | "rejected", result: BatchDecision, proposals: Proposal[]) => {
    setDialog(null);
    const done = verb === "approved" ? result.approved : result.rejected;
    toast({
      kind: result.skipped > 0 ? "info" : "ok",
      title: t(verb === "approved" ? "discovery.batch.done_approved" : "discovery.batch.done_rejected", { count: done }),
      body: result.skipped > 0 ? t("discovery.batch.done_skipped", { count: result.skipped }) : undefined,
    });
    selection.clear();
    source.reload();
    if (result.skipped > 0) setSkipped({ result, labels: new Map(proposals.map((p) => [p.id, ruleText(p)])) });
  };

  const rowActions: RowAction<Proposal>[] = [
    { id: "open", label: () => t("discovery.action.open"), run: open },
    {
      id: "approve",
      label: () => t("discovery.action.approve"),
      disabled: (p) => !isDecider() || !canApprove(p),
      run: (p) => setDialog({ kind: "approve", proposal: p }),
    },
    {
      id: "reject",
      label: () => t("discovery.action.reject"),
      disabled: (p) => !isDecider() || !isOpen(p),
      run: (p) => setDialog({ kind: "reject", proposal: p }),
    },
  ];

  const filtered = () => state() !== "open" || kinds().length > 0 || severities().length > 0 || levels().length > 0 || !!prefix() || subject() !== "";
  const countText = createMemo(() => {
    const n = rows().length;
    if (source.initial()) return undefined;
    const more = source.hasMore();
    return state() === "open" && !filtered()
      ? t("discovery.count_open", { count: n, more: more ? "yes" : "no" })
      : t("discovery.count", { count: n, more: more ? "yes" : "no" });
  });

  // A click anywhere in a row opens the proposal; links and buttons inside it do their own thing.
  const onGridClick = (e: MouseEvent) => {
    const el = e.target as HTMLElement;
    if (el.closest("a, button, input, select, textarea, td.check")) return;
    const id = el.closest<HTMLElement>("tr[data-id]")?.dataset.id;
    const row = id ? rows().find((p) => p.id === id) : undefined;
    if (row) open(row);
  };

  return (
    <div class="page discovery-page" data-testid="page-discovery">
      <PageHeader
        title={t("shell.nav.discovery")}
        sub={countText()}
        info={<p>{t("discovery.info")}</p>}
        actions={
          <Show when={isDecider()}>
            <button type="button" class="btn" data-testid="discovery-reconcile" disabled={running()} onClick={() => void runReconcile()}>
              <Icon name="refresh" />
              {t("discovery.action.reconcile")}
            </button>
          </Show>
        }
        tabs={<DiscoveryNav />}
      />
      <FilterBar
        label={t("discovery.filter.label")}
        placeholder={t("discovery.filter.placeholder")}
        value={text()}
        onInput={setText}
        columns={columnState}
      >
        <span class="divider" />
        <select
          class="select"
          aria-label={t("discovery.filter.state")}
          data-testid="filter-state"
          onChange={(e) => setSearch({ state: e.currentTarget.value === "open" ? undefined : e.currentTarget.value })}
        >
          <For each={STATE_FILTERS}>
            {(s) => (
              <option value={s} selected={state() === s}>
                {s === "all" ? t("discovery.filter.all") : stateWord(s)}
              </option>
            )}
          </For>
        </select>
        <span class="divider" />
        <For each={SEVERITIES}>
          {(s) => (
            <ToggleChip pressed={severities().includes(s)} onToggle={() => toggleIn("severity", severities(), s)} testid={`filter-severity-${s}`}>
              <Icon name={severityIcon(s)} />
              {severityWord(s)}
            </ToggleChip>
          )}
        </For>
        <span class="divider" />
        <For each={PROPOSAL_KINDS}>
          {(k) => (
            <ToggleChip pressed={kinds().includes(k)} onToggle={() => toggleIn("kind", kinds(), k)} testid={`filter-kind-${k}`}>
              <Icon name={kindIcon(k)} />
              {kindWord(k)}
            </ToggleChip>
          )}
        </For>
        <For each={levels()}>
          {(level) => (
            <span class="chip applied" data-testid="filter-level" data-level={level}>
              {t(LEVEL_LABEL[level])}
              <button
                type="button"
                class="chip-x"
                aria-label={t("discovery.filter.remove_level", { level: t(LEVEL_LABEL[level]) })}
                onClick={() => toggleIn("severity", levels(), level)}
              >
                <Icon name="x" size="xs" />
              </button>
            </span>
          )}
        </For>
        <Show when={prefix()}>
          {(id) => (
            <>
              <span class="divider" />
              <span class="chip applied" data-testid="filter-prefix">
                {t("discovery.filter.prefix", { prefix: prefixInfo()?.cidr ?? id().slice(0, 8) })}
                <button
                  type="button"
                  class="chip-x"
                  data-testid="filter-chip-remove"
                  aria-label={t("discovery.filter.remove_prefix")}
                  onClick={() => setSearch({ prefix: undefined })}
                >
                  <Icon name="x" size="xs" />
                </button>
              </span>
            </>
          )}
        </Show>
      </FilterBar>
      <div class="discovery-split" classList={{ "with-panel": !!params.id }}>
        <div class="discovery-grid" onClick={onGridClick}>
          <DataGrid
            id="proposals"
            label={t("discovery.grid.label")}
            columns={columns}
            columnState={columnState}
            rows={rows()}
            rowId={(p) => p.id}
            rowKey={(p) => subjectLabel(p)}
            rowLabel={(p) => ruleText(p)}
            rowClass={(p) => [p.kind === "conflict" ? "conflict" : p.kind === "address_mismatch" || p.kind === "orphaned_intent" ? "differs" : "proposal", p.id === params.id ? "current" : ""].join(" ")}
            noSelection={!isDecider()}
            selectable={selectable}
            selection={selection}
            sort={sort()}
            onSort={setSort}
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
            rowActions={rowActions}
            empty={
              <div class="empty" data-testid="discovery-empty">
                <h3>{filtered() ? t("discovery.empty.filtered") : t("discovery.empty.title")}</h3>
                <Show when={!filtered()}>
                  <p>{t("discovery.empty.body")}</p>
                </Show>
              </div>
            }
          />
          <ActionBar count={selection.count()} onClear={selection.clear}>
            <ActionButton
              primary
              icon="check"
              label={t("discovery.batch.approve", { count: selection.count() })}
              testid="action-approve"
              onClick={() => setDialog({ kind: "approve_many", proposals: selected() })}
            />
            <ActionButton
              icon="x"
              label={t("discovery.batch.reject", { count: selection.count() })}
              testid="action-reject"
              onClick={() => setDialog({ kind: "reject_many", proposals: selected() })}
            />
            <Show when={source.hasMore() && selection.all()}>
              <span class="muted" data-testid="selection-loaded-only">
                {t("discovery.batch.loaded_only", { count: selection.count() })}
              </span>
            </Show>
          </ActionBar>
        </div>
        <Show when={params.id} keyed>
          {(id) => (
            <ProposalPanel
              id={id}
              names={names()}
              decider={isDecider()}
              onApprove={(p, request) => setDialog({ kind: "approve", proposal: p, request })}
              onReject={(p) => setDialog({ kind: "reject", proposal: p })}
              onClose={close}
            />
          )}
        </Show>
      </div>

      <Show when={dialog()} keyed>
        {(d) => {
          if (d.kind === "approve") {
            return <ApproveDialog proposal={d.proposal} request={d.request} onClose={() => setDialog(null)} onDone={(r) => decided(t("discovery.toast.approved"), r)} />;
          }
          if (d.kind === "approve_many") {
            return (
              <ApproveManyDialog
                proposals={d.proposals}
                send={() => approveProposals(d.proposals.map((p) => p.id))}
                onClose={() => setDialog(null)}
                onDone={(r) => batchDone("approved", r, d.proposals)}
              />
            );
          }
          if (d.kind === "reject_many") {
            return (
              <RejectDialog
                proposals={d.proposals}
                send={(reason) => rejectProposals(d.proposals.map((p) => p.id), reason)}
                onClose={() => setDialog(null)}
                onDone={(r) => batchDone("rejected", r, d.proposals)}
              />
            );
          }
          return (
            <RejectDialog
              proposals={[d.proposal]}
              send={(reason) => rejectProposal(d.proposal, reason)}
              onClose={() => setDialog(null)}
              onDone={(r) => decided(d.proposal.kind === "conflict" ? t("discovery.toast.dismissed") : t("discovery.toast.rejected"), r)}
            />
          );
        }}
      </Show>
      <Show when={skipped()}>
        {(s) => (
          <SkippedDialog
            result={s().result}
            label={(id) => s().labels.get(id) ?? id}
            onKeep={(ids) => {
              setSkipped(null);
              selection.set(ids);
            }}
            onClose={() => setSkipped(null)}
          />
        )}
      </Show>
      <Show when={report()}>{(r) => <ReconcileReportDialog report={r()} onClose={() => setReport(null)} />}</Show>
    </div>
  );
}
