// Discovery (/discovery, /discovery/<id>): the findings list for every kind (U4, UI-Q2), the one
// place that answers "what needs my decision?". One 28 px table over `GET /findings`, grouped by
// severity in the order Act now, Review, Info; a group row says its count and, when every row of
// the group shares it, the rule sentence once ("Intent wins: the host is managed, ..."). Info
// groups of more than ten rows start closed. Each row: the glyph and the kind, the subject as a
// link, one line of evidence, since when, and the default action the finding names as a button
// (FindingAction.tsx).
//
// The header's facts ("1 to act on · 5 to review · 23 info") come from the one findings store of
// the shell (`useFindingCounts`), so they are the numbers of the rail badge and the status bar.
// The list follows the `findings` topic.
//
// Filters live in the URL: `severity` (act, review, info: a chip each, the status bar links set
// it), `kind` (a chip per kind with its count, applied on the loaded rows so the other chips keep
// theirs), `prefix` (a chip that removes it) and `q` (the query field, sent after a pause).
//
// Selecting a row opens the side panel: a proposal's (/discovery/<proposal id>, as before), or a
// row of the reconciliation view's (/discovery/<finding id>); a finding of another source (a job,
// an alarm, a health condition) opens its subject instead. The proposals with their states, the
// decided ones included, and the decisions on many at once are on the Proposals tab.
import { useLocation, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createResource, createSignal, For, on, onCleanup, Show } from "solid-js";
import { decodeSegment, paths } from "../app/paths";
import { errorMessage } from "../api/problem";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { toast } from "../components/toast";
import { FilterBar, ToggleChip } from "../grid/FilterBar";
import { GroupedGrid, type RowGroup } from "../grid/GroupedGrid";
import { sharedValue } from "../grid/groups";
import { createColumnState } from "../grid/prefs";
import { createListSource } from "../grid/source";
import type { RowAction } from "../grid/types";
import { t } from "../i18n";
import { useWriteToast } from "../ipam/plan/PlanDialog";
import { useCommands } from "../shell/commands";
import { useFindingCounts } from "../shell/findings";
import { isDecider } from "./access";
import { getProposal, reconcileNow, rejectProposal, type Proposal, type ReconcileReport } from "./api";
import { ReconcileReportDialog, RejectDialog } from "./dialogs";
import { DiscoveryNav } from "./DiscoveryNav";
import { findingColumns } from "./findingColumns";
import { DecisionPanel, type PanelTarget } from "./FindingPanel";
import { FINDING_KINDS, findingRule, kindGlyph, kindWord, LEVELS, levelWord, proposalOf, rowClassOf, selectionOf, type Finding, type FindingKind, type FindingLevel } from "./findings";
import { readPrefix, useSourceNames } from "./refs";
import "./discovery.css";
import "./findings.css";

/** Rows per page: a moderate network fits in one. */
const PAGE_SIZE = 500;
/** An Info group with more rows than this starts closed. */
const INFO_OPEN_MAX = 10;

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

/** What the id of the URL stands for: a proposal (its id, or `proposal:<id>`) or another finding. */
export function panelTargetOf(id: string): PanelTarget {
  const decoded = decodeSegment(id);
  if (decoded.startsWith("proposal:")) return { proposal: decoded.slice("proposal:".length) };
  return decoded.includes(":") ? { findingId: decoded } : { proposal: decoded };
}

export default function FindingsView() {
  const params = useParams<{ id?: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const [search, setSearch] = useSearchParams();
  const names = useSourceNames();
  const counts = useFindingCounts();
  const writeToast = useWriteToast();

  const levels = () => listOf<FindingLevel>(search.severity, LEVELS);
  const kinds = () => listOf<FindingKind>(search.kind, FINDING_KINDS);
  const prefix = () => one(search.prefix);

  // The text filter: typed here, sent to the server after a pause, kept in the URL.
  const [text, setText] = createSignal(one(search.q) ?? "");
  const [query, setQuery] = createSignal(one(search.q) ?? "");
  let typing: ReturnType<typeof setTimeout> | undefined;
  createEffect(
    on(
      text,
      (value) => {
        clearTimeout(typing);
        typing = setTimeout(() => {
          setQuery(value.trim());
          setSearch({ q: value.trim() || undefined }, { replace: true });
        }, 300);
      },
      { defer: true },
    ),
  );
  onCleanup(() => clearTimeout(typing));

  const source = createListSource<Finding>({
    path: "/api/v1/findings",
    query: () => ({ severity: levels(), prefix: prefix(), q: query() || undefined }),
    rowId: (f) => f.id,
    pageSize: PAGE_SIZE,
    topics: ["findings"],
  });
  const [prefixInfo] = createResource(prefix, (id) => readPrefix(id));

  /** The rows of the chosen kinds; every chip counts the loaded rows of its kind. */
  const rows = createMemo(() => {
    const chosen = kinds();
    return chosen.length === 0 ? source.rows() : source.rows().filter((f) => chosen.includes(f.kind));
  });
  const kindCounts = createMemo(() => {
    const out = new Map<FindingKind, number>();
    for (const f of source.rows()) out.set(f.kind, (out.get(f.kind) ?? 0) + 1);
    return out;
  });
  const shownKinds = () => FINDING_KINDS.filter((k) => kindCounts().has(k) || kinds().includes(k));

  const groups = createMemo((): RowGroup<Finding>[] => {
    const all = rows();
    const present = LEVELS.filter((level) => all.some((f) => f.severity === level));
    const last = present[present.length - 1];
    return present.map((level) => {
      const members = all.filter((f) => f.severity === level);
      return {
        key: level,
        label: <span class={`sev-word ${level}`}>{levelWord(level)}</span>,
        text: levelWord(level),
        count: members.length,
        more: source.hasMore() && level === last,
        rows: members,
        sentence: sharedValue(members, findingRule),
        collapsed: level === "info" && members.length > INFO_OPEN_MAX,
        tone: level,
      };
    });
  });

  const filtered = () => levels().length > 0 || kinds().length > 0 || !!prefix() || query() !== "";
  // The facts of the header: the one store's totals, the numbers of the rail and the status bar.
  const facts = () => {
    const total = counts()?.total;
    if (!total) return undefined;
    return t("discovery.findings.facts", { act: total.act, review: total.review, info: total.info });
  };

  const withQuery = (path: string) => `${path}${location.search}`;
  const open = (f: Finding) => {
    const target = selectionOf(f);
    if ("panel" in target) navigate(withQuery(paths.proposal(target.panel)));
    else navigate(target.href);
  };
  const close = () => navigate(withQuery(paths.discovery()));

  const [report, setReport] = createSignal<ReconcileReport | null>(null);
  const [running, setRunning] = createSignal(false);
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

  // Reject (ignore, dismiss) a proposal's finding from the row menu: the proposal is read first,
  // for its revision and its words.
  const [rejecting, setRejecting] = createSignal<Proposal | null>(null);
  const reject = async (f: Finding) => {
    const id = proposalOf(f);
    if (!id) return;
    try {
      setRejecting(await getProposal(id));
    } catch (err) {
      toast({ kind: "bad", title: t("discovery.findings.action.failed"), body: errorMessage(err) });
    }
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
      id: "discovery.proposals",
      group: "goto",
      icon: "proposal",
      label: () => t("discovery.nav.proposals"),
      run: () => navigate(paths.proposals()),
    },
    {
      id: "discovery.observations",
      group: "goto",
      icon: "search",
      label: () => t("discovery.nav.observations"),
      run: () => navigate(paths.observations()),
    },
  ]);

  const columns = findingColumns({ onPanel: open, onDone: () => source.reload() });
  const columnState = createColumnState("findings", () => columns);
  const rowActions: RowAction<Finding>[] = [
    { id: "open", label: () => t("discovery.action.open"), run: open },
    {
      id: "reject",
      label: () => t("discovery.findings.action.ignore"),
      hidden: (f) => !proposalOf(f) || !isDecider(),
      run: (f) => void reject(f),
    },
  ];

  const toggleIn = <T extends string>(name: string, list: T[], value: T) => {
    const next = list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
    setSearch({ [name]: next.length ? next.join(",") : undefined });
  };

  const levelCount = (level: FindingLevel) => (filtered() ? undefined : counts()?.total[level]);
  const target = () => (params.id ? panelTargetOf(params.id) : undefined);
  const current = () => {
    const tg = target();
    if (!tg) return undefined;
    return "proposal" in tg ? tg.proposal : "findingId" in tg ? tg.findingId : undefined;
  };

  // A click anywhere in a row opens the finding; links, buttons and group rows do their own thing.
  const onGridClick = (e: MouseEvent) => {
    const el = e.target as HTMLElement;
    if (el.closest("a, button, input, select, textarea")) return;
    const id = el.closest<HTMLElement>("tr[data-id]")?.dataset.id;
    const row = id ? rows().find((f) => f.id === id) : undefined;
    if (row) open(row);
  };

  return (
    <div class="page discovery-page findings-page" data-testid="page-discovery">
      <PageHeader
        title={t("shell.nav.discovery")}
        sub={<span data-testid="discovery-facts">{facts()}</span>}
        info={<p>{t("discovery.findings.info")}</p>}
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
      <FilterBar label={t("discovery.findings.filter.label")} placeholder={t("discovery.findings.filter.placeholder")} value={text()} onInput={setText} columns={columnState}>
        <span class="divider" />
        <For each={LEVELS}>
          {(level) => (
            <ToggleChip pressed={levels().includes(level)} onToggle={() => toggleIn("severity", levels(), level)} testid={`filter-severity-${level}`} count={levelCount(level)}>
              {levelWord(level)}
            </ToggleChip>
          )}
        </For>
        <span class="divider" />
        <For each={shownKinds()}>
          {(k) => (
            <ToggleChip
              pressed={kinds().includes(k)}
              onToggle={() => toggleIn("kind", kinds(), k)}
              testid={`filter-kind-${k}`}
              count={kindCounts().get(k) ?? 0}
              more={source.hasMore()}
              tone={k === "conflict" && (kindCounts().get(k) ?? 0) > 0 ? "conflict" : undefined}
            >
              <span class={`fglyph ${kindGlyph(k, "review").tone}`}>
                <Icon name={kindGlyph(k, "review").icon} size="xs" />
              </span>
              {kindWord(k)}
            </ToggleChip>
          )}
        </For>
        <Show when={prefix()}>
          {(id) => (
            <>
              <span class="divider" />
              <span class="chip applied" data-testid="filter-prefix">
                {t("discovery.filter.prefix", { prefix: prefixInfo()?.cidr ?? id().slice(0, 8) })}
                <button type="button" class="chip-x" data-testid="filter-chip-remove" aria-label={t("discovery.filter.remove_prefix")} onClick={() => setSearch({ prefix: undefined })}>
                  <Icon name="x" size="xs" />
                </button>
              </span>
            </>
          )}
        </Show>
      </FilterBar>
      <div class="discovery-split" classList={{ "with-panel": !!params.id }}>
        <div class="discovery-grid" onClick={onGridClick}>
          <GroupedGrid
            id="findings"
            label={t("discovery.findings.grid")}
            columns={columns}
            columnState={columnState}
            groups={groups()}
            rowId={(f) => f.id}
            rowKey={(f) => f.subject.label}
            rowLabel={(f) => t("discovery.findings.row", { kind: kindWord(f.kind), subject: f.subject.label })}
            rowClass={(f) => [rowClassOf(f), proposalOf(f) === current() || f.id === current() ? "current" : ""].filter(Boolean).join(" ") || undefined}
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
            rowActions={rowActions}
            empty={
              <div class="empty" data-testid="discovery-empty">
                <h3>{filtered() ? t("discovery.empty.filtered") : t("discovery.findings.empty")}</h3>
                <Show when={!filtered()}>
                  <p>{t("discovery.findings.empty_body")}</p>
                </Show>
              </div>
            }
          />
        </div>
        <Show when={target()} keyed>
          {(tg) => <DecisionPanel target={tg} names={names()} onClose={close} onDone={() => source.reload()} />}
        </Show>
      </div>
      <Show when={rejecting()} keyed>
        {(p) => (
          <RejectDialog
            proposals={[p]}
            send={(reason) => rejectProposal(p, reason)}
            onClose={() => setRejecting(null)}
            onDone={(r) => {
              setRejecting(null);
              writeToast(p.kind === "conflict" ? t("discovery.toast.dismissed") : t("discovery.toast.rejected"), r);
              source.reload();
            }}
          />
        )}
      </Show>
      <Show when={report()}>{(r) => <ReconcileReportDialog report={r()} onClose={() => setReport(null)} />}</Show>
    </div>
  );
}
