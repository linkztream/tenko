// The reconciliation view (/ipam/reconcile), the per-network evidence view of the findings (U4,
// UI-Q2): what intent, the leases, the DNS zones and the scans each say about an address, in one
// 28 px table scoped to the network it is opened from (`prefix`, which names the VRF; or a host).
// It answers "what is wrong in this network?"; Discovery answers "what needs my decision?".
//
// Rows are grouped by severity, then kind: conflicts to act on first, then unknown devices,
// orphaned records and PTR mismatches to review, ghost addresses as information (and to review
// once unseen for long). The severity of a row is its finding's (`GET /findings` of the same
// scope, followed on the `findings` topic), so a ghost that aged turns Review here as it does in
// Discovery; a row without a finding takes its kind's. A group row says what the group means in a
// short line and, when every row shares it, the rule that decides who wins, once. The truth that
// wins carries a small check glyph in its column; no cell is filled. The explanation of the kinds
// is behind the info button.
//
// Selecting a row opens the side panel Discovery uses (FindingPanel.tsx): a row with a proposal
// opens the proposal and its decisions, any other row its four truths, the rule and its default
// action. The row of the panel is in the URL (`row`, the row's key). Each kind is read page by
// page; a group whose kind has more rows ends with "Show more". Filters live in the URL: `prefix`
// and `host` take ids, `kind` narrows the page to one kind.
import { useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createResource, createSignal, For, on, Show } from "solid-js";
import { api } from "../../api/client";
import { fetchAll } from "../../api/paginate";
import { errorMessage } from "../../api/problem";
import type { Host, Prefix } from "../../api/types";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { PageHeader } from "../../components/PageHeader";
import { toast } from "../../components/toast";
import { DecisionPanel, type PanelTarget } from "../../discovery/FindingPanel";
import { levelWord, LEVELS, type Finding, type FindingLevel } from "../../discovery/findings";
import { useSourceNames } from "../../discovery/refs";
import { FilterBar, ToggleChip } from "../../grid/FilterBar";
import { GroupedGrid, type RowGroup } from "../../grid/GroupedGrid";
import { sharedValue } from "../../grid/groups";
import { createColumnState } from "../../grid/prefs";
import { createListSource, type ListSource } from "../../grid/source";
import { t } from "../../i18n";
import { IpamNav } from "../IpamNav";
import { reconcileColumns } from "./columns";
import { isKind, KIND_HELP, KIND_NOTE, KIND_TITLE, KINDS, RULE_TEXT, type ReconcileKind, type ReconcileRow } from "./model";
import "../../discovery/discovery.css";
import "./reconcile.css";

/** Rows per page of one kind. */
const PAGE_SIZE = 200;
/** Findings of the scope read at most, for the severities and actions of the rows. */
const FINDINGS_MAX = 5000;
/** An Info group with more rows than this starts closed. */
const INFO_OPEN_MAX = 10;
/** The kinds in the order of their groups within a severity. */
const GROUP_ORDER: readonly ReconcileKind[] = ["conflict", "rogue", "orphan", "ptr_mismatch", "ghost"];

/** A single value of a query parameter; a repeated parameter counts as absent. */
function one(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** The severity of a row without a finding: what its kind is by default (docs/reconciliation.md 12.2). */
export function defaultLevel(row: Pick<ReconcileRow, "kind" | "proposal">): FindingLevel {
  switch (row.kind) {
    case "conflict":
      return "act";
    case "rogue":
      return row.proposal ? "review" : "info";
    case "ghost":
      return "info";
    default:
      return "review";
  }
}

/** The findings of the rows, by the row they stand for: a row's own, its proposal's, or a conflict proposal about its address. */
export function findingsByRow(findings: readonly Finding[]): (row: ReconcileRow) => Finding | undefined {
  const byKey = new Map<string, Finding>();
  const byProposal = new Map<string, Finding>();
  const conflicts = new Map<string, Finding>();
  for (const f of findings) {
    if (f.source === "reconcile") byKey.set(f.evidence.id, f);
    else if (f.source === "proposal") {
      byProposal.set(f.evidence.id, f);
      if (f.kind === "conflict" && f.subject.ip) conflicts.set(f.subject.ip, f);
    }
  }
  return (row) => byKey.get(row.key) ?? (row.proposal ? byProposal.get(row.proposal) : undefined) ?? (row.kind === "conflict" ? conflicts.get(row.address) : undefined);
}

/** A finding for a row the index has none for, so the panel can show its evidence. */
function rowFinding(row: ReconcileRow): Finding {
  return {
    id: `reconcile:${row.key}`,
    kind: row.kind === "rogue" ? "unknown_device" : row.kind === "orphan" ? "orphaned_record" : row.kind,
    severity: defaultLevel(row),
    area: "ipam",
    subject: { kind: "address", label: row.address, ip: row.address, vrf: row.vrf ?? null, prefix: row.prefix ?? null, host: row.host ?? null, objects: [] },
    summary: t(RULE_TEXT[row.rule_id]),
    code: `ipam.reconcile.view.${row.kind}`,
    params: { ip: row.address, rule: row.rule_id, macs: (row.macs ?? []).join(", ") },
    evidence: { id: row.key, path: "/ipam/reconcile" },
    action: "none",
    since: row.last_seen ?? new Date().toISOString(),
    source: "reconcile",
  };
}

export default function ReconcileView() {
  const [search, setSearch] = useSearchParams();
  const names = useSourceNames();

  const kind = () => {
    const k = one(search.kind);
    return isKind(k) ? k : undefined;
  };
  const prefix = () => one(search.prefix);
  const host = () => one(search.host);
  const selected = () => one(search.row);
  const shown = (k: ReconcileKind) => !kind() || kind() === k;

  // The networks to choose from. A list that cannot be read leaves the drop-down with the
  // network of the URL only; the page still works.
  const [prefixes] = createResource(async (): Promise<Prefix[]> => {
    try {
      return (await fetchAll<Prefix>("/api/v1/prefixes", { max: 5000 })).items;
    } catch {
      return [];
    }
  });
  const prefixOptions = () => [...(prefixes() ?? [])].sort((a, b) => a.cidr.localeCompare(b.cidr, undefined, { numeric: true }));
  const scopePrefix = () => (prefixes() ?? []).find((p) => p.id === prefix());

  // The name of the host of the URL, for its chip.
  const [hostInfo] = createResource(host, async (id): Promise<Host | null> => {
    try {
      return (await api.get("/api/v1/hosts/{id}", { path: { id } })) as Host;
    } catch {
      return null;
    }
  });

  // One source per kind, read while the page shows the kind. The memo keeps a kind that stays
  // shown from reading again when the page narrows to it.
  const sources = Object.fromEntries(
    KINDS.map((k) => {
      const enabled = createMemo(() => shown(k));
      return [
        k,
        createListSource<ReconcileRow>({
          path: "/api/v1/ipam/reconcile",
          query: () => ({ kind: k, prefix: prefix(), host: host() }),
          rowId: (r) => r.key,
          pageSize: PAGE_SIZE,
          enabled,
          topics: ["ipam", "discovery"],
        }),
      ];
    }),
  ) as Record<ReconcileKind, ListSource<ReconcileRow>>;

  // The findings of the scope: the severity and the default action of each row.
  const findings = createListSource<Finding>({
    path: "/api/v1/findings",
    query: () => ({ prefix: prefix(), source: ["reconcile", "proposal"] }),
    rowId: (f) => f.id,
    pageSize: 1000,
    topics: ["findings"],
  });
  createEffect(() => {
    if (findings.hasMore() && !findings.loading() && !findings.error() && findings.rows().length < FINDINGS_MAX) findings.loadMore();
  });
  const findingOf = createMemo(() => findingsByRow(findings.rows()));
  const levelOf = (row: ReconcileRow) => findingOf()(row)?.severity ?? defaultLevel(row);

  const allRows = createMemo(() => KINDS.flatMap((k) => (shown(k) ? sources[k].rows() : [])));
  const groups = createMemo((): RowGroup<ReconcileRow>[] => {
    const out: RowGroup<ReconcileRow>[] = [];
    const lastOfKind = new Map<ReconcileKind, number>();
    for (const level of LEVELS) {
      for (const k of GROUP_ORDER) {
        if (!shown(k)) continue;
        const members = sources[k].rows().filter((r) => levelOf(r) === level);
        if (members.length === 0) continue;
        lastOfKind.set(k, out.length);
        const title = t(KIND_TITLE[k]);
        out.push({
          key: `${level}:${k}`,
          label: (
            <>
              <span class={`sev-word ${level}`}>{levelWord(level)}</span>
              <span>{title}</span>
            </>
          ),
          text: `${levelWord(level)} · ${title}`,
          count: members.length,
          note: t(KIND_NOTE[k]),
          sentence: sharedValue(members, (r) => t(RULE_TEXT[r.rule_id])),
          rows: members,
          collapsed: level === "info" && members.length > INFO_OPEN_MAX,
          tone: level,
        });
      }
    }
    // The last group of a kind with more rows to read says so and ends with "Show more".
    for (const [k, at] of lastOfKind) {
      const source = sources[k];
      if (!source.hasMore()) continue;
      const group = out[at]!;
      out[at] = {
        ...group,
        more: true,
        tail: () => (
          <button type="button" class="btn sm ghost" data-testid="reconcile-more" data-kind={k} disabled={source.loading()} onClick={() => source.loadMore()}>
            {t("ipam.reconcile.more")}
          </button>
        ),
      };
    }
    return out;
  });

  // The rows each kind has read, for the count on its chip; kept from before for a kind the page
  // no longer shows, dropped when the filters change.
  const [counts, setCounts] = createSignal<Partial<Record<ReconcileKind, { count: number; more: boolean }>>>({});
  createEffect(on([prefix, host], () => setCounts({}), { defer: true }));
  createEffect(() => {
    for (const k of KINDS) {
      const source = sources[k];
      if (shown(k) && !source.initial() && !source.error()) {
        const next = { count: source.rows().length, more: source.hasMore() };
        setCounts((c) => (c[k]?.count === next.count && c[k]?.more === next.more ? c : { ...c, [k]: next }));
      }
    }
  });

  const levels = createMemo(() => {
    const out = { act: 0, review: 0, info: 0 };
    for (const row of allRows()) out[levelOf(row)] += 1;
    return out;
  });
  const anyMore = () => KINDS.some((k) => shown(k) && sources[k].hasMore());
  const facts = () => {
    const scope = prefix() ? (scopePrefix()?.cidr ?? prefix()!.slice(0, 8)) : host() ? t("ipam.reconcile.filter.host_chip", { host: hostInfo()?.name ?? host()!.slice(0, 8) }) : t("ipam.reconcile.filter.all_prefixes");
    const l = levels();
    return t("ipam.reconcile.facts", { scope, act: l.act, review: l.review, info: l.info, more: anyMore() ? "yes" : "no" });
  };

  const [hostText, setHostText] = createSignal("");
  const [unknown, setUnknown] = createSignal<string | null>(null);
  const applyHost = async (e: SubmitEvent) => {
    e.preventDefault();
    const name = hostText().trim();
    if (!name) return;
    try {
      const page = await api.get("/api/v1/hosts", { query: { q: name, limit: 50 } });
      const found = (page.items as Host[]).find((h) => h.name.toLowerCase() === name.toLowerCase());
      if (!found) {
        setUnknown(name);
        return;
      }
      setUnknown(null);
      setHostText("");
      setSearch({ host: found.id });
    } catch (err) {
      toast({ kind: "bad", title: t("ipam.reconcile.filter.host"), body: errorMessage(err) });
    }
  };

  const open = (row: ReconcileRow) => setSearch({ row: row.key });
  const close = () => setSearch({ row: undefined });
  const reload = () => {
    for (const k of KINDS) if (shown(k)) sources[k].reload();
    findings.reload();
  };
  const panelTarget = createMemo((): PanelTarget | undefined => {
    const key = selected();
    if (!key) return undefined;
    const row = allRows().find((r) => r.key === key);
    if (!row) return undefined;
    const finding = findingOf()(row);
    if (finding?.source === "proposal") return { proposal: finding.evidence.id };
    if (row.proposal) return { proposal: row.proposal };
    return { finding: finding ?? rowFinding(row), row };
  });

  const columns = reconcileColumns({ finding: (row) => findingOf()(row), onPanel: (f) => {
    const row = allRows().find((r) => r.key === f.evidence.id || r.proposal === f.evidence.id || (f.kind === "conflict" && r.address === f.subject.ip && r.kind === "conflict"));
    if (row) open(row);
  }, onDone: reload });
  const columnState = createColumnState("reconcile", () => columns);
  const errors = () => KINDS.filter((k) => shown(k) && sources[k].error());
  const loading = () => KINDS.some((k) => shown(k) && sources[k].loading());
  const initial = () => KINDS.some((k) => shown(k) && sources[k].initial());

  // A click anywhere in a row opens it; links, buttons and group rows do their own thing.
  const onGridClick = (e: MouseEvent) => {
    const el = e.target as HTMLElement;
    if (el.closest("a, button, input, select, textarea")) return;
    const id = el.closest<HTMLElement>("tr[data-id]")?.dataset.id;
    const row = id ? allRows().find((r) => r.key === id) : undefined;
    if (row) open(row);
  };

  return (
    <div class="page reconcile-page" data-testid="page-ipam-reconcile">
      <IpamNav />
      <PageHeader
        title={t("ipam.reconcile.title")}
        sub={<span data-testid="reconcile-facts">{facts()}</span>}
        info={
          <>
            <p>{t("ipam.reconcile.info")}</p>
            <dl class="kv reconcile-help">
              <For each={GROUP_ORDER}>
                {(k) => (
                  <>
                    <dt>{t(KIND_TITLE[k])}</dt>
                    <dd>{t(KIND_HELP[k])}</dd>
                  </>
                )}
              </For>
            </dl>
          </>
        }
      />
      <FilterBar label={t("ipam.reconcile.filter.label")} testid="reconcile-filters" density={false} columns={columnState}>
        <select class="select" aria-label={t("ipam.reconcile.filter.prefix")} data-testid="filter-prefix" onChange={(e) => setSearch({ prefix: e.currentTarget.value || undefined, row: undefined })}>
          <option value="" selected={!prefix()}>
            {t("ipam.reconcile.filter.all_prefixes")}
          </option>
          <For each={prefixOptions()}>
            {(p) => (
              <option value={p.id} selected={prefix() === p.id}>
                {p.cidr}
              </option>
            )}
          </For>
        </select>
        <form class="reconcile-host-form" onSubmit={(e) => void applyHost(e)}>
          <input
            class="input mono"
            aria-label={t("ipam.reconcile.filter.host")}
            placeholder={t("ipam.reconcile.filter.host_placeholder")}
            data-testid="filter-host-input"
            autocomplete="off"
            spellcheck={false}
            value={hostText()}
            onInput={(e) => setHostText(e.currentTarget.value)}
          />
          <button type="submit" class="btn" data-testid="filter-host-apply" disabled={hostText().trim() === ""}>
            {t("ipam.reconcile.filter.host_apply")}
          </button>
        </form>
        <Show when={host()}>
          {(id) => (
            <span class="chip applied" data-testid="filter-host">
              {t("ipam.reconcile.filter.host_chip", { host: hostInfo()?.name ?? id().slice(0, 8) })}
              <button type="button" class="chip-x" data-testid="filter-chip-remove" aria-label={t("ipam.reconcile.filter.remove_host")} onClick={() => setSearch({ host: undefined })}>
                <Icon name="x" size="xs" />
              </button>
            </span>
          )}
        </Show>
        <span class="divider" />
        <div class="reconcile-kinds" role="group" aria-label={t("ipam.reconcile.filter.kind")}>
          <ToggleChip pressed={!kind()} onToggle={() => setSearch({ kind: undefined })} testid="filter-kind-all">
            {t("ipam.reconcile.filter.all_kinds")}
          </ToggleChip>
          <For each={GROUP_ORDER}>
            {(k) => (
              <ToggleChip
                pressed={kind() === k}
                onToggle={() => setSearch({ kind: kind() === k ? undefined : k })}
                testid={`filter-kind-${k}`}
                count={counts()[k]?.count}
                more={counts()[k]?.more}
                tone={k === "conflict" && (counts()[k]?.count ?? 0) > 0 ? "conflict" : undefined}
              >
                {t(KIND_TITLE[k])}
              </ToggleChip>
            )}
          </For>
        </div>
      </FilterBar>
      <Show when={unknown()}>
        {(name) => (
          <p class="muted reconcile-note" role="status" data-testid="filter-host-unknown">
            {t("ipam.reconcile.filter.host_unknown", { name: name() })}
          </p>
        )}
      </Show>
      <For each={errors()}>
        {(k) => (
          <div class="reconcile-error" data-testid={`reconcile-error-${k}`}>
            <ErrorNotice error={sources[k].error()} />
            <button type="button" class="btn" data-testid="reconcile-retry" onClick={() => sources[k].reload()}>
              {t("ipam.reconcile.retry")}
            </button>
          </div>
        )}
      </For>
      <div class="discovery-split reconcile-split" classList={{ "with-panel": !!panelTarget() }}>
        <div class="discovery-grid" onClick={onGridClick}>
          <GroupedGrid
            id="reconcile"
            label={t("ipam.reconcile.grid")}
            columns={columns}
            columnState={columnState}
            groups={groups()}
            rowId={(r) => r.key}
            rowKey={(r) => r.address}
            rowLabel={(r) => t("ipam.reconcile.row", { address: r.address, kind: t(KIND_TITLE[r.kind]) })}
            rowClass={(r) => [r.kind === "conflict" ? "conflict" : undefined, r.key === selected() ? "current" : undefined].filter(Boolean).join(" ") || undefined}
            noSelection
            loading={loading()}
            initial={initial()}
            onOpen={open}
            onDetails={open}
            empty={
              <div class="empty" data-testid="reconcile-empty">
                <h3>{t("ipam.reconcile.empty")}</h3>
              </div>
            }
          />
        </div>
        <Show when={panelTarget()} keyed>
          {(target) => <DecisionPanel target={target} names={names()} inReconcile onClose={close} onDone={reload} />}
        </Show>
      </div>
    </div>
  );
}
