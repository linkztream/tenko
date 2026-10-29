// The jobs list (/jobs, docs/plans/ui-plan.md section 5.4): is anything running or waiting for me?
// The default chip, "Active and needs you", leads with the jobs that run or wait, the ones that
// wait for a person first, and follows with the finished jobs grouped by the day they finished
// (Today and Yesterday open, Earlier closed; a long day shows its first ten). With nothing running
// or waiting one calm line says so above the days. Live updates come from the `jobs` topic.
//
// Two reads: the jobs that are not over (every page, there are few) and the finished ones, page by
// page; the last day group offers the next page instead of the grid reading on by itself, so a
// closed Earlier never pulls the whole history in. The number of jobs waiting for a person in the
// header is the one of the findings store, the number of the rail badge.
//
// Filters: the chips, the query field over title, kind and id (on the client), and `kind` and
// `target` from the URL, which the server filters. `?group=` is filtered on the client, because
// the API has no group filter; a group also shows its summary and the grouped checklist of its
// manual tasks above the grid (design decision 7), and loads the whole list so the group is
// complete.
import { useNavigate, useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createSignal, For, onCleanup, Show, type JSX } from "solid-js";
import type { JobSummary, Principal } from "../api/types";
import { session } from "../auth/session";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { PrincipalLabel, shortId } from "../components/Principal";
import { FilterBar, ToggleChip } from "../grid/FilterBar";
import { GroupedGrid, type RowGroup } from "../grid/GroupedGrid";
import { createColumnState, type ColumnState } from "../grid/prefs";
import { createListSource } from "../grid/source";
import { formatNumber, t, tx } from "../i18n";
import { useFindingCounts } from "../shell/findings";
import { now } from "../shell/status";
import { jobColumns } from "./columns";
import { GroupPanel } from "./GroupPanel";
import { DAY_ROWS, dayBuckets, leadRows, sharedStarter, startOfDay, waitingCount, type Day } from "./layout";
import { ACTIVE_STATES, FINAL_STATES, groupLabel, isFinal, leadsWithActive, matchesView, needsPerson, parseView, VIEWS, type JobView } from "./model";
import { kindText } from "./Target";
import { jobTitle } from "./words";
import "./jobs.css";

const VIEW_LABEL = {
  active: "jobs.view.active",
  failed: "jobs.view.failed",
  finished: "jobs.view.finished",
  all: "jobs.view.all",
} as const satisfies Record<JobView, string>;

const DAY_LABEL = {
  today: "jobs.day.today",
  yesterday: "jobs.day.yesterday",
  earlier: "jobs.day.earlier",
} as const satisfies Record<Day, string>;

const REST_LABEL = {
  today: "jobs.day.rest.today",
  yesterday: "jobs.day.rest.yesterday",
  earlier: "jobs.day.rest.earlier",
} as const satisfies Record<Day, string>;

const PATH = "/api/v1/jobs";

/** A single value of a query parameter; a repeated parameter counts as absent. */
function one(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** The free-text filter: title, kind and id, all in lowercase. */
function matchesText(job: JobSummary, text: string): boolean {
  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const hay = `${jobTitle(job)} ${job.kind} ${job.id}`.toLowerCase();
  return words.every((w) => hay.includes(w));
}

/** "host 0190d1c2" for `host/0190d1c2-...`; a value that is not `kind/id` stays as it is. */
function targetLabel(target: string): string {
  const slash = target.indexOf("/");
  return slash < 0 ? target : `${kindText(target.slice(0, slash))} ${shortId(target.slice(slash + 1))}`;
}

/** A count that may grow: "200+" while more pages are to come. */
function countText(count: number, more: boolean): string {
  return more ? t("grid.filter.count_more", { count: formatNumber(count) }) : formatNumber(count);
}

/** A filter that comes from the URL: its words and a button that removes it. */
function AppliedFilter(props: { label: string; testid: string; onRemove: () => void }) {
  return (
    <span class="chip applied" data-testid={props.testid}>
      {props.label}
      <button
        type="button"
        class="chip-x"
        aria-label={t("jobs.filter.remove", { filter: props.label })}
        onClick={() => props.onRemove()}
      >
        <Icon name="x" size="xs" />
      </button>
    </span>
  );
}

/** The one starter of every listed job: "you" for the signed-in user, else the principal. */
function Starter(props: { principal: Principal }) {
  const me = () => props.principal.kind === "user" && props.principal.id === session()?.user.id;
  return <Show when={me()} fallback={<PrincipalLabel principal={props.principal} />}>{t("jobs.by_you")}</Show>;
}

/** The last row of an open day: the rest of the day, or the next page of the history. */
function TailButton(props: { label: string; onClick: () => void }) {
  return (
    <button type="button" class="job-tail" tabIndex={-1} data-testid="jobs-tail" onClick={() => props.onClick()}>
      {props.label}
    </button>
  );
}

export default function JobsView() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [text, setText] = createSignal("");

  // The jobs waiting for a person, from the one findings store: the same number as the rail badge.
  const findings = useFindingCounts();
  const waiting = () => waitingCount(findings());

  const view = () => parseView(params.view);
  const kind = () => one(params.kind);
  const target = () => one(params.target);
  const group = () => one(params.group);

  const active = createListSource<JobSummary>({
    path: PATH,
    query: () => ({ kind: kind(), target: target(), state: [...ACTIVE_STATES] }),
    rowId: (job) => job.id,
    topics: ["jobs"],
  });
  const finished = createListSource<JobSummary>({
    path: PATH,
    query: () => ({ kind: kind(), target: target(), state: [...FINAL_STATES] }),
    rowId: (job) => job.id,
    topics: ["jobs"],
  });

  // Every job that is not over is listed, and a group is only complete when every page is in.
  createEffect(() => {
    if (active.hasMore() && !active.loading()) active.loadMore();
  });
  createEffect(() => {
    if (group() && finished.hasMore() && !finished.loading()) finished.loadMore();
  });

  const inGroup = (job: JobSummary) => {
    const g = group();
    return !g || job.group === g;
  };
  // A job that just finished may still be in the older answer of the other read: the finished
  // read decides.
  const finishedIds = createMemo(() => new Set(finished.rows().map((job) => job.id)));
  const openRows = createMemo(() => active.rows().filter((job) => !isFinal(job.state) && !finishedIds().has(job.id) && inGroup(job)));
  const doneRows = createMemo(() => finished.rows().filter((job) => isFinal(job.state) && inGroup(job)));
  const openCounts = createMemo(() => leadRows(openRows()));

  const lead = createMemo(() => (leadsWithActive(view()) ? leadRows(openRows().filter((job) => matchesText(job, text()))) : { needs: [], active: [] }));
  const listedDone = createMemo(() => doneRows().filter((job) => matchesView(view(), job) && matchesText(job, text())));

  // The day groups follow the local midnight; the memo changes once a day, not every second.
  const today = createMemo(() => {
    now();
    return startOfDay(Date.now());
  });
  const buckets = createMemo(() => dayBuckets(listedDone(), today()));

  // The days whose rest the person asked for, for the life of the page.
  const [rest, setRest] = createSignal<ReadonlySet<Day>>(new Set());
  const showRest = (day: Day) => setRest((cur) => new Set([...cur, day]));

  const groups = createMemo((): RowGroup<JobSummary>[] => {
    const out: RowGroup<JobSummary>[] = [];
    const { needs, active: running } = lead();
    if (needs.length > 0) {
      const word = t("jobs.lead.needs");
      out.push({ key: "needs", label: <span class="sev-word act">{word}</span>, text: word, count: needs.length, rows: needs, tone: "act" });
    }
    if (running.length > 0) {
      const word = t("jobs.lead.active");
      out.push({ key: "active", label: <b>{word}</b>, text: word, count: running.length, rows: running });
    }
    const days = buckets();
    const last = days[days.length - 1];
    for (const bucket of days) {
      const word = t(DAY_LABEL[bucket.day]);
      const whole = rest().has(bucket.day) || bucket.rows.length <= DAY_ROWS;
      const rows = whole ? bucket.rows : bucket.rows.slice(0, DAY_ROWS);
      const hidden = bucket.rows.length - rows.length;
      const more = bucket === last && finished.hasMore();
      let tail: (() => JSX.Element) | undefined;
      if (hidden > 0) {
        const day = bucket.day;
        tail = () => <TailButton label={t(REST_LABEL[day], { count: hidden })} onClick={() => showRest(day)} />;
      } else if (more) {
        tail = () => <TailButton label={t("jobs.day.older")} onClick={() => finished.loadMore()} />;
      }
      out.push({
        key: bucket.day,
        label: <b>{word}</b>,
        text: word,
        count: bucket.rows.length,
        more,
        note: t("jobs.day.note", { outcome: bucket.outcome, failed: bucket.failed }),
        rows,
        collapsed: bucket.day === "earlier",
        tail,
      });
    }
    return out;
  });

  const listed = createMemo(() => [...lead().needs, ...lead().active, ...listedDone()]);

  // Started by is said once when one person started every listed job, and the column comes back
  // as soon as there are two. The current step is only shown while a listed job runs or waits.
  const starter = createMemo(() => sharedStarter(listed()));
  const autoHidden = createMemo(() => {
    const out = new Set<string>();
    if (starter()) out.add("by");
    if (lead().needs.length + lead().active.length === 0) out.add("step");
    return out;
  });
  const columns = jobColumns();
  const columnState = createColumnState("jobs", () => columns);
  const shownColumns: ColumnState<JobSummary> = {
    ...columnState,
    visible: () => columnState.visible().filter((c) => !autoHidden().has(c.id)),
  };

  const loaded = () => !active.initial() && !finished.initial();
  const nothingOpen = () => loaded() && !active.hasMore() && openRows().length === 0;
  const calm = () => leadsWithActive(view()) && nothingOpen() && text().trim() === "" && listedDone().length > 0;

  // The facts of the header: what runs, what waits for a person (the store's number) and how much is done.
  const facts = () => {
    if (!loaded()) return undefined;
    const running = openCounts().active.length;
    const done = countText(doneRows().length, finished.hasMore());
    const w = waiting();
    return w === undefined ? t("jobs.facts_open", { running, finished: done }) : t("jobs.facts", { running, waiting: w, finished: done });
  };

  const chipCount = (v: JobView): { count?: number; more?: boolean } => {
    if (v === "active") return { count: openRows().length };
    if (v === "failed") {
      return { count: doneRows().filter((job) => matchesView("failed", job)).length, more: finished.hasMore() };
    }
    return {};
  };

  const filtered = () => view() !== "active" || !!kind() || !!target() || !!group() || text().trim() !== "";
  const open = (job: JobSummary) => navigate(paths.job(job.id));

  // A click anywhere in a job's row opens the job; links and buttons inside it, group rows and
  // the last row of a day do their own thing.
  const onGridClick = (e: MouseEvent) => {
    const el = e.target as HTMLElement;
    if (el.closest("a, button, input, select, textarea")) return;
    const row = el.closest<HTMLElement>("tr[data-id]");
    if (!row || row.classList.contains("group-row") || row.classList.contains("group-tail")) return;
    const id = row.dataset.id;
    if (id) navigate(paths.job(id));
  };

  // Enter and Space on the last row of a day press its button: the grid itself only opens rows.
  let wrap: HTMLDivElement | undefined;
  const onTailKey = (e: KeyboardEvent) => {
    if ((e.key !== "Enter" && e.key !== " ") || e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
    const active = (e.target as HTMLElement).getAttribute?.("aria-activedescendant");
    const cell = active ? document.getElementById(active) : null;
    const button = cell?.closest("tr.group-tail")?.querySelector<HTMLButtonElement>("button.job-tail");
    if (!button) return;
    e.preventDefault();
    e.stopPropagation();
    button.click();
  };
  createEffect(() => {
    const el = wrap;
    if (!el) return;
    el.addEventListener("keydown", onTailKey, true);
    onCleanup(() => el.removeEventListener("keydown", onTailKey, true));
  });

  const reload = () => {
    active.reload();
    finished.reload();
  };

  return (
    <div class="page jobs-page" data-testid="page-jobs">
      <PageHeader
        title={t("jobs.title")}
        sub={facts()}
        info={
          <>
            <p>{t("jobs.sub")}</p>
            <p>{t("jobs.info")}</p>
          </>
        }
      />
      <Show when={group()} keyed>
        {(g) => (
          <GroupPanel
            group={g}
            jobs={[...openRows(), ...doneRows()]}
            loading={active.hasMore() || active.loading() || finished.hasMore() || finished.loading()}
            onChanged={reload}
          />
        )}
      </Show>
      <FilterBar
        label={t("jobs.filter.label")}
        placeholder={t("jobs.filter.placeholder")}
        value={text()}
        onInput={setText}
        columns={shownColumns}
        actions={
          <Show when={starter()}>
            {(p) => (
              <span class="jobs-starter" data-testid="jobs-starter">
                {tx("jobs.by_all", { who: <Starter principal={p()} /> })}
              </span>
            )}
          </Show>
        }
      >
        <span class="divider" />
        <For each={VIEWS}>
          {(v) => (
            <ToggleChip
              pressed={view() === v}
              onToggle={() => setParams({ view: v === "active" ? undefined : v })}
              testid={`view-${v}`}
              count={loaded() ? chipCount(v).count : undefined}
              more={chipCount(v).more}
              tone={v === "active" && (waiting() ?? 0) > 0 ? "conflict" : undefined}
            >
              {t(VIEW_LABEL[v])}
            </ToggleChip>
          )}
        </For>
        <Show when={kind() || target() || group()}>
          <span class="divider" />
        </Show>
        <Show when={kind()}>
          {(k) => (
            <AppliedFilter
              testid="filter-kind"
              label={t("jobs.filter.kind", { kind: k() })}
              onRemove={() => setParams({ kind: undefined })}
            />
          )}
        </Show>
        <Show when={target()}>
          {(tg) => (
            <AppliedFilter
              testid="filter-target"
              label={t("jobs.filter.target", { target: targetLabel(tg()) })}
              onRemove={() => setParams({ target: undefined })}
            />
          )}
        </Show>
        <Show when={group()}>
          {(g) => (
            <AppliedFilter
              testid="filter-group"
              label={t("jobs.filter.group", { group: groupLabel(g()) })}
              onRemove={() => setParams({ group: undefined })}
            />
          )}
        </Show>
      </FilterBar>
      <Show when={calm()}>
        <p class="jobs-calm" role="status" data-testid="jobs-calm">
          <Icon name="check" size="sm" />
          <span>{t("jobs.calm")}</span>
        </p>
      </Show>
      <div class="jobs-grid" ref={wrap} onClick={onGridClick}>
        <GroupedGrid
          id="jobs"
          label={t("jobs.title")}
          columns={columns}
          columnState={shownColumns}
          groups={groups()}
          rowId={(job) => job.id}
          rowKey={(job) => job.id}
          rowLabel={(job) => jobTitle(job)}
          rowClass={(job) => (needsPerson(job) && !isFinal(job.state) ? "needs" : undefined)}
          noSelection
          loading={active.loading() || finished.loading()}
          initial={active.initial() || finished.initial()}
          error={active.error() ?? finished.error()}
          onRetry={reload}
          flashed={(id) => active.flashed(id) || finished.flashed(id)}
          onOpen={open}
          onOpenPage={open}
          count={{ value: listed().length, noun: t("grid.rows", { count: listed().length }) }}
          empty={
            <div class="empty">
              <h3>{filtered() ? t("jobs.empty.filtered") : t("jobs.empty.title")}</h3>
              <Show when={!filtered()}>
                <p>{t("jobs.empty.body")}</p>
              </Show>
            </div>
          }
        />
      </div>
    </div>
  );
}
