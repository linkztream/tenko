// The jobs list (/jobs): background work, newest first, over GET /jobs with live updates from
// the `jobs` topic. A job that waits for a person carries a marker with an icon and words.
//
// Filters: the state chips (the server filters by state; "needs you" narrows down on the client
// because the list has no filter for manual steps), and `kind` and `target` from the URL, which
// the server filters too. `?group=` is filtered on the client, because the API has no group
// filter; a group also shows its summary and the grouped checklist of its manual tasks above the
// grid (design decision 7), and loads the whole list so the group is complete.
import { useNavigate, useSearchParams } from "@solidjs/router";
import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import type { JobSummary } from "../api/types";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { shortId } from "../components/Principal";
import { DataGrid } from "../grid/DataGrid";
import { FilterBar, ToggleChip } from "../grid/FilterBar";
import { createColumnState } from "../grid/prefs";
import { createListSource } from "../grid/source";
import { t } from "../i18n";
import { areaCounts, useFindingCounts } from "../shell/findings";
import { jobColumns } from "./columns";
import { GroupPanel } from "./GroupPanel";
import { groupLabel, matchesView, parseView, VIEWS, viewStates, type JobView } from "./model";
import { kindText } from "./Target";
import { jobTitle } from "./words";
import "./jobs.css";

const VIEW_LABEL = {
  all: "jobs.view.all",
  active: "jobs.view.active",
  needs: "jobs.needs_you",
  failed: "jobs.view.failed",
  finished: "jobs.view.finished",
} as const satisfies Record<JobView, string>;

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

export default function JobsView() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [text, setText] = createSignal("");

  // The jobs waiting for a person, from the one findings store: the same number as the rail badge.
  const findings = useFindingCounts();
  const waiting = () => areaCounts(findings(), "jobs").act;

  const view = () => parseView(params.view);
  const kind = () => one(params.kind);
  const target = () => one(params.target);
  const group = () => one(params.group);

  const source = createListSource<JobSummary>({
    path: "/api/v1/jobs",
    // A group is filtered on the client over every state, so its counts are complete.
    query: () => ({ kind: kind(), target: target(), state: group() ? undefined : viewStates(view()) }),
    rowId: (job) => job.id,
    topics: ["jobs"],
  });

  const columns = jobColumns();
  const columnState = createColumnState("jobs", () => columns);

  const groupRows = createMemo(() => {
    const g = group();
    return g ? source.rows().filter((job) => job.group === g) : [];
  });
  const rows = createMemo(() => {
    const g = group();
    return source.rows().filter((job) => (!g || job.group === g) && matchesView(view(), job) && matchesText(job, text()));
  });

  // The group is only complete when every page is in: read on until the list ends.
  createEffect(() => {
    if (group() && source.hasMore() && !source.loading()) source.loadMore();
  });

  const filtered = () => view() !== "all" || !!kind() || !!target() || !!group() || text().trim() !== "";
  const open = (job: JobSummary) => navigate(paths.job(job.id));

  // A click anywhere in a row opens the job; links and buttons inside it do their own thing.
  const onGridClick = (e: MouseEvent) => {
    const el = e.target as HTMLElement;
    if (el.closest("a, button, input, select, textarea")) return;
    const id = el.closest<HTMLElement>("tr[data-id]")?.dataset.id;
    if (id) navigate(paths.job(id));
  };

  return (
    <div class="page jobs-page" data-testid="page-jobs">
      <PageHeader
        title={t("jobs.title")}
        sub={findings() ? t("jobs.sub_waiting", { count: waiting() }) : undefined}
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
            jobs={groupRows()}
            loading={source.hasMore() || source.loading()}
            onChanged={() => source.reload()}
          />
        )}
      </Show>
      <FilterBar
        label={t("jobs.filter.label")}
        placeholder={t("jobs.filter.placeholder")}
        value={text()}
        onInput={setText}
        columns={columnState}
      >
        <span class="divider" />
        <For each={VIEWS}>
          {(v) => (
            <ToggleChip
              pressed={view() === v}
              onToggle={() => setParams({ view: v === "all" ? undefined : v })}
              testid={`view-${v}`}
              count={v === "needs" && waiting() > 0 ? waiting() : undefined}
              tone={v === "needs" && waiting() > 0 ? "conflict" : undefined}
            >
              <Show when={v === "needs"}>
                <Icon name="alert" />
              </Show>
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
      <div class="jobs-grid" onClick={onGridClick}>
        <DataGrid
          id="jobs"
          label={t("jobs.title")}
          columns={columns}
          columnState={columnState}
          rows={rows()}
          rowId={(job) => job.id}
          rowKey={(job) => job.id}
          rowLabel={(job) => jobTitle(job)}
          rowClass={(job) => ((job.manual_steps?.length ?? 0) > 0 ? "needs" : undefined)}
          noSelection
          loading={source.loading()}
          initial={source.initial()}
          hasMore={source.hasMore()}
          onLoadMore={source.loadMore}
          error={source.error()}
          onRetry={source.reload}
          flashed={source.flashed}
          onOpen={open}
          onOpenPage={open}
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
