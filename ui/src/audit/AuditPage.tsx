// The audit log (/audit, IAM-18): the status of the hash chain, a filter bar whose values
// live in the URL, and a grid over GET /api/v1/audit read page by page.
//
// Live records: the log grows while it is open. When the list is newest first and scrolled to
// the top, new records are read in and appear. Otherwise rows never move: a bar in the footer
// says how many records are new, and a button shows them.
import { useNavigate, useSearchParams } from "@solidjs/router";
import { batch, createEffect, createMemo, createResource, createSignal, on, onCleanup, Show } from "solid-js";
import { api } from "../api/client";
import { events } from "../api/events";
import { fetchAll } from "../api/paginate";
import type { AuditRecord, UserInfo } from "../api/types";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/PageHeader";
import { DataGrid } from "../grid/DataGrid";
import { createListSource } from "../grid/source";
import { t } from "../i18n";
import { useCommands } from "../shell/commands";
import { AuditFilters, type FilterPatch } from "./AuditFilters";
import { ChainStatus, createChain } from "./ChainStatus";
import { auditColumns } from "./columns";
import { filterState, readFilters } from "./filters";
import "./audit.css";

/** Records the "new records" probe looks at; a full page of new ones reads "N or more". */
const PROBE_LIMIT = 100;
/** Pause that lets a burst of events become one probe. */
const PROBE_DELAY_MS = 200;
/** Scroll offset in pixels below which the list counts as scrolled to the top. */
const TOP_SLACK = 2;

interface Fresh {
  /** The revision the list was read at when the count was taken. */
  base: number;
  count: number;
  capped: boolean;
}

async function loadUsers(): Promise<UserInfo[]> {
  // The principal field suggests users when the account may read them.
  try {
    return (await fetchAll<UserInfo>("/api/v1/users")).items;
  } catch {
    return [];
  }
}

export default function AuditPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useSearchParams();
  const values = createMemo(() => readFilters(search));
  const state = createMemo(() => filterState(values()));
  const query = createMemo(() => state().query, undefined, {
    equals: (a, b) => JSON.stringify(a) === JSON.stringify(b),
  });
  const order = () => state().order;

  const chain = createChain();
  const [users] = createResource(loadUsers);
  const userList = () => (users.state === "ready" ? (users() ?? []) : []);

  const columns = auditColumns();

  // The list scrolls inside the grid; new rows only appear unannounced while it is at the top.
  let table: HTMLTableElement | undefined;
  let wrap: HTMLElement | null = null;
  const [atTop, setAtTop] = createSignal(true);
  const onScroll = () => setAtTop((wrap?.scrollTop ?? 0) < TOP_SLACK);
  const gridRef = (el: HTMLTableElement) => {
    table = el;
    wrap = el.closest<HTMLElement>(".grid-wrap");
    wrap?.addEventListener("scroll", onScroll, { passive: true });
    onCleanup(() => wrap?.removeEventListener("scroll", onScroll));
  };
  const following = () => order() === "desc" && atTop();

  const list = createListSource<AuditRecord>({
    path: "/api/v1/audit",
    query,
    rowId: (record) => String(record.seq),
    // A record never changes, so no row flashes; new ones simply appear.
    signature: (record) => record.hash,
    topics: ["audit"],
    relevant: () => following(),
  });

  // Records that arrived while the list holds still: counted with the same filters.
  const [fresh, setFresh] = createSignal<Fresh | null>(null);
  const pending = () => {
    const f = fresh();
    return f && f.base === list.revision() ? f : null;
  };
  let probeTimer: ReturnType<typeof setTimeout> | undefined;
  let probeAbort: AbortController | undefined;
  let probeRun = 0;
  const probe = async () => {
    const base = list.revision();
    if (base === undefined) return;
    probeAbort?.abort();
    probeAbort = new AbortController();
    const run = (probeRun += 1);
    try {
      const page = await api.get("/api/v1/audit", {
        query: { ...query(), order: "desc", limit: PROBE_LIMIT },
        signal: probeAbort.signal,
      });
      if (run !== probeRun) return;
      const count = page.items.filter((record) => record.revision > base).length;
      setFresh(count > 0 ? { base, count, capped: count >= PROBE_LIMIT } : null);
    } catch {
      // The bar is a convenience: a failed count shows nothing.
    }
  };
  // The newest revision announced while the list held still.
  let latestHeld = 0;
  // eslint-disable-next-line solid/reactivity -- an event callback, like an event handler
  const off = events.subscribe("audit", (event) => {
    if (following()) return;
    const base = list.revision();
    if (event.revision !== undefined && base !== undefined && event.revision <= base) return;
    latestHeld = Math.max(latestHeld, event.revision ?? 0);
    clearTimeout(probeTimer);
    probeTimer = setTimeout(() => void probe(), PROBE_DELAY_MS);
  });
  onCleanup(() => {
    off();
    clearTimeout(probeTimer);
    probeAbort?.abort();
  });

  // Back at the top of a newest-first list: what arrived meanwhile is read in.
  createEffect(
    on(
      following,
      (now, before) => {
        if (!now || before !== false || latestHeld <= (list.revision() ?? 0)) return;
        setFresh(null);
        list.reload();
      },
      { defer: true },
    ),
  );

  const change = (patch: FilterPatch, replace = false) => {
    setSearch(patch, { replace });
  };

  const showNew = () => {
    if (order() === "asc") {
      // The new records are at the far end of an oldest-first list: show the newest first.
      change({ order: undefined });
      return;
    }
    batch(() => {
      setFresh(null);
      setAtTop(true);
    });
    if (wrap) wrap.scrollTop = 0;
    list.reload();
    table?.focus({ preventScroll: true });
  };

  const open = (record: AuditRecord) => navigate(paths.auditRecord(record.seq));

  // A click on a row opens its record; links, buttons and a text selection keep their meaning.
  // The listener runs before the grid's own, which may scroll and replace the row under the click.
  const onGridClick = (e: MouseEvent) => {
    if (e.defaultPrevented || e.button !== 0 || e.shiftKey || e.ctrlKey || e.metaKey || e.altKey) return;
    const target = e.target as HTMLElement;
    if (target.closest("a, button, input, select, textarea, label")) return;
    const row = target.closest<HTMLElement>("tbody tr[data-id]");
    if (!row?.dataset.id) return;
    if (window.getSelection()?.toString()) return;
    navigate(paths.auditRecord(Number(row.dataset.id)));
  };

  const watchClicks = (el: HTMLDivElement) => {
    el.addEventListener("click", onGridClick, true);
    onCleanup(() => el.removeEventListener("click", onGridClick, true));
  };

  useCommands(() => [
    {
      id: "audit.verify",
      group: "actions",
      icon: "shield",
      label: () => t("shell.command.audit_verify"),
      run: () => chain.verify(),
    },
  ]);

  return (
    <div class="page audit-page" data-testid="page-audit">
      <PageHeader
        title={t("audit.title")}
        sub={list.initial() ? undefined : t("audit.sub_count", { count: list.rows().length, more: list.hasMore() ? "yes" : "no" })}
        info={
          <>
            <p>{t("audit.sub")}</p>
            <p>{t("audit.info")}</p>
          </>
        }
      />
      <ChainStatus chain={chain} />
      <AuditFilters values={values()} state={state()} users={userList()} onChange={change} />
      <div class="audit-grid" ref={watchClicks}>
        <DataGrid
          id="audit"
          label={t("audit.grid.label")}
          columns={columns}
          rows={list.rows()}
          rowId={(record) => String(record.seq)}
          rowKey={(record) => String(record.seq)}
          rowLabel={(record) => t("audit.row", { seq: String(record.seq) })}
          noSelection
          statusBar={false}
          loading={list.loading()}
          initial={list.initial()}
          hasMore={list.hasMore()}
          onLoadMore={list.loadMore}
          error={list.error()}
          onRetry={list.reload}
          onOpen={open}
          onOpenPage={open}
          ref={gridRef}
          empty={
            <div class="empty" data-testid="audit-empty">
              <h3>{state().filtered ? t("audit.empty.filtered") : t("audit.empty.none")}</h3>
              <Show when={state().filtered}>
                <p>{t("audit.empty.filtered_hint")}</p>
              </Show>
            </div>
          }
          footer={
            <>
              <span class="audit-new" role="status" data-testid="audit-new">
                <Show when={pending()}>
                  {(p) => (
                    <>
                      <Icon name="refresh" size="xs" />
                      {p().capped ? t("audit.live.new_many", { count: p().count }) : t("audit.live.new", { count: p().count })}
                    </>
                  )}
                </Show>
              </span>
              <Show when={pending()}>
                <button type="button" class="btn sm primary" data-testid="audit-show-new" onClick={showNew}>
                  {order() === "asc" ? t("audit.live.show_latest") : t("audit.live.show")}
                </button>
              </Show>
            </>
          }
        />
      </div>
    </div>
  );
}
