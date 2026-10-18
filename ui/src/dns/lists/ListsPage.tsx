// The block lists of the DNS area (/dns/lists, plan section 2.8, P2-Q6): each list with its
// source (a URL a controller fetches on a schedule, or a file the operator uploads), its format,
// how often it is fetched, what a blocked name answers, whether it is applied, and its newest
// compiled version (the names it blocks, when it was read, the ETag of the file, the last
// failed fetch). Create, edit, delete, "fetch now" for a URL list and the upload of a file for
// an uploaded one; both start a job, which the page follows on the `jobs` topic and links to.
// While WP5.2 is not merged the server answers 501 and the page says so.
import { A } from "@solidjs/router";
import { createEffect, createSignal, on, Show } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery, latest } from "../../api/live";
import { errorMessage } from "../../api/problem";
import { paths } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { DataGrid } from "../../grid/DataGrid";
import { TimeAgo } from "../../grid/cells";
import type { Column, RowAction } from "../../grid/types";
import { formatNumber, t } from "../../i18n";
import { JobStateChip } from "../../jobs/StateChip";
import { mayWriteDns } from "../access";
import { DnsNav } from "../DnsNav";
import { DnsProblem, unavailable } from "../Parts";
import { fetchBlockList, listBlockLists, type BlockListItem } from "./api";
import { DeleteListDialog, ListDialog, UploadListDialog } from "./ListDialog";
import { redirectOf } from "./model";
import "../dns.css";

function intervalText(l: BlockListItem): string {
  return l.source.kind === "url" && l.interval_hours ? t("dns.list.every", { hours: l.interval_hours }) : "";
}

const FINAL = new Set(["succeeded", "failed", "cancelled", "rolled_back"]);

/** The job a fetch or an upload started, followed until it ends; the lists are read again then. */
function ListJob(props: { id: string; name: string; onFinished: () => void }) {
  const job = createLiveQuery({
    topics: ["jobs"],
    relevant: (e) => e.objects.some((o) => o.kind === "job" && o.id === props.id),
    fetch: async (signal) => {
      const detail = await api.get("/api/v1/jobs/{id}", { path: { id: props.id }, signal });
      return { value: detail, revision: Number(detail.revision) };
    },
  });
  const state = () => latest(job)?.job.state;
  createEffect(on(state, (s) => (s && FINAL.has(s) ? props.onFinished() : undefined), { defer: true }));
  const done = () => latest(job)?.job.steps.filter((s) => s.state.state === "done" || s.state.state === "skipped").length ?? 0;
  const total = () => latest(job)?.job.steps.length ?? 0;
  return (
    <div class="dns-list-job" data-testid="list-job" data-id={props.id} data-state={state() ?? "pending"}>
      <span class="grow">{t("dns.list.job", { name: props.name })}</span>
      <Show when={state()}>{(s) => <JobStateChip state={s()} done={done()} total={total()} />}</Show>
      <A class="btn sm" href={paths.job(props.id)} data-testid="list-job-open">
        {t("dns.list.open_job")}
      </A>
    </div>
  );
}

type DialogState =
  | { kind: "edit"; list?: BlockListItem }
  | { kind: "upload"; list: BlockListItem }
  | { kind: "delete"; list: BlockListItem }
  | null;

export default function ListsPage() {
  const [dialog, setDialog] = createSignal<DialogState>(null);
  const [job, setJob] = createSignal<{ id: string; name: string } | null>(null);
  const query = createLiveQuery({
    topics: ["dns"],
    fetch: async (signal) => {
      const page = await listBlockLists(signal);
      return { value: [...page.items].sort((a, b) => a.name.localeCompare(b.name)), revision: page.revision };
    },
  });
  const blocked = () => unavailable(query.value.error);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };
  const follow = (id: string | undefined, name: string) => {
    if (id) setJob({ id, name });
  };

  const fetchNow = async (list: BlockListItem) => {
    try {
      follow(await fetchBlockList(list.id), list.name);
      toast({ kind: "ok", title: t("dns.list.fetch_started", { name: list.name }) });
    } catch (err) {
      toast({ kind: "bad", title: t("dns.list.fetch_failed", { name: list.name }), body: errorMessage(err) });
    }
  };

  const columns: Column<BlockListItem>[] = [
    {
      id: "name",
      header: () => t("dns.col.name"),
      width: 200,
      fixed: true,
      text: (l) => l.name,
      render: (l) => (
        <span class="dns-chips">
          <span>{l.name}</span>
          <Show when={l.enabled === false}>
            <span class="tag" data-testid="list-disabled">
              {t("dns.list.disabled")}
            </span>
          </Show>
        </span>
      ),
    },
    {
      id: "source",
      header: () => t("dns.list.col.source"),
      text: (l) => (l.source.kind === "url" ? l.source.url : t("dns.list.source.upload")),
      render: (l) => (
        <span class="dns-chips">
          <span class="tag" data-testid="list-source" data-kind={l.source.kind}>
            {t(`dns.list.source.${l.source.kind}`)}
          </span>
          <Show when={l.source.kind === "url" ? l.source.url : undefined}>{(url) => <span class="mono dns-data">{url()}</span>}</Show>
        </span>
      ),
    },
    { id: "format", header: () => t("dns.list.col.format"), width: 120, text: (l) => t(`dns.list.format.${l.format}`), render: (l) => <span>{t(`dns.list.format.${l.format}`)}</span> },
    {
      id: "interval",
      header: () => t("dns.list.col.interval"),
      width: 110,
      text: (l) => intervalText(l),
      render: (l) => <span>{intervalText(l)}</span>,
    },
    {
      id: "action",
      header: () => t("dns.list.col.action"),
      width: 170,
      text: (l) => t(`dns.list.action.${l.action.kind}`),
      render: (l) => (
        <span data-testid="list-action" data-kind={l.action.kind}>
          {t(`dns.list.action.${l.action.kind}`)}
          <Show when={redirectOf(l.action)}>{(a) => <span class="mono"> {a()}</span>}</Show>
        </span>
      ),
    },
    {
      id: "entries",
      header: () => t("dns.list.col.entries"),
      width: 110,
      align: "right",
      text: (l) => (l.version ? String(l.version.entries) : ""),
      render: (l) => (
        <Show when={l.version} fallback={<span class="muted">{t("dns.list.no_version")}</span>}>
          {(v) => (
            <span data-testid="list-version" data-key={String(v().revision)} data-count={v().entries}>
              {formatNumber(v().entries)}
            </span>
          )}
        </Show>
      ),
    },
    {
      id: "fetched",
      header: () => t("dns.list.col.fetched"),
      width: 140,
      text: (l) => l.version?.fetched ?? "",
      render: (l) => <Show when={l.version}>{(v) => <TimeAgo at={v().fetched} />}</Show>,
    },
    { id: "etag", header: () => t("dns.list.col.etag"), width: 140, text: (l) => l.version?.etag ?? "", render: (l) => <span class="mono dns-data">{l.version?.etag ?? ""}</span> },
    {
      id: "last_error",
      header: () => t("dns.list.col.last_error"),
      width: 180,
      text: (l) => l.last_error ?? "",
      render: (l) => (
        <Show when={l.last_error}>
          {(code) => (
            <span class="tag conflict mono" data-testid="list-last-error" data-code={code()}>
              {code()}
            </span>
          )}
        </Show>
      ),
    },
  ];
  const actions: RowAction<BlockListItem>[] = [
    { id: "fetch", label: () => t("dns.list.fetch"), hidden: (l) => !mayWriteDns() || l.source.kind !== "url", run: (l) => void fetchNow(l) },
    { id: "upload", label: () => t("dns.list.upload"), hidden: (l) => !mayWriteDns() || l.source.kind !== "upload", run: (l) => setDialog({ kind: "upload", list: l }) },
    { id: "edit", label: () => t("dns.do.edit"), hidden: () => !mayWriteDns(), run: (l) => setDialog({ kind: "edit", list: l }) },
    { id: "delete", label: () => t("dns.do.delete"), danger: true, hidden: () => !mayWriteDns(), run: (l) => setDialog({ kind: "delete", list: l }) },
  ];

  return (
    <div class="page dns-page list-page" data-testid="page-dns-lists">
      <DnsNav />
      <PageHead
        title={t("dns.lists.title")}
        sub={t("dns.lists.sub")}
        actions={
          <Show when={mayWriteDns() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dns-list-create" onClick={() => setDialog({ kind: "edit" })}>
              <Icon name="plus" />
              {t("dns.list.create")}
            </button>
          </Show>
        }
      />
      <Show when={!blocked()} fallback={<div class="page-body"><DnsProblem error={query.value.error} /></div>}>
        <Show when={job()} keyed>
          {(j) => <ListJob id={j.id} name={j.name} onFinished={() => query.refetch()} />}
        </Show>
        <div class="dns-list-body">
          <DataGrid
            id="dns-lists"
            label={t("dns.lists.title")}
            noSelection
            columns={columns}
            rows={latest(query) ?? []}
            rowId={(l) => l.id}
            rowKey={(l) => l.name}
            rowLabel={(l) => l.name}
            loading={query.value.loading}
            initial={latest(query) === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(l) => (mayWriteDns() ? setDialog({ kind: "edit", list: l }) : undefined)}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dns-lists-empty">
                <h3>{t("dns.lists.empty")}</h3>
                <p>{t("dns.lists.empty_body")}</p>
              </div>
            }
          />
        </div>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "edit" ? (
            <ListDialog
              list={d.list}
              onClose={() => close(false)}
              onDone={(started) => {
                if (started) follow(started.id, started.name);
                close(true);
              }}
            />
          ) : d.kind === "upload" ? (
            <UploadListDialog
              list={d.list}
              onClose={() => close(false)}
              onDone={(id) => {
                follow(id, d.list.name);
                close(true);
              }}
            />
          ) : (
            <DeleteListDialog list={d.list} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
