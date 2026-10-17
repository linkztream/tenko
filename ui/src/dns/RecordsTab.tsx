// The records of a zone on the Phase 1 grid: one row per record, the records of an RRset
// together with the owner, type, TTL and origin on the RRset's first row; paged through
// `list_dns_records` with the owner-prefix, type and origin filters. Enter edits the TTL (of
// the RRset) or the data (of one record) in place. Writes go out as one change each, or, in
// batch mode, collect until Review sends them as a dry run, shows the diff and applies them.
// RRsets IPAM keeps (`ipam`, and the other writers' origins) are read-only until the person
// takes one over; the change then carries `take_over`.
import { createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import type { PathsWith } from "../api/client";
import { errorMessage } from "../api/problem";
import { Icon } from "../components/Icon";
import { ConfirmDialog } from "../components/Dialog";
import { toast } from "../components/toast";
import { DataGrid, type CellEditor } from "../grid/DataGrid";
import { createListSource } from "../grid/source";
import { TextEditor } from "../grid/TextEditor";
import type { Column, RowAction } from "../grid/types";
import { formatNumber, t } from "../i18n";
import { changeRecords, ORIGINS, RECORDS_PATH, type BatchResult, type Origin, type RecordChange, type RrSet, type Zone } from "./api";
import { mayWriteDns } from "./access";
import { isEditableType, isOwned, parseRecord, parseTtl, recordRows, recordText, relativeName, rrsetKey, type RecordRow } from "./model";
import { checkMessage, OriginTag, originWord } from "./Parts";
import { DiffDialog, RrsetDialog, TakeOverDialog } from "./RecordDialogs";

/** The types offered by the type filter. */
const FILTER_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "CAA"] as const;

type Dialog =
  | { kind: "add"; rrset?: RrSet }
  | { kind: "delete"; rrset: RrSet }
  | { kind: "takeover"; rrset: RrSet }
  | { kind: "diff"; result: BatchResult };

export function RecordsTab(props: { zone: Zone; onWritten: () => void }) {
  const zoneName = () => props.zone.name;
  const [nameText, setNameText] = createSignal("");
  const [name, setName] = createSignal("");
  const [type, setType] = createSignal("");
  const [origin, setOrigin] = createSignal<Origin | "">("");
  const [batch, setBatch] = createSignal(false);
  const [draft, setDraft] = createSignal<RecordChange[]>([]);
  const [taken, setTaken] = createSignal<ReadonlySet<string>>(new Set());
  const [dialog, setDialog] = createSignal<Dialog | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [applyError, setApplyError] = createSignal<unknown>();

  let timer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => clearTimeout(timer));
  const onName = (value: string) => {
    setNameText(value);
    clearTimeout(timer);
    timer = setTimeout(() => setName(value.trim().toLowerCase()), 200);
  };

  const source = createListSource<RrSet>({
    path: RECORDS_PATH as PathsWith<"get">,
    pathParams: () => ({ id: props.zone.id }),
    query: () => ({ name: name() || undefined, type: type() || undefined, origin: origin() || undefined }),
    rowId: rrsetKey,
    topics: ["dns"],
    relevant: (e) => e.objects.some((o) => o.kind === "zone" && o.id === props.zone.id),
  });
  const rows = createMemo(() => recordRows(source.rows()));
  const pending = createMemo(() => new Set(draft().map((c) => rrsetKey({ scope: "default", name: c.name, type: c.type }))));

  const owned = (set: RrSet) => isOwned(set.origin) || taken().has(rrsetKey(set));
  const editable = (set: RrSet) => mayWriteDns() && owned(set) && set.type !== "SOA";
  const takeOver = (set: RrSet) => (isOwned(set.origin) ? {} : { take_over: true });

  /** Sends one change now, or adds it to the batch. */
  const submit = async (change: RecordChange): Promise<void> => {
    if (batch()) {
      setDraft([...draft(), change]);
      return;
    }
    const result = await changeRecords(props.zone.id, [change], false);
    toast({ kind: "ok", title: t("dns.rrset.saved", { count: result.changes.length, serial: String(result.serial ?? "") }) });
    source.reload();
    props.onWritten();
  };

  const review = async () => {
    setBusy(true);
    setApplyError(undefined);
    try {
      const result = await changeRecords(props.zone.id, draft(), true);
      setDialog({ kind: "diff", result });
    } catch (err) {
      setApplyError(err);
      setDialog({ kind: "diff", result: { changes: [], dry_run: true } });
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    setBusy(true);
    setApplyError(undefined);
    try {
      const result = await changeRecords(props.zone.id, draft(), false);
      setDraft([]);
      setDialog(null);
      toast({ kind: "ok", title: t("dns.batch.applied", { count: result.changes.length, serial: String(result.serial ?? "") }) });
      source.reload();
      props.onWritten();
    } catch (err) {
      setApplyError(err);
    } finally {
      setBusy(false);
    }
  };

  const ttlEditor: CellEditor<RecordRow> = (p) => (
    <TextEditor
      value={String(p.row.rrset.ttl)}
      label={t("dns.rrset.edit_ttl", { name: relativeName(p.row.rrset.name, zoneName()), type: p.row.rrset.type })}
      hint={batch() ? t("dns.batch.hint") : t("dns.rrset.edit_hint")}
      validate={(v) => (parseTtl(v) === null ? t("dns.check.ttl") : null)}
      commit={(v) =>
        submit({ op: "set", name: p.row.rrset.name, type: p.row.rrset.type, ttl: parseTtl(v), records: p.row.rrset.records, ...takeOver(p.row.rrset) })
      }
      close={p.close}
    />
  );

  const dataEditor: CellEditor<RecordRow> = (p) => (
    <TextEditor
      value={recordText(p.row.record)}
      label={t("dns.rrset.edit_data", { name: relativeName(p.row.rrset.name, zoneName()), type: p.row.rrset.type })}
      hint={batch() ? t("dns.batch.hint") : t("dns.rrset.edit_hint")}
      validate={(v) => {
        const parsed = parseRecord(p.row.rrset.type, v, zoneName());
        return parsed.ok ? null : checkMessage(parsed.code);
      }}
      commit={(v) => {
        const parsed = parseRecord(p.row.rrset.type, v, zoneName());
        if (!parsed.ok) return Promise.reject(new Error(parsed.code));
        const records = p.row.rrset.records.map((r, i) => (i === p.row.index ? parsed.data : r));
        return submit({ op: "set", name: p.row.rrset.name, type: p.row.rrset.type, ttl: p.row.rrset.ttl, records, ...takeOver(p.row.rrset) });
      }}
      close={p.close}
    />
  );

  const columns: Column<RecordRow>[] = [
    {
      id: "name",
      header: () => t("dns.col.name"),
      width: 240,
      fixed: true,
      text: (r) => relativeName(r.rrset.name, zoneName()),
      render: (r) => (
        <Show when={r.first}>
          <span class="mono">{relativeName(r.rrset.name, zoneName())}</span>
        </Show>
      ),
    },
    { id: "type", header: () => t("dns.col.type"), width: 80, text: (r) => r.rrset.type, render: (r) => <Show when={r.first}><span class="mono">{r.rrset.type}</span></Show> },
    {
      id: "ttl",
      header: () => t("dns.col.ttl"),
      width: 90,
      align: "right",
      text: (r) => String(r.rrset.ttl),
      editable: (r) => r.first && editable(r.rrset),
      render: (r) => <Show when={r.first}><span class="num">{r.rrset.ttl}</span></Show>,
    },
    {
      id: "data",
      header: () => t("dns.col.data"),
      text: (r) => recordText(r.record),
      editable: (r) => editable(r.rrset) && isEditableType(r.rrset.type),
      render: (r) => <span class="mono dns-data">{recordText(r.record)}</span>,
    },
    {
      id: "origin",
      header: () => t("dns.col.origin"),
      width: 190,
      text: (r) => r.rrset.origin,
      render: (r) => (
        <Show when={r.first}>
          <span class="dns-chips">
            <OriginTag origin={r.rrset.origin} />
            <Show when={!isOwned(r.rrset.origin) && taken().has(rrsetKey(r.rrset))}>
              <span class="tag discrepancy" data-testid="rrset-taken-over">
                {t("dns.takeover.tag")}
              </span>
            </Show>
            <Show when={pending().has(rrsetKey(r.rrset))}>
              <span class="tag accent" data-testid="rrset-pending">
                {t("dns.batch.pending_tag")}
              </span>
            </Show>
          </span>
        </Show>
      ),
    },
  ];

  const actions: RowAction<RecordRow>[] = [
    { id: "add", label: () => t("dns.do.add_records"), hidden: (r) => !editable(r.rrset) || !isEditableType(r.rrset.type), run: (r) => setDialog({ kind: "add", rrset: r.rrset }) },
    {
      id: "remove",
      label: () => t("dns.do.remove_record"),
      hidden: (r) => !editable(r.rrset) || r.rrset.records.length < 2,
      run: (r) =>
        void submit({ op: "remove", name: r.rrset.name, type: r.rrset.type, records: [r.record], ...takeOver(r.rrset) }).catch((err: unknown) =>
          toast({ kind: "bad", title: t("dns.rrset.failed"), body: errorMessage(err) }),
        ),
    },
    { id: "delete", label: () => t("dns.do.delete_rrset"), danger: true, hidden: (r) => !editable(r.rrset), run: (r) => setDialog({ kind: "delete", rrset: r.rrset }) },
    {
      id: "takeover",
      label: () => t("dns.do.take_over"),
      hidden: (r) => !mayWriteDns() || owned(r.rrset) || r.rrset.type === "SOA",
      run: (r) => setDialog({ kind: "takeover", rrset: r.rrset }),
    },
  ];

  return (
    <div class="dns-records" data-testid="zone-records">
      <div class="filterbar" role="toolbar" aria-label={t("dns.records.filter_label")} data-testid="filterbar">
        <label class="query">
          <Icon name="search" size="sm" />
          <input
            class="dns-search"
            value={nameText()}
            placeholder={t("dns.records.filter_placeholder")}
            aria-label={t("dns.records.filter_label")}
            spellcheck={false}
            data-testid="filter-input"
            onInput={(e) => onName(e.currentTarget.value)}
          />
        </label>
        <select class="select" aria-label={t("dns.records.type_filter")} value={type()} data-testid="filter-type" onChange={(e) => setType(e.currentTarget.value)}>
          <option value="">{t("dns.records.any_type")}</option>
          <For each={FILTER_TYPES}>{(k) => <option value={k}>{k}</option>}</For>
        </select>
        <select class="select" aria-label={t("dns.records.origin_filter")} value={origin()} data-testid="filter-origin" onChange={(e) => setOrigin(e.currentTarget.value as Origin | "")}>
          <option value="">{t("dns.records.any_origin")}</option>
          <For each={ORIGINS}>{(o) => <option value={o}>{originWord(o)}</option>}</For>
        </select>
        <Show when={mayWriteDns()}>
          <span class="grow" />
          <label class="dns-toggle">
            <input
              type="checkbox"
              class="cb"
              checked={batch()}
              data-testid="dns-batch-toggle"
              onChange={(e) => {
                setBatch(e.currentTarget.checked);
                if (!e.currentTarget.checked) setDraft([]);
              }}
            />
            {t("dns.batch.mode")}
          </label>
          <button type="button" class="btn sm" data-testid="dns-rrset-add" onClick={() => setDialog({ kind: "add" })}>
            <Icon name="plus" size="sm" />
            {t("dns.rrset.add_action")}
          </button>
        </Show>
      </div>
      <Show when={batch()}>
        <div class="dns-batchbar" role="status" data-testid="dns-batch" data-count={draft().length}>
          <span>{t("dns.batch.count", { count: draft().length, changes: formatNumber(draft().length) })}</span>
          <ul class="dns-draft" aria-label={t("dns.batch.list_label")}>
            <For each={draft()}>
              {(c, i) => (
                <li data-testid="batch-item" data-index={i()} data-key={`${c.name}/${c.type}`}>
                  <span class="tag">{t(`dns.op.${c.op}`)}</span> <span class="mono">{relativeName(c.name, zoneName())}</span>{" "}
                  <span class="mono">{c.type}</span>
                  <button
                    type="button"
                    class="icon-btn"
                    aria-label={t("dns.batch.drop", { name: relativeName(c.name, zoneName()), type: c.type })}
                    data-testid="batch-item-drop"
                    onClick={() => setDraft(draft().filter((_, j) => j !== i()))}
                  >
                    <Icon name="x" size="xs" />
                  </button>
                </li>
              )}
            </For>
          </ul>
          <span class="grow" />
          <button type="button" class="btn sm ghost" data-testid="dns-batch-discard" disabled={draft().length === 0} onClick={() => setDraft([])}>
            {t("dns.batch.discard")}
          </button>
          <button type="button" class="btn sm primary" data-testid="dns-batch-review" disabled={draft().length === 0 || busy()} onClick={() => void review()}>
            {t("dns.batch.review")}
          </button>
        </div>
      </Show>
      <div class="dns-list-body">
        <DataGrid
          id="dns-records"
          label={t("dns.records.label", { zone: zoneName() })}
          noSelection
          columns={columns}
          rows={rows()}
          rowId={(r) => r.id}
          rowKey={(r) => `${relativeName(r.rrset.name, zoneName())}/${r.rrset.type}/${r.index}`}
          rowLabel={(r) => `${relativeName(r.rrset.name, zoneName())} ${r.rrset.type} ${recordText(r.record)}`}
          rowClass={(r) => (r.first ? "dns-rrset-first" : "dns-rrset-more")}
          loading={source.loading()}
          initial={source.initial()}
          hasMore={source.hasMore()}
          onLoadMore={source.loadMore}
          error={source.error()}
          onRetry={source.reload}
          flashed={(id) => source.flashed(id.split("#")[0] ?? id)}
          editors={{ ttl: ttlEditor, data: dataEditor }}
          rowActions={actions}
          empty={
            <div class="empty" data-testid="dns-records-empty">
              <h3>{name() || type() || origin() ? t("grid.empty.filtered") : t("dns.records.empty")}</h3>
            </div>
          }
        />
      </div>
      <Show when={dialog()} keyed>
        {(d) => {
          switch (d.kind) {
            case "add":
              return <RrsetDialog zone={props.zone} rrset={d.rrset} batch={batch()} onSubmit={submit} onClose={() => setDialog(null)} />;
            case "delete":
              return (
                <ConfirmDialog
                  title={t("dns.rrset.delete_title", { name: relativeName(d.rrset.name, zoneName()), type: d.rrset.type })}
                  testid="dialog-rrset-delete"
                  danger
                  confirmLabel={batch() ? t("dns.batch.add_to") : t("dns.rrset.delete_confirm")}
                  cancelLabel={t("common.action.cancel")}
                  body={<p>{t("dns.rrset.delete_body", { count: d.rrset.records.length })}</p>}
                  onClose={() => setDialog(null)}
                  onConfirm={() => {
                    setDialog(null);
                    void submit({ op: "delete", name: d.rrset.name, type: d.rrset.type, ...takeOver(d.rrset) }).catch((err: unknown) =>
                      toast({ kind: "bad", title: t("dns.rrset.failed"), body: errorMessage(err) }),
                    );
                  }}
                />
              );
            case "takeover":
              return (
                <TakeOverDialog
                  rrset={d.rrset}
                  zone={zoneName()}
                  onClose={() => setDialog(null)}
                  onConfirm={() => {
                    setTaken(new Set([...taken(), rrsetKey(d.rrset)]));
                    setDialog(null);
                  }}
                />
              );
            case "diff":
              return <DiffDialog zone={props.zone} result={d.result} busy={busy()} error={applyError()} onApply={() => void apply()} onClose={() => setDialog(null)} />;
          }
        }}
      </Show>
    </div>
  );
}
