// The dialogs of the record grid: add an RRset (or records to one), the diff of a batch after
// its dry run with Apply, and the confirmation that takes over an RRset another writer owns
// (IPAM keeps `ipam` records; a change of one replaces it and makes it manual).
import { createSignal, For, Show, untrack } from "solid-js";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import type { BatchResult, RecordChange, RrSet, Zone } from "./api";
import { diffKind, EDITABLE_TYPES, ownerName, parseRecords, parseTtl, recordText, relativeName, validName, type EditableType } from "./model";
import { checkMessage, describedBy, Field, originWord } from "./Parts";

/** An example of the data of each type, one record per line, for the help line. */
const EXAMPLE: Record<EditableType, string> = {
  A: "192.0.2.10",
  AAAA: "2001:db8::10",
  CNAME: "www",
  DNAME: "other.example.test.",
  MX: "10 mail",
  NS: "ns1",
  PTR: "host.example.test.",
  SRV: "0 100 389 ldap",
  TXT: '"v=spf1 -all"',
  CAA: '0 issue "ca.example.test"',
};

export function RrsetDialog(props: {
  zone: Pick<Zone, "name" | "soa">;
  /** An existing RRset to add records to (name and type fixed). */
  rrset?: RrSet | undefined;
  /** Whether the change joins the batch instead of being sent now. */
  batch: boolean;
  onSubmit: (change: RecordChange) => Promise<void>;
  onClose: () => void;
}) {
  let first!: HTMLInputElement | HTMLTextAreaElement;
  // The RRset and the zone are fixed for the life of the dialog.
  const { fixed, zoneName, zoneTtl } = untrack(() => ({ fixed: props.rrset, zoneName: props.zone.name, zoneTtl: props.zone.soa.ttl }));
  const [name, setName] = createSignal(fixed ? relativeName(fixed.name, zoneName) : "");
  const [type, setType] = createSignal<string>(fixed?.type ?? "A");
  const [ttl, setTtl] = createSignal(String(fixed?.ttl ?? zoneTtl ?? 3600));
  const [data, setData] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const example = () => EXAMPLE[type() as EditableType] ?? "";

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    const owner = ownerName(name(), props.zone.name);
    if (!validName(owner)) e.name = t("dns.check.name");
    const seconds = parseTtl(ttl());
    if (seconds === null) e.ttl = t("dns.check.ttl");
    const parsed = parseRecords(type(), data(), props.zone.name);
    if (!parsed.ok) e.data = t("dns.record.line_error", { line: parsed.line, message: checkMessage(parsed.code) });
    setErrors(e);
    if (Object.keys(e).length > 0 || !parsed.ok) return;
    setBusy(true);
    setError(undefined);
    try {
      await props.onSubmit({ op: "add", name: owner, type: type(), ttl: seconds, records: parsed.records });
      props.onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = () => (fixed ? t("dns.rrset.add_records_title", { name: relativeName(fixed.name, props.zone.name), type: fixed.type }) : t("dns.rrset.add_title"));

  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-rrset-form" initialFocus={() => first}>
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        <div class="field-row">
          <Field id="name" label={t("dns.rrset.field.name")} error={errors().name} help={t("dns.rrset.field.name_help", { zone: props.zone.name })}>
            <input
              ref={(el) => {
                if (!fixed) first = el;
              }}
              id="dns-f-name"
              class="input mono"
              value={name()}
              disabled={!!fixed}
              spellcheck={false}
              autocomplete="off"
              aria-invalid={errors().name ? "true" : undefined}
              aria-describedby={describedBy("name", errors().name, "help")}
              data-testid="field-name"
              onInput={(e) => setName(e.currentTarget.value)}
            />
          </Field>
          <Field id="type" label={t("dns.rrset.field.type")}>
            <select id="dns-f-type" class="select" value={type()} disabled={!!fixed} data-testid="field-type" onChange={(e) => setType(e.currentTarget.value)}>
              <For each={EDITABLE_TYPES}>{(k) => <option value={k}>{k}</option>}</For>
            </select>
          </Field>
          <Field id="ttl" label={t("dns.rrset.field.ttl")} error={errors().ttl}>
            <input
              id="dns-f-ttl"
              class="input mono"
              inputMode="numeric"
              value={ttl()}
              aria-invalid={errors().ttl ? "true" : undefined}
              aria-describedby={describedBy("ttl", errors().ttl)}
              data-testid="field-ttl"
              onInput={(e) => setTtl(e.currentTarget.value)}
            />
          </Field>
        </div>
        <Field id="data" label={t("dns.rrset.field.data")} error={errors().data} help={t("dns.rrset.field.data_help", { example: example() })}>
          <textarea
            ref={(el) => {
              if (fixed) first = el;
            }}
            id="dns-f-data"
            class="input mono"
            rows={4}
            value={data()}
            spellcheck={false}
            aria-invalid={errors().data ? "true" : undefined}
            aria-describedby={describedBy("data", errors().data, "help")}
            data-testid="field-data"
            onInput={(e) => setData(e.currentTarget.value)}
          />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {props.batch ? t("dns.batch.add_to") : t("dns.rrset.add_submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/** An RRset of the diff in one line: TTL, the records, and the origin when it is not manual. */
function setText(set: RrSet | null | undefined): string {
  if (!set) return "";
  return `${set.ttl} ${set.records.map((r) => recordText(r)).join(" | ")}${set.origin !== "manual" ? ` (${originWord(set.origin)})` : ""}`;
}

/** The diff of a dry run: one line per RRset that changes, with Apply. */
export function DiffDialog(props: {
  zone: Pick<Zone, "name">;
  result: BatchResult;
  busy: boolean;
  error: unknown;
  onApply: () => void;
  onClose: () => void;
}) {
  let apply!: HTMLButtonElement;
  return (
    <Dialog label={t("dns.batch.diff_title")} onClose={props.onClose} class="dialog wide dns-dialog dns-diff" testid="dialog-batch-diff" initialFocus={() => apply}>
      <h2 class="dialog-title">{t("dns.batch.diff_title")}</h2>
      <div class="dialog-body">
        <p data-testid="plan-summary" data-count={props.result.changes.length}>
          {t("dns.batch.diff_summary", { count: props.result.changes.length })}
        </p>
        <Show when={props.result.changes.length > 0}>
          <div class="table-wrap">
            <table class="plain">
              <thead>
                <tr>
                  <th>{t("dns.batch.col.change")}</th>
                  <th>{t("dns.col.name")}</th>
                  <th>{t("dns.col.type")}</th>
                  <th>{t("dns.batch.col.before")}</th>
                  <th>{t("dns.batch.col.after")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={props.result.changes}>
                  {(d) => (
                    <tr data-testid="plan-change" data-kind={diffKind(d)} data-key={`${d.name}/${d.type}`}>
                      <td>
                        <span class={`tag dns-diff-${diffKind(d)}`}>{t(`dns.batch.kind.${diffKind(d)}`)}</span>
                      </td>
                      <td class="mono">{relativeName(d.name, props.zone.name)}</td>
                      <td class="mono">{d.type}</td>
                      <td class="mono muted">{setText(d.before)}</td>
                      <td class="mono">{setText(d.after)}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
        <ErrorNotice error={props.error} />
      </div>
      <div class="dialog-actions">
        <button type="button" class="btn ghost" data-testid="plan-cancel" onClick={() => props.onClose()}>
          {t("dns.batch.back")}
        </button>
        <button
          ref={apply}
          type="button"
          class="btn primary"
          data-testid="plan-confirm"
          disabled={props.busy || props.result.changes.length === 0}
          onClick={() => props.onApply()}
        >
          {t("dns.batch.apply", { count: props.result.changes.length })}
        </button>
      </div>
    </Dialog>
  );
}

/** Asks before an RRset of another origin becomes editable here. */
export function TakeOverDialog(props: { rrset: RrSet; zone: string; onConfirm: () => void; onClose: () => void }) {
  return (
    <ConfirmDialog
      title={t("dns.takeover.title", { name: relativeName(props.rrset.name, props.zone), type: props.rrset.type })}
      testid="dialog-take-over"
      confirmLabel={t("dns.takeover.confirm")}
      cancelLabel={t("common.action.cancel")}
      onConfirm={() => props.onConfirm()}
      onClose={props.onClose}
      body={<p>{t("dns.takeover.body", { origin: originWord(props.rrset.origin) })}</p>}
    />
  );
}
