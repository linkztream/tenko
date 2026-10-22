// The MAC filters (/dhcp/filters, DHCP-08): a pattern of hardware addresses that is allowed or
// denied on the whole server. A deny entry drops the client everywhere; a scope that is restricted
// serves only the clients an allow entry matches, and deny wins over allow. The pattern is checked
// here the way the server checks it: six hexadecimal octets, `*` for any octet, or a prefix
// ending in `*`.
import { createSignal, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { ApiError, errorMessage } from "../../api/problem";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { DataGrid } from "../../grid/DataGrid";
import type { Column, RowAction } from "../../grid/types";
import { t } from "../../i18n";
import { mayWriteDhcp } from "../access";
import { createFilter, deleteFilter, listFilters, updateFilter, type FilterKind, type MacFilter } from "../api";
import { DhcpNav } from "../DhcpNav";
import { checkMacPattern } from "../model";
import { describedBy, DhcpProblem, errorFor, Field, fieldErrors, hasField, unavailable } from "../Parts";
import "../dhcp.css";

function FilterDialog(props: { item?: MacFilter; onClose: () => void; onDone: () => void }) {
  let macInput!: HTMLInputElement;
  const item = untrack(() => props.item);
  const [mac, setMac] = createSignal(item?.mac ?? "");
  const [kind, setKind] = createSignal<FilterKind>(item?.kind ?? "deny");
  const [note, setNote] = createSignal(item?.note ?? "");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const pattern = checkMacPattern(mac());
    if (pattern === null) {
      setErrors({ mac: t("dhcp.check.mac_pattern") });
      return;
    }
    setErrors({});
    setBusy(true);
    setError(undefined);
    try {
      const text = note().trim();
      if (item) await updateFilter(item, { mac: pattern, kind: kind(), note: text });
      else await createFilter({ mac: pattern, kind: kind(), ...(text !== "" ? { note: text } : {}) });
      toast({ kind: "ok", title: item ? t("dhcp.filter.saved", { mac: pattern }) : t("dhcp.filter.created", { mac: pattern }) });
      props.onDone();
    } catch (err) {
      const fields = fieldErrors(err);
      if (hasField(fields, ["mac", "note"])) setErrors(fields);
      else if (err instanceof ApiError && err.code === "dhcp.filter.exists") setErrors({ mac: errorMessage(err) });
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = () => (item ? t("dhcp.filter.edit_title", { mac: item.mac }) : t("dhcp.filter.create_title"));
  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog dhcp-dialog" testid="dialog-filter-form" initialFocus={() => macInput}>
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dhcp-form" onSubmit={(ev) => void submit(ev)} novalidate>
        <Field id="mac" label={t("dhcp.filter.field.mac")} error={errorFor(errors(), "mac")} help={t("dhcp.filter.field.mac_help")}>
          <input
            ref={macInput}
            id="dhcp-f-mac"
            class="input mono"
            value={mac()}
            placeholder={t("dhcp.example.mac_pattern")}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().mac ? "true" : undefined}
            aria-describedby={describedBy("mac", errors().mac, "help")}
            data-testid="field-mac"
            onInput={(ev) => setMac(ev.currentTarget.value)}
          />
        </Field>
        <fieldset class="dns-modes">
          <legend>{t("dhcp.filter.field.kind")}</legend>
          <label class="choice">
            <input type="radio" name="dhcp-filter-kind" checked={kind() === "allow"} data-testid="field-kind-allow" onChange={() => setKind("allow")} /> <span>{t("dhcp.filter.kind.allow")}</span>
          </label>
          <label class="choice">
            <input type="radio" name="dhcp-filter-kind" checked={kind() === "deny"} data-testid="field-kind-deny" onChange={() => setKind("deny")} /> <span>{t("dhcp.filter.kind.deny")}</span>
          </label>
        </fieldset>
        <Field id="note" label={t("dhcp.filter.field.note")} error={errorFor(errors(), "note")}>
          <input id="dhcp-f-note" class="input" value={note()} data-testid="field-note" onInput={(ev) => setNote(ev.currentTarget.value)} />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {item ? t("dhcp.filter.save") : t("dhcp.filter.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteFilterDialog(props: { item: MacFilter; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dhcp.filter.delete_title", { mac: props.item.mac })}
      testid="dialog-filter-delete"
      danger
      busy={busy()}
      confirmLabel={t("dhcp.filter.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteFilter(props.item)
          .then(() => {
            toast({ kind: "ok", title: t("dhcp.filter.deleted", { mac: props.item.mac }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dhcp.filter.delete_body")}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

export default function FiltersPage() {
  const [dialog, setDialog] = createSignal<{ kind: "edit"; item?: MacFilter } | { kind: "delete"; item: MacFilter } | null>(null);
  const query = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const page = await listFilters(signal);
      return { value: page.items, revision: page.revision };
    },
  });
  const blocked = () => unavailable(query.value.error);
  const filters = () => latest(query);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };

  const columns: Column<MacFilter>[] = [
    { id: "mac", header: () => t("dhcp.col.mac"), width: 220, fixed: true, text: (f) => f.mac, render: (f) => <span class="mono">{f.mac}</span> },
    {
      id: "kind",
      header: () => t("dhcp.col.filter_kind"),
      width: 130,
      text: (f) => t(`dhcp.filter.kind.${f.kind}`),
      render: (f) => (
        <span class={f.kind === "deny" ? "tag conflict" : "tag accent"} data-testid="filter-kind" data-key={f.kind}>
          {t(`dhcp.filter.kind.${f.kind}`)}
        </span>
      ),
    },
    { id: "note", header: () => t("dhcp.col.note"), render: (f) => <span class="muted">{f.note ?? ""}</span> },
  ];
  const actions: RowAction<MacFilter>[] = [
    { id: "edit", label: () => t("dhcp.do.edit"), hidden: () => !mayWriteDhcp(), run: (f) => setDialog({ kind: "edit", item: f }) },
    { id: "delete", label: () => t("dhcp.do.delete"), danger: true, hidden: () => !mayWriteDhcp(), run: (f) => setDialog({ kind: "delete", item: f }) },
  ];

  return (
    <div class="page dhcp-page list-page" data-testid="page-dhcp-filters">
      <DhcpNav />
      <PageHead
        title={t("dhcp.filters.title")}
        sub={t("dhcp.filters.sub")}
        actions={
          <Show when={mayWriteDhcp() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dhcp-filter-create" onClick={() => setDialog({ kind: "edit" })}>
              <Icon name="plus" />
              {t("dhcp.filter.create")}
            </button>
          </Show>
        }
      />
      <Show
        when={!blocked()}
        fallback={
          <div class="page-body">
            <DhcpProblem error={query.value.error} />
          </div>
        }
      >
        <Notice kind="info" testid="filters-note">
          {t("dhcp.filters.note")}
        </Notice>
        <div class="dhcp-list-body">
          <DataGrid
            id="dhcp-filters"
            label={t("dhcp.filters.title")}
            noSelection
            columns={columns}
            rows={filters() ?? []}
            rowId={(f) => f.id}
            rowKey={(f) => f.mac}
            rowLabel={(f) => f.mac}
            loading={query.value.loading}
            initial={filters() === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(f) => (mayWriteDhcp() ? setDialog({ kind: "edit", item: f }) : undefined)}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dhcp-filters-empty">
                <h3>{t("dhcp.filters.empty")}</h3>
                <p>{t("dhcp.filters.empty_body")}</p>
              </div>
            }
          />
        </div>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "edit" ? (
            <FilterDialog item={d.item} onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <DeleteFilterDialog item={d.item} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
