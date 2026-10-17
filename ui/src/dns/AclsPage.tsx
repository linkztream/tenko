// The access lists of the DNS area (/dns/acls): prefixes, TSIG keys and `any`, allowed or
// denied, first match decides; the zones whose transfers use a list. Create, edit (with the
// list's revision) and delete; a list in use is refused by the server and says by whom.
import { createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../api/live";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { toast } from "../components/toast";
import { DataGrid } from "../grid/DataGrid";
import type { Column, RowAction } from "../grid/types";
import { formatList, t } from "../i18n";
import { createAcl, deleteAcl, listAcls, updateAcl, type Acl } from "./api";
import { mayWriteDns } from "./access";
import { DnsNav } from "./DnsNav";
import { aclEntryText, parseAclEntries } from "./model";
import { describedBy, DnsProblem, Field, fieldErrors, unavailable } from "./Parts";
import "./dns.css";

function AclDialog(props: { acl?: Acl; onClose: () => void; onDone: () => void }) {
  let nameInput!: HTMLInputElement;
  const acl = untrack(() => props.acl);
  const [name, setName] = createSignal(acl?.name ?? "");
  const [description, setDescription] = createSignal(acl?.description ?? "");
  const [entries, setEntries] = createSignal((acl?.entries ?? []).map(aclEntryText).join("\n"));
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    if (!/^[a-z0-9][a-z0-9_-]{0,62}$/i.test(name().trim())) e.name = t("dns.acl.name_invalid");
    const parsed = parseAclEntries(entries());
    if (!parsed.ok) e.entries = t("dns.acl.entry_invalid", { line: parsed.line });
    setErrors(e);
    if (Object.keys(e).length > 0 || !parsed.ok) return;
    setBusy(true);
    setError(undefined);
    try {
      const body = { name: name().trim(), description: description().trim() || null, entries: parsed.entries };
      if (acl) await updateAcl(acl, body);
      else await createAcl(body);
      toast({ kind: "ok", title: acl ? t("dns.acl.saved", { name: body.name }) : t("dns.acl.created", { name: body.name }) });
      props.onDone();
    } catch (err) {
      const fields = fieldErrors(err);
      if (Object.keys(fields).length > 0) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = () => (acl ? t("dns.acl.edit_title", { name: acl.name }) : t("dns.acl.create_title"));
  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-acl-form" initialFocus={() => nameInput}>
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        <Field id="name" label={t("dns.acl.field.name")} error={errors().name}>
          <input
            ref={nameInput}
            id="dns-f-name"
            class="input mono"
            value={name()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().name ? "true" : undefined}
            aria-describedby={describedBy("name", errors().name)}
            data-testid="field-name"
            onInput={(ev) => setName(ev.currentTarget.value)}
          />
        </Field>
        <Field id="entries" label={t("dns.acl.field.entries")} error={errors().entries} help={t("dns.acl.field.entries_help")}>
          <textarea
            id="dns-f-entries"
            class="input mono"
            rows={6}
            value={entries()}
            spellcheck={false}
            aria-invalid={errors().entries ? "true" : undefined}
            aria-describedby={describedBy("entries", errors().entries, "help")}
            data-testid="field-entries"
            onInput={(ev) => setEntries(ev.currentTarget.value)}
          />
        </Field>
        <Field id="description" label={t("dns.zone.field.description")}>
          <input id="dns-f-description" class="input" value={description()} data-testid="field-description" onInput={(ev) => setDescription(ev.currentTarget.value)} />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {acl ? t("dns.acl.save") : t("dns.acl.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteAclDialog(props: { acl: Acl; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dns.acl.delete_title", { name: props.acl.name })}
      testid="dialog-acl-delete"
      danger
      busy={busy()}
      confirmLabel={t("dns.acl.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteAcl(props.acl.id)
          .then(() => {
            toast({ kind: "ok", title: t("dns.acl.deleted", { name: props.acl.name }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <Show when={props.acl.used_by.length > 0} fallback={<p>{t("dns.acl.delete_body")}</p>}>
            <p>{t("dns.acl.delete_used", { zones: formatList(props.acl.used_by) })}</p>
          </Show>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

export default function AclsPage() {
  const [dialog, setDialog] = createSignal<{ kind: "edit"; acl?: Acl } | { kind: "delete"; acl: Acl } | null>(null);
  const query = createLiveQuery({
    topics: ["dns"],
    fetch: async (signal) => {
      const page = await listAcls(signal);
      return { value: page.items, revision: page.revision };
    },
  });
  const blocked = () => unavailable(query.value.error);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };

  const columns: Column<Acl>[] = [
    { id: "name", header: () => t("dns.col.name"), width: 200, fixed: true, text: (a) => a.name, render: (a) => <span class="mono">{a.name}</span> },
    {
      id: "entries",
      header: () => t("dns.acl.col.entries"),
      text: (a) => a.entries.map(aclEntryText).join(", "),
      render: (a) => (
        <span class="dns-chips">
          <For each={a.entries}>
            {(entry) => (
              <span class={entry.deny ? "tag conflict mono" : "tag mono"} data-testid="acl-entry">
                {aclEntryText(entry)}
              </span>
            )}
          </For>
        </span>
      ),
    },
    {
      id: "used_by",
      header: () => t("dns.acl.col.used_by"),
      width: 240,
      text: (a) => a.used_by.join(", "),
      render: (a) => <span class="mono">{a.used_by.join(", ")}</span>,
    },
    { id: "description", header: () => t("dns.col.description"), width: 220, render: (a) => <span class="muted">{a.description ?? ""}</span> },
  ];
  const actions: RowAction<Acl>[] = [
    { id: "edit", label: () => t("dns.do.edit"), hidden: () => !mayWriteDns(), run: (a) => setDialog({ kind: "edit", acl: a }) },
    { id: "delete", label: () => t("dns.do.delete"), danger: true, hidden: () => !mayWriteDns(), run: (a) => setDialog({ kind: "delete", acl: a }) },
  ];

  return (
    <div class="page dns-page list-page" data-testid="page-dns-acls">
      <DnsNav />
      <PageHead
        title={t("dns.acls.title")}
        sub={t("dns.acls.sub")}
        actions={
          <Show when={mayWriteDns() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dns-acl-create" onClick={() => setDialog({ kind: "edit" })}>
              <Icon name="plus" />
              {t("dns.acl.create")}
            </button>
          </Show>
        }
      />
      <Show when={!blocked()} fallback={<div class="page-body"><DnsProblem error={query.value.error} /></div>}>
        <div class="dns-list-body">
          <DataGrid
            id="dns-acls"
            label={t("dns.acls.title")}
            noSelection
            columns={columns}
            rows={latest(query) ?? []}
            rowId={(a) => a.id}
            rowKey={(a) => a.name}
            rowLabel={(a) => a.name}
            loading={query.value.loading}
            initial={latest(query) === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(a) => (mayWriteDns() ? setDialog({ kind: "edit", acl: a }) : undefined)}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dns-acls-empty">
                <h3>{t("dns.acls.empty")}</h3>
              </div>
            }
          />
        </div>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "edit" ? (
            <AclDialog acl={d.acl} onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <DeleteAclDialog acl={d.acl} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
