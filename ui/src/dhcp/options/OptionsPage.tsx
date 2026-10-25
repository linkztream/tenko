// The DHCP options (/dhcp/options), in three sections: the server's option set, which every scope
// starts from; the custom definitions, which give a code of the site-specific range or of a vendor
// space a name and a type; and the built-in catalog, read-only, with the codes the server sets
// itself. A definition that option sets use is not deleted, and the confirmation shows the
// server's message.
import { createSignal, For, Show } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { DataGrid } from "../../grid/DataGrid";
import type { Column, RowAction } from "../../grid/types";
import { formatNumber, t } from "../../i18n";
import { mayWriteDhcp } from "../access";
import { createOptionDef, deleteOptionDef, listCatalog, listOptionDefs, type CatalogEntry, type OptionDef, type OptionKind } from "../api";
import { DhcpNav } from "../DhcpNav";
import { validDhcpName } from "../model";
import { Check, describedBy, DhcpProblem, errorFor, Field, fieldErrors, hasField, unavailable } from "../Parts";
import { OPTION_KINDS } from "../types";
import { kindWords } from "../words";
import { OptionSetEditor } from "./OptionSetEditor";
import "../dhcp.css";

const REPEATING: ReadonlySet<OptionKind> = new Set(["ipv4_address", "ipv6_address", "ipv6_prefix", "u8", "u16", "u32", "bool", "fqdn"]);

function DefineDialog(props: { onClose: () => void; onDone: () => void }) {
  let codeInput!: HTMLInputElement;
  const [space, setSpace] = createSignal("dhcp4");
  const [code, setCode] = createSignal("");
  const [name, setName] = createSignal("");
  const [kind, setKind] = createSignal<OptionKind>("string");
  const [array, setArray] = createSignal(false);
  const [vendor, setVendor] = createSignal("");
  const [description, setDescription] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    const n = Number(code().trim());
    if (!/^\d+$/.test(code().trim()) || n < 1 || n > 254) e.code = t("dhcp.check.def_code");
    if (!validDhcpName(name().trim())) e.name = t("dhcp.check.name");
    if (!/^[a-z0-9][a-z0-9_.-]{0,63}$/i.test(space().trim())) e.space = t("dhcp.check.space");
    setErrors(e);
    if (Object.keys(e).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      await createOptionDef({
        ...(space().trim() !== "dhcp4" ? { space: space().trim() } : {}),
        code: n,
        name: name().trim(),
        kind: kind(),
        ...(array() ? { array: true } : {}),
        ...(vendor().trim() !== "" ? { vendor_class: vendor().trim() } : {}),
        ...(description().trim() !== "" ? { description: description().trim() } : {}),
      });
      toast({ kind: "ok", title: t("dhcp.def.created", { name: name().trim() }) });
      props.onDone();
    } catch (err) {
      const fields = fieldErrors(err);
      if (hasField(fields, ["space", "code", "name", "kind"])) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog label={t("dhcp.def.create_title")} onClose={props.onClose} class="dialog wide dhcp-dialog" testid="dialog-def-form" initialFocus={() => codeInput}>
      <h2 class="dialog-title">{t("dhcp.def.create_title")}</h2>
      <form class="dialog-body dhcp-form" onSubmit={(ev) => void submit(ev)} novalidate>
        <p class="muted">{t("dhcp.def.help")}</p>
        <div class="field-row">
          <Field id="space" label={t("dhcp.def.field.space")} error={errorFor(errors(), "space")} help={t("dhcp.def.field.space_help")}>
            <input
              id="dhcp-f-space"
              class="input mono"
              value={space()}
              spellcheck={false}
              aria-describedby={describedBy("space", errors().space, "help")}
              data-testid="field-space"
              onInput={(ev) => setSpace(ev.currentTarget.value)}
            />
          </Field>
          <Field id="code" label={t("dhcp.def.field.code")} error={errorFor(errors(), "code")} help={t("dhcp.def.field.code_help")}>
            <input
              ref={codeInput}
              id="dhcp-f-code"
              class="input mono"
              inputmode="numeric"
              value={code()}
              aria-invalid={errors().code ? "true" : undefined}
              aria-describedby={describedBy("code", errors().code, "help")}
              data-testid="field-code"
              onInput={(ev) => setCode(ev.currentTarget.value)}
            />
          </Field>
        </div>
        <Field id="name" label={t("dhcp.def.field.name")} error={errorFor(errors(), "name")} help={t("dhcp.field.name_help")}>
          <input
            id="dhcp-f-name"
            class="input mono"
            value={name()}
            spellcheck={false}
            aria-invalid={errors().name ? "true" : undefined}
            aria-describedby={describedBy("name", errors().name, "help")}
            data-testid="field-name"
            onInput={(ev) => setName(ev.currentTarget.value)}
          />
        </Field>
        <div class="field-row">
          <Field id="kind" label={t("dhcp.def.field.kind")} error={errorFor(errors(), "kind")}>
            <select
              id="dhcp-f-kind"
              class="select"
              value={kind()}
              data-testid="field-kind"
              onChange={(ev) => {
                const next = ev.currentTarget.value as OptionKind;
                setKind(next);
                if (!REPEATING.has(next)) setArray(false);
              }}
            >
              <For each={OPTION_KINDS}>{(k) => <option value={k}>{t(`dhcp.optset.kind.${k}`)}</option>}</For>
            </select>
          </Field>
          <Check id="array" label={t("dhcp.def.field.array")} checked={array()} disabled={!REPEATING.has(kind())} onChange={setArray} />
        </div>
        <Field id="vendor_class" label={t("dhcp.def.field.vendor_class")} help={t("dhcp.def.field.vendor_class_help")}>
          <input id="dhcp-f-vendor_class" class="input mono" value={vendor()} spellcheck={false} data-testid="field-vendor_class" onInput={(ev) => setVendor(ev.currentTarget.value)} />
        </Field>
        <Field id="description" label={t("dhcp.field.description")}>
          <input id="dhcp-f-description" class="input" value={description()} data-testid="field-description" onInput={(ev) => setDescription(ev.currentTarget.value)} />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dhcp.def.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteDefDialog(props: { def: OptionDef; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dhcp.def.delete_title", { name: props.def.name })}
      testid="dialog-def-delete"
      danger
      busy={busy()}
      confirmLabel={t("dhcp.def.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteOptionDef(props.def)
          .then(() => {
            toast({ kind: "ok", title: t("dhcp.def.deleted", { name: props.def.name }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dhcp.def.delete_body")}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

const CATALOG_COLUMNS: Column<CatalogEntry>[] = [
  { id: "code", header: () => t("dhcp.col.code"), width: 80, align: "right", fixed: true, text: (c) => String(c.code), render: (c) => <span class="mono">{c.code}</span> },
  { id: "name", header: () => t("dhcp.col.name"), width: 260, text: (c) => c.name, render: (c) => <span class="mono">{c.name}</span> },
  { id: "kind", header: () => t("dhcp.col.type"), width: 200, text: (c) => kindWords(c.kind, c.array), render: (c) => <span>{kindWords(c.kind, c.array)}</span> },
  {
    id: "server_managed",
    header: () => t("dhcp.col.server_managed"),
    text: (c) => (c.server_managed ? t("dhcp.catalog.managed") : ""),
    render: (c) => (
      <Show when={c.server_managed}>
        <span class="tag accent" data-testid="catalog-managed">
          {t("dhcp.catalog.managed")}
        </span>
      </Show>
    ),
  },
];

/** The built-in options, read once: the catalog does not change while the server runs. */
function CatalogSection() {
  const catalog = createLiveQuery({
    topics: [],
    fetch: async (signal) => ({ value: await listCatalog(signal) }),
  });
  return (
    <section class="page-section" aria-labelledby="dhcp-catalog-title" data-testid="options-catalog">
      <h2 id="dhcp-catalog-title">{t("dhcp.options.catalog")}</h2>
      <p class="muted">{t("dhcp.options.catalog_help")}</p>
      <div class="dhcp-box">
        <DataGrid
          id="dhcp-catalog"
          label={t("dhcp.options.catalog")}
          noSelection
          columns={CATALOG_COLUMNS}
          rows={latest(catalog) ?? []}
          rowId={(c) => `${c.space}:${c.code}`}
          rowKey={(c) => `${c.space}:${c.code}`}
          rowLabel={(c) => c.name}
          loading={catalog.value.loading}
          initial={latest(catalog) === undefined && !catalog.value.error}
          error={catalog.value.error}
          onRetry={catalog.refetch}
        />
      </div>
    </section>
  );
}

export default function OptionsPage() {
  const [dialog, setDialog] = createSignal<{ kind: "define" } | { kind: "delete"; def: OptionDef } | null>(null);
  const defs = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const page = await listOptionDefs(signal);
      return { value: page.items, revision: page.revision };
    },
  });
  const blocked = () => unavailable(defs.value.error);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) defs.refetch();
  };

  const defColumns: Column<OptionDef>[] = [
    { id: "space", header: () => t("dhcp.col.space"), width: 110, text: (d) => d.space, render: (d) => <span class="mono">{d.space}</span> },
    { id: "code", header: () => t("dhcp.col.code"), width: 80, align: "right", fixed: true, text: (d) => String(d.code), render: (d) => <span class="mono">{d.code}</span> },
    { id: "name", header: () => t("dhcp.col.name"), width: 200, text: (d) => d.name, render: (d) => <span class="mono">{d.name}</span> },
    { id: "kind", header: () => t("dhcp.col.type"), width: 180, text: (d) => kindWords(d.kind, d.array), render: (d) => <span>{kindWords(d.kind, d.array)}</span> },
    { id: "vendor_class", header: () => t("dhcp.col.vendor_class"), width: 160, text: (d) => d.vendor_class ?? "", render: (d) => <span class="mono">{d.vendor_class ?? ""}</span> },
    { id: "used_by", header: () => t("dhcp.col.used_by"), width: 90, align: "right", text: (d) => String(d.used_by), render: (d) => <span class="num">{formatNumber(d.used_by)}</span> },
    { id: "description", header: () => t("dhcp.col.description"), render: (d) => <span class="muted">{d.description ?? ""}</span> },
  ];
  const defActions: RowAction<OptionDef>[] = [
    { id: "delete", label: () => t("dhcp.do.delete"), danger: true, hidden: () => !mayWriteDhcp(), run: (d) => setDialog({ kind: "delete", def: d }) },
  ];

  return (
    <div class="page dhcp-page" data-testid="page-dhcp-options">
      <DhcpNav />
      <PageHead title={t("dhcp.options.title")} sub={t("dhcp.options.sub")} />
      <Show when={!blocked()} fallback={<div class="page-body"><DhcpProblem error={defs.value.error} /></div>}>
        {/* The sections wait for the first answer, so a module that is off never starts their requests. */}
        <Show when={defs.value.state !== "pending"} fallback={<p class="page-body muted">{t("common.loading")}</p>}>
        <div class="page-body dhcp-sections">
          <section class="page-section" aria-labelledby="dhcp-server-options-title" data-testid="options-server">
            <h2 id="dhcp-server-options-title">{t("dhcp.options.server")}</h2>
            <p class="muted">{t("dhcp.options.server_help")}</p>
            <OptionSetEditor owner="server" label={t("dhcp.options.server")} space="both" canWrite={mayWriteDhcp()} testid="server-optset" refresh={latest(defs)} onSaved={() => defs.refetch()} />
          </section>
          <section class="page-section" aria-labelledby="dhcp-defs-title" data-testid="options-defs">
            <div class="dhcp-section-head">
              <h2 id="dhcp-defs-title">{t("dhcp.options.defs")}</h2>
              <Show when={mayWriteDhcp()}>
                <button type="button" class="btn" data-testid="dhcp-def-create" onClick={() => setDialog({ kind: "define" })}>
                  <Icon name="plus" />
                  {t("dhcp.def.create")}
                </button>
              </Show>
            </div>
            <p class="muted">{t("dhcp.options.defs_help")}</p>
            <div class="dhcp-box">
              <DataGrid
                id="dhcp-option-defs"
                label={t("dhcp.options.defs")}
                noSelection
                columns={defColumns}
                rows={latest(defs) ?? []}
                rowId={(d) => d.id}
                rowKey={(d) => `${d.space}:${d.code}`}
                rowLabel={(d) => d.name}
                loading={defs.value.loading}
                initial={latest(defs) === undefined && !defs.value.error}
                error={defs.value.error}
                onRetry={defs.refetch}
                rowActions={defActions}
                empty={
                  <div class="empty" data-testid="dhcp-defs-empty">
                    <h3>{t("dhcp.defs.empty")}</h3>
                  </div>
                }
              />
            </div>
          </section>
          <CatalogSection />
        </div>
        </Show>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "define" ? (
            <DefineDialog onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <DeleteDefDialog def={d.def} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
