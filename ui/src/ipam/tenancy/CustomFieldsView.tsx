// Custom field definitions (/ipam/custom-fields, IPAM-08): a key, a value type, the kinds of
// object it applies to and whether it is required. The key cannot change after creation.
import { createMemo, createSignal, For, Show, untrack } from "solid-js";
import { api, ANY_REVISION } from "../../api/client";
import { createLiveQuery } from "../../api/live";
import type { CustomFieldDef, CustomFieldInput, CustomFieldPatch, CustomKind, ObjectKind } from "../../api/types";
import { Icon } from "../../components/Icon";
import { DataGrid } from "../../grid/DataGrid";
import type { Column } from "../../grid/types";
import { t } from "../../i18n";
import { IpamNav } from "../IpamNav";
import { writeQuery } from "../plan/describe";
import { PlanDialog, useWriteToast } from "../plan/PlanDialog";
import { customKindWord, kindWord } from "../words";
import { FormDialog, TextField } from "./FormDialog";
import "../ipam.css";

const TYPES: readonly CustomKind["type"][] = ["text", "integer", "boolean", "date", "url", "select"];
const KINDS: readonly ObjectKind[] = ["tenant", "vrf", "site", "vlan", "prefix", "range", "address", "host", "interface"];
const KEY = /^[a-z][a-z0-9_]{0,63}$/;

function FieldForm(props: { def?: CustomFieldDef; onDone: () => void; onClose: () => void }) {
  const def = untrack(() => props.def);
  const [key, setKey] = createSignal(def?.key ?? "");
  const [type, setType] = createSignal<CustomKind["type"]>(def?.kind.type ?? "text");
  const [options, setOptions] = createSignal(def?.kind.type === "select" ? def.kind.options.join("\n") : "");
  const [appliesTo, setAppliesTo] = createSignal<ObjectKind[]>([...(def?.applies_to ?? ["host"])]);
  const [required, setRequired] = createSignal(def?.required ?? false);
  const [errors, setErrors] = createSignal<Record<string, string>>({});

  const kind = (): CustomKind =>
    type() === "select"
      ? { type: "select", options: options().split("\n").map((o) => o.trim()).filter(Boolean) }
      : ({ type: type() } as CustomKind);

  const validate = () => {
    const e: Record<string, string> = {};
    if (!def && !KEY.test(key())) e.key = t("ipam.cfdef.key_invalid");
    if (type() === "select" && (kind() as { options: string[] }).options.length === 0) e.options = t("ipam.cfdef.options_required");
    if (appliesTo().length === 0) e.applies = t("ipam.cfdef.applies_required");
    setErrors(e);
    return Object.keys(e).length === 0;
  };
  const send = (o: { dryRun: boolean; acknowledge: string[] }) => {
    if (!def) {
      const body: CustomFieldInput = { key: key(), kind: kind(), applies_to: appliesTo(), required: required() };
      return api.post("/api/v1/custom-fields", { query: writeQuery(o.dryRun, o.acknowledge), body });
    }
    const patch: CustomFieldPatch = {};
    if (JSON.stringify(kind()) !== JSON.stringify(def.kind)) patch.kind = kind();
    if (JSON.stringify([...appliesTo()].sort()) !== JSON.stringify([...def.applies_to].sort())) patch.applies_to = appliesTo();
    if (required() !== (def.required ?? false)) patch.required = required();
    return api.patch("/api/v1/custom-fields/{key}", { path: { key: def.key }, query: writeQuery(o.dryRun, o.acknowledge), body: patch, ifMatch: ANY_REVISION });
  };

  return (
    <FormDialog
      title={def ? t("ipam.cfdef.edit_title", { key: def.key }) : t("ipam.cfdef.create_title")}
      submitLabel={def ? t("ipam.tenancy.save") : t("ipam.cfdef.create")}
      testid="dialog-custom-field-form"
      validate={validate}
      send={send}
      doneTitle={() => (def ? t("ipam.tenancy.saved", { name: key() }) : t("ipam.tenancy.created", { name: key() }))}
      onDone={() => props.onDone()}
      onClose={props.onClose}
    >
      <Show when={!def} fallback={<p class="mono">{def?.key}</p>}>
        <TextField id="key" label={t("ipam.cfdef.key")} value={key()} onInput={setKey} error={errors().key} mono help={t("ipam.cfdef.key_help")} />
      </Show>
      <div class="field">
        <label for="cf-type">{t("ipam.cfdef.type")}</label>
        <select id="cf-type" class="select" value={type()} data-testid="field-type" onChange={(e) => setType(e.currentTarget.value as CustomKind["type"])}>
          <For each={TYPES}>{(k) => <option value={k}>{customKindWord(k)}</option>}</For>
        </select>
      </div>
      <Show when={type() === "select"}>
        <div class="field">
          <label for="cf-options">{t("ipam.cfdef.options")}</label>
          <textarea
            id="cf-options"
            class="input"
            rows="4"
            value={options()}
            aria-invalid={errors().options ? "true" : undefined}
            onInput={(e) => setOptions(e.currentTarget.value)}
          />
          <span class={errors().options ? "help bad" : "help"}>{errors().options ?? t("ipam.cfdef.options_help")}</span>
        </div>
      </Show>
      <fieldset class="field-group kinds-choice">
        <legend class="label">{t("ipam.cfdef.applies_to")}</legend>
        <For each={KINDS}>
          {(k) => (
            <label class="ackrow">
              <input
                type="checkbox"
                class="cb"
                checked={appliesTo().includes(k)}
                onChange={(e) => setAppliesTo(e.currentTarget.checked ? [...appliesTo(), k] : appliesTo().filter((x) => x !== k))}
              />
              {kindWord(k, 2)}
            </label>
          )}
        </For>
        <Show when={errors().applies}>
          <span class="help bad">{errors().applies}</span>
        </Show>
      </fieldset>
      <label class="ackrow">
        <input type="checkbox" class="cb" checked={required()} onChange={(e) => setRequired(e.currentTarget.checked)} />
        {t("ipam.cfdef.required")}
      </label>
    </FormDialog>
  );
}

export default function CustomFieldsView() {
  const writeToast = useWriteToast();
  const live = createLiveQuery<CustomFieldDef[]>({
    topics: ["ipam"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => o.kind === "custom_field"),
    fetch: async (signal) => {
      const list = await api.get("/api/v1/custom-fields", { signal });
      return { value: list.items as CustomFieldDef[], revision: list.revision };
    },
  });
  const rows = createMemo(() => [...(live.value.latest ?? [])].sort((a, b) => a.key.localeCompare(b.key)));
  const [dialog, setDialog] = createSignal<{ kind: "create" } | { kind: "edit" | "delete"; def: CustomFieldDef } | null>(null);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) live.refetch();
  };

  const columns: Column<CustomFieldDef>[] = [
    { id: "key", header: () => t("ipam.cfdef.key"), width: 220, fixed: true, text: (d) => d.key, render: (d) => <span class="mono">{d.key}</span> },
    {
      id: "type",
      header: () => t("ipam.cfdef.type"),
      width: 260,
      render: (d) => (d.kind.type === "select" ? `${customKindWord("select")}: ${d.kind.options.join(", ")}` : customKindWord(d.kind.type)),
    },
    { id: "applies", header: () => t("ipam.cfdef.applies_to"), render: (d) => d.applies_to.map((k) => kindWord(k, 2)).join(", ") },
    { id: "required", header: () => t("ipam.cfdef.required_col"), width: 110, render: (d) => (d.required ? t("ipam.cfdef.yes") : t("ipam.cfdef.no")) },
  ];

  return (
    <div class="page list-page" data-testid="page-ipam-custom-fields">
      <IpamNav />
      <div class="page-head">
        <div>
          <h1 tabIndex={-1}>{t("ipam.nav.custom_fields")}</h1>
        </div>
        <div class="actions">
          <button type="button" class="btn primary" data-testid="custom-field-create" onClick={() => setDialog({ kind: "create" })}>
            <Icon name="plus" />
            {t("ipam.cfdef.create")}
          </button>
        </div>
      </div>
      <div class="list-body">
        <DataGrid
          id="custom-fields"
          label={t("ipam.nav.custom_fields")}
          noSelection
          columns={columns}
          rows={rows()}
          rowId={(d) => d.id}
          rowKey={(d) => d.key}
          loading={live.value.loading}
          initial={live.value.latest === undefined}
          error={live.value.error}
          onRetry={live.refetch}
          onOpen={(d) => setDialog({ kind: "edit", def: d })}
          rowActions={[
            { id: "edit", label: () => t("ipam.do.edit"), run: (d) => setDialog({ kind: "edit", def: d }) },
            { id: "delete", label: () => t("ipam.do.delete"), danger: true, run: (d) => setDialog({ kind: "delete", def: d }) },
          ]}
          empty={
            <div class="empty">
              <h3>{t("ipam.cfdef.empty")}</h3>
            </div>
          }
        />
      </div>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "create" ? (
            <FieldForm onDone={() => close(true)} onClose={() => close(false)} />
          ) : d.kind === "edit" ? (
            <FieldForm def={d.def} onDone={() => close(true)} onClose={() => close(false)} />
          ) : (
            <PlanDialog
              title={t("ipam.cfdef.delete_title", { key: d.def.key })}
              confirmLabel={t("ipam.cfdef.delete_title", { key: d.def.key })}
              danger
              testid="dialog-delete"
              send={(o) => api.delete("/api/v1/custom-fields/{key}", { path: { key: d.def.key }, query: writeQuery(o.dryRun, o.acknowledge), ifMatch: ANY_REVISION })}
              onClose={() => close(false)}
              onDone={(r) => {
                writeToast(t("ipam.cfdef.deleted", { key: d.def.key }), r);
                close(true);
              }}
            />
          )
        }
      </Show>
    </div>
  );
}
