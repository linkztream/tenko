// Editing an address (IPAM-04): renumber it, name it in DNS, change its status, description,
// tags and custom values. The address stays in its VRF; the server picks the prefix that
// holds the new address. Only the fields that changed are sent, with the revision the person saw.
import { createMemo, createSignal, untrack } from "solid-js";
import { api } from "../../api/client";
import type { Address, AddressPatch, CustomValue, Status, WriteResponse } from "../../api/types";
import { t } from "../../i18n";
import { CustomFieldsEditor, customPatch, TagsInput } from "../fields/CustomFieldsEditor";
import { customFieldErrors, Field, FieldRow, sameTags, SelectInput, serverFieldMessage, statusOptions, tracked, WriteForm } from "../formKit";
import { formatIp, parseIp } from "../ip";
import { writeQuery } from "../plan/describe";
import { kindWord } from "../words";

const PLACED = ["ip", "dns_name", "status", "description", "tags", "custom"] as const;

/** A DNS name the way the server keeps it: lowercase, no trailing dot, at least two labels. */
export function normalizeDnsName(text: string): string | null {
  let name = text.trim();
  if (name.endsWith(".")) name = name.slice(0, -1);
  name = name.toLowerCase();
  if (name === "" || name.length > 253) return null;
  const labels = name.split(".");
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (label === "" || label.length > 63 || label.startsWith("-") || label.endsWith("-") || !/^[a-z0-9_-]+$/.test(label)) return null;
  }
  return name;
}

export function AddressForm(props: { address: Address; onDone: (address: Address) => void; onClose: () => void }) {
  // The form works on the address the person opened it with: its revision is what the edit is checked against.
  const original = untrack(() => props.address);
  const [ip, setIp] = createSignal(original.ip);
  const [ipTouched, setIpTouched] = createSignal(false);
  const [dns, setDns] = createSignal(original.dns_name ?? "");
  const [dnsTouched, setDnsTouched] = createSignal(false);
  const [status, setStatus] = createSignal<Status>(original.status);
  const [description, setDescription] = createSignal(original.meta.description ?? "");
  const [tags, setTags] = createSignal<string[]>([...(original.meta.tags ?? [])]);
  const [custom, setCustom] = createSignal<Record<string, CustomValue>>({ ...(original.meta.custom ?? {}) });
  const [customProblems, setCustomProblems] = createSignal<Record<string, string>>({});

  const kind = () => kindWord("address");
  const parsed = createMemo(() => parseIp(ip()));
  const dnsName = createMemo(() => (dns().trim() === "" ? undefined : normalizeDnsName(dns())));

  const ipMessage = (): string | undefined => {
    if (ip().trim() === "") return t("ipam.field.ip_required");
    return parsed() ? undefined : t("ipam.field.ip_invalid");
  };
  const dnsMessage = (): string | undefined => (dnsName() === null ? t("ipam.field.dns_invalid") : undefined);

  const patch = createMemo<AddressPatch>(() => {
    const out: AddressPatch = {};
    const address = parsed();
    if (address && formatIp(address) !== original.ip) out.ip = formatIp(address);
    const name = dnsName();
    if (name !== null && (name ?? null) !== (original.dns_name ?? null)) out.dns_name = name ?? null;
    if (status() !== original.status) out.status = status();
    const text = description().trim();
    if (text !== (original.meta.description ?? "")) out.description = text === "" ? null : text;
    if (!sameTags(tags(), original.meta.tags ?? [])) out.tags = tags();
    const values = customPatch(original.meta.custom ?? {}, custom());
    if (values) out.custom = values as AddressPatch["custom"];
    return out;
  });
  // A value that does not parse counts as a change: the submit then reports it.
  const changed = () => Object.keys(patch()).length > 0 || !parsed() || dnsName() === null;

  const validate = (): boolean => {
    setIpTouched(true);
    setDnsTouched(true);
    return !!parsed() && dnsName() !== null && Object.keys(customProblems()).length === 0;
  };

  return (
    <WriteForm<Address>
      name="address-form"
      title={t("ipam.form.edit_title", { kind: kind(), label: original.ip })}
      submitLabel={t("ipam.form.save_changes")}
      changed={changed()}
      placed={PLACED}
      validate={validate}
      planTitle={() => t("ipam.form.save_title", { kind: kind(), label: original.ip })}
      planConfirm={t("ipam.form.save_changes")}
      send={(o) =>
        api.patch("/api/v1/addresses/{id}", {
          path: { id: original.id },
          query: writeQuery(o.dryRun, o.acknowledge),
          body: patch(),
          ifMatch: original.meta.revision,
        }) as Promise<WriteResponse<Address>>
      }
      doneTitle={(item) => t("ipam.form.saved", { label: item.ip })}
      onDone={props.onDone}
      onClose={props.onClose}
    >
      {(flow) => (
        <>
          <Field
            name="ip"
            label={t("ipam.field.ip")}
            help={t("ipam.field.ip_renumber_help")}
            required
            error={serverFieldMessage(flow.error(), "ip") ?? (ipTouched() ? ipMessage() : undefined)}
          >
            {(c) => (
              <input
                class="input mono"
                type="text"
                autocomplete="off"
                spellcheck={false}
                {...c}
                value={ip()}
                onInput={(e) => tracked(setIp, flow)(e.currentTarget.value)}
                onBlur={() => setIpTouched(true)}
              />
            )}
          </Field>
          <Field
            name="dns_name"
            label={t("ipam.col.dns_name")}
            help={t("ipam.field.dns_help")}
            error={serverFieldMessage(flow.error(), "dns_name") ?? (dnsTouched() ? dnsMessage() : undefined)}
          >
            {(c) => (
              <input
                class="input mono"
                type="text"
                autocomplete="off"
                autocapitalize="off"
                spellcheck={false}
                {...c}
                value={dns()}
                onInput={(e) => tracked(setDns, flow)(e.currentTarget.value)}
                onBlur={() => setDnsTouched(true)}
              />
            )}
          </Field>
          <FieldRow>
            <Field name="status" label={t("ipam.col.status")} error={serverFieldMessage(flow.error(), "status")}>
              {(c) => <SelectInput {...c} value={status()} options={statusOptions()} onChange={tracked(setStatus, flow)} />}
            </Field>
            <Field name="description" label={t("ipam.col.description")} error={serverFieldMessage(flow.error(), "description")}>
              {(c) => (
                <input
                  class="input"
                  type="text"
                  autocomplete="off"
                  {...c}
                  value={description()}
                  onInput={(e) => tracked(setDescription, flow)(e.currentTarget.value)}
                />
              )}
            </Field>
          </FieldRow>
          <TagsInput label={t("ipam.col.tags")} value={tags()} onChange={tracked(setTags, flow)} error={serverFieldMessage(flow.error(), "tags")} />
          <CustomFieldsEditor
            kind="address"
            values={custom()}
            onChange={tracked(setCustom, flow)}
            errors={customFieldErrors(flow.error())}
            showRequired={flow.submitted()}
            onProblems={setCustomProblems}
          />
        </>
      )}
    </WriteForm>
  );
}
