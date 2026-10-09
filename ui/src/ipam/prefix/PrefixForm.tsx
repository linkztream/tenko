// Creating and editing a prefix (IPAM-02, IPAM-06, IPAM-08). The form checks what it can before
// anything is sent (the network, the alarm thresholds); the server has the last word and its
// field errors land under the field they are about. The write itself goes through the plan
// dialog. Editing sends only the fields that changed, with the revision the person saw.
import { createMemo, createSignal, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import type { AllocPolicy, CustomValue, Prefix, PrefixInput, PrefixPatch, PrefixRole, Status, Vrf, WriteResponse } from "../../api/types";
import { t } from "../../i18n";
import { CustomFieldsEditor, customPatch, TagsInput } from "../fields/CustomFieldsEditor";
import {
  customFieldErrors,
  Field,
  FieldRow,
  sameTags,
  SelectInput,
  serverFieldMessage,
  statusOptions,
  tracked,
  useSiteChoices,
  useVlanChoices,
  withCurrent,
  WriteForm,
  type Option,
} from "../formKit";
import { formatCidr } from "../ip";
import { writeQuery } from "../plan/describe";
import { kindWord } from "../words";
import { checkAlarm, checkNetwork, networkHint } from "./inputs";

const ROLES: readonly PrefixRole[] = ["network", "supernet"];
const POLICIES: readonly AllocPolicy[] = ["lowest", "highest"];
const PLACED = ["cidr", "description", "status", "role", "vlan", "site", "alloc", "alarm", "tags", "custom"] as const;

export function PrefixForm(props: {
  vrf: Vrf;
  /** Editing this prefix; without it the form creates one. */
  prefix?: Prefix | undefined;
  /** The supernet the new prefix goes into: its network part is typed into the field as a start. */
  parentCidr?: string | undefined;
  onDone: (prefix: Prefix) => void;
  onClose: () => void;
}) {
  // The form works on the prefix the person opened it with: its revision is what the edit is checked against.
  const original = untrack(() => props.prefix);
  const [cidr, setCidr] = createSignal(original?.cidr ?? networkHint(untrack(() => props.parentCidr)));
  const [cidrTouched, setCidrTouched] = createSignal(false);
  const [description, setDescription] = createSignal(original?.meta.description ?? "");
  const [status, setStatus] = createSignal<Status>(original?.status ?? "active");
  const [role, setRole] = createSignal<string>(original?.role ?? "");
  const [vlan, setVlan] = createSignal(original?.vlan ?? "");
  const [site, setSite] = createSignal(original?.site ?? "");
  const [alloc, setAlloc] = createSignal<AllocPolicy>(original?.alloc ?? "lowest");
  const [warn, setWarn] = createSignal(original?.alarm ? String(original.alarm.warn_pct) : "");
  const [crit, setCrit] = createSignal(original?.alarm ? String(original.alarm.crit_pct) : "");
  const [alarmTouched, setAlarmTouched] = createSignal(false);
  const [tags, setTags] = createSignal<string[]>([...(original?.meta.tags ?? [])]);
  const [custom, setCustom] = createSignal<Record<string, CustomValue>>({ ...(original?.meta.custom ?? {}) });
  const [customProblems, setCustomProblems] = createSignal<Record<string, string>>({});

  const vlanChoices = useVlanChoices();
  const siteChoices = useSiteChoices();
  const kind = () => kindWord("prefix");

  const network = createMemo(() => checkNetwork(cidr()));
  const alarm = createMemo(() => checkAlarm(warn(), crit()));

  const networkMessage = (): string | undefined => {
    const c = network();
    if (c.ok) return undefined;
    switch (c.reason) {
      case "empty":
        return t("ipam.field.cidr_required");
      case "invalid":
        return t("ipam.field.cidr_invalid");
      case "host_bits":
        return t("errors.ipam.prefix.host_bits", { cidr: c.given, network: c.network });
    }
  };

  /** The network the text should have been, when only the host bits are wrong. */
  const hostBitsFix = (): string | undefined => {
    const c = network();
    return !c.ok && c.reason === "host_bits" && cidrTouched() ? c.network : undefined;
  };

  const alarmMessage = (which: "warn" | "crit"): string | undefined => {
    const a = alarm();
    if (a.ok || !alarmTouched()) return undefined;
    switch (a[which]) {
      case "required":
        return t("ipam.field.alarm_both");
      case "range":
        return t("ipam.field.alarm_range");
      case "order":
        return t("ipam.field.alarm_order");
      default:
        return undefined;
    }
  };

  // The fields that changed, for an edit.
  const patch = createMemo<PrefixPatch>(() => {
    const out: PrefixPatch = {};
    if (!original) return out;
    const net = network();
    if (net.ok && formatCidr(net.cidr) !== original.cidr) out.cidr = formatCidr(net.cidr);
    const text = description().trim();
    if (text !== (original.meta.description ?? "")) out.description = text === "" ? null : text;
    if (status() !== original.status) out.status = status();
    if (role() !== "" && role() !== original.role) out.role = role() as PrefixRole;
    if ((vlan() || null) !== (original.vlan ?? null)) out.vlan = vlan() || null;
    if ((site() || null) !== (original.site ?? null)) out.site = site() || null;
    if (alloc() !== (original.alloc ?? "lowest")) out.alloc = alloc();
    const a = alarm();
    if (a.ok && (a.alarm?.warn_pct !== original.alarm?.warn_pct || a.alarm?.crit_pct !== original.alarm?.crit_pct)) out.alarm = a.alarm;
    if (!sameTags(tags(), original.meta.tags ?? [])) out.tags = tags();
    const values = customPatch(original.meta.custom ?? {}, custom());
    if (values) out.custom = values as PrefixPatch["custom"];
    return out;
  });
  // A value that does not parse counts as a change: the submit then reports it.
  const changed = () => !original || Object.keys(patch()).length > 0 || !network().ok || !alarm().ok;

  const validate = (): boolean => {
    setCidrTouched(true);
    setAlarmTouched(true);
    return network().ok && alarm().ok && Object.keys(customProblems()).length === 0;
  };

  const createBody = (): PrefixInput => {
    const net = network();
    const a = alarm();
    return {
      cidr: net.ok ? formatCidr(net.cidr) : cidr().trim(),
      vrf: props.vrf.id,
      status: status(),
      alloc: alloc(),
      ...(role() !== "" ? { role: role() as PrefixRole } : {}),
      ...(description().trim() !== "" ? { description: description().trim() } : {}),
      ...(vlan() !== "" ? { vlan: vlan() } : {}),
      ...(site() !== "" ? { site: site() } : {}),
      ...(a.ok && a.alarm ? { alarm: a.alarm } : {}),
      ...(tags().length > 0 ? { tags: tags() } : {}),
      ...(Object.keys(custom()).length > 0 ? { custom: custom() } : {}),
    };
  };

  const roleOptions = (): Option[] => [
    ...(original ? [] : [{ value: "", label: t("ipam.form.role_auto") }]),
    ...ROLES.map((r) => ({ value: r as string, label: t(`ipam.prefix_role.${r}`) })),
  ];
  const allocOptions = (): Option<AllocPolicy>[] =>
    POLICIES.map((p) => ({ value: p, label: t(p === "lowest" ? "ipam.prefix.alloc_lowest" : "ipam.prefix.alloc_highest") }));

  return (
    <WriteForm<Prefix>
      name="prefix-form"
      title={original ? t("ipam.form.edit_title", { kind: kind(), label: original.cidr }) : t("ipam.form.create_kind", { kind: kind() })}
      submitLabel={original ? t("ipam.form.save_changes") : t("ipam.form.create_kind", { kind: kind() })}
      changed={changed()}
      placed={PLACED}
      validate={validate}
      planTitle={() => {
        const net = network();
        const label = net.ok ? formatCidr(net.cidr) : cidr().trim();
        return original
          ? t("ipam.form.save_title", { kind: kind(), label: original.cidr })
          : t("ipam.form.create_title", { kind: kind(), label });
      }}
      planConfirm={original ? t("ipam.form.save_changes") : t("ipam.form.create_kind", { kind: kind() })}
      send={(o) =>
        (original
          ? api.patch("/api/v1/prefixes/{id}", {
              path: { id: original.id },
              query: writeQuery(o.dryRun, o.acknowledge),
              body: patch(),
              ifMatch: original.meta.revision,
            })
          : api.post("/api/v1/prefixes", { query: writeQuery(o.dryRun, o.acknowledge), body: createBody() })) as Promise<WriteResponse<Prefix>>
      }
      doneTitle={(item) => (original ? t("ipam.form.saved", { label: item.cidr }) : t("ipam.form.created", { kind: kind(), label: item.cidr }))}
      onDone={props.onDone}
      onClose={props.onClose}
    >
      {(flow) => {
        const setCidrText = tracked(setCidr, flow);
        return (
          <>
            <Field
              name="cidr"
              label={t("ipam.field.cidr")}
              help={t("ipam.field.cidr_help")}
              required
              error={serverFieldMessage(flow.error(), "cidr") ?? (cidrTouched() ? networkMessage() : undefined)}
            >
              {(c) => (
                <input
                  class="input mono"
                  type="text"
                  autocomplete="off"
                  autocapitalize="off"
                  spellcheck={false}
                  {...c}
                  value={cidr()}
                  onInput={(e) => setCidrText(e.currentTarget.value)}
                  onBlur={() => setCidrTouched(true)}
                />
              )}
            </Field>
            <Show when={hostBitsFix()}>
              {(fix) => (
                <div class="field-actions">
                  <button type="button" class="btn sm" data-testid="cidr-fix" onClick={() => setCidrText(fix())}>
                    {t("ipam.form.use_network", { network: fix() })}
                  </button>
                </div>
              )}
            </Show>
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
            <FieldRow>
              <Field name="status" label={t("ipam.col.status")} error={serverFieldMessage(flow.error(), "status")}>
                {(c) => <SelectInput {...c} value={status()} options={statusOptions()} onChange={tracked(setStatus, flow)} />}
              </Field>
              <Field name="role" label={t("ipam.col.role")} help={t("ipam.form.role_help")} error={serverFieldMessage(flow.error(), "role")}>
                {(c) => <SelectInput {...c} value={role()} options={roleOptions()} onChange={tracked(setRole, flow)} />}
              </Field>
            </FieldRow>
            <FieldRow>
              <Field name="vlan" label={t("ipam.col.vlan")} error={serverFieldMessage(flow.error(), "vlan")}>
                {(c) => (
                  <SelectInput
                    {...c}
                    value={vlan()}
                    options={withCurrent(vlanChoices(), vlan(), (id) => id.slice(0, 8))}
                    onChange={tracked(setVlan, flow)}
                  />
                )}
              </Field>
              <Field name="site" label={t("ipam.col.site")} error={serverFieldMessage(flow.error(), "site")}>
                {(c) => (
                  <SelectInput
                    {...c}
                    value={site()}
                    options={withCurrent(siteChoices(), site(), (id) => id.slice(0, 8))}
                    onChange={tracked(setSite, flow)}
                  />
                )}
              </Field>
            </FieldRow>
            <FieldRow three>
              <Field name="alloc" label={t("ipam.prefix.alloc")} error={serverFieldMessage(flow.error(), "alloc")}>
                {(c) => <SelectInput {...c} value={alloc()} options={allocOptions()} onChange={tracked(setAlloc, flow)} />}
              </Field>
              <Field
                name="alarm-warn"
                label={t("ipam.field.alarm_warn")}
                help={t("ipam.field.alarm_help")}
                error={serverFieldMessage(flow.error(), "alarm", "alarm.warn_pct") ?? alarmMessage("warn")}
              >
                {(c) => (
                  <input
                    class="input"
                    type="text"
                    inputmode="numeric"
                    autocomplete="off"
                    {...c}
                    value={warn()}
                    onInput={(e) => tracked(setWarn, flow)(e.currentTarget.value)}
                    onBlur={() => setAlarmTouched(true)}
                  />
                )}
              </Field>
              <Field
                name="alarm-crit"
                label={t("ipam.field.alarm_crit")}
                error={serverFieldMessage(flow.error(), "alarm.crit_pct") ?? alarmMessage("crit")}
              >
                {(c) => (
                  <input
                    class="input"
                    type="text"
                    inputmode="numeric"
                    autocomplete="off"
                    {...c}
                    value={crit()}
                    onInput={(e) => tracked(setCrit, flow)(e.currentTarget.value)}
                    onBlur={() => setAlarmTouched(true)}
                  />
                )}
              </Field>
            </FieldRow>
            <TagsInput label={t("ipam.col.tags")} value={tags()} onChange={tracked(setTags, flow)} error={serverFieldMessage(flow.error(), "tags")} />
            <CustomFieldsEditor
              kind="prefix"
              values={custom()}
              onChange={tracked(setCustom, flow)}
              errors={customFieldErrors(flow.error())}
              showRequired={flow.submitted()}
              onProblems={setCustomProblems}
            />
          </>
        );
      }}
    </WriteForm>
  );
}
