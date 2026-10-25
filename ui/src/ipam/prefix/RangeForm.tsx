// Creating and editing a range of a network (IPAM-03): the first and last address inside the
// prefix, what the range is for and, for a DHCP pool, its lease time. A delegation pool (WP9.2, an
// IPv6 network only) also has the length of the prefixes it hands to routers, with the first and
// last address on boundaries of that length. Editing sends only the fields that changed, with
// the revision the person saw.
import { createMemo, createSignal, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { RANGE_ROLES, type CustomValue, type NewRange, type Prefix, type Range, type RangePatch, type RangeRole, type Status, type WriteResponse } from "../../api/types";
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
  WriteForm,
  type Option,
} from "../formKit";
import { formatIp, parseCidr, parseIp } from "../ip";
import { writeQuery } from "../plan/describe";
import { kindWord, rangeRoleWord } from "../words";
import { checkDelegatedLen, onBoundary } from "./delegation";
import { addressIn } from "./inputs";

const PLACED = ["first", "last", "role", "status", "description", "lease_secs", "delegated_len", "tags", "custom", "prefix"] as const;

export type LeaseUnit = "minutes" | "hours" | "days";
const UNIT_SECS: Readonly<Record<LeaseUnit, number>> = { minutes: 60, hours: 3600, days: 86400 };
const UNITS: readonly LeaseUnit[] = ["minutes", "hours", "days"];
export const MIN_LEASE_SECS = 60;
export const MAX_LEASE_SECS = 31_536_000;

/** A lease time in its largest whole unit: 86,400 s is 1 day, 5,400 s is 90 minutes. */
export function leaseParts(secs: number): { value: string; unit: LeaseUnit } {
  if (secs % 86_400 === 0) return { value: String(secs / 86_400), unit: "days" };
  if (secs % 3_600 === 0) return { value: String(secs / 3_600), unit: "hours" };
  return { value: String(Math.round((secs / 60) * 100) / 100), unit: "minutes" };
}

export type LeaseCheck = { ok: true; secs: number | null } | { ok: false; reason: "number" | "range" };

/** The seconds of a number and a unit; empty is no lease time. */
export function checkLease(value: string, unit: LeaseUnit): LeaseCheck {
  const text = value.trim().replace(",", ".");
  if (text === "") return { ok: true, secs: null };
  if (!/^\d{1,9}(\.\d{1,6})?$/.test(text)) return { ok: false, reason: "number" };
  const secs = Math.round(Number(text) * UNIT_SECS[unit]);
  if (secs < MIN_LEASE_SECS || secs > MAX_LEASE_SECS) return { ok: false, reason: "range" };
  return { ok: true, secs };
}

function rangeLabel(first: string, last: string): string {
  return `${first} - ${last}`;
}

export function RangeForm(props: {
  prefix: Prefix;
  /** Editing this range; without it the form creates one. */
  range?: Range | undefined;
  onDone: (range: Range) => void;
  onClose: () => void;
}) {
  const original = untrack(() => props.range);
  const prefixCidr = untrack(() => parseCidr(props.prefix.cidr));
  const networkLength = prefixCidr?.length ?? null;
  // WP9.2: a delegation pool is a range of an IPv6 network.
  const isV6 = prefixCidr?.version === 6;
  const startLease = original?.lease_secs ? leaseParts(original.lease_secs) : { value: "", unit: "hours" as LeaseUnit };

  const [first, setFirst] = createSignal(original?.first ?? "");
  const [last, setLast] = createSignal(original?.last ?? "");
  const [firstTouched, setFirstTouched] = createSignal(false);
  const [lastTouched, setLastTouched] = createSignal(false);
  const [role, setRole] = createSignal<RangeRole>(original?.role ?? "dhcp_pool");
  const [status, setStatus] = createSignal<Status>(original?.status ?? "active");
  const [description, setDescription] = createSignal(original?.meta.description ?? "");
  const [lease, setLease] = createSignal(startLease.value);
  const [unit, setUnit] = createSignal<LeaseUnit>(startLease.unit);
  const [leaseTouched, setLeaseTouched] = createSignal(false);
  const [delegated, setDelegated] = createSignal(original?.delegated_len != null ? String(original.delegated_len) : "");
  const [delegatedTouched, setDelegatedTouched] = createSignal(false);
  const [tags, setTags] = createSignal<string[]>([...(original?.meta.tags ?? [])]);
  const [custom, setCustom] = createSignal<Record<string, CustomValue>>({ ...(original?.meta.custom ?? {}) });
  const [customProblems, setCustomProblems] = createSignal<Record<string, string>>({});

  const kind = () => kindWord("range");
  const isPd = () => role() === "dhcp_pd_pool";
  /** A lease time belongs to both kinds of pool. */
  const isPool = () => role() === "dhcp_pool" || isPd();

  const addressProblem = (text: string): "empty" | "invalid" | "outside" | undefined => {
    if (text.trim() === "") return "empty";
    if (!prefixCidr) return parseIp(text) ? undefined : "invalid";
    const where = addressIn(prefixCidr, text);
    return where === "ok" ? undefined : where;
  };
  const firstProblem = createMemo(() => addressProblem(first()));
  const lastProblem = createMemo(() => addressProblem(last()));
  const order = createMemo((): "ok" | "reversed" => {
    const a = parseIp(first());
    const b = parseIp(last());
    return a && b && a.version === b.version && a.value > b.value ? "reversed" : "ok";
  });
  const delegatedCheck = createMemo(() => (isPd() ? checkDelegatedLen(delegated(), networkLength) : null));
  /** The first or last address of a delegation pool off a boundary of the delegated length. */
  const boundaryProblem = (end: "first" | "last"): boolean => {
    const check = delegatedCheck();
    if (!check?.ok) return false;
    const text = end === "first" ? first() : last();
    return (end === "first" ? !firstProblem() : !lastProblem()) && !onBoundary(text, check.len, end);
  };
  const leaseCheck = createMemo(() => (isPool() ? checkLease(lease(), unit()) : ({ ok: true, secs: null } as LeaseCheck)));

  const addressMessage = (problem: "empty" | "invalid" | "outside" | undefined): string | undefined => {
    switch (problem) {
      case "empty":
        return t("ipam.field.ip_required");
      case "invalid":
        return t("ipam.field.ip_invalid");
      case "outside":
        return t("errors.ipam.range.outside_prefix", { cidr: props.prefix.cidr });
      default:
        return undefined;
    }
  };
  const firstMessage = (): string | undefined => {
    const c = delegatedCheck();
    return addressMessage(firstProblem()) ?? (c?.ok && boundaryProblem("first") ? t("ipam.field.delegated_first", { len: c.len }) : undefined);
  };
  const lastMessage = (): string | undefined => {
    const c = delegatedCheck();
    return (
      addressMessage(lastProblem()) ??
      (order() === "reversed" ? t("ipam.field.last_before_first") : undefined) ??
      (c?.ok && boundaryProblem("last") ? t("ipam.field.delegated_last", { len: c.len }) : undefined)
    );
  };
  const delegatedMessage = (): string | undefined => {
    const c = delegatedCheck();
    if (!c || c.ok) return undefined;
    switch (c.reason) {
      case "required":
        return t("ipam.field.delegated_required");
      case "number":
        return t("ipam.field.delegated_number");
      default:
        return t("ipam.field.delegated_range", { length: networkLength ?? 0 });
    }
  };
  const leaseMessage = (): string | undefined => {
    const c = leaseCheck();
    if (c.ok) return undefined;
    return c.reason === "number" ? t("ipam.field.lease_number") : t("ipam.field.lease_range");
  };

  const normalized = (text: string): string => {
    const ip = parseIp(text);
    return ip ? formatIp(ip) : text.trim();
  };

  const patch = createMemo(() => {
    const out: RangePatch & { lease_secs?: number | null } = {};
    if (!original) return out;
    if (!firstProblem() && normalized(first()) !== original.first) out.first = normalized(first());
    if (!lastProblem() && normalized(last()) !== original.last) out.last = normalized(last());
    if (role() !== original.role) out.role = role();
    if (status() !== original.status) out.status = status();
    const text = description().trim();
    if (text !== (original.meta.description ?? "")) out.description = text === "" ? null : text;
    const c = leaseCheck();
    if (c.ok && c.secs !== (original.lease_secs ?? null)) out.lease_secs = c.secs;
    const d = delegatedCheck();
    if (d?.ok) {
      if (d.len !== (original.delegated_len ?? null)) out.delegated_len = d.len;
    } else if (!isPd() && original.role === "dhcp_pd_pool") out.delegated_len = null;
    if (!sameTags(tags(), original.meta.tags ?? [])) out.tags = tags();
    const values = customPatch(original.meta.custom ?? {}, custom());
    if (values) out.custom = values as RangePatch["custom"];
    return out;
  });
  const valid = () =>
    !firstProblem() &&
    !lastProblem() &&
    order() === "ok" &&
    leaseCheck().ok &&
    (delegatedCheck()?.ok ?? true) &&
    !boundaryProblem("first") &&
    !boundaryProblem("last");
  const changed = () => !original || Object.keys(patch()).length > 0 || !valid();

  const validate = (): boolean => {
    setFirstTouched(true);
    setLastTouched(true);
    setLeaseTouched(true);
    setDelegatedTouched(true);
    return valid() && Object.keys(customProblems()).length === 0;
  };

  const createBody = (): NewRange & { lease_secs?: number | null } => {
    const c = leaseCheck();
    const d = delegatedCheck();
    return {
      first: normalized(first()),
      last: normalized(last()),
      role: role(),
      status: status(),
      ...(description().trim() !== "" ? { description: description().trim() } : {}),
      ...(c.ok && c.secs !== null ? { lease_secs: c.secs } : {}),
      ...(d?.ok ? { delegated_len: d.len } : {}),
      ...(tags().length > 0 ? { tags: tags() } : {}),
      ...(Object.keys(custom()).length > 0 ? { custom: custom() } : {}),
    };
  };

  // A delegation pool is offered on an IPv6 network; a range that is one already keeps its role in the list.
  const roleOptions = (): Option<RangeRole>[] =>
    RANGE_ROLES.filter((r) => r !== "dhcp_pd_pool" || isV6 || original?.role === "dhcp_pd_pool").map((r) => ({ value: r, label: rangeRoleWord(r) }));
  const unitOptions = (): Option<LeaseUnit>[] => UNITS.map((u) => ({ value: u, label: t(`ipam.field.unit_${u}`) }));

  return (
    <WriteForm<Range>
      name="range-form"
      title={original ? t("ipam.form.edit_title", { kind: kind(), label: rangeLabel(original.first, original.last) }) : t("ipam.form.create_kind", { kind: kind() })}
      submitLabel={original ? t("ipam.form.save_changes") : t("ipam.form.create_kind", { kind: kind() })}
      changed={changed()}
      placed={PLACED}
      validate={validate}
      planTitle={() =>
        original
          ? t("ipam.form.save_title", { kind: kind(), label: rangeLabel(original.first, original.last) })
          : t("ipam.form.create_title", { kind: kind(), label: rangeLabel(normalized(first()), normalized(last())) })
      }
      planConfirm={original ? t("ipam.form.save_changes") : t("ipam.form.create_kind", { kind: kind() })}
      send={(o) =>
        (original
          ? api.patch("/api/v1/ranges/{id}", {
              path: { id: original.id },
              query: writeQuery(o.dryRun, o.acknowledge),
              body: patch(),
              ifMatch: original.meta.revision,
            })
          : api.post("/api/v1/prefixes/{id}/ranges", {
              path: { id: props.prefix.id },
              query: writeQuery(o.dryRun, o.acknowledge),
              body: createBody(),
            })) as Promise<WriteResponse<Range>>
      }
      doneTitle={(item) =>
        original
          ? t("ipam.form.saved", { label: rangeLabel(item.first, item.last) })
          : t("ipam.form.created", { kind: kind(), label: rangeLabel(item.first, item.last) })
      }
      onDone={props.onDone}
      onClose={props.onClose}
    >
      {(flow) => (
        <>
          <FieldRow>
            <Field
              name="first"
              label={t("ipam.field.first")}
              help={t("ipam.field.inside_prefix", { cidr: props.prefix.cidr })}
              required
              error={serverFieldMessage(flow.error(), "first", "prefix") ?? (firstTouched() ? firstMessage() : undefined)}
            >
              {(c) => (
                <input
                  class="input mono"
                  type="text"
                  autocomplete="off"
                  spellcheck={false}
                  {...c}
                  value={first()}
                  onInput={(e) => tracked(setFirst, flow)(e.currentTarget.value)}
                  onBlur={() => setFirstTouched(true)}
                />
              )}
            </Field>
            <Field
              name="last"
              label={t("ipam.field.last")}
              required
              error={serverFieldMessage(flow.error(), "last") ?? (lastTouched() ? lastMessage() : undefined)}
            >
              {(c) => (
                <input
                  class="input mono"
                  type="text"
                  autocomplete="off"
                  spellcheck={false}
                  {...c}
                  value={last()}
                  onInput={(e) => tracked(setLast, flow)(e.currentTarget.value)}
                  onBlur={() => setLastTouched(true)}
                />
              )}
            </Field>
          </FieldRow>
          <FieldRow>
            <Field name="role" label={t("ipam.col.role")} error={serverFieldMessage(flow.error(), "role")}>
              {(c) => <SelectInput {...c} value={role()} options={roleOptions()} onChange={tracked(setRole, flow)} />}
            </Field>
            <Field name="status" label={t("ipam.col.status")} error={serverFieldMessage(flow.error(), "status")}>
              {(c) => <SelectInput {...c} value={status()} options={statusOptions()} onChange={tracked(setStatus, flow)} />}
            </Field>
          </FieldRow>
          <Show when={isPd()}>
            <Field
              name="delegated_len"
              label={t("ipam.field.delegated")}
              help={t("ipam.field.delegated_help", { length: networkLength ?? 0 })}
              required
              error={serverFieldMessage(flow.error(), "delegated_len") ?? (delegatedTouched() ? delegatedMessage() : undefined)}
            >
              {(c) => (
                <input
                  class="input mono"
                  type="text"
                  inputmode="numeric"
                  autocomplete="off"
                  spellcheck={false}
                  {...c}
                  value={delegated()}
                  onInput={(e) => tracked(setDelegated, flow)(e.currentTarget.value)}
                  onBlur={() => setDelegatedTouched(true)}
                />
              )}
            </Field>
          </Show>
          <Show when={isPool()}>
            <Field
              name="lease"
              label={t("ipam.col.lease")}
              help={t("ipam.field.lease_help")}
              error={serverFieldMessage(flow.error(), "lease_secs") ?? (leaseTouched() ? leaseMessage() : undefined)}
            >
              {(c) => (
                <div class="field-with-unit">
                  <input
                    class="input"
                    type="text"
                    inputmode="decimal"
                    autocomplete="off"
                    {...c}
                    value={lease()}
                    onInput={(e) => tracked(setLease, flow)(e.currentTarget.value)}
                    onBlur={() => setLeaseTouched(true)}
                  />
                  <SelectInput
                    data-testid="field-lease-unit"
                    aria-label={t("ipam.field.lease_unit")}
                    value={unit()}
                    options={unitOptions()}
                    onChange={tracked(setUnit, flow)}
                  />
                </div>
              )}
            </Field>
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
          <TagsInput label={t("ipam.col.tags")} value={tags()} onChange={tracked(setTags, flow)} error={serverFieldMessage(flow.error(), "tags")} />
          <CustomFieldsEditor
            kind="range"
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
