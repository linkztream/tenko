// Claiming the next free address of a network and carving the next free prefix out of a
// supernet (IPAM-07). A small form says what to create and from where, then the plan dialog
// shows what the server found (the address or network it would take) before anything is written.
import { createMemo, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import type { Address, AllocPolicy, NextFreeAddress, NextFreePrefix, Prefix, PrefixRole, Range, Status, WriteResponse } from "../../api/types";
import { t, tx } from "../../i18n";
import { normalizeDnsName } from "../address/AddressForm";
import {
  Field,
  FieldRow,
  SelectInput,
  serverFieldMessage,
  statusOptions,
  tracked,
  useVlanChoices,
  withCurrent,
  WriteForm,
  type Option,
} from "../formKit";
import { bitsOf, parseCidr } from "../ip";
import { writeQuery } from "../plan/describe";
import { kindWord, prefixRoleWord, rangeRoleWord } from "../words";

const POLICIES: readonly AllocPolicy[] = ["lowest", "highest"];

function policyOptions(): Option<AllocPolicy>[] {
  return POLICIES.map((p) => ({ value: p, label: t(p === "lowest" ? "ipam.prefix.alloc_lowest" : "ipam.prefix.alloc_highest") }));
}

// ---------------------------------------------------------------------------------
// The next free address

export function NextFreeAddressDialog(props: {
  prefix: Prefix;
  ranges: Range[];
  onDone: (address: Address) => void;
  onClose: () => void;
}) {
  const prefix = untrack(() => props.prefix);
  const [dns, setDns] = createSignal("");
  const [dnsTouched, setDnsTouched] = createSignal(false);
  const [status, setStatus] = createSignal<Status>("active");
  const [description, setDescription] = createSignal("");
  const [range, setRange] = createSignal("");
  const [policy, setPolicy] = createSignal<AllocPolicy>(prefix.alloc ?? "lowest");

  const dnsName = createMemo(() => (dns().trim() === "" ? undefined : normalizeDnsName(dns())));
  const rangeOptions = (): Option[] => [
    { value: "", label: t("ipam.next_free.whole_network", { cidr: prefix.cidr }) },
    ...props.ranges.map((r) => ({ value: r.id, label: `${r.first} - ${r.last} (${rangeRoleWord(r.role)})` })),
  ];

  const body = (): NextFreeAddress =>
    ({
      policy: policy(),
      status: status(),
      ...(dnsName() ? { dns_name: dnsName() } : {}),
      ...(description().trim() !== "" ? { description: description().trim() } : {}),
      ...(range() !== "" ? { range: range() } : {}),
    }) as NextFreeAddress;

  return (
    <WriteForm<Address>
      name="next-free-address"
      title={t("ipam.next_free.address_title", { cidr: prefix.cidr })}
      submitLabel={t("ipam.next_free.find_address")}
      placed={["dns_name", "status", "description", "range", "policy"]}
      validate={() => {
        setDnsTouched(true);
        return dnsName() !== null;
      }}
      planTitle={() => t("ipam.next_free.address_title", { cidr: prefix.cidr })}
      planConfirm={t("ipam.do.next_free_address")}
      send={(o) =>
        api.post("/api/v1/prefixes/{id}/next-free-address", {
          path: { id: prefix.id },
          query: writeQuery(o.dryRun, o.acknowledge),
          body: body(),
        }) as Promise<WriteResponse<Address>>
      }
      describe={(preview) => (
        <p class="next-free-result" data-testid="next-free-result">
          {tx("ipam.next_free.address", { ip: <span class="mono">{preview.item?.ip ?? ""}</span> })}
        </p>
      )}
      confirmFor={(preview) => t("ipam.addresses.claim", { ip: preview.item?.ip ?? "" })}
      doneTitle={(item) => t("ipam.address.claimed", { ip: item.ip })}
      onDone={props.onDone}
      onClose={props.onClose}
    >
      {(flow) => (
        <>
          <Field
            name="dns_name"
            label={t("ipam.col.dns_name")}
            help={t("ipam.field.dns_help")}
            error={serverFieldMessage(flow.error(), "dns_name") ?? (dnsTouched() && dnsName() === null ? t("ipam.field.dns_invalid") : undefined)}
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
            <Field name="policy" label={t("ipam.prefix.alloc")} error={serverFieldMessage(flow.error(), "policy")}>
              {(c) => <SelectInput {...c} value={policy()} options={policyOptions()} onChange={tracked(setPolicy, flow)} />}
            </Field>
          </FieldRow>
          <Show when={props.ranges.length > 0}>
            <Field name="range" label={t("ipam.next_free.from")} error={serverFieldMessage(flow.error(), "range")}>
              {(c) => <SelectInput {...c} value={range()} options={rangeOptions()} onChange={tracked(setRange, flow)} />}
            </Field>
          </Show>
        </>
      )}
    </WriteForm>
  );
}

// ---------------------------------------------------------------------------------
// The next free prefix

/** The IPv6 lengths on a nibble boundary just below the parent's smallest useful subnets, at most eight. */
export function nibbleLengths(parentLength: number): number[] {
  const out: number[] = [];
  const limit = Math.min(128, Math.max(64, parentLength + 32));
  for (let length = (Math.floor(parentLength / 4) + 1) * 4; length <= limit && out.length < 8; length += 4) out.push(length);
  return out;
}

export function NextFreePrefixDialog(props: { prefix: Prefix; onDone: (prefix: Prefix) => void; onClose: () => void }) {
  const parent = untrack(() => props.prefix);
  const net = parseCidr(parent.cidr);
  const min = (net?.length ?? 0) + 1;
  const max = net ? bitsOf(net.version) : 32;
  const [length, setLength] = createSignal("");
  const [lengthTouched, setLengthTouched] = createSignal(false);
  const [description, setDescription] = createSignal("");
  const [role, setRole] = createSignal<PrefixRole>("network");
  const [status, setStatus] = createSignal<Status>("active");
  const [vlan, setVlan] = createSignal("");
  const [policy, setPolicy] = createSignal<AllocPolicy>(parent.alloc ?? "lowest");
  const vlanChoices = useVlanChoices();

  const lengthValue = createMemo((): number | null => {
    const text = length().trim();
    if (!/^\d{1,3}$/.test(text)) return null;
    const value = Number(text);
    return value >= min && value <= max ? value : null;
  });
  const lengthMessage = (): string | undefined => {
    if (lengthValue() !== null) return undefined;
    return length().trim() === "" ? t("ipam.next_free.length_required") : t("ipam.next_free.length_invalid", { min, max });
  };
  const picks = (): number[] => (net?.version === 6 ? nibbleLengths(net.length) : []);
  const roleOptions = (): Option<PrefixRole>[] => (["network", "supernet"] as const).map((r) => ({ value: r, label: prefixRoleWord(r) }));
  const kind = () => kindWord("prefix");

  const body = (): NextFreePrefix => ({
    length: lengthValue() ?? 0,
    role: role(),
    status: status(),
    policy: policy(),
    ...(description().trim() !== "" ? { description: description().trim() } : {}),
    ...(vlan() !== "" ? { vlan: vlan() } : {}),
  });

  return (
    <WriteForm<Prefix>
      name="next-free-prefix"
      title={t("ipam.next_free.prefix_title", { cidr: parent.cidr })}
      submitLabel={t("ipam.next_free.find_prefix")}
      placed={["length", "description", "role", "status", "vlan", "policy"]}
      validate={() => {
        setLengthTouched(true);
        return lengthValue() !== null;
      }}
      planTitle={() => t("ipam.next_free.prefix_title", { cidr: parent.cidr })}
      planConfirm={t("ipam.form.create_kind", { kind: kind() })}
      send={(o) =>
        api.post("/api/v1/prefixes/{id}/next-free-prefix", {
          path: { id: parent.id },
          query: writeQuery(o.dryRun, o.acknowledge),
          body: body(),
        }) as Promise<WriteResponse<Prefix>>
      }
      describe={(preview) => (
        <p class="next-free-result" data-testid="next-free-result">
          {tx("ipam.next_free.prefix", { cidr: <span class="mono">{preview.item?.cidr ?? ""}</span> })}
        </p>
      )}
      confirmFor={(preview) => t("ipam.next_free.create", { cidr: preview.item?.cidr ?? "" })}
      doneTitle={(item) => t("ipam.form.created", { kind: kind(), label: item.cidr })}
      onDone={props.onDone}
      onClose={props.onClose}
    >
      {(flow) => (
        <>
          <Field
            name="length"
            label={t("ipam.next_free.length")}
            help={t("ipam.next_free.length_help", { cidr: parent.cidr, min, max })}
            required
            error={serverFieldMessage(flow.error(), "length") ?? (lengthTouched() ? lengthMessage() : undefined)}
          >
            {(c) => (
              <input
                class="input"
                type="text"
                inputmode="numeric"
                autocomplete="off"
                {...c}
                value={length()}
                onInput={(e) => tracked(setLength, flow)(e.currentTarget.value)}
                onBlur={() => setLengthTouched(true)}
              />
            )}
          </Field>
          <Show when={picks().length > 0}>
            <div class="length-picks" data-testid="length-picks">
              <span class="muted">{t("ipam.next_free.suggest")}</span>
              <For each={picks()}>
                {(pick) => (
                  <button type="button" class="btn sm ghost" data-testid="length-pick" onClick={() => tracked(setLength, flow)(String(pick))}>
                    {`/${pick}`}
                  </button>
                )}
              </For>
            </div>
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
            <Field name="role" label={t("ipam.col.role")} error={serverFieldMessage(flow.error(), "role")}>
              {(c) => <SelectInput {...c} value={role()} options={roleOptions()} onChange={tracked(setRole, flow)} />}
            </Field>
            <Field name="status" label={t("ipam.col.status")} error={serverFieldMessage(flow.error(), "status")}>
              {(c) => <SelectInput {...c} value={status()} options={statusOptions()} onChange={tracked(setStatus, flow)} />}
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
            <Field name="policy" label={t("ipam.prefix.alloc")} error={serverFieldMessage(flow.error(), "policy")}>
              {(c) => <SelectInput {...c} value={policy()} options={policyOptions()} onChange={tracked(setPolicy, flow)} />}
            </Field>
          </FieldRow>
        </>
      )}
    </WriteForm>
  );
}
