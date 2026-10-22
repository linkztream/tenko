// The lease times of a scope, a pool, a policy and the server, edited in minutes, hours or days and
// sent in seconds. `LeaseFields` is the three values; `LeaseChoice` adds the switch "use the server's
// lease times" that a scope, a pool and a policy have.
import { For, Show } from "solid-js";
import { t } from "../i18n";
import { LEASE_UNITS, type LeaseDraft, type LeaseField, type LeaseProblem, type LeaseUnit } from "./model";
import { Check, describedBy } from "./Parts";

const FIELDS: readonly LeaseField[] = ["min", "default", "max"];

/** The translated message of a local lease check. */
export function leaseProblem(problem: LeaseProblem): string {
  return t(`dhcp.check.lease_${problem}`);
}

export function LeaseFields(props: {
  /** Base of the field ids and test ids (`lease` gives `field-lease-default`). */
  id: string;
  value: LeaseDraft;
  onChange: (next: LeaseDraft) => void;
  disabled?: boolean | undefined;
  errors?: Partial<Record<LeaseField, string>> | undefined;
}) {
  const set = (field: LeaseField, patch: Partial<LeaseDraft[LeaseField]>) => props.onChange({ ...props.value, [field]: { ...props.value[field], ...patch } });
  return (
    <fieldset class="dhcp-lease" data-testid={`${props.id}-fields`}>
      <legend>{t("dhcp.lease.legend")}</legend>
      <For each={FIELDS}>
        {(field) => {
          const id = `${props.id}-${field}`;
          const error = () => props.errors?.[field];
          return (
            <div class="field">
              <label for={`dhcp-f-${id}`}>{t(`dhcp.lease.${field}`)}</label>
              <span class="dhcp-span">
                <input
                  id={`dhcp-f-${id}`}
                  class="input"
                  inputmode="decimal"
                  value={props.value[field].value}
                  disabled={props.disabled}
                  aria-invalid={error() ? "true" : undefined}
                  aria-describedby={describedBy(id, error())}
                  data-testid={`field-${id}`}
                  onInput={(e) => set(field, { value: e.currentTarget.value })}
                />
                <select
                  class="select"
                  aria-label={t("dhcp.lease.unit", { name: t(`dhcp.lease.${field}`) })}
                  value={props.value[field].unit}
                  disabled={props.disabled}
                  data-testid={`field-${id}-unit`}
                  onChange={(e) => set(field, { unit: e.currentTarget.value as LeaseUnit })}
                >
                  <For each={LEASE_UNITS}>{(unit) => <option value={unit}>{t(`dhcp.unit.${unit}`)}</option>}</For>
                </select>
              </span>
              <Show when={error()}>
                <span class="help bad" id={`dhcp-f-${id}-error`} data-testid="field-error" data-field={id}>
                  {error()}
                </span>
              </Show>
            </div>
          );
        }}
      </For>
    </fieldset>
  );
}

/** "Use the server's lease times", and the three values while it is off. */
export function LeaseChoice(props: {
  id: string;
  inherit: boolean;
  onInherit: (on: boolean) => void;
  value: LeaseDraft;
  onChange: (next: LeaseDraft) => void;
  disabled?: boolean | undefined;
  errors?: Partial<Record<LeaseField, string>> | undefined;
  /** What "the server's" is now, in words. */
  serverWords?: string | undefined;
}) {
  return (
    <>
      <Check id={`${props.id}-inherit`} label={t("dhcp.lease.inherit")} checked={props.inherit} disabled={props.disabled} onChange={props.onInherit} help={props.serverWords} />
      <Show when={!props.inherit}>
        <LeaseFields id={props.id} value={props.value} onChange={props.onChange} disabled={props.disabled} errors={props.errors} />
      </Show>
    </>
  );
}
