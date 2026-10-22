// The fields of DDNS settings (docs/dhcp.md, section 13.1) as a controlled fieldset over a draft:
// on or off, the forward zone from the DNS zones Tenko serves, PTR records, the TTL, name
// protection, the client's own A record, legacy clients and names outside the zone. The scope's
// DDNS tab and the DDNS action of a policy use it. It says what the security profile does: a
// zone's rule for DHCP updates, and that Hardened treats Replace as Protect.
import { createEffect, createResource, For, Show } from "solid-js";
import { session } from "../../auth/session";
import { Notice } from "../../components/Notice";
import { listZones, type Zone } from "../../dns/api";
import { t } from "../../i18n";
import { Check, describedBy, Field } from "../Parts";
import { draftOfDdns, isForwardZone, profileOpensZones, zoneTakesDhcp, type DdnsDraft, type DdnsField, type Profile } from "./model";
import "./ddns.css";

/** The forward zones Tenko serves, or why they are not known. */
export interface ZoneChoices {
  state: "loading" | "ready" | "unavailable";
  zones: readonly Zone[];
}

/** Reads the DNS zones once. A DNS module that is off, or a role that may not read zones, gives `unavailable`. */
export function createZoneChoices(): () => ZoneChoices {
  const [zones] = createResource(async () => (await listZones()).items);
  return () => {
    if (zones.error) return { state: "unavailable", zones: [] };
    if (zones.latest === undefined) return { state: "loading", zones: [] };
    return { state: "ready", zones: zones.latest.filter(isForwardZone).sort((a, b) => a.name.localeCompare(b.name)) };
  };
}

/** The security profile in force. */
export function currentProfile(): Profile {
  return (session()?.profile ?? "home") as Profile;
}

/** The name of a zone for words; the identifier of a zone that is not in the list. */
export function zoneNameIn(choices: ZoneChoices): (id: string) => string | undefined {
  return (id) => choices.zones.find((z) => z.id === id)?.name;
}

const CONFLICTS = ["protect", "replace"] as const;

export function DdnsFields(props: {
  value: DdnsDraft;
  onChange: (next: DdnsDraft) => void;
  zones: () => ZoneChoices;
  disabled?: boolean | undefined;
  errors?: Partial<Record<DdnsField, string>> | undefined;
}) {
  let zoneSelect!: HTMLSelectElement;
  const set = (patch: Partial<DdnsDraft>) => props.onChange({ ...props.value, ...patch });
  // The zones arrive after the menu is built: choose again once the entries are there.
  createEffect(() => {
    props.zones();
    zoneSelect.value = props.value.zone;
  });
  const profile = currentProfile;
  const profileName = () => t(`profile.${profile()}.name`);
  const chosen = () => props.zones().zones.find((z) => z.id === props.value.zone);
  const zoneError = () => props.errors?.forward_zone;
  const ttlError = () => props.errors?.ttl;
  return (
    <fieldset class="dhcp-ddns" data-testid="ddns-fields">
      <legend>{t("dhcp.ddns.legend")}</legend>
      <Check id="ddns-enabled" label={t("dhcp.ddns.field.enabled")} checked={props.value.enabled} disabled={props.disabled} onChange={(on) => set({ enabled: on })} />
      <Field id="ddns-zone" label={t("dhcp.ddns.field.zone")} error={zoneError()}>
        <select
          ref={zoneSelect}
          id="dhcp-f-ddns-zone"
          class="select"
          value={props.value.zone}
          disabled={props.disabled || props.zones().state === "unavailable"}
          aria-invalid={zoneError() ? "true" : undefined}
          aria-describedby={describedBy("ddns-zone", zoneError())}
          data-testid="field-ddns-zone"
          onChange={(e) => set({ zone: e.currentTarget.value })}
        >
          <option value="">{t("dhcp.ddns.zone_none")}</option>
          <Show when={props.value.zone !== "" && !chosen()}>
            <option value={props.value.zone}>{t("dhcp.ddns.zone_unknown", { id: props.value.zone })}</option>
          </Show>
          <For each={props.zones().zones}>{(z) => <option value={z.id}>{z.name}</option>}</For>
        </select>
        <Show when={props.zones().state === "unavailable"}>
          <span class="help" data-testid="ddns-zones-unavailable">
            {t("dhcp.ddns.zone_unavailable")}
          </span>
        </Show>
        <Show when={chosen()}>
          {(zone) => {
            const state = () => zoneTakesDhcp(zone().update, profile());
            return (
              <span class="help" data-testid="ddns-zone-state" data-key={state()}>
                {t(`dhcp.ddns.zone_state.${state()}`, { profile: profileName() })}
              </span>
            );
          }}
        </Show>
      </Field>
      <Check id="ddns-reverse" label={t("dhcp.ddns.field.reverse")} checked={props.value.reverse} disabled={props.disabled} onChange={(on) => set({ reverse: on })} help={t("dhcp.ddns.field.reverse_help")} />
      <Field id="ddns-ttl" label={t("dhcp.ddns.field.ttl")} error={ttlError()} help={t("dhcp.ddns.field.ttl_help")}>
        <input
          id="dhcp-f-ddns-ttl"
          class="input mono"
          inputmode="numeric"
          value={props.value.ttl}
          disabled={props.disabled}
          aria-invalid={ttlError() ? "true" : undefined}
          aria-describedby={describedBy("ddns-ttl", ttlError(), "help")}
          data-testid="field-ddns-ttl"
          onInput={(e) => set({ ttl: e.currentTarget.value })}
        />
      </Field>
      <Field id="ddns-conflict" label={t("dhcp.ddns.field.conflict")} error={props.errors?.conflict}>
        <select
          id="dhcp-f-ddns-conflict"
          class="select"
          value={props.value.conflict}
          disabled={props.disabled}
          aria-invalid={props.errors?.conflict ? "true" : undefined}
          aria-describedby={describedBy("ddns-conflict", props.errors?.conflict)}
          data-testid="field-ddns-conflict"
          onChange={(e) => set({ conflict: e.currentTarget.value as DdnsDraft["conflict"] })}
        >
          <For each={CONFLICTS}>{(c) => <option value={c}>{t(`dhcp.ddns.conflict.${c}`)}</option>}</For>
        </select>
      </Field>
      <Show when={profile() === "hardened" && props.value.conflict === "replace"}>
        <Notice kind="info" testid="ddns-hardened-note">
          {t("dhcp.ddns.hardened_note", { profile: profileName() })}
        </Notice>
      </Show>
      <Check
        id="ddns-client-a"
        label={t("dhcp.ddns.field.client_a")}
        checked={props.value.clientMayUpdateA}
        disabled={props.disabled}
        onChange={(on) => set({ clientMayUpdateA: on })}
        help={t("dhcp.ddns.field.client_a_help")}
      />
      <Check
        id="ddns-legacy"
        label={t("dhcp.ddns.field.legacy")}
        checked={props.value.legacyClients}
        disabled={props.disabled}
        onChange={(on) => set({ legacyClients: on })}
        help={t("dhcp.ddns.field.legacy_help")}
      />
      <Check
        id="ddns-foreign"
        label={t("dhcp.ddns.field.foreign")}
        checked={props.value.refuseForeign}
        disabled={props.disabled}
        onChange={(on) => set({ refuseForeign: on })}
        help={t("dhcp.ddns.field.foreign_help")}
      />
      <p class="help" data-testid="ddns-profile" data-key={profile()}>
        {profileOpensZones(profile()) ? t("dhcp.ddns.profile_open", { profile: profileName() }) : t("dhcp.ddns.profile_strict", { profile: profileName() })}
      </p>
    </fieldset>
  );
}

/** The draft for a policy's DDNS action that starts from the server's settings and turns DDNS on. */
export function startingDraft(server: Parameters<typeof draftOfDdns>[0]): DdnsDraft {
  return { ...draftOfDdns(server), enabled: true };
}
