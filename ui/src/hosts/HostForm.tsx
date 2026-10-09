// Host and interface forms. A new host may get its first interface right away; MAC
// addresses are accepted with any separator and sent in the API's form (lowercase, colon
// separated), DUIDs as hexadecimal. Every save previews its plan first (PlanDialog), so the
// IPAM-18 warning (a reserved host without MAC or DUID) shows before anything changes.
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../api/client";
import { fetchAll } from "../api/paginate";
import type { AssignmentMode, CustomValue, Host, HostInput, HostPatch, Interface, InterfacePatch, Site, Tenant } from "../api/types";
import { ASSIGNMENT_MODES } from "../api/types";
import { Dialog } from "../components/Dialog";
import { t } from "../i18n";
import { CustomFieldsEditor, TagsInput } from "../ipam/fields/CustomFieldsEditor";
import { writeQuery } from "../ipam/plan/describe";
import { PlanDialog, useWriteToast, type SendOptions } from "../ipam/plan/PlanDialog";
import { modeHint, modeWord } from "../ipam/words";
import "../ipam/forms.css";

/** A documentation MAC (RFC 7042) as the example in the MAC field. */
const MAC_EXAMPLE = "00:00:5e:00:53:01";

/** `00-00-5E-00-53-01`, `0000.5e00.5301` or `00005e005301` as `00:00:5e:00:53:01`; null when not a MAC. */
export function normalizeMac(text: string): string | null {
  const hex = text.trim().replace(/[-:.\s]/g, "").toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(hex)) return null;
  return hex.match(/.{2}/g)!.join(":");
}

/** A DUID as lowercase hexadecimal (separators dropped); null when it is not one (2 to 130 bytes). */
export function normalizeDuid(text: string): string | null {
  const hex = text.trim().replace(/[-:.\s]/g, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0 || hex.length < 4 || hex.length > 260) return null;
  return hex;
}

function sameList(a: readonly string[] | null | undefined, b: readonly string[] | null | undefined): boolean {
  return JSON.stringify(a ?? []) === JSON.stringify(b ?? []);
}

// ---------------------------------------------------------------------------------
// Host

export function HostForm(props: { host?: Host; onDone: (host: Host) => void; onClose: () => void }) {
  const writeToast = useWriteToast();
  const host = untrack(() => props.host);
  const [name, setName] = createSignal(host?.name ?? "");
  const [mode, setMode] = createSignal<AssignmentMode>(host?.mode ?? "reserved");
  const [lock, setLock] = createSignal(host?.lock ?? false);
  const [site, setSite] = createSignal(host?.site ?? "");
  const [tenant, setTenant] = createSignal(host?.tenant ?? "");
  const [description, setDescription] = createSignal(host?.meta.description ?? "");
  const [tags, setTags] = createSignal<string[]>([...(host?.meta.tags ?? [])]);
  const [custom, setCustom] = createSignal<Record<string, CustomValue>>({ ...(host?.meta.custom ?? {}) });
  const [iface, setIface] = createSignal("eth0");
  const [mac, setMac] = createSignal("");
  const [duid, setDuid] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [planning, setPlanning] = createSignal(false);

  const [lists] = createResource(async () => {
    const [sites, tenants] = await Promise.all([fetchAll<Site>("/api/v1/sites"), fetchAll<Tenant>("/api/v1/tenants")]);
    return { sites: sites.items, tenants: tenants.items };
  });

  const validate = (): boolean => {
    const e: Record<string, string> = {};
    if (!/^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(name().trim())) {
      e.name = t("hosts.form.name_invalid");
    }
    if (!host && mac().trim() && !normalizeMac(mac())) e.mac = t("hosts.form.mac_invalid");
    if (!host && duid().trim() && !normalizeDuid(duid())) e.duid = t("hosts.form.duid_invalid");
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const send = (o: SendOptions) => {
    if (!host) {
      const body: HostInput = {
        name: name().trim(),
        mode: mode(),
        lock: lock(),
        site: site() || null,
        tenant: tenant() || null,
        description: description().trim() || null,
        tags: tags(),
        custom: custom(),
        interfaces: iface().trim()
          ? [{ name: iface().trim(), mac: normalizeMac(mac()) ?? null, duid: normalizeDuid(duid()) ?? null }]
          : [],
      };
      return api.post("/api/v1/hosts", { query: writeQuery(o.dryRun, o.acknowledge), body });
    }
    const patch: HostPatch = {};
    if (name().trim() !== host.name) patch.name = name().trim();
    if (mode() !== host.mode) patch.mode = mode();
    if (lock() !== (host.lock ?? false)) patch.lock = lock();
    if ((site() || null) !== (host.site ?? null)) patch.site = site() || null;
    if ((description().trim() || null) !== (host.meta.description ?? null)) patch.description = description().trim() || null;
    if (!sameList(tags(), host.meta.tags)) patch.tags = tags();
    if (JSON.stringify(custom()) !== JSON.stringify(host.meta.custom ?? {})) patch.custom = custom();
    return api.patch("/api/v1/hosts/{id}", {
      path: { id: host.id },
      query: writeQuery(o.dryRun, o.acknowledge),
      body: patch,
      ifMatch: host.meta.revision,
    });
  };

  const title = () => (host ? t("hosts.form.edit_title", { name: host.name }) : t("hosts.form.create_title"));

  return (
    <Show
      when={planning()}
      fallback={
        <Dialog label={title()} onClose={props.onClose} class="dialog form-dialog">
          <form
            class="form"
            data-testid="dialog-host-form"
            novalidate
            onSubmit={(e) => {
              e.preventDefault();
              if (validate()) setPlanning(true);
            }}
          >
            <h2 class="dialog-title">{title()}</h2>
            <div class="field">
              <label for="host-name">{t("ipam.col.name")}</label>
              <input
                id="host-name"
                class="input"
                value={name()}
                spellcheck={false}
                aria-invalid={errors().name ? "true" : undefined}
                aria-describedby={errors().name ? "host-name-error" : undefined}
                data-testid="field-name"
                onInput={(e) => setName(e.currentTarget.value)}
              />
              <Show when={errors().name}>
                <span class="help bad" id="host-name-error">
                  {errors().name}
                </span>
              </Show>
            </div>
            <fieldset class="field mode-choice">
              <legend class="label">{t("ipam.col.mode")}</legend>
              <For each={ASSIGNMENT_MODES}>
                {(m) => (
                  <label class="radio-row">
                    <input type="radio" name="host-mode" value={m} checked={mode() === m} onChange={() => setMode(m)} />
                    <span class={`mode ${m}`}>{modeWord(m)}</span>
                    <span class="muted">{modeHint(m)}</span>
                  </label>
                )}
              </For>
            </fieldset>
            <label class="ackrow">
              <input type="checkbox" class="cb" checked={lock()} onChange={(e) => setLock(e.currentTarget.checked)} />
              {t("hosts.form.lock")}
            </label>
            <div class="form-cols">
              <div class="field">
                <label for="host-site">{t("ipam.col.site")}</label>
                <select id="host-site" class="select" value={site()} onChange={(e) => setSite(e.currentTarget.value)}>
                  <option value="">{t("hosts.form.none")}</option>
                  <For each={lists()?.sites ?? []}>{(s) => <option value={s.id}>{s.name}</option>}</For>
                </select>
              </div>
              <Show when={!host}>
                <div class="field">
                  <label for="host-tenant">{t("ipam.col.tenant")}</label>
                  <select id="host-tenant" class="select" value={tenant()} onChange={(e) => setTenant(e.currentTarget.value)}>
                    <option value="">{t("hosts.form.default_tenant")}</option>
                    <For each={lists()?.tenants ?? []}>{(tn) => <option value={tn.id}>{tn.name}</option>}</For>
                  </select>
                </div>
              </Show>
            </div>
            <div class="field">
              <label for="host-description">{t("ipam.col.description")}</label>
              <input id="host-description" class="input" value={description()} onInput={(e) => setDescription(e.currentTarget.value)} />
            </div>
            <Show when={!host}>
              <fieldset class="field">
                <legend class="label">{t("hosts.form.first_interface")}</legend>
                <div class="form-cols three">
                  <div class="field">
                    <label for="host-iface">{t("hosts.col.interface")}</label>
                    <input id="host-iface" class="input mono" value={iface()} onInput={(e) => setIface(e.currentTarget.value)} />
                  </div>
                  <div class="field">
                    <label for="host-mac">{t("ipam.col.mac")}</label>
                    <input
                      id="host-mac"
                      class="input mono"
                      value={mac()}
                      placeholder={MAC_EXAMPLE}
                      aria-invalid={errors().mac ? "true" : undefined}
                      data-testid="field-mac"
                      onInput={(e) => setMac(e.currentTarget.value)}
                    />
                    <Show when={errors().mac}>
                      <span class="help bad">{errors().mac}</span>
                    </Show>
                  </div>
                  <div class="field">
                    <label for="host-duid">{t("hosts.col.duid")}</label>
                    <input
                      id="host-duid"
                      class="input mono"
                      value={duid()}
                      aria-invalid={errors().duid ? "true" : undefined}
                      onInput={(e) => setDuid(e.currentTarget.value)}
                    />
                    <Show when={errors().duid}>
                      <span class="help bad">{errors().duid}</span>
                    </Show>
                  </div>
                </div>
              </fieldset>
            </Show>
            <TagsInput label={t("ipam.col.tags")} value={tags()} onChange={setTags} />
            <CustomFieldsEditor kind="host" values={custom()} onChange={setCustom} />
            <div class="dialog-actions">
              <button type="button" class="btn ghost" onClick={() => props.onClose()}>
                {t("common.action.cancel")}
              </button>
              <button type="submit" class="btn primary" data-testid="form-submit">
                {host ? t("hosts.form.save") : t("hosts.form.create")}
              </button>
            </div>
          </form>
        </Dialog>
      }
    >
      <PlanDialog
        title={title()}
        confirmLabel={host ? t("hosts.form.save") : t("hosts.form.create")}
        send={send}
        onClose={() => setPlanning(false)}
        onDone={(r) => {
          const item = r.item as Host | null | undefined;
          writeToast(host ? t("hosts.form.saved", { name: name().trim() }) : t("hosts.form.created", { name: name().trim() }), r);
          if (item) props.onDone(item);
          else props.onClose();
        }}
      />
    </Show>
  );
}

// ---------------------------------------------------------------------------------
// Interface

export function InterfaceForm(props: { host: Host; iface?: Interface; onDone: () => void; onClose: () => void }) {
  const writeToast = useWriteToast();
  const iface = untrack(() => props.iface);
  const [name, setName] = createSignal(iface?.name ?? "");
  const [mac, setMac] = createSignal(iface?.mac ?? "");
  const [duid, setDuid] = createSignal(iface?.duid ?? "");
  const [clientId, setClientId] = createSignal(iface?.client_id ?? "");
  const [description, setDescription] = createSignal(iface?.meta.description ?? "");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [planning, setPlanning] = createSignal(false);

  const validate = () => {
    const e: Record<string, string> = {};
    if (!name().trim()) e.name = t("hosts.form.iface_name_required");
    if (mac().trim() && !normalizeMac(mac())) e.mac = t("hosts.form.mac_invalid");
    if (duid().trim() && !normalizeDuid(duid())) e.duid = t("hosts.form.duid_invalid");
    if (clientId().trim() && !/^[0-9a-f]+$/i.test(clientId().replace(/[-:.\s]/g, ""))) e.client_id = t("hosts.form.hex_invalid");
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const send = (o: SendOptions) => {
    const m = normalizeMac(mac());
    const d = normalizeDuid(duid());
    const c = clientId().trim() ? clientId().replace(/[-:.\s]/g, "").toLowerCase() : null;
    if (!iface) {
      return api.post("/api/v1/hosts/{id}/interfaces", {
        path: { id: props.host.id },
        query: writeQuery(o.dryRun, o.acknowledge),
        body: { name: name().trim(), mac: m, duid: d, client_id: c, description: description().trim() || null },
      });
    }
    const patch: InterfacePatch = {};
    if (name().trim() !== iface.name) patch.name = name().trim();
    if (m !== (iface.mac ?? null)) patch.mac = m;
    if (d !== (iface.duid ?? null)) patch.duid = d;
    if (c !== (iface.client_id ?? null)) patch.client_id = c;
    if ((description().trim() || null) !== (iface.meta.description ?? null)) patch.description = description().trim() || null;
    return api.patch("/api/v1/interfaces/{id}", {
      path: { id: iface.id },
      query: writeQuery(o.dryRun, o.acknowledge),
      body: patch,
      ifMatch: iface.meta.revision,
    });
  };

  const title = () =>
    iface ? t("hosts.form.iface_edit_title", { name: iface.name, host: props.host.name }) : t("hosts.form.iface_create_title", { host: props.host.name });

  const field = (id: string, label: string, value: () => string, set: (v: string) => void, mono = true) => (
    <div class="field">
      <label for={`iface-${id}`}>{label}</label>
      <input
        id={`iface-${id}`}
        class={mono ? "input mono" : "input"}
        value={value()}
        spellcheck={false}
        aria-invalid={errors()[id] ? "true" : undefined}
        data-testid={`field-${id}`}
        onInput={(e) => set(e.currentTarget.value)}
      />
      <Show when={errors()[id]}>
        <span class="help bad">{errors()[id]}</span>
      </Show>
    </div>
  );

  return (
    <Show
      when={planning()}
      fallback={
        <Dialog label={title()} onClose={props.onClose} class="dialog form-dialog">
          <form
            class="form"
            data-testid="dialog-interface-form"
            novalidate
            onSubmit={(e) => {
              e.preventDefault();
              if (validate()) setPlanning(true);
            }}
          >
            <h2 class="dialog-title">{title()}</h2>
            {field("name", t("hosts.col.interface"), name, setName)}
            <div class="form-cols">
              {field("mac", t("ipam.col.mac"), mac, setMac)}
              {field("duid", t("hosts.col.duid"), duid, setDuid)}
            </div>
            {field("client_id", t("hosts.col.client_id"), clientId, setClientId)}
            {field("description", t("ipam.col.description"), description, setDescription, false)}
            <div class="dialog-actions">
              <button type="button" class="btn ghost" onClick={() => props.onClose()}>
                {t("common.action.cancel")}
              </button>
              <button type="submit" class="btn primary" data-testid="form-submit">
                {iface ? t("hosts.form.save") : t("hosts.form.iface_create")}
              </button>
            </div>
          </form>
        </Dialog>
      }
    >
      <PlanDialog
        title={title()}
        confirmLabel={iface ? t("hosts.form.save") : t("hosts.form.iface_create")}
        send={send}
        onClose={() => setPlanning(false)}
        onDone={(r) => {
          writeToast(t("hosts.form.iface_saved", { name: name().trim(), host: props.host.name }), r);
          props.onDone();
        }}
      />
    </Show>
  );
}
