// The dialogs of the zone list: create a zone (name, kind, SOA names, name servers, serial
// policy, the primaries of a secondary or stub zone) and delete one with its records. The form
// checks the names before it sends; the server's refusals land on the field they name.
import { createMemo, createSignal, For, Show } from "solid-js";
import { ApiError } from "../api/problem";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatNumber, t } from "../i18n";
import { createZone, deleteZone, SERIAL_POLICIES, ZONE_KINDS, type SerialPolicy, type Zone, type ZoneCreate, type ZoneKind } from "./api";
import { canonical, defaultSoa, parseTtl, splitList, validName } from "./model";
import { describedBy, Field, fieldErrors, kindWord } from "./Parts";

function policyWord(policy: SerialPolicy): string {
  return t(`dns.serial.${policy}`);
}

export function CreateZoneDialog(props: { onClose: () => void; onDone: (zone: Zone) => void }) {
  let nameInput!: HTMLInputElement;
  const [name, setName] = createSignal("");
  const [kind, setKind] = createSignal<ZoneKind>("primary");
  const [mname, setMname] = createSignal<string | null>(null);
  const [rname, setRname] = createSignal<string | null>(null);
  const [servers, setServers] = createSignal("");
  const [policy, setPolicy] = createSignal<SerialPolicy>("date_counter");
  const [ttl, setTtl] = createSignal("3600");
  const [primaries, setPrimaries] = createSignal("");
  const [description, setDescription] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const zoneName = () => canonical(name());
  // The SOA names follow the zone name until the person types their own.
  const soa = createMemo(() => {
    const d = defaultSoa(zoneName() || "example.test");
    return { mname: mname() ?? d.mname, rname: rname() ?? d.rname };
  });
  const needsPrimaries = () => kind() === "secondary" || kind() === "stub";

  const validate = (): boolean => {
    const e: Record<string, string> = {};
    if (!validName(zoneName()) || zoneName() === ".") e.name = t("dns.check.name");
    // SOA names that follow a broken zone name are not a second mistake.
    if ((mname() !== null || !e.name) && !validName(canonical(soa().mname))) e["soa.mname"] = t("dns.check.name");
    if ((rname() !== null || !e.name) && !validName(canonical(soa().rname))) e["soa.rname"] = t("dns.check.name");
    if (splitList(servers()).some((s) => !validName(canonical(s)))) e.name_servers = t("dns.check.name");
    if (parseTtl(ttl()) === null) e["soa.ttl"] = t("dns.check.ttl");
    if (needsPrimaries() && splitList(primaries()).length === 0) e.source = t("dns.zone.create.primaries_required");
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy() || !validate()) return;
    setBusy(true);
    setError(undefined);
    const body: ZoneCreate = {
      name: zoneName(),
      kind: kind(),
      serial: policy(),
      soa: { mname: canonical(soa().mname), rname: canonical(soa().rname), ttl: parseTtl(ttl()) ?? 3600 },
      name_servers: splitList(servers()).map(canonical),
      description: description().trim() || null,
      source: needsPrimaries() ? { primaries: splitList(primaries()).map((address) => ({ address })) } : null,
    };
    try {
      const zone = await createZone(body);
      toast({ kind: "ok", title: t("dns.zone.create.done", { name: zone.name }) });
      props.onDone(zone);
    } catch (err) {
      const fields = fieldErrors(err);
      if (Object.keys(fields).length > 0) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const input = (id: string, value: () => string, set: (v: string) => void, mono = true) => (
    <input
      id={`dns-f-${id}`}
      class={mono ? "input mono" : "input"}
      value={value()}
      spellcheck={false}
      aria-invalid={errors()[id] ? "true" : undefined}
      aria-describedby={describedBy(id, errors()[id])}
      data-testid={`field-${id}`}
      onInput={(e) => set(e.currentTarget.value)}
    />
  );

  return (
    <Dialog label={t("dns.zone.create.title")} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-zone-form" initialFocus={() => nameInput}>
      <h2 class="dialog-title">{t("dns.zone.create.title")}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        <Field id="name" label={t("dns.zone.field.name")} error={errors().name} help={t("dns.zone.field.name_help")}>
          <input
            ref={nameInput}
            id="dns-f-name"
            class="input mono"
            value={name()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().name ? "true" : undefined}
            aria-describedby={describedBy("name", errors().name, t("dns.zone.field.name_help"))}
            data-testid="field-name"
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </Field>
        <div class="field-row">
          <Field id="kind" label={t("dns.zone.field.kind")}>
            <select id="dns-f-kind" class="select" value={kind()} data-testid="field-kind" onChange={(e) => setKind(e.currentTarget.value as ZoneKind)}>
              <For each={ZONE_KINDS}>{(k) => <option value={k}>{kindWord(k)}</option>}</For>
            </select>
          </Field>
          <Field id="serial" label={t("dns.zone.field.serial")}>
            <select id="dns-f-serial" class="select" value={policy()} data-testid="field-serial" onChange={(e) => setPolicy(e.currentTarget.value as SerialPolicy)}>
              <For each={SERIAL_POLICIES}>{(p) => <option value={p}>{policyWord(p)}</option>}</For>
            </select>
          </Field>
        </div>
        <Show when={needsPrimaries()}>
          <Field id="source" label={t("dns.zone.field.primaries")} error={errors().source} help={t("dns.zone.field.primaries_help")}>
            {input("source", primaries, setPrimaries)}
          </Field>
        </Show>
        <div class="field-row">
          <Field id="soa.mname" label={t("dns.zone.field.mname")} error={errors()["soa.mname"]}>
            {input("soa.mname", () => soa().mname, setMname)}
          </Field>
          <Field id="soa.rname" label={t("dns.zone.field.rname")} error={errors()["soa.rname"]}>
            {input("soa.rname", () => soa().rname, setRname)}
          </Field>
        </div>
        <div class="field-row">
          <Field id="name_servers" label={t("dns.zone.field.name_servers")} error={errors().name_servers} help={t("dns.zone.field.name_servers_help")}>
            {input("name_servers", servers, setServers)}
          </Field>
          <Field id="soa.ttl" label={t("dns.zone.field.ttl")} error={errors()["soa.ttl"]}>
            {input("soa.ttl", ttl, setTtl)}
          </Field>
        </div>
        <Field id="description" label={t("dns.zone.field.description")}>
          {input("description", description, setDescription, false)}
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dns.zone.create.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function DeleteZoneDialog(props: { zone: Zone; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  const confirm = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await deleteZone(props.zone.id);
      toast({ kind: "ok", title: t("dns.zone.delete.done", { name: props.zone.name }) });
      props.onDone();
    } catch (err) {
      // A zone that is gone already is what the person wanted.
      if (err instanceof ApiError && err.code === "dns.zone.not_found") props.onDone();
      else setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <ConfirmDialog
      title={t("dns.zone.delete.title", { name: props.zone.name })}
      testid="dialog-zone-delete"
      danger
      busy={busy()}
      confirmLabel={t("dns.zone.delete.confirm")}
      cancelLabel={t("common.action.cancel")}
      onConfirm={() => void confirm()}
      onClose={props.onClose}
      body={
        <>
          <p>{t("dns.zone.delete.body", { name: props.zone.name, count: props.zone.rrsets, rrsets: formatNumber(props.zone.rrsets) })}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}
