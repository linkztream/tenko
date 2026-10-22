// The dialogs of a scope: create one for an IPAM network that has none, and delete one (the prefix
// and its ranges stay in IPAM).
import { createMemo, createResource, createSignal, For, Show } from "solid-js";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { parseIp } from "../ipam/ip";
import { createScope, deleteScope, getSettings, listNetworks, listSharedNetworks, type LeaseTimes, type Scope, type ScopeCreate } from "./api";
import { LeaseChoice, leaseProblem } from "./LeaseFields";
import { draftOfLease, isIpv4, leaseOfDraft, type LeaseDraft, type LeaseField } from "./model";
import { Check, describedBy, errorFor, Field, fieldErrors, hasField } from "./Parts";
import { leaseWords } from "./words";
import "./dhcp.css";

const FALLBACK_LEASE: LeaseDraft = draftOfLease({ default_secs: 86_400, min_secs: 3600, max_secs: 604_800 });

/** The tri-state of a setting a scope may leave to the server. */
export type Tri = "inherit" | "true" | "false";

export function triOf(value: boolean | null | undefined): Tri {
  return value === undefined || value === null ? "inherit" : value ? "true" : "false";
}

export function boolOf(value: Tri): boolean | undefined {
  return value === "inherit" ? undefined : value === "true";
}

/** The choice between the server's setting, yes and no; `lock` keeps the server's setting from being chosen again (a scope cannot go back to it). */
export function TriSelect(props: { id: string; label: string; value: Tri; onChange: (v: Tri) => void; lockInherit?: boolean | undefined; disabled?: boolean | undefined; help?: string | undefined }) {
  return (
    <Field id={props.id} label={props.label} help={props.help}>
      <select
        id={`dhcp-f-${props.id}`}
        class="select"
        value={props.value}
        disabled={props.disabled}
        aria-describedby={describedBy(props.id, undefined, props.help)}
        data-testid={`field-${props.id}`}
        onChange={(e) => props.onChange(e.currentTarget.value as Tri)}
      >
        <option value="inherit" disabled={props.lockInherit}>
          {t("dhcp.tri.inherit")}
        </option>
        <option value="true">{t("common.yes")}</option>
        <option value="false">{t("common.no")}</option>
      </select>
    </Field>
  );
}

export function CreateScopeDialog(props: { scopes: readonly Scope[]; onClose: () => void; onDone: (scope: Scope) => void }) {
  let prefixSelect!: HTMLSelectElement;
  const [networks] = createResource(() => listNetworks());
  const [shared] = createResource(() => listSharedNetworks());
  const [settings] = createResource(() => getSettings());
  const [prefix, setPrefix] = createSignal("");
  const [inherit, setInherit] = createSignal(true);
  const [lease, setLease] = createSignal<LeaseDraft>(FALLBACK_LEASE);
  const [authoritative, setAuthoritative] = createSignal<Tri>("inherit");
  const [serverId, setServerId] = createSignal("");
  const [network, setNetwork] = createSignal("");
  const [restricted, setRestricted] = createSignal(false);
  const [description, setDescription] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [leaseErrors, setLeaseErrors] = createSignal<Partial<Record<LeaseField, string>>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  // The networks of IPAM (IPv4) that no scope serves yet.
  const free = createMemo(() => {
    const taken = new Set(props.scopes.map((s) => s.prefix));
    return (networks.latest ?? []).filter((p) => !p.meta.deleted && p.role === "network" && isIpv4(p.cidr) && !taken.has(p.id));
  });
  const serverLease = () => (settings.error ? undefined : settings.latest?.lease);

  const toggleInherit = (on: boolean) => {
    setInherit(on);
    const base = serverLease();
    if (!on && base) setLease(draftOfLease(base));
  };

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    const body: ScopeCreate = { prefix: prefix() };
    if (prefix() === "") e.prefix = t("dhcp.check.prefix");
    if (serverId().trim() !== "") {
      const ip = parseIp(serverId());
      if (!ip || ip.version !== 4) e.server_id = t("dhcp.check.server_id");
      else body.server_id = serverId().trim();
    }
    const le: Partial<Record<LeaseField, string>> = {};
    if (!inherit()) {
      const parsed = leaseOfDraft(lease());
      if (parsed.ok) body.lease = parsed.lease;
      else le[parsed.field] = leaseProblem(parsed.problem);
    }
    setErrors(e);
    setLeaseErrors(le);
    if (Object.keys(e).length > 0 || Object.keys(le).length > 0) return;
    const auth = boolOf(authoritative());
    if (auth !== undefined) body.authoritative = auth;
    if (network() !== "") body.shared_network = network();
    if (restricted()) body.restricted = true;
    if (description().trim() !== "") body.description = description().trim();
    setBusy(true);
    setError(undefined);
    try {
      const scope = await createScope(body);
      toast({ kind: "ok", title: t("dhcp.scope.created", { network: scope.cidr }) });
      props.onDone(scope);
    } catch (err) {
      const fields = fieldErrors(err);
      if (hasField(fields, ["prefix", "server_id"])) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("dhcp.scope.create_title")} onClose={props.onClose} class="dialog wide dhcp-dialog" testid="dialog-scope-form" initialFocus={() => prefixSelect}>
      <h2 class="dialog-title">{t("dhcp.scope.create_title")}</h2>
      <form class="dialog-body dhcp-form" onSubmit={(e) => void submit(e)} novalidate>
        <Field id="prefix" label={t("dhcp.scope.field.prefix")} error={errors().prefix} help={t("dhcp.scope.field.prefix_help")}>
          <select
            ref={prefixSelect}
            id="dhcp-f-prefix"
            class="select"
            value={prefix()}
            aria-invalid={errors().prefix ? "true" : undefined}
            aria-describedby={describedBy("prefix", errors().prefix, "help")}
            data-testid="field-prefix"
            onChange={(e) => setPrefix(e.currentTarget.value)}
          >
            <option value="">{t("dhcp.scope.field.prefix_pick")}</option>
            <For each={free()}>{(p) => <option value={p.id}>{p.meta.description ? `${p.cidr} ${p.meta.description}` : p.cidr}</option>}</For>
          </select>
        </Field>
        <LeaseChoice
          id="lease"
          inherit={inherit()}
          onInherit={toggleInherit}
          value={lease()}
          onChange={setLease}
          errors={leaseErrors()}
          serverWords={inherit() && serverLease() ? t("dhcp.lease.server_now", { lease: leaseWords(serverLease() as LeaseTimes) }) : undefined}
        />
        <TriSelect id="authoritative" label={t("dhcp.scope.field.authoritative")} value={authoritative()} onChange={setAuthoritative} />
        <Field id="server_id" label={t("dhcp.scope.field.server_id")} error={errorFor(errors(), "server_id")} help={t("dhcp.scope.field.server_id_help")}>
          <input
            id="dhcp-f-server_id"
            class="input mono"
            value={serverId()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().server_id ? "true" : undefined}
            aria-describedby={describedBy("server_id", errors().server_id, "help")}
            data-testid="field-server_id"
            onInput={(e) => setServerId(e.currentTarget.value)}
          />
        </Field>
        <Field id="shared_network" label={t("dhcp.scope.field.shared_network")}>
          <select id="dhcp-f-shared_network" class="select" value={network()} data-testid="field-shared_network" onChange={(e) => setNetwork(e.currentTarget.value)}>
            <option value="">{t("dhcp.scope.shared_none")}</option>
            <For each={shared.error ? [] : (shared.latest?.items ?? [])}>{(n) => <option value={n.id}>{n.name}</option>}</For>
          </select>
        </Field>
        <Check id="restricted" label={t("dhcp.scope.field.restricted")} checked={restricted()} onChange={setRestricted} help={t("dhcp.scope.field.restricted_help")} />
        <Field id="description" label={t("dhcp.field.description")}>
          <input id="dhcp-f-description" class="input" value={description()} data-testid="field-description" onInput={(e) => setDescription(e.currentTarget.value)} />
        </Field>
        <Show when={!networks.loading && free().length === 0}>
          <p class="muted" data-testid="scope-no-networks">
            {t("dhcp.scope.no_networks")}
          </p>
        </Show>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dhcp.scope.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function DeleteScopeDialog(props: { scope: Scope; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dhcp.scope.delete_title", { network: props.scope.cidr })}
      testid="dialog-scope-delete"
      danger
      busy={busy()}
      confirmLabel={t("dhcp.scope.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteScope(props.scope)
          .then(() => {
            toast({ kind: "ok", title: t("dhcp.scope.deleted", { network: props.scope.cidr }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dhcp.scope.delete_body", { network: props.scope.cidr })}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}
