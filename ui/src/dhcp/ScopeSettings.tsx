// The settings tab of a scope: enabled, the lease times with "use the server's", authoritative,
// the server identifier, the shared network, restricted, the classes the scope admits and the
// description, saved with the scope's revision; DDNS as read-only text; and how full the scope is.
// Only what changed is sent. The server cannot take back an authoritative setting or a server
// identifier once the scope has one, so the form does not offer to.
import { A } from "@solidjs/router";
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../api/live";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatDateTime, formatNumber, t } from "../i18n";
import { parseIp } from "../ipam/ip";
import { mayWriteDhcp } from "./access";
import { getSettings, getUtilization, listClasses, listSharedNetworks, updateScope, type Scope, type ScopePatch } from "./api";
import { LeaseChoice, leaseProblem } from "./LeaseFields";
import { draftOfLease, leaseOfDraft, percentOf, sameLease, type LeaseDraft, type LeaseField } from "./model";
import { Check, describedBy, errorFor, Field, fieldErrors, hasField } from "./Parts";
import { dhcpPaths } from "./paths";
import { boolOf, triOf, TriSelect, type Tri } from "./ScopeDialogs";
import { NIL_ID } from "./types";
import { leaseWords } from "./words";

const SERVER_LEASE = { default_secs: 86_400, min_secs: 3600, max_secs: 604_800 };

function Utilization(props: { prefix: string }) {
  const query = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => ({ value: await getUtilization(props.prefix, signal) }),
  });
  const figures = () => latest(query);
  return (
    <section class="page-section" aria-labelledby="dhcp-util-title" data-testid="scope-utilization">
      <h2 id="dhcp-util-title">{t("dhcp.util.title")}</h2>
      <Show when={figures()} fallback={<ErrorNotice error={query.value.error} />}>
        {(u) => (
          <>
            <dl class="kv dhcp-kv">
              <For each={[["pool_size", u().pool_size], ["leased", u().leased], ["reserved", u().reserved], ["abandoned", u().abandoned], ["free", u().free]] as const}>
                {([key, value]) => (
                  <>
                    <dt>{t(`dhcp.util.${key}`)}</dt>
                    <dd class="num" data-testid={`util-${key}`} data-value={String(value)}>
                      {formatNumber(value)}
                    </dd>
                  </>
                )}
              </For>
              <dt>{t("dhcp.util.percent")}</dt>
              <dd class="num" data-testid="util-percent" data-value={String(percentOf(u().utilization))}>
                {formatNumber(u().utilization, { style: "percent" })}
              </dd>
            </dl>
            <p class="muted">{t("dhcp.util.at", { time: formatDateTime(u().at) })}</p>
          </>
        )}
      </Show>
    </section>
  );
}

export function SettingsTab(props: { scope: Scope; onSaved: (scope: Scope) => void }) {
  const initial = untrack(() => props.scope);
  const writable = () => mayWriteDhcp();
  const [shared] = createResource(() => listSharedNetworks());
  const [classes] = createResource(() => listClasses());
  const [settings] = createResource(() => getSettings());
  const serverLease = () => (settings.error ? SERVER_LEASE : (settings.latest?.lease ?? SERVER_LEASE));

  const [enabled, setEnabled] = createSignal(initial.enabled ?? true);
  const [inherit, setInherit] = createSignal(!initial.lease);
  const [lease, setLease] = createSignal<LeaseDraft>(draftOfLease(initial.lease ?? serverLease()));
  const [authoritative, setAuthoritative] = createSignal<Tri>(triOf(initial.authoritative));
  const [serverId, setServerId] = createSignal(initial.server_id ?? "");
  const [network, setNetwork] = createSignal(initial.shared_network ?? "");
  const [restricted, setRestricted] = createSignal(initial.restricted ?? false);
  const [admitted, setAdmitted] = createSignal<string[]>([...(initial.classes ?? [])]);
  const [description, setDescription] = createSignal(initial.description ?? "");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [leaseErrors, setLeaseErrors] = createSignal<Partial<Record<LeaseField, string>>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const toggleInherit = (on: boolean) => {
    setInherit(on);
    if (!on && !props.scope.lease) setLease(draftOfLease(serverLease()));
  };
  const toggleClass = (id: string, on: boolean) => setAdmitted((list) => (on ? [...list, id] : list.filter((x) => x !== id)));

  const save = async (event: Event) => {
    event.preventDefault();
    if (busy() || !writable()) return;
    const scope = props.scope;
    const e: Record<string, string> = {};
    const le: Partial<Record<LeaseField, string>> = {};
    const patch: ScopePatch = {};
    if (enabled() !== (scope.enabled ?? true)) patch.enabled = enabled();
    if (inherit()) {
      if (scope.lease) patch.clear_lease = true;
    } else {
      const parsed = leaseOfDraft(lease(), scope.lease);
      if (!parsed.ok) le[parsed.field] = leaseProblem(parsed.problem);
      else if (!sameLease(parsed.lease, scope.lease)) patch.lease = parsed.lease;
    }
    const auth = boolOf(authoritative());
    if (auth !== undefined && auth !== scope.authoritative) patch.authoritative = auth;
    const id = serverId().trim();
    if (id !== (scope.server_id ?? "")) {
      const ip = parseIp(id);
      if (id === "") e.server_id = t("dhcp.check.server_id_clear");
      else if (!ip || ip.version !== 4) e.server_id = t("dhcp.check.server_id");
      else patch.server_id = id;
    }
    if (network() !== (scope.shared_network ?? "")) patch.shared_network = network() === "" ? NIL_ID : network();
    if (restricted() !== (scope.restricted ?? false)) patch.restricted = restricted();
    const was = [...(scope.classes ?? [])].sort().join(",");
    if ([...admitted()].sort().join(",") !== was) patch.classes = admitted();
    if (description().trim() !== (scope.description ?? "")) patch.description = description().trim();
    setErrors(e);
    setLeaseErrors(le);
    setError(undefined);
    if (Object.keys(e).length > 0 || Object.keys(le).length > 0) return;
    if (Object.keys(patch).length === 0) {
      toast({ kind: "info", title: t("dhcp.scope.unchanged") });
      return;
    }
    setBusy(true);
    try {
      const next = await updateScope(scope, patch);
      toast({ kind: "ok", title: t("dhcp.scope.saved", { network: next.cidr }) });
      props.onSaved(next);
    } catch (err) {
      const fields = fieldErrors(err);
      if (hasField(fields, ["server_id", "shared_network", "description", "lease"])) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const lockedAuth = () => props.scope.authoritative !== undefined && props.scope.authoritative !== null;
  return (
    <>
      <form class="page-body dhcp-form" data-testid="scope-settings" onSubmit={(ev) => void save(ev)} novalidate>
        <section class="page-section" aria-labelledby="dhcp-scope-title">
          <h2 id="dhcp-scope-title">{t("dhcp.scope.settings")}</h2>
          <Check id="enabled" label={t("dhcp.scope.field.enabled")} checked={enabled()} onChange={setEnabled} disabled={!writable()} help={t("dhcp.scope.field.enabled_help")} />
          <LeaseChoice
            id="lease"
            inherit={inherit()}
            onInherit={toggleInherit}
            value={lease()}
            onChange={setLease}
            disabled={!writable()}
            errors={{ ...leaseErrors(), ...(errorFor(errors(), "lease") && !leaseErrors().default ? { default: errorFor(errors(), "lease") } : {}) }}
            serverWords={t("dhcp.lease.server_now", { lease: leaseWords(serverLease()) })}
          />
          <TriSelect
            id="authoritative"
            label={t("dhcp.scope.field.authoritative")}
            value={authoritative()}
            onChange={setAuthoritative}
            lockInherit={lockedAuth()}
            disabled={!writable()}
            help={t("dhcp.scope.field.authoritative_help")}
          />
          <Field id="server_id" label={t("dhcp.scope.field.server_id")} error={errorFor(errors(), "server_id")} help={t("dhcp.scope.field.server_id_help")}>
            <input
              id="dhcp-f-server_id"
              class="input mono"
              value={serverId()}
              disabled={!writable()}
              spellcheck={false}
              autocomplete="off"
              aria-invalid={errors().server_id ? "true" : undefined}
              aria-describedby={describedBy("server_id", errors().server_id, "help")}
              data-testid="field-server_id"
              onInput={(ev) => setServerId(ev.currentTarget.value)}
            />
          </Field>
          <Field id="shared_network" label={t("dhcp.scope.field.shared_network")} error={errorFor(errors(), "shared_network")}>
            <select id="dhcp-f-shared_network" class="select" value={network()} disabled={!writable()} data-testid="field-shared_network" onChange={(ev) => setNetwork(ev.currentTarget.value)}>
              <option value="">{t("dhcp.scope.shared_none")}</option>
              <For each={shared.error ? [] : (shared.latest?.items ?? [])}>{(n) => <option value={n.id}>{n.name}</option>}</For>
            </select>
          </Field>
          <Check id="restricted" label={t("dhcp.scope.field.restricted")} checked={restricted()} onChange={setRestricted} disabled={!writable()} help={t("dhcp.scope.field.restricted_help")} />
          <fieldset class="dhcp-classes" data-testid="scope-classes">
            <legend>{t("dhcp.scope.field.classes")}</legend>
            <Show when={(classes.latest?.items ?? []).length > 0 && !classes.error} fallback={<p class="muted">{t("dhcp.scope.no_classes")}</p>}>
              <For each={classes.latest?.items ?? []}>
                {(c) => (
                  <label class="choice">
                    <input
                      type="checkbox"
                      checked={admitted().includes(c.id)}
                      disabled={!writable()}
                      data-testid="scope-class"
                      data-key={c.name}
                      onChange={(ev) => toggleClass(c.id, ev.currentTarget.checked)}
                    />{" "}
                    <span class="mono">{c.name}</span>
                  </label>
                )}
              </For>
              <span class="help">{t("dhcp.scope.field.classes_help")}</span>
            </Show>
          </fieldset>
          <Field id="description" label={t("dhcp.field.description")} error={errorFor(errors(), "description")}>
            <input id="dhcp-f-description" class="input" value={description()} disabled={!writable()} data-testid="field-description" onInput={(ev) => setDescription(ev.currentTarget.value)} />
          </Field>
          {/* WP8.6: the DDNS settings have their own tab. */}
          <p class="muted" data-testid="scope-ddns" data-key={props.scope.ddns?.enabled ? "on" : "off"}>
            {props.scope.ddns?.enabled ? t("dhcp.scope.ddns_line_on") : t("dhcp.scope.ddns_line_off")}{" "}
            <A href={dhcpPaths.scope(props.scope.prefix, "ddns")} data-testid="scope-ddns-link">
              {t("dhcp.scope.ddns_link")}
            </A>
          </p>
          <ErrorNotice error={error()} />
          <Show when={writable()}>
            <div class="dhcp-actions">
              <button type="submit" class="btn primary" disabled={busy()} data-testid="scope-save">
                {t("dhcp.scope.save")}
              </button>
            </div>
          </Show>
        </section>
      </form>
      <div class="page-body">
        <Utilization prefix={props.scope.prefix} />
      </div>
    </>
  );
}
