// The dialog that reserves an address in DHCP (docs/dhcp.md, section 12.1), opened from the IPAM
// address page, the address list's row menu and the lease list. A reservation is derived from
// IPAM's rows, so the dialog collects them: the host (the address's, the lease's client's, or a
// new one with a name prefilled from the address's DNS name, the lease's host name or what the
// observations saw), the interface (one of the host's, or a new one), the MAC address (prefilled
// from the interface, the lease on the address or the observations) and an optional client
// identifier, and the status (an active address stays active). Before the save it says in
// sentences what will change; an address inside a DHCP pool cannot be reserved (IPAM keeps
// reservations out of the pools), and from a lease the dialog offers the next free address
// outside the pools instead. The save is one request (`POST /addresses/{id}/reserve`, or
// `POST /addresses/reserve` for an address IPAM does not hold yet) that writes every row in one
// batch, so a refusal changes nothing. Afterwards the dialog shows the reservation as the host
// page does, with the scope and the host. Callers show the dialog only to principals who may
// write IPAM in the address's prefix and DHCP, for an address in a prefix with a scope.
import { A } from "@solidjs/router";
import { createEffect, createMemo, createResource, createSignal, For, on, Show } from "solid-js";
import { api } from "../../api/client";
import { fetchAll } from "../../api/paginate";
import { ApiError } from "../../api/problem";
import type { AddressRow, Host, Interface, Range } from "../../api/types";
import { paths } from "../../app/paths";
import { Dialog } from "../../components/Dialog";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { getSubject } from "../../discovery/api";
import { t, tDynamic } from "../../i18n";
import { containsIp, parseCidr, parseIp } from "../../ipam/ip";
import { listScopes, type Scope } from "../api";
import type { Lease } from "../leases/model";
import { clientIdOf, macOf } from "../leases/model";
import { describedBy, Field } from "../Parts";
import { dhcpPaths } from "../paths";
import HostReservations, { roleServes } from "./HostReservations";
import {
  DEFAULT_INTERFACE,
  draftProblems,
  macPrefill,
  namePrefill,
  poolOf,
  preview,
  reserveRequest,
  statusChoices,
  statusPrefill,
  type HostChoice,
  type InterfaceChoice,
  type ReserveContext,
  type ReserveDraft,
  type ReserveResponse,
  type ReserveStatus,
} from "./reserve";
import "../dhcp.css";
import "./reservations.css";

/** Where the dialog was opened: an IPAM address (read with `expand=host`), or a lease. */
export interface ReserveSource {
  address?: AddressRow | undefined;
  lease?: Lease | undefined;
}

/** What the dialog reads once when it opens. */
interface Loaded {
  ip: string;
  vrf: string;
  /** The IPAM address, when IPAM holds the address. */
  address: AddressRow | undefined;
  scope: Scope | undefined;
  serving: boolean;
  pools: Range[];
  hosts: HostChoice[];
  leaseMac: string | undefined;
  leaseClientId: string | undefined;
  leaseHostname: string | undefined;
  observedMac: string | undefined;
  observedName: string | undefined;
}

/** The arguments of a preview sentence with the status and the mode in words. */
function localized(args: Readonly<Record<string, string>> | undefined): Record<string, string> {
  const out: Record<string, string> = { ...args };
  if (out.status) out.status = tDynamic(`dhcp.reserve.status.${out.status}`) ?? out.status;
  if (out.mode) out.mode = tDynamic(`dhcp.reserve.mode.${out.mode}`) ?? out.mode;
  return out;
}

/** A read the dialog can do without: its failure leaves the prefill empty. */
async function optional<T>(read: Promise<T>): Promise<T | undefined> {
  try {
    return await read;
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    return undefined;
  }
}

/** The IPAM address with this value in the VRF, with its host. */
async function findAddress(ip: string, vrf: string): Promise<AddressRow | undefined> {
  const page = await api.get("/api/v1/addresses", { query: { q: ip, vrf, expand: "host", limit: 50 } });
  return page.items.find((a) => a.ip === ip && !a.meta.deleted);
}

async function load(source: ReserveSource): Promise<Loaded> {
  const lease = source.lease;
  const ip = source.address?.ip ?? lease?.addr ?? "";
  const vrf = source.address?.vrf ?? lease?.vrf ?? "";
  const address = source.address ?? (await optional(findAddress(ip, vrf)));
  const prefix = address?.prefix ?? lease?.scope ?? "";
  const signal = new AbortController().signal;
  const [scopes, serving, ranges, current, observed, leaseHost] = await Promise.all([
    listScopes(),
    optional(roleServes(signal)),
    optional(fetchAll<Range>("/api/v1/prefixes/{id}/ranges", { path: { id: prefix } })),
    lease ? Promise.resolve(lease) : optional(api.get("/api/v1/dhcp/leases/{addr}", { path: { addr: ip }, query: { vrf } })),
    optional(getSubject(ip)),
    lease?.host ? optional(api.get("/api/v1/hosts/{id}", { path: { id: lease.host } })) : Promise.resolve(undefined),
  ]);
  const hosts: HostChoice[] = [];
  const own = address?.host;
  if (own) hosts.push({ id: own.id, name: own.name, mode: own.mode });
  if (leaseHost && !leaseHost.meta.deleted && !hosts.some((h) => h.id === leaseHost.id)) hosts.push({ id: leaseHost.id, name: leaseHost.name, mode: leaseHost.mode });
  return {
    ip,
    vrf,
    address,
    scope: scopes.items.find((s) => s.prefix === prefix),
    serving: serving ?? false,
    pools: (ranges?.items ?? []).filter((r) => r.role === "dhcp_pool" && !r.meta.deleted),
    hosts,
    leaseMac: current ? macOf(current.client) : undefined,
    leaseClientId: lease ? clientIdOf(lease.client) : undefined,
    leaseHostname: current?.hostname ?? undefined,
    observedMac: observed?.summary.macs[0],
    observedName: observed?.summary.names[0],
  };
}

export default function ReserveDialog(props: { source: ReserveSource; onClose: () => void; onDone?: (result: ReserveResponse) => void }) {
  const [loaded] = createResource(() => load(props.source));
  const [done, setDone] = createSignal<ReserveResponse>();
  const ip = () => props.source.address?.ip ?? props.source.lease?.addr ?? "";
  return (
    <Dialog label={t("dhcp.reserve.title", { ip: ip() })} onClose={props.onClose} class="dialog wide dhcp-dialog" testid="dialog-reserve">
      <h2 class="dialog-title">{t("dhcp.reserve.title", { ip: ip() })}</h2>
      <Show
        when={done()}
        fallback={
          <>
            <Show when={loaded.error}>
              <div class="dialog-body">
                <ErrorNotice error={loaded.error} />
              </div>
            </Show>
            <Show when={loaded.loading}>
              <div class="dialog-body">
                <p class="muted">{t("dhcp.reserve.loading")}</p>
              </div>
            </Show>
            <Show when={loaded()} keyed>
              {(data) => (
                <ReserveForm
                  data={data}
                  fromLease={!props.source.address}
                  onClose={props.onClose}
                  onSaved={(result) => {
                    setDone(result);
                    props.onDone?.(result);
                  }}
                />
              )}
            </Show>
          </>
        }
      >
        {(result) => <Reserved result={result()} onClose={props.onClose} />}
      </Show>
    </Dialog>
  );
}

/** After the save: the reservation as the host page shows it, the scope and the host. */
function Reserved(props: { result: ReserveResponse; onClose: () => void }) {
  const host = () => props.result.host as Host | null | undefined;
  const iface = () => props.result.interface as Interface | null | undefined;
  return (
    <div class="dialog-body" data-testid="reserve-done">
      <Notice kind="ok" role="status" testid="reserve-saved">
        {props.result.unchanged
          ? t("dhcp.reserve.saved_unchanged", { ip: props.result.address?.ip ?? "", host: host()?.name ?? "" })
          : t("dhcp.reserve.saved", { ip: props.result.address?.ip ?? "", host: host()?.name ?? "" })}
      </Notice>
      <Show when={host() && iface() && props.result.address}>
        <HostReservations host={host() as Host} interfaces={[iface() as Interface]} addresses={[props.result.address as NonNullable<ReserveResponse["address"]>]} />
      </Show>
      <div class="dialog-actions">
        <Show when={host()}>
          {(h) => (
            <A class="btn" href={paths.host(h().name)} data-testid="reserve-open-host" onClick={() => props.onClose()}>
              {t("dhcp.reserve.open_host", { host: h().name })}
            </A>
          )}
        </Show>
        <button type="button" class="btn primary" data-testid="reserve-close" onClick={() => props.onClose()}>
          {t("common.action.close")}
        </button>
      </div>
    </div>
  );
}

function ReserveForm(props: { data: Loaded; fromLease: boolean; onClose: () => void; onSaved: (result: ReserveResponse) => void }) {
  // eslint-disable-next-line solid/reactivity -- read once: the parent mounts the form anew (keyed) for new data
  const data = props.data;
  const [draft, setDraft] = createSignal<ReserveDraft>({
    ip: data.ip,
    host: data.hosts[0]?.id ?? "new",
    newHost: namePrefill({ dnsName: data.address?.dns_name, leaseHostname: data.leaseHostname, observedName: data.observedName }),
    iface: "",
    newInterface: DEFAULT_INTERFACE,
    mac: macPrefill({ interfaceMac: data.address?.interface_detail?.mac, leaseMac: data.leaseMac, observedMac: data.observedMac }),
    clientId: data.leaseClientId ?? "",
    status: statusPrefill(data.address?.status),
  });
  const set = <K extends keyof ReserveDraft>(key: K, value: ReserveDraft[K]) => setDraft((d) => ({ ...d, [key]: value }));
  const [checked, setChecked] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();

  // From a lease the address may change: the IPAM address of what is typed, read when the field is left.
  const [committedIp, setCommittedIp] = createSignal(data.ip);
  const [typed] = createResource(
    () => (props.fromLease && committedIp() !== data.ip ? committedIp() : undefined),
    (value) => (parseIp(value) ? optional(findAddress(value, data.vrf)) : Promise.resolve(undefined)),
  );
  const address = () => (props.fromLease && committedIp() !== data.ip ? typed.latest : data.address);

  // A memo of the host alone, so that typing in the other fields keeps the interface options as they are.
  const hostId = createMemo(() => draft().host);
  const [interfaces] = createResource(
    () => (hostId() !== "new" ? hostId() : undefined),
    async (host) => (await fetchAll<Interface>("/api/v1/hosts/{id}/interfaces", { path: { id: host } })).items.filter((i) => !i.meta.deleted),
  );
  const choices = createMemo((): InterfaceChoice[] =>
    hostId() === "new" ? [] : (interfaces.latest ?? []).map((i) => ({ id: i.id, name: i.name, mac: i.mac ?? null, client_id: i.client_id ?? null })),
  );

  // The interface the dialog starts with for a host: the address's on that host, else its only one, else a new one.
  createEffect(
    on(choices, (list) => {
      const current = draft().iface;
      if (current !== "" && (current === "new" || list.some((i) => i.id === current))) return;
      if (draft().host !== "new" && interfaces.state !== "ready") return;
      const own = list.find((i) => i.id === address()?.interface);
      const pick = own ?? (list.length === 1 ? list[0] : undefined);
      set("iface", pick?.id ?? "new");
      // An interface with a client identifier keeps it unless the lease gave one.
      if (pick?.client_id && draft().clientId === "") set("clientId", pick.client_id);
    }),
  );

  const scope = () => data.scope;
  const ctx = createMemo((): ReserveContext | undefined => {
    const s = scope();
    if (!s) return undefined;
    const a = address();
    return {
      address: a ? { id: a.id, ip: a.ip, vrf: a.vrf, status: a.status, interface: a.interface } : undefined,
      vrf: data.vrf,
      hosts: data.hosts,
      interfaces: choices(),
      scope: { cidr: s.cidr, enabled: s.enabled !== false },
      serving: data.serving,
      leaseMac: data.leaseMac,
    };
  });
  const ipNow = () => address()?.ip ?? draft().ip.trim();
  const outside = () => {
    const s = scope();
    const net = s ? parseCidr(s.cidr) : null;
    const at = parseIp(ipNow());
    return !!net && !!at && !containsIp(net, at);
  };
  const pool = () => poolOf(ipNow(), data.pools);
  const [candidate] = createResource(
    () => (props.fromLease && pool() && data.scope ? data.scope.prefix : undefined),
    (prefix) =>
      optional(api.post("/api/v1/prefixes/{id}/next-free-address", { path: { id: prefix }, query: { dry_run: true } })).then((r) => r?.item?.ip ?? undefined),
  );
  const problems = createMemo(() => {
    const c = ctx();
    return c ? draftProblems(draft(), c) : {};
  });
  const shown = (field: keyof ReturnType<typeof problems>) => (checked() ? problems()[field] : undefined);
  const word = (key: string | undefined) => (key ? (tDynamic(key) ?? key) : undefined);
  const sentences = createMemo(() => {
    const c = ctx();
    return c ? preview(draft(), c) : [];
  });
  const blocked = () => !ctx() || !!pool() || outside() || (draft().host !== "new" && interfaces.loading);

  const save = async (event: Event) => {
    event.preventDefault();
    setChecked(true);
    const c = ctx();
    if (busy() || !c || blocked() || Object.keys(problems()).length > 0) return;
    const request = reserveRequest(draft(), c);
    setBusy(true);
    setError(undefined);
    try {
      const result = request.address
        ? await api.post("/api/v1/addresses/{id}/reserve", { path: { id: request.address }, body: request.body })
        : await api.post("/api/v1/addresses/reserve", { body: request.body });
      toast({ kind: "ok", title: t("dhcp.reserve.saved", { ip: result.address?.ip ?? ipNow(), host: result.host?.name ?? "" }) });
      props.onSaved(result);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form class="dialog-body dhcp-form" onSubmit={(e) => void save(e)} novalidate data-testid="reserve-form">
      <Show when={!scope()}>
        <Notice kind="warn" role="status" testid="reserve-no-scope">
          {t("dhcp.reserve.no_scope", { ip: ipNow() })}
        </Notice>
      </Show>
      <Show when={scope()}>
        {(s) => (
          <p data-testid="reserve-scope" data-state={s().enabled === false ? "disabled" : data.serving ? "served" : "not_serving"}>
            {t(s().enabled === false ? "dhcp.reserve.scope_disabled" : data.serving ? "dhcp.reserve.scope_served" : "dhcp.reserve.scope_not_serving", { cidr: s().cidr })}{" "}
            <A href={dhcpPaths.scope(s().prefix)} data-testid="reserve-scope-link">
              {t("dhcp.reserve.scope_link")}
            </A>
          </p>
        )}
      </Show>
      <Show
        when={props.fromLease}
        fallback={
          <p>
            <span class="muted">{t("dhcp.reserve.field.address")}</span> <span class="mono" data-testid="reserve-address">{data.ip}</span>
          </p>
        }
      >
        <Field id="reserve-ip" label={t("dhcp.reserve.field.address")} error={word(shown("ip"))} help={t("dhcp.reserve.field.address_help")}>
          <input
            id="dhcp-f-reserve-ip"
            class="input mono"
            value={draft().ip}
            spellcheck={false}
            autocomplete="off"
            aria-describedby={describedBy("reserve-ip", word(shown("ip")), "help")}
            data-testid="field-reserve-ip"
            onInput={(e) => set("ip", e.currentTarget.value)}
            onChange={(e) => setCommittedIp(e.currentTarget.value.trim())}
          />
        </Field>
      </Show>
      <Show when={outside() && scope()}>
        <Notice kind="warn" role="status" testid="reserve-outside">
          {t("dhcp.reserve.outside", { ip: ipNow(), cidr: scope()?.cidr ?? "" })}
        </Notice>
      </Show>
      <Show when={pool()}>
        {(p) => (
          <Notice kind="warn" role="status" testid="reserve-in-pool">
            <p>{t(props.fromLease ? "dhcp.reserve.in_pool_lease" : "dhcp.reserve.in_pool", { ip: ipNow(), first: p().first, last: p().last })}</p>
            <Show when={props.fromLease && candidate()}>
              {(next) => (
                <button
                  type="button"
                  class="btn"
                  data-testid="reserve-use-free"
                  onClick={() => {
                    set("ip", next());
                    setCommittedIp(next());
                  }}
                >
                  {t("dhcp.reserve.use_free", { ip: next() })}
                </button>
              )}
            </Show>
          </Notice>
        )}
      </Show>

      <Field id="reserve-host" label={t("dhcp.reserve.field.host")}>
        <select id="dhcp-f-reserve-host" class="select" data-testid="field-reserve-host" onChange={(e) => setDraft((d) => ({ ...d, host: e.currentTarget.value, iface: "" }))}>
          <For each={data.hosts}>
            {(h) => (
              <option value={h.id} selected={draft().host === h.id}>
                {t("dhcp.reserve.host_option", { name: h.name, mode: tDynamic(`dhcp.reserve.mode.${h.mode}`) ?? h.mode })}
              </option>
            )}
          </For>
          <option value="new" selected={draft().host === "new"}>
            {t("dhcp.reserve.host_new")}
          </option>
        </select>
      </Field>
      <Show when={draft().host === "new"}>
        <Field id="reserve-new-host" label={t("dhcp.reserve.field.new_host")} error={word(shown("host_name"))}>
          <input
            id="dhcp-f-reserve-new-host"
            class="input"
            value={draft().newHost}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={shown("host_name") ? "true" : undefined}
            aria-describedby={describedBy("reserve-new-host", word(shown("host_name")))}
            data-testid="field-reserve-new-host"
            onInput={(e) => set("newHost", e.currentTarget.value)}
          />
        </Field>
      </Show>
      <Field id="reserve-iface" label={t("dhcp.reserve.field.interface")}>
        <select id="dhcp-f-reserve-iface" class="select" disabled={draft().host === "new"} data-testid="field-reserve-iface" onChange={(e) => set("iface", e.currentTarget.value)}>
          <For each={choices()}>
            {(i) => (
              <option value={i.id} selected={draft().iface === i.id}>
                {i.mac ? `${i.name} (${i.mac})` : i.name}
              </option>
            )}
          </For>
          <option value="new" selected={draft().iface === "new"}>
            {t("dhcp.reserve.interface_new")}
          </option>
        </select>
      </Field>
      <Show when={draft().iface === "new" || draft().host === "new"}>
        <Field id="reserve-new-iface" label={t("dhcp.reserve.field.new_interface")} error={word(shown("interface_name"))}>
          <input
            id="dhcp-f-reserve-new-iface"
            class="input"
            value={draft().newInterface}
            spellcheck={false}
            autocomplete="off"
            data-testid="field-reserve-new-iface"
            onInput={(e) => set("newInterface", e.currentTarget.value)}
          />
        </Field>
      </Show>
      <Field id="reserve-mac" label={t("dhcp.reserve.field.mac")} error={word(shown("mac") ?? shown("identity"))} help={t("dhcp.reserve.field.mac_help")}>
        <input
          id="dhcp-f-reserve-mac"
          class="input mono"
          value={draft().mac}
          spellcheck={false}
          autocomplete="off"
          placeholder={t("dhcp.example.mac")}
          aria-invalid={shown("mac") || shown("identity") ? "true" : undefined}
          aria-describedby={describedBy("reserve-mac", word(shown("mac") ?? shown("identity")), "help")}
          data-testid="field-reserve-mac"
          onInput={(e) => set("mac", e.currentTarget.value)}
        />
      </Field>
      <Field id="reserve-client-id" label={t("dhcp.reserve.field.client_id")} error={word(shown("client_id"))} help={t("dhcp.reserve.field.client_id_help")}>
        <input
          id="dhcp-f-reserve-client-id"
          class="input mono"
          value={draft().clientId}
          spellcheck={false}
          autocomplete="off"
          aria-invalid={shown("client_id") ? "true" : undefined}
          aria-describedby={describedBy("reserve-client-id", word(shown("client_id")), "help")}
          data-testid="field-reserve-client-id"
          onInput={(e) => set("clientId", e.currentTarget.value)}
        />
      </Field>
      <fieldset class="field" data-testid="field-reserve-status">
        <legend>{t("dhcp.reserve.field.status")}</legend>
        <For each={statusChoices(address()?.status)}>
          {(status: ReserveStatus) => (
            <label class="choice">
              <input type="radio" name="reserve-status" value={status} checked={draft().status === status} onChange={() => set("status", status)} />{" "}
              <span>{tDynamic(`dhcp.reserve.status.${status}`) ?? status}</span>
            </label>
          )}
        </For>
      </fieldset>

      <section class="reserve-preview" aria-labelledby="reserve-preview-title" data-testid="reserve-preview">
        <h3 id="reserve-preview-title">{t("dhcp.reserve.preview")}</h3>
        <ul>
          <For each={sentences()}>
            {(s) => (
              <li data-testid="reserve-sentence" data-key={s.key}>
                {tDynamic(s.key, localized(s.args)) ?? s.key}
              </li>
            )}
          </For>
        </ul>
      </section>

      <ErrorNotice error={error()} />
      <Show when={error() instanceof ApiError && (error() as ApiError).status === 412}>
        <p class="muted">{t("dhcp.reserve.stale")}</p>
      </Show>
      <div class="dialog-actions">
        <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
          {t("common.action.cancel")}
        </button>
        <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy() || blocked()}>
          {t("dhcp.reserve.save")}
        </button>
      </div>
    </form>
  );
}
