// The DHCP reservations of a host of mode `reserved`, on the host page (docs/dhcp.md, section
// 12.1): one row per live IPv4 address of the host on a live interface, with what the reservation
// is keyed by (the interface's client identifier, else its MAC address), the scope the address
// falls in, whether the reservation is served (the scope is enabled and the dhcp role of this
// server answers) and the lease on the address with its end, and a warning when another client
// holds it. The block loads lazily with the dhcp words; it follows the `dhcp` topic, and it hides
// itself for a principal who may not read DHCP and where the DHCP routes are not there.
import { A } from "@solidjs/router";
import { createEffect, createMemo, For, on, Show } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery } from "../../api/live";
import { ApiError } from "../../api/problem";
import type { Address, Host, Interface } from "../../api/types";
import { paths } from "../../app/paths";
import { Addr, Mac } from "../../components/Addr";
import { ErrorNotice } from "../../components/Notice";
import { formatRelative, t } from "../../i18n";
import { mayWriteDhcp } from "../access";
import { listScopes, type Scope } from "../api";
import { thisNodeDhcp } from "../leases/api";
import { colons, historyHref, macOf, type Lease } from "../leases/model";
import { unavailable } from "../Parts";
import { dhcpPaths } from "../paths";
import { hasLeaseToRead, hexDigits, reservationRows, sameClient, type ReservationRow } from "./model";
import "./reservations.css";

/** The lease on an address as the lookup found it: the lease, none, or a read that failed. */
type LeaseResult = { kind: "lease"; lease: Lease } | { kind: "none" } | { kind: "failed" };

interface Loaded {
  scopes: Scope[];
  /** Whether the dhcp role of this server answers. */
  serving: boolean;
  /** By `<vrf>/<address>`. */
  leases: Map<string, LeaseResult>;
}

const keyOf = (address: Pick<Address, "ip" | "vrf">) => `${address.vrf}/${address.ip}`;

/** Whether the dhcp role of this server serves: a server without the role (409 `dhcp.node.not_dhcp`) or without a node (404 `cluster.node.not_found`) does not. */
async function roleServes(signal: AbortSignal): Promise<boolean> {
  try {
    const node = await thisNodeDhcp(signal);
    return node?.serving ?? false;
  } catch (err) {
    if (err instanceof ApiError && (err.code === "dhcp.node.not_dhcp" || err.code === "cluster.node.not_found")) return false;
    throw err;
  }
}

async function readLease(address: Address, signal: AbortSignal): Promise<LeaseResult> {
  try {
    const lease = await api.get("/api/v1/dhcp/leases/{addr}", { path: { addr: address.ip }, query: { vrf: address.vrf }, signal });
    return { kind: "lease", lease };
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    if (err.code === "dhcp.lease.not_found") return { kind: "none" };
    // A principal who may not read the leases, or a server without the routes, shows nothing of the block.
    if (err.status === 403 || unavailable(err)) throw err;
    return { kind: "failed" };
  }
}

/** The value of `data-lease`: the binding state of the lease, or `none`; `unknown` when it could not be read, `loading` while it is read. */
function leaseKind(row: ReservationRow, result: LeaseResult | undefined): string {
  if (!hasLeaseToRead(row.state)) return "none";
  if (!result) return "loading";
  return result.kind === "lease" ? result.lease.state : result.kind === "failed" ? "unknown" : "none";
}

/** Whether an active lease on the address is held by another client than the one the reservation is for. */
function heldByOther(row: ReservationRow, result: LeaseResult | undefined): Lease | undefined {
  if (result?.kind !== "lease" || result.lease.state !== "active" || !row.identity) return undefined;
  return sameClient(row.identity, row.iface, result.lease.client) ? undefined : result.lease;
}

function IdentityCell(props: { row: ReservationRow }) {
  return (
    <Show
      when={props.row.identity}
      fallback={
        <span data-testid="host-reservation-identity" data-kind="none">
          {t("dhcp.reservations.identity_none")}
        </span>
      }
    >
      {(identity) => (
        <span data-testid="host-reservation-identity" data-kind={identity().kind}>
          <span class="muted">{identity().kind === "client_id" ? t("dhcp.reservations.identity_client_id") : t("dhcp.reservations.identity_mac")}</span>{" "}
          <Show when={identity().kind === "mac"} fallback={<span class="mono">{colons(hexDigits(identity().value))}</span>}>
            <Mac value={identity().value} />
          </Show>
        </span>
      )}
    </Show>
  );
}

function ScopeCell(props: { row: ReservationRow }) {
  return (
    <Show
      when={props.row.scope}
      fallback={
        <>
          <span>{t("dhcp.reservations.scope_none")}</span>
          <Show when={mayWriteDhcp()}>
            <div>
              <A href={dhcpPaths.scopes()} data-testid="host-reservation-scopes">
                {t("dhcp.reservations.scope_setup")}
              </A>
            </div>
          </Show>
        </>
      }
    >
      {(scope) => (
        <A class="mono" href={dhcpPaths.scope(scope().prefix)} data-testid="host-reservation-scope" data-key={scope().cidr}>
          {scope().cidr}
        </A>
      )}
    </Show>
  );
}

/** The word for a state that is read from the server: whether the reservation is served. */
function stateWord(state: ReservationRow["state"]): string {
  switch (state) {
    case "served":
      return t("dhcp.reservations.state_served");
    case "scope_disabled":
      return t("dhcp.reservations.state_scope_disabled");
    case "not_serving":
      return t("dhcp.reservations.state_not_serving");
    default:
      return "";
  }
}

function ServedCell(props: { row: ReservationRow }) {
  return (
    <Show when={hasLeaseToRead(props.row.state)} fallback={<span class="muted">–</span>}>
      <span class={`tag reservation-state ${props.row.state}`} data-testid="host-reservation-state-tag">
        {stateWord(props.row.state)}
      </span>
    </Show>
  );
}

function LeaseCell(props: { row: ReservationRow; result: LeaseResult | undefined }) {
  const lease = () => (props.result?.kind === "lease" ? props.result.lease : undefined);
  return (
    <Show when={hasLeaseToRead(props.row.state)} fallback={<span class="muted">–</span>}>
      <Show when={props.result} fallback={<span class="muted">…</span>}>
        <Show when={props.result?.kind === "none"}>
          <span class="muted" data-testid="host-reservation-no-lease">
            {t("dhcp.reservations.lease_none")}
          </span>
        </Show>
        <Show when={props.result?.kind === "failed"}>
          <span class="muted" data-testid="host-reservation-lease-failed">
            {t("dhcp.reservations.lease_failed")}
          </span>
        </Show>
        <Show when={lease()}>
          {(held) => (
            <>
              <span class="tag" data-testid="host-reservation-lease-state" data-key={held().state}>
                {t(`dhcp.leases.state.${held().state}`)}
              </span>
              <Show when={held().state === "active"}>
                {" "}
                <span class="muted">{t("dhcp.reservations.lease_ends", { when: formatRelative(held().ends) })}</span>
              </Show>
            </>
          )}
        </Show>
        <Show when={heldByOther(props.row, props.result)}>
          {(other) => (
            <div class="note warn" role="status" data-testid="host-reservation-mismatch">
              {t("dhcp.reservations.lease_other", { client: macOf(other().client) })}
            </div>
          )}
        </Show>
      </Show>
    </Show>
  );
}

export default function HostReservations(props: { host: Host; interfaces: readonly Interface[]; addresses: readonly Address[] }) {
  const live = createLiveQuery<Loaded>({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const [scopes, serving] = await Promise.all([listScopes(signal), roleServes(signal)]);
      const { rows } = reservationRows(props.interfaces, props.addresses, scopes.items, serving);
      const wanted = rows.filter((r) => hasLeaseToRead(r.state));
      const results = await Promise.all(wanted.map((r) => readLease(r.address, signal)));
      const leases = new Map<string, LeaseResult>();
      wanted.forEach((r, i) => leases.set(keyOf(r.address), results[i] ?? { kind: "failed" }));
      return { value: { scopes: scopes.items, serving, leases }, revision: scopes.revision };
    },
  });

  // What the rows are made of changes with the host's interfaces and addresses: the leases are read again.
  const signature = createMemo(() =>
    JSON.stringify([
      props.interfaces.map((i) => [i.id, i.mac, i.client_id, i.meta.deleted ? 1 : 0]),
      props.addresses.map((a) => [a.id, a.ip, a.vrf, a.interface, a.status, a.meta.deleted ? 1 : 0]),
    ]),
  );
  createEffect(on(signature, () => live.refetch(), { defer: true }));

  const data = () => live.latest();
  const hidden = () => {
    const err = live.value.error;
    return err instanceof ApiError && (err.status === 403 || unavailable(err));
  };
  const view = createMemo(() => {
    const d = data();
    return d ? reservationRows(props.interfaces, props.addresses, d.scopes, d.serving) : undefined;
  });

  return (
    <Show when={!hidden() && (data() !== undefined || live.value.error !== undefined)}>
      <section class="page-section" aria-labelledby="host-reservations-title" data-testid="host-reservations" data-host={props.host.name} data-count={view()?.rows.length ?? 0}>
        <h2 id="host-reservations-title">{t("dhcp.reservations.title")}</h2>
        <ErrorNotice error={live.value.error} />
        <Show when={view()}>
          {(v) => (
            <>
              <p class="muted">{t("dhcp.reservations.help")}</p>
              <Show
                when={v().rows.length > 0}
                fallback={
                  <p class="muted" data-testid="host-reservations-empty">
                    {t("dhcp.reservations.empty")}
                  </p>
                }
              >
                <div class="table-wrap">
                  <table class="plain host-reservations">
                    <caption class="sr-only">{t("dhcp.reservations.title")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("dhcp.col.address")}</th>
                        <th scope="col">{t("dhcp.reservations.col_identity")}</th>
                        <th scope="col">{t("dhcp.col.scope")}</th>
                        <th scope="col">{t("dhcp.reservations.col_served")}</th>
                        <th scope="col">{t("dhcp.reservations.col_lease")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={v().rows}>
                        {(row) => {
                          const result = () => data()?.leases.get(keyOf(row.address));
                          return (
                            <tr
                              data-testid="host-reservation"
                              data-key={row.address.ip}
                              data-state={row.state}
                              data-lease={leaseKind(row, result())}
                              data-mismatch={heldByOther(row, result()) ? "true" : undefined}
                            >
                              <td>
                                <A href={paths.address(row.address.ip, row.address.vrf)} class="addr-link">
                                  <Addr value={row.address.ip} />
                                </A>
                              </td>
                              <td>
                                <IdentityCell row={row} />
                              </td>
                              <td>
                                <ScopeCell row={row} />
                              </td>
                              <td>
                                <ServedCell row={row} />
                              </td>
                              <td>
                                <LeaseCell row={row} result={result()} />
                                <Show when={hasLeaseToRead(row.state)}>
                                  <div>
                                    <A href={historyHref(row.address.ip)} data-testid="host-reservation-history">
                                      {t("dhcp.lease.history_link")}
                                    </A>
                                  </div>
                                </Show>
                              </td>
                            </tr>
                          );
                        }}
                      </For>
                    </tbody>
                  </table>
                </div>
              </Show>
              <Show when={v().ipv6 > 0}>
                <p class="muted" data-testid="host-reservations-ipv6">
                  {t("dhcp.reservations.ipv6_later")}
                </p>
              </Show>
            </>
          )}
        </Show>
      </section>
    </Show>
  );
}
