// One address (/ipam/addresses/<ip>, `?vrf=` when the address exists in several VRFs): its
// prefix, its interface and host, DNS name, status, tags and custom fields, with edit,
// move, delete or restore, and its history. In a prefix with a DHCP scope, a principal who may
// write IPAM there and DHCP reserves the address in DHCP from here; the address of a reserved host
// shows its reservation as the host page does.
import { A, useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { createResource, createSignal, For, lazy, onCleanup, Show } from "solid-js";
import { api } from "../../api/client";
import { events } from "../../api/events";
import type { AddressRow as Address, Host, Interface } from "../../api/types";
import { decodeSegment, paths } from "../../app/paths";
import { may } from "../../auth/gate";
import { Addr, Mac } from "../../components/Addr";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { DeletedTag, DnsName, LockFlag, ModeBadge, StatusBadge, Tags, TimeAgo } from "../../grid/cells";
import { createScopeIndex, mayReserve } from "../../dhcp/reservations/gate";
import { t, withPacks } from "../../i18n";
import { DeleteDialog, RestoreDialog } from "../DeleteDialog";
import { CustomValues } from "../fields/CustomFieldsEditor";
import { HistoryPanel } from "../history/HistoryPanel";
import { IpamNav } from "../IpamNav";
import { MoveDialog } from "../move/MoveDialog";
import { useScope } from "../scope";
import { useTree } from "../tree/PrefixTree";
import { DnsRecords } from "../../hosts/DnsRecords";
import { AddressForm } from "./AddressForm";
import "../ipam.css";

const ReserveDialog = lazy(withPacks(["dhcp"], () => import("../../dhcp/reservations/ReserveDialog")));
const HostReservations = lazy(withPacks(["dhcp"], () => import("../../dhcp/reservations/HostReservations")));

/** The reservation of an address of a reserved host, as the host page shows it. */
function AddressReservation(props: { address: Address }) {
  const [rows] = createResource(
    () => {
      const a = props.address;
      return a.host?.mode === "reserved" && a.interface && !a.meta.deleted ? { host: a.host.id, iface: a.interface, revision: a.meta.revision } : undefined;
    },
    async ({ host, iface }) => {
      const [h, i] = await Promise.all([api.get("/api/v1/hosts/{id}", { path: { id: host } }), api.get("/api/v1/interfaces/{id}", { path: { id: iface } })]);
      return { host: h as Host, iface: i as Interface };
    },
  );
  return (
    <Show when={!rows.error && rows.latest}>
      {(r) => <HostReservations host={r().host} interfaces={[r().iface]} addresses={[props.address]} />}
    </Show>
  );
}

export default function AddressView() {
  const params = useParams();
  const [search] = useSearchParams();
  const navigate = useNavigate();
  const scope = useScope();
  const ip = () => decodeSegment(params.ip);
  const vrfParam = () => (typeof search.vrf === "string" ? search.vrf : undefined);
  const [dialog, setDialog] = createSignal<"edit" | "move" | "delete" | "restore" | "reserve" | null>(null);
  const scopes = createScopeIndex();

  const [found, { refetch }] = createResource(
    () => [ip(), vrfParam()] as const,
    async ([address, vrf]) => {
      const page = await api.get("/api/v1/addresses", { query: { q: address, vrf, deleted: "include", expand: "host", limit: 50 } });
      return page.items.filter((a) => a.ip === address) as Address[];
    },
  );
  const address = () => {
    const list = found() ?? [];
    if (list.length <= 1) return list[0];
    return list.find((a) => a.vrf === scope.vrf()?.id) ?? (list.find((a) => !a.meta.deleted) ? undefined : list[0]);
  };
  const tree = useTree(() => address()?.vrf);
  const prefix = () => tree.tree()?.nodes.find((n) => n.id === address()?.prefix);

  const off = events.subscribe("ipam", (e) => {
    const id = address()?.id;
    if (id && [...e.objects, ...e.deleted].some((o) => o.id === id || o.kind === "interface")) void refetch();
  });
  onCleanup(off);

  return (
    <div class="page" data-testid="page-ipam-address">
      <IpamNav />
      <Show when={found.error}>
        <div class="page-body">
          <ErrorNotice error={found.error} />
        </div>
      </Show>
      <Show when={found() && found()!.length === 0}>
        <div class="page-body">
          <p class="muted">{t("ipam.address.not_found", { ip: ip() })}</p>
        </div>
      </Show>
      <Show when={(found()?.length ?? 0) > 1 && !address()}>
        <div class="page-body">
          <p>{t("ipam.address.in_several", { ip: ip() })}</p>
          <ul class="list">
            <For each={found() ?? []}>
              {(a) => (
                <li>
                  <A href={paths.address(a.ip, a.vrf)}>{scope.vrfById(a.vrf)?.name ?? a.vrf}</A>
                </li>
              )}
            </For>
          </ul>
        </div>
      </Show>
      <Show when={address()}>
        {(a) => (
          <>
            <div class="page-head">
              <div>
                <nav class="crumbs" aria-label={t("ipam.prefix.crumbs")}>
                  <span>{scope.vrfById(a().vrf)?.name}</span>
                  <Show when={prefix()}>
                    {(p) => (
                      <>
                        <Icon name="chev-r" />
                        <A href={paths.prefix(p().cidr, a().vrf)}>{p().cidr}</A>
                      </>
                    )}
                  </Show>
                </nav>
                <h1 tabIndex={-1}>
                  <Addr value={a().ip} />
                  <span class="sub">
                    <DnsName name={a().dns_name} />
                  </span>
                  <DeletedTag deleted={a().meta.deleted} />
                </h1>
              </div>
              <div class="actions">
                <Show when={may.inPrefix(a().prefix)}>
                  <Show
                    when={!a().meta.deleted}
                    fallback={
                      <button type="button" class="btn primary" data-testid="address-restore" onClick={() => setDialog("restore")}>
                        <Icon name="undo" />
                        {t("ipam.do.restore")}
                      </button>
                    }
                  >
                    <button type="button" class="btn" data-testid="address-edit" onClick={() => setDialog("edit")}>
                      <Icon name="settings" />
                      {t("ipam.do.edit")}
                    </button>
                    <button type="button" class="btn" data-testid="address-move" onClick={() => setDialog("move")}>
                      <Icon name="move" />
                      {t("ipam.do.move")}
                    </button>
                    <Show when={mayReserve(a(), scopes())}>
                      <button type="button" class="btn" data-testid="address-reserve" onClick={() => setDialog("reserve")}>
                        <Icon name="pin" />
                        {t("ipam.do.reserve")}
                      </button>
                    </Show>
                    <button type="button" class="btn danger" data-testid="address-delete" onClick={() => setDialog("delete")}>
                      <Icon name="trash" />
                      {t("ipam.do.delete")}
                    </button>
                  </Show>
                </Show>
              </div>
            </div>
            <div class="page-body detail-body">
              <section class="page-section" aria-labelledby="address-facts">
                <h2 id="address-facts">{t("ipam.address.facts")}</h2>
                <dl class="kv">
                  <dt>{t("ipam.col.status")}</dt>
                  <dd>
                    <StatusBadge status={a().status} />
                  </dd>
                  <dt>{t("ipam.col.prefix")}</dt>
                  <dd>
                    <Show when={prefix()} fallback="–">
                      {(p) => (
                        <A href={paths.prefix(p().cidr, a().vrf)}>
                          <Addr value={p().cidr} />
                        </A>
                      )}
                    </Show>
                  </dd>
                  <dt>{t("ipam.col.vrf")}</dt>
                  <dd>{scope.vrfById(a().vrf)?.name ?? a().vrf}</dd>
                  <dt>{t("ipam.col.host")}</dt>
                  <dd>
                    <Show when={a().host} fallback={t("ipam.address.unassigned")}>
                      {(h) => (
                        <>
                          <A href={paths.host(h().name)}>{h().name}</A> <ModeBadge mode={h().mode} showHint /> <LockFlag locked={h().lock} />
                        </>
                      )}
                    </Show>
                  </dd>
                  <dt>{t("ipam.address.interface")}</dt>
                  <dd>
                    <Show when={a().interface_detail} fallback="–">
                      {(i) => (
                        <>
                          {i().name} <Show when={i().mac}>{(m) => <Mac value={m()} />}</Show>
                        </>
                      )}
                    </Show>
                  </dd>
                  <dt>{t("ipam.col.description")}</dt>
                  <dd>{a().meta.description ?? "–"}</dd>
                  <dt>{t("ipam.col.tags")}</dt>
                  <dd>
                    <Tags tags={a().meta.tags} max={10} />
                  </dd>
                  <dt>{t("ipam.col.updated")}</dt>
                  <dd>
                    <TimeAgo at={a().meta.updated.at} />
                  </dd>
                </dl>
                <CustomValues values={a().meta.custom} />
              </section>
              <AddressReservation address={a()} />
              <DnsRecords addresses={[a()]} />
              <section class="page-section" aria-labelledby="address-history">
                <h2 id="address-history">{t("ipam.prefix.tab.history")}</h2>
                <HistoryPanel
                  collection="addresses"
                  id={a().id}
                  label={a().ip}
                  deleted={!!a().meta.deleted}
                  mayRestore={may.inPrefix(a().prefix)}
                  revision={a().meta.revision}
                  onRestored={() => void refetch()}
                />
              </section>
            </div>
            <Show when={dialog() === "edit" && may.inPrefix(a().prefix)}>
              <AddressForm
                address={a()}
                onClose={() => setDialog(null)}
                onDone={(next) => {
                  setDialog(null);
                  if (next.ip !== a().ip) navigate(paths.address(next.ip, next.vrf));
                  else void refetch();
                }}
              />
            </Show>
            <Show when={dialog() === "reserve" && mayReserve(a(), scopes())}>
              <ReserveDialog source={{ address: a() }} onClose={() => setDialog(null)} onDone={() => void refetch()} />
            </Show>
            <Show when={dialog() === "move" && may.inPrefix(a().prefix)}>
              <MoveDialog
                tree={tree.tree()}
                items={[{ kind: "address", id: a().id, label: a().dns_name ?? a().ip, ip: a().ip }]}
                onClose={() => setDialog(null)}
              />
            </Show>
            <Show when={dialog() === "delete" && may.inPrefix(a().prefix)}>
              <DeleteDialog
                collection="addresses"
                id={a().id}
                kind="address"
                label={a().ip}
                revision={a().meta.revision}
                onClose={() => setDialog(null)}
                onDone={() => {
                  setDialog(null);
                  void refetch();
                }}
              />
            </Show>
            <Show when={dialog() === "restore" && may.inPrefix(a().prefix)}>
              <RestoreDialog
                collection="addresses"
                id={a().id}
                kind="address"
                label={a().ip}
                revision={a().meta.revision}
                onClose={() => setDialog(null)}
                onDone={() => {
                  setDialog(null);
                  void refetch();
                }}
              />
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}
