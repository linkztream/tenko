// One host (/ipam/hosts/<name>): its assignment mode with what it means (IPAM-14), the lock
// (IPAM-16), its interfaces with MAC, DUID and addresses, the warning for a reserved host
// without MAC or DUID (IPAM-18), remote access hand-off (API-11), its jobs and its history.
// Observations (leases, DNS records, scans) arrive with Slice 2: the section is there, empty.
import { A, useNavigate, useParams } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { ANY_REVISION, api } from "../api/client";
import { events } from "../api/events";
import { fetchAll } from "../api/paginate";
import { errorMessage } from "../api/problem";
import type { Address, AssignmentMode, Host, Interface, JobSummary, Site, Tenant } from "../api/types";
import { ASSIGNMENT_MODES } from "../api/types";
import { decodeSegment, paths } from "../app/paths";
import { Addr, Mac } from "../components/Addr";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { DeletedTag, LockFlag, ModeBadge, StatusBadge, Tags, TimeAgo } from "../grid/cells";
import { DataGrid } from "../grid/DataGrid";
import { Menu } from "../grid/Menu";
import { t } from "../i18n";
import { DeleteDialog, RestoreDialog } from "../ipam/DeleteDialog";
import { CustomValues } from "../ipam/fields/CustomFieldsEditor";
import { HistoryPanel } from "../ipam/history/HistoryPanel";
import { parseIp } from "../ipam/ip";
import { IpamNav } from "../ipam/IpamNav";
import { MoveDialog } from "../ipam/move/MoveDialog";
import { writeQuery } from "../ipam/plan/describe";
import { PlanDialog, useWriteToast } from "../ipam/plan/PlanDialog";
import { useScope } from "../ipam/scope";
import { useTree } from "../ipam/tree/PrefixTree";
import { modeHint, modeWord } from "../ipam/words";
import { JobStateChip } from "../jobs/StateChip";
import { jobTitle } from "../jobs/words";
import { isTyping } from "../shell/keyboard";
import { Connect } from "./Connect";
import { CredentialSlot } from "./credentials";
import { HostForm, InterfaceForm } from "./HostForm";
import "../ipam/ipam.css";
import "./hosts.css";

interface HostData {
  host: Host;
  interfaces: Interface[];
  addresses: Address[];
  jobs: JobSummary[];
}

/** IPAM-18: a reserved host needs a MAC address for its IPv4 and a DUID for its IPv6 addresses. */
export function missingIdentifiers(host: Host, interfaces: readonly Interface[], addresses: readonly Address[]): {
  mac: boolean;
  duid: boolean;
} {
  if (host.mode !== "reserved") return { mac: false, duid: false };
  const live = interfaces.filter((i) => !i.meta.deleted);
  const byId = new Map(live.map((i) => [i.id, i]));
  const bound = addresses.filter((a) => !a.meta.deleted && a.interface && byId.has(a.interface));
  const v4 = bound.filter((a) => parseIp(a.ip)?.version === 4);
  const v6 = bound.filter((a) => parseIp(a.ip)?.version === 6);
  const noMac = v4.some((a) => !byId.get(a.interface as string)?.mac) || (v4.length === 0 && v6.length === 0 && !live.some((i) => i.mac || i.duid));
  const noDuid = v6.some((a) => !byId.get(a.interface as string)?.duid);
  return { mac: noMac, duid: noDuid };
}

export default function HostView() {
  const params = useParams();
  const navigate = useNavigate();
  const writeToast = useWriteToast();
  const scope = useScope();
  const tree = useTree(() => scope.vrf()?.id);
  const name = () => decodeSegment(params.fqdn);

  const [found, { refetch }] = createResource(name, async (n) => {
    const page = await api.get("/api/v1/hosts", { query: { q: n, deleted: "include", limit: 50 } });
    return page.items.filter((h) => h.name.toLowerCase() === n.toLowerCase()) as Host[];
  });
  const [chosen, setChosen] = createSignal<string | null>(null);
  const host = () => {
    const list = found() ?? [];
    return list.find((h) => h.id === chosen()) ?? (list.length === 1 ? list[0] : list.find((h) => !h.meta.deleted && list.filter((x) => !x.meta.deleted).length === 1));
  };

  const [data, details] = createResource(
    () => host()?.id ?? false,
    async (id): Promise<Omit<HostData, "host">> => {
      const [interfaces, addresses, jobs] = await Promise.all([
        fetchAll<Interface>("/api/v1/hosts/{id}/interfaces", { path: { id }, query: { deleted: "include" } }),
        fetchAll<Address>("/api/v1/addresses", { query: { host: id } }),
        api.get("/api/v1/jobs", { query: { target: `host/${id}`, limit: 10 } }).catch(() => ({ items: [] as JobSummary[] })),
      ]);
      return { interfaces: interfaces.items, addresses: addresses.items, jobs: jobs.items };
    },
  );
  const [lists] = createResource(async () => {
    const [sites, tenants] = await Promise.all([fetchAll<Site>("/api/v1/sites"), fetchAll<Tenant>("/api/v1/tenants")]);
    return { sites: sites.items, tenants: tenants.items };
  });

  // Keep the page current: events about the host, its interfaces or addresses read it again.
  // eslint-disable-next-line solid/reactivity -- an event callback, like an event handler
  const offIpam = events.subscribe("ipam", (e) => {
    const h = host();
    if (!h) return;
    const mine = new Set([h.id, ...(data()?.interfaces ?? []).map((i) => i.id), ...(data()?.addresses ?? []).map((a) => a.id)]);
    if ([...e.objects, ...e.deleted].some((o) => mine.has(o.id) || o.kind === "address")) {
      void refetch();
      void details.refetch();
    }
  });
  const offJobs = events.subscribe("jobs", () => void details.refetch());
  onCleanup(() => {
    offIpam();
    offJobs();
  });

  const [dialog, setDialog] = createSignal<
    | { kind: "edit" }
    | { kind: "mode"; mode: AssignmentMode }
    | { kind: "move" }
    | { kind: "delete" }
    | { kind: "restore" }
    | { kind: "iface"; iface?: Interface }
    | { kind: "iface_delete"; iface: Interface }
    | null
  >(null);
  const [modeMenu, setModeMenu] = createSignal<HTMLElement | null>(null);

  const interfaces = () => (data()?.interfaces ?? []).filter((i) => !i.meta.deleted);
  const addresses = () => data()?.addresses ?? [];
  const missing = createMemo(() => {
    const h = host();
    return h ? missingIdentifiers(h, interfaces(), addresses()) : { mac: false, duid: false };
  });
  const siteName = (id?: string | null) => (id ? lists()?.sites.find((s) => s.id === id)?.name : undefined);
  const tenantName = (id: string) => lists()?.tenants.find((tn) => tn.id === id)?.name ?? id;

  const toggleLock = async () => {
    const h = host();
    if (!h || h.meta.deleted) return;
    const next = !h.lock;
    try {
      const r = await api.patch("/api/v1/hosts/{id}", { path: { id: h.id }, body: { lock: next }, ifMatch: h.meta.revision });
      writeToast(next ? t("hosts.locked", { name: h.name }) : t("hosts.unlocked", { name: h.name }), r, [
        {
          label: t("hosts.undo"),
          // Undo only what this toggle did: a change by someone else in between is a conflict.
          run: () =>
            void api
              .patch("/api/v1/hosts/{id}", { path: { id: h.id }, body: { lock: !next }, ifMatch: r.item?.meta.revision ?? ANY_REVISION })
              .then(() => refetch())
              .catch((err: unknown) => toast({ kind: "bad", title: t("hosts.lock_failed", { name: h.name }), body: errorMessage(err) })),
        },
      ]);
      void refetch();
    } catch (err) {
      toast({ kind: "bad", title: t("hosts.lock_failed", { name: h.name }), body: errorMessage(err) });
    }
  };

  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || isTyping(e) || e.ctrlKey || e.metaKey || e.altKey || dialog()) return;
      if (document.querySelector("[aria-modal='true']") || !host() || host()?.meta.deleted) return;
      if (e.key === "M" && e.shiftKey) {
        e.preventDefault();
        setModeMenu(document.querySelector<HTMLElement>("[data-testid='host-mode']"));
      } else if (e.key === "m") {
        e.preventDefault();
        setDialog({ kind: "move" });
      } else if (e.key === "l" || e.key === "L") {
        e.preventDefault();
        void toggleLock();
      }
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  const addressesOf = (iface: Interface) => addresses().filter((a) => a.interface === iface.id);

  return (
    <div class="page" data-testid="page-host">
      <IpamNav />
      <ErrorNotice error={found.error} />
      <Show when={found() && found()!.length === 0}>
        <div class="page-body">
          <p class="muted">{t("hosts.not_found", { name: name() })}</p>
        </div>
      </Show>
      <Show when={(found()?.length ?? 0) > 1 && !host()}>
        <div class="page-body">
          <p>{t("hosts.in_several", { name: name() })}</p>
          <ul class="list">
            <For each={found() ?? []}>
              {(h) => (
                <li>
                  <button type="button" class="btn sm" onClick={() => setChosen(h.id)}>
                    {tenantName(h.tenant)}
                  </button>{" "}
                  <DeletedTag deleted={h.meta.deleted} />
                </li>
              )}
            </For>
          </ul>
        </div>
      </Show>
      <Show when={host()}>
        {(h) => (
          <>
            <div class="page-head">
              <div>
                <nav class="crumbs" aria-label={t("hosts.crumbs")}>
                  <A href={paths.hosts()}>{t("ipam.nav.hosts")}</A>
                  <Icon name="chev-r" />
                  <span>{tenantName(h().tenant)}</span>
                </nav>
                <h1 tabIndex={-1}>
                  <span class="hostname">{h().name}</span>
                  <span class="sub">
                    <ModeBadge mode={h().mode} /> <LockFlag locked={h().lock} />
                  </span>
                  <DeletedTag deleted={h().meta.deleted} />
                </h1>
              </div>
              <div class="actions">
                <Show
                  when={!h().meta.deleted}
                  fallback={
                    <button type="button" class="btn primary" data-testid="host-restore" onClick={() => setDialog({ kind: "restore" })}>
                      <Icon name="undo" />
                      {t("ipam.do.restore")}
                    </button>
                  }
                >
                  <button type="button" class="btn" data-testid="host-edit" onClick={() => setDialog({ kind: "edit" })}>
                    <Icon name="settings" />
                    {t("ipam.do.edit")}
                  </button>
                  <button type="button" class="btn" data-testid="host-mode" aria-haspopup="menu" onClick={(e) => setModeMenu(e.currentTarget)}>
                    {t("hosts.do.set_mode")}
                    <Kbd keys={["Shift", "M"]} />
                  </button>
                  <button type="button" class="btn" data-testid="host-lock" aria-pressed={!!h().lock} onClick={() => void toggleLock()}>
                    <Icon name={h().lock ? "unlock" : "lock"} />
                    {h().lock ? t("hosts.do.unlock") : t("hosts.do.lock")}
                    <Kbd keys={["L"]} />
                  </button>
                  <button type="button" class="btn" data-testid="host-move" onClick={() => setDialog({ kind: "move" })}>
                    <Icon name="move" />
                    {t("ipam.do.move")}
                    <Kbd keys={["M"]} />
                  </button>
                  <button type="button" class="btn danger" data-testid="host-delete" onClick={() => setDialog({ kind: "delete" })}>
                    <Icon name="trash" />
                    {t("ipam.do.delete")}
                  </button>
                </Show>
              </div>
            </div>

            <div class="page-body detail-body host-body">
              <Show when={missing().mac || missing().duid}>
                <Notice kind="warn" role="status" title={t("hosts.warn.identifier_title")}>
                  <span
                    data-testid="host-identifier-warning"
                    data-key={missing().mac && missing().duid ? "mac+duid" : missing().mac ? "mac" : "duid"}
                  >
                    {missing().mac && missing().duid
                      ? t("hosts.warn.both")
                      : missing().mac
                        ? t("hosts.warn.mac")
                        : t("hosts.warn.duid")}
                  </span>
                </Notice>
              </Show>

              <section class="page-section" aria-labelledby="host-mode-title" data-testid="host-modes">
                <h2 id="host-mode-title">{t("hosts.mode.title")}</h2>
                <ul class="mode-list">
                  <For each={ASSIGNMENT_MODES}>
                    {(m) => (
                      <li classList={{ current: h().mode === m }} aria-current={h().mode === m ? "true" : undefined}>
                        <span class={`mode ${m}`}>{modeWord(m)}</span>
                        <span>{modeHint(m)}</span>
                        <Show when={h().mode === m}>
                          <span class="tag accent">{t("hosts.mode.current")}</span>
                        </Show>
                      </li>
                    )}
                  </For>
                </ul>
                <Show when={h().lock}>
                  <p class="muted">{t("hosts.mode.locked_note")}</p>
                </Show>
              </section>

              <section class="page-section" aria-labelledby="host-ifaces-title">
                <h2 id="host-ifaces-title">
                  {t("hosts.interfaces.title")}
                  <Show when={!h().meta.deleted}>
                    <button type="button" class="btn sm aside-btn" data-testid="interface-add" onClick={() => setDialog({ kind: "iface" })}>
                      <Icon name="plus" size="sm" />
                      {t("hosts.interfaces.add")}
                    </button>
                  </Show>
                </h2>
                <div class="host-grid">
                  <DataGrid
                    id="host-interfaces"
                    label={t("hosts.interfaces.title")}
                    noSelection
                    statusBar={false}
                    rows={interfaces()}
                    rowId={(i) => i.id}
                    rowKey={(i) => i.name}
                    loading={data.loading}
                    initial={!data()}
                    columns={[
                      { id: "name", header: () => t("hosts.col.interface"), width: 110, fixed: true, text: (i: Interface) => i.name, render: (i) => <span class="mono">{i.name}</span> },
                      { id: "mac", header: () => t("ipam.col.mac"), width: 170, render: (i) => <Show when={i.mac}>{(m) => <Mac value={m()} />}</Show> },
                      { id: "duid", header: () => t("hosts.col.duid"), width: 200, render: (i) => <span class="mono">{i.duid ?? ""}</span> },
                      {
                        id: "addresses",
                        header: () => t("hosts.col.addresses"),
                        render: (i) => (
                          <For each={addressesOf(i)}>
                            {(a) => (
                              <A href={paths.address(a.ip, a.vrf)} tabIndex={-1} class="addr-link">
                                <Addr value={a.ip} />
                              </A>
                            )}
                          </For>
                        ),
                      },
                      { id: "tags", header: () => t("ipam.col.tags"), width: 140, hidden: true, render: (i) => <Tags tags={i.meta.tags} /> },
                    ]}
                    onOpen={(i) => setDialog({ kind: "iface", iface: i })}
                    rowActions={[
                      { id: "edit", label: () => t("ipam.do.edit"), run: (i) => setDialog({ kind: "iface", iface: i }) },
                      { id: "delete", label: () => t("ipam.do.delete"), danger: true, run: (i) => setDialog({ kind: "iface_delete", iface: i }) },
                    ]}
                    empty={
                      <div class="empty">
                        <h3>{t("hosts.interfaces.empty")}</h3>
                      </div>
                    }
                  />
                </div>
              </section>

              <section class="page-section" aria-labelledby="host-addresses-title">
                <h2 id="host-addresses-title">{t("hosts.addresses.title")}</h2>
                <Show when={addresses().length > 0} fallback={<p class="muted">{t("hosts.addresses.none")}</p>}>
                  <ul class="plain-list">
                    <For each={addresses()}>
                      {(a) => (
                        <li data-key={a.ip}>
                          <A href={paths.address(a.ip, a.vrf)}>
                            <Addr value={a.ip} />
                          </A>{" "}
                          <span class="muted">{a.dns_name ?? ""}</span> <StatusBadge status={a.status} />
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </section>

              <section class="page-section" aria-labelledby="host-connect-title">
                <h2 id="host-connect-title">{t("hosts.connect.title")}</h2>
                <Connect host={h()} addresses={addresses()} />
                <CredentialSlot host={h()} />
              </section>

              <section class="page-section" aria-labelledby="host-facts-title">
                <h2 id="host-facts-title">{t("hosts.facts.title")}</h2>
                <dl class="kv">
                  <dt>{t("ipam.col.tenant")}</dt>
                  <dd>{tenantName(h().tenant)}</dd>
                  <dt>{t("ipam.col.site")}</dt>
                  <dd>{siteName(h().site) ?? "–"}</dd>
                  <dt>{t("ipam.col.description")}</dt>
                  <dd data-testid="host-description">{h().meta.description ?? "–"}</dd>
                  <dt>{t("ipam.col.tags")}</dt>
                  <dd data-testid="host-tags">
                    <Tags tags={h().meta.tags} max={10} />
                  </dd>
                  <dt>{t("ipam.col.updated")}</dt>
                  <dd>
                    <TimeAgo at={h().meta.updated.at} />
                  </dd>
                </dl>
                <CustomValues values={h().meta.custom} />
              </section>

              <section class="page-section" aria-labelledby="host-obs-title" data-testid="host-observations">
                <h2 id="host-obs-title">{t("hosts.observations.title")}</h2>
                <p class="muted">{t("hosts.observations.empty")}</p>
              </section>

              <section class="page-section" aria-labelledby="host-jobs-title">
                <h2 id="host-jobs-title">
                  {t("hosts.jobs.title")}
                  <A class="aside" href={paths.jobs({ target: `host/${h().id}` })}>
                    {t("hosts.jobs.all")}
                  </A>
                </h2>
                <Show when={(data()?.jobs.length ?? 0) > 0} fallback={<p class="muted">{t("hosts.jobs.none")}</p>}>
                  <ul class="plain-list">
                    <For each={data()?.jobs ?? []}>
                      {(j) => (
                        <li>
                          <JobStateChip state={j.state} done={j.steps_done} total={j.step_count} /> <A href={paths.job(j.id)}>{jobTitle(j)}</A>{" "}
                          <TimeAgo at={j.created.at} />
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </section>

              <section class="page-section" aria-labelledby="host-history-title">
                <h2 id="host-history-title">{t("ipam.prefix.tab.history")}</h2>
                <HistoryPanel collection="hosts" id={h().id} label={h().name} deleted={!!h().meta.deleted} revision={h().meta.revision} onRestored={() => void refetch()} />
              </section>
            </div>

            <Show when={modeMenu()}>
              {(anchor) => (
                <Menu
                  anchor={anchor()}
                  label={t("hosts.do.set_mode")}
                  testid="mode-menu"
                  onClose={() => setModeMenu(null)}
                  items={ASSIGNMENT_MODES.map((mode) => ({
                    id: mode,
                    label: modeWord(mode),
                    hint: modeHint(mode),
                    checked: h().mode === mode,
                    disabled: h().mode === mode,
                    run: () => setDialog({ kind: "mode", mode }),
                  }))}
                />
              )}
            </Show>
            <Show when={dialog()} keyed>
              {(d) => {
                switch (d.kind) {
                  case "edit":
                    return (
                      <HostForm
                        host={h()}
                        onClose={() => setDialog(null)}
                        onDone={(next) => {
                          setDialog(null);
                          if (next.name !== h().name) navigate(paths.host(next.name), { replace: true });
                          else void refetch();
                        }}
                      />
                    );
                  case "mode":
                    return (
                      <PlanDialog
                        title={t("hosts.mode.change_title", { name: h().name, mode: modeWord(d.mode) })}
                        confirmLabel={t("hosts.mode.change", { mode: modeWord(d.mode) })}
                        intro={<p class="muted">{modeHint(d.mode)}</p>}
                        testid="dialog-host-mode"
                        send={(o) =>
                          api.patch("/api/v1/hosts/{id}", {
                            path: { id: h().id },
                            query: writeQuery(o.dryRun, o.acknowledge),
                            body: { mode: d.mode },
                            ifMatch: h().meta.revision,
                          })
                        }
                        onClose={() => setDialog(null)}
                        onDone={(r) => {
                          setDialog(null);
                          writeToast(t("hosts.mode.changed", { name: h().name, mode: modeWord(d.mode) }), r);
                          void refetch();
                        }}
                      />
                    );
                  case "move":
                    return <MoveDialog tree={tree.tree()} items={[{ kind: "host", id: h().id, label: h().name }]} onClose={() => setDialog(null)} />;
                  case "delete":
                    return (
                      <DeleteDialog
                        collection="hosts"
                        id={h().id}
                        kind="host"
                        label={h().name}
                        revision={h().meta.revision}
                        cascade
                        onClose={() => setDialog(null)}
                        onDone={() => {
                          setDialog(null);
                          void refetch();
                        }}
                      />
                    );
                  case "restore":
                    return (
                      <RestoreDialog
                        collection="hosts"
                        id={h().id}
                        kind="host"
                        label={h().name}
                        revision={h().meta.revision}
                        onClose={() => setDialog(null)}
                        onDone={() => {
                          setDialog(null);
                          void refetch();
                        }}
                      />
                    );
                  case "iface":
                    return (
                      <InterfaceForm
                        host={h()}
                        iface={d.iface}
                        onClose={() => setDialog(null)}
                        onDone={() => {
                          setDialog(null);
                          void details.refetch();
                        }}
                      />
                    );
                  case "iface_delete":
                    return (
                      <DeleteDialog
                        collection="interfaces"
                        id={d.iface.id}
                        kind="interface"
                        label={`${h().name} ${d.iface.name}`}
                        revision={d.iface.meta.revision}
                        cascade
                        onClose={() => setDialog(null)}
                        onDone={() => {
                          setDialog(null);
                          void details.refetch();
                        }}
                      />
                    );
                }
              }}
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}
