// The pools and the exclusions of a scope. A pool is an IPAM range of role DHCP pool: it is made on
// the prefix's page in IPAM, and here it gets what DHCP adds (the classes it admits and its lease
// times). A DHCPv6 scope (WP9.2) lists its delegation pools, IPAM ranges of the role Delegation
// pool, in a section of their own below the address pools. An exclusion is an explicit range inside the scope's network that is never leased.
import { A } from "@solidjs/router";
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../api/live";
import { paths } from "../app/paths";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { DataGrid } from "../grid/DataGrid";
import type { Column, RowAction } from "../grid/types";
import { formatDuration, formatNumber, t } from "../i18n";
import { parseIp, rangeSize } from "../ipam/ip";
import { mayWriteDhcp } from "./access";
import {
  clearPool,
  createExclusion,
  deleteExclusion,
  getSettings,
  listClasses,
  listExclusions,
  listPools,
  setPool,
  type DhcpClass,
  type Exclusion,
  type Pool,
  type PoolSet,
  type Scope,
} from "./api";
import { LeaseChoice, leaseProblem } from "./LeaseFields";
import { checkExclusion, draftOfLease, isV6, leaseOfDraft, networkOf, rangeBits, type LeaseDraft, type LeaseField } from "./model";
import { describedBy, DhcpProblem, errorFor, Field, fieldErrors, hasField, unavailable } from "./Parts";
import { PdPools } from "./v6/PdPools";
import { V4Only } from "./v6/V4Only";
import { leaseWords, poolCountWords } from "./words";

const SERVER_LEASE = { default_secs: 86_400, min_secs: 3600, max_secs: 604_800 };

// ---------------------------------------------------------------------------------
// Pools

function PoolDialog(props: { pool: Pool; classes: readonly DhcpClass[]; /** A pool of a DHCPv6 scope admits no classes. */ v6?: boolean | undefined; onClose: () => void; onDone: () => void }) {
  const pool = untrack(() => props.pool);
  const [settings] = createResource(() => getSettings());
  const serverLease = () => (settings.error ? SERVER_LEASE : (settings.latest?.lease ?? SERVER_LEASE));
  const [admitted, setAdmitted] = createSignal<string[]>([...(pool.settings?.classes ?? [])]);
  const [inherit, setInherit] = createSignal(!pool.settings?.lease);
  const [lease, setLease] = createSignal<LeaseDraft>(draftOfLease(pool.settings?.lease ?? SERVER_LEASE));
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [leaseErrors, setLeaseErrors] = createSignal<Partial<Record<LeaseField, string>>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const toggleClass = (id: string, on: boolean) => setAdmitted((list) => (on ? [...list, id] : list.filter((x) => x !== id)));

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const body: PoolSet = { classes: admitted() };
    const le: Partial<Record<LeaseField, string>> = {};
    if (!inherit()) {
      const parsed = leaseOfDraft(lease(), pool.settings?.lease);
      if (parsed.ok) body.lease = parsed.lease;
      else le[parsed.field] = leaseProblem(parsed.problem);
    }
    setLeaseErrors(le);
    if (Object.keys(le).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      await setPool(pool, body);
      toast({ kind: "ok", title: t("dhcp.pool.saved", { first: pool.first, last: pool.last }) });
      props.onDone();
    } catch (err) {
      const fields = fieldErrors(err);
      if (hasField(fields, ["lease"])) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };
  const title = t("dhcp.pool.edit_title", { first: pool.first, last: pool.last });
  return (
    <Dialog label={title} onClose={props.onClose} class="dialog wide dhcp-dialog" testid="dialog-pool-form">
      <h2 class="dialog-title">{title}</h2>
      <form class="dialog-body dhcp-form" onSubmit={(e) => void submit(e)} novalidate>
        <Show when={!props.v6} fallback={<V4Only part="classes" />}>
          <fieldset class="dhcp-classes">
            <legend>{t("dhcp.pool.field.classes")}</legend>
            <Show when={props.classes.length > 0} fallback={<p class="muted">{t("dhcp.scope.no_classes")}</p>}>
              <For each={props.classes}>
                {(c) => (
                  <label class="choice">
                    <input type="checkbox" checked={admitted().includes(c.id)} data-testid="pool-class" data-key={c.name} onChange={(e) => toggleClass(c.id, e.currentTarget.checked)} />{" "}
                    <span class="mono">{c.name}</span>
                  </label>
                )}
              </For>
              <span class="help">{t("dhcp.pool.field.classes_help")}</span>
            </Show>
          </fieldset>
        </Show>
        <LeaseChoice
          id="lease"
          inherit={inherit()}
          onInherit={(on) => {
            setInherit(on);
            if (!on && !pool.settings?.lease) setLease(draftOfLease(serverLease()));
          }}
          value={lease()}
          onChange={setLease}
          errors={leaseErrors()}
          serverWords={t("dhcp.pool.lease_inherit_help")}
        />
        <Show when={errorFor(errors(), "lease")}>
          <span class="help bad" data-testid="field-error" data-field="lease">
            {errorFor(errors(), "lease")}
          </span>
        </Show>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dhcp.pool.save")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/** The lease time a pool serves with, in words: its own settings, else the range's, else the scope's. */
function poolLease(pool: Pool): string {
  if (pool.settings?.lease) return leaseWords(pool.settings.lease);
  if (pool.lease_secs) return t("dhcp.pool.lease_range", { lease: formatDuration(pool.lease_secs) });
  return t("dhcp.pool.lease_scope");
}

export function PoolsTab(props: { scope: Scope }) {
  const [dialog, setDialog] = createSignal<{ kind: "edit"; pool: Pool } | { kind: "clear"; pool: Pool } | null>(null);
  const query = createLiveQuery({
    topics: ["dhcp", "ipam"],
    fetch: async (signal) => {
      const page = await listPools(props.scope.prefix, signal);
      return { value: page.items, revision: page.revision };
    },
  });
  const [classes] = createResource(() => listClasses());
  const classList = () => (classes.error ? [] : (classes.latest?.items ?? []));
  const nameOf = (id: string) => classList().find((c) => c.id === id)?.name ?? id;
  const pools = () => latest(query);
  // WP9.2: the address pools and the delegation pools come in one list; the grid below lists the first.
  const addressPools = () => (pools() ?? []).filter((p) => p.role !== "dhcp_pd_pool");
  const delegationPools = () => (pools() ?? []).filter((p) => p.role === "dhcp_pd_pool");
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };
  const columns: Column<Pool>[] = [
    {
      id: "range",
      header: () => t("dhcp.col.range"),
      width: 260,
      fixed: true,
      text: (p) => `${p.first} – ${p.last}`,
      render: (p) => <span class="mono">{`${p.first} – ${p.last}`}</span>,
    },
    { id: "size", header: () => t("dhcp.col.size"), width: 100, align: "right", text: (p) => String(p.size), render: (p) => <span class="num" data-testid="pool-size" data-value={String(p.size)}>{poolCountWords(p.size, p.size >= 2 ** 32 ? rangeBits(p.first, p.last) : null)}</span> },
    { id: "leased", header: () => t("dhcp.col.leased"), width: 100, align: "right", text: (p) => String(p.leased), render: (p) => <span class="num">{formatNumber(p.leased)}</span> },
    { id: "lease", header: () => t("dhcp.col.lease"), width: 260, text: poolLease, render: (p) => <span>{poolLease(p)}</span> },
    {
      id: "classes",
      header: () => t("dhcp.col.classes"),
      text: (p) => (p.settings?.classes ?? []).map(nameOf).join(", "),
      render: (p) => (
        <span class="dhcp-chips">
          <For each={p.settings?.classes ?? []}>{(id) => <span class="tag mono">{nameOf(id)}</span>}</For>
        </span>
      ),
    },
  ];
  const actions: RowAction<Pool>[] = [
    { id: "edit", label: () => t("dhcp.pool.settings"), hidden: () => !mayWriteDhcp(), run: (p) => setDialog({ kind: "edit", pool: p }) },
    { id: "clear", label: () => t("dhcp.pool.clear"), danger: true, hidden: (p) => !mayWriteDhcp() || !p.settings, run: (p) => setDialog({ kind: "clear", pool: p }) },
  ];
  return (
    <div class="dhcp-tab" classList={{ "dhcp-tab-v6-pools": isV6(props.scope) }} data-testid="scope-pools">
      <Notice kind="info" testid="pools-note">
        {t("dhcp.pools.note")}{" "}
        <A href={paths.prefix(props.scope.cidr)} data-testid="pools-ipam-link">
          {t("dhcp.pools.ipam_link", { network: props.scope.cidr })}
        </A>
      </Notice>
      <Show when={isV6(props.scope)}>
        <h2 class="dhcp-subhead" data-testid="pools-address-title">
          {t("dhcp.pools.address_title")}
        </h2>
      </Show>
      <div class="dhcp-list-body" classList={{ "dhcp-list-body-v6": isV6(props.scope) }}>
        <DataGrid
          id="dhcp-pools"
          label={t("dhcp.pools.title")}
          noSelection
          columns={columns}
          rows={addressPools()}
          rowId={(p) => p.range}
          rowKey={(p) => `${p.first}-${p.last}`}
          rowLabel={(p) => `${p.first} – ${p.last}`}
          loading={query.value.loading}
          initial={pools() === undefined && !query.value.error}
          error={query.value.error}
          onRetry={query.refetch}
          onOpen={(p) => (mayWriteDhcp() ? setDialog({ kind: "edit", pool: p }) : undefined)}
          rowActions={actions}
          empty={
            <div class="empty" data-testid="dhcp-pools-empty">
              <h3>{t("dhcp.pools.empty")}</h3>
              <p>{t("dhcp.pools.empty_body")}</p>
            </div>
          }
        />
      </div>
      <Show when={isV6(props.scope)}>
        <PdPools
          scope={props.scope}
          pools={delegationPools()}
          loading={query.value.loading}
          initial={pools() === undefined && !query.value.error}
          error={query.value.error}
          onRetry={query.refetch}
          onChanged={query.refetch}
        />
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "edit" ? (
            <PoolDialog pool={d.pool} classes={classList()} v6={isV6(props.scope)} onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <ClearPoolDialog pool={d.pool} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}

function ClearPoolDialog(props: { pool: Pool; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dhcp.pool.clear_title", { first: props.pool.first, last: props.pool.last })}
      testid="dialog-pool-clear"
      danger
      busy={busy()}
      confirmLabel={t("dhcp.pool.clear")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        clearPool(props.pool)
          .then(() => {
            toast({ kind: "ok", title: t("dhcp.pool.cleared", { first: props.pool.first, last: props.pool.last }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dhcp.pool.clear_body")}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

// ---------------------------------------------------------------------------------
// Exclusions

function ExclusionDialog(props: { scope: Scope; onClose: () => void; onDone: () => void }) {
  let firstInput!: HTMLInputElement;
  const [first, setFirst] = createSignal("");
  const [last, setLast] = createSignal("");
  const [description, setDescription] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const problem = checkExclusion(first(), last(), networkOf(props.scope.cidr));
    if (problem) {
      setErrors({ [problem === "outside" || problem === "order" ? "last" : problem]: t(`dhcp.check.exclusion_${problem}`, { network: props.scope.cidr }) });
      return;
    }
    setErrors({});
    setBusy(true);
    setError(undefined);
    try {
      const a = parseIp(first());
      const b = parseIp(last());
      await createExclusion(props.scope.prefix, {
        first: first().trim(),
        last: last().trim(),
        ...(description().trim() !== "" ? { description: description().trim() } : {}),
      });
      toast({ kind: "ok", title: t("dhcp.exclusion.created", { count: a && b ? Number(rangeSize(a, b)) : 0 }) });
      props.onDone();
    } catch (err) {
      const fields = fieldErrors(err);
      if (hasField(fields, ["first", "last"])) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog label={t("dhcp.exclusion.create_title")} onClose={props.onClose} class="dialog dhcp-dialog" testid="dialog-exclusion-form" initialFocus={() => firstInput}>
      <h2 class="dialog-title">{t("dhcp.exclusion.create_title")}</h2>
      <form class="dialog-body dhcp-form" onSubmit={(e) => void submit(e)} novalidate>
        <p class="muted">{t("dhcp.exclusion.help", { network: props.scope.cidr })}</p>
        <div class="field-row">
          <Field id="first" label={t("dhcp.exclusion.field.first")} error={errorFor(errors(), "first")}>
            <input
              ref={firstInput}
              id="dhcp-f-first"
              class="input mono"
              value={first()}
              spellcheck={false}
              aria-invalid={errors().first ? "true" : undefined}
              aria-describedby={describedBy("first", errors().first)}
              data-testid="field-first"
              onInput={(e) => setFirst(e.currentTarget.value)}
            />
          </Field>
          <Field id="last" label={t("dhcp.exclusion.field.last")} error={errorFor(errors(), "last")}>
            <input
              id="dhcp-f-last"
              class="input mono"
              value={last()}
              spellcheck={false}
              aria-invalid={errors().last ? "true" : undefined}
              aria-describedby={describedBy("last", errors().last)}
              data-testid="field-last"
              onInput={(e) => setLast(e.currentTarget.value)}
            />
          </Field>
        </div>
        <Field id="description" label={t("dhcp.field.description")}>
          <input id="dhcp-f-description" class="input" value={description()} data-testid="field-description" onInput={(e) => setDescription(e.currentTarget.value)} />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dhcp.exclusion.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteExclusionDialog(props: { exclusion: Exclusion; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  const range = () => `${props.exclusion.first} – ${props.exclusion.last}`;
  return (
    <ConfirmDialog
      title={t("dhcp.exclusion.delete_title", { range: range() })}
      testid="dialog-exclusion-delete"
      danger
      busy={busy()}
      confirmLabel={t("dhcp.exclusion.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteExclusion(props.exclusion)
          .then(() => {
            toast({ kind: "ok", title: t("dhcp.exclusion.deleted", { range: range() }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dhcp.exclusion.delete_body")}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

export function ExclusionsTab(props: { scope: Scope }) {
  const [dialog, setDialog] = createSignal<{ kind: "add" } | { kind: "delete"; exclusion: Exclusion } | null>(null);
  const query = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const page = await listExclusions(props.scope.prefix, signal);
      return { value: page.items, revision: page.revision };
    },
  });
  const rows = () => latest(query);
  const blocked = () => unavailable(query.value.error);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };
  const size = (e: Exclusion) => {
    const a = parseIp(e.first);
    const b = parseIp(e.last);
    return a && b ? Number(rangeSize(a, b)) : 0;
  };
  // WP9.4: a DHCPv6 exclusion can span 2^32 addresses or more.
  const sizeWords = (e: Exclusion) => poolCountWords(size(e), rangeBits(e.first, e.last));
  const columns: Column<Exclusion>[] = [
    { id: "first", header: () => t("dhcp.col.first"), width: 180, fixed: true, text: (e) => e.first, render: (e) => <span class="mono">{e.first}</span> },
    { id: "last", header: () => t("dhcp.col.last"), width: 180, text: (e) => e.last, render: (e) => <span class="mono">{e.last}</span> },
    { id: "size", header: () => t("dhcp.col.size"), width: 100, align: "right", text: (e) => String(size(e)), render: (e) => <span class="num">{sizeWords(e)}</span> },
    { id: "description", header: () => t("dhcp.col.description"), render: (e) => <span class="muted">{e.description ?? ""}</span> },
  ];
  const actions: RowAction<Exclusion>[] = [
    { id: "delete", label: () => t("dhcp.do.delete"), danger: true, hidden: () => !mayWriteDhcp(), run: (e) => setDialog({ kind: "delete", exclusion: e }) },
  ];
  return (
    <div class="dhcp-tab" data-testid="scope-exclusions">
      <Show when={mayWriteDhcp() && !blocked()}>
        <div class="dhcp-actions">
          <button type="button" class="btn primary" data-testid="exclusion-add" onClick={() => setDialog({ kind: "add" })}>
            <Icon name="plus" />
            {t("dhcp.exclusion.create")}
          </button>
        </div>
      </Show>
      <Show when={!blocked()} fallback={<DhcpProblem error={query.value.error} />}>
        <div class="dhcp-list-body">
          <DataGrid
            id="dhcp-exclusions"
            label={t("dhcp.exclusions.title")}
            noSelection
            columns={columns}
            rows={rows() ?? []}
            rowId={(e) => e.id}
            rowKey={(e) => `${e.first}-${e.last}`}
            rowLabel={(e) => `${e.first} – ${e.last}`}
            loading={query.value.loading}
            initial={rows() === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dhcp-exclusions-empty">
                <h3>{t("dhcp.exclusions.empty")}</h3>
                <p>{t("dhcp.exclusions.empty_body")}</p>
              </div>
            }
          />
        </div>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "add" ? (
            <ExclusionDialog scope={props.scope} onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <DeleteExclusionDialog exclusion={d.exclusion} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
