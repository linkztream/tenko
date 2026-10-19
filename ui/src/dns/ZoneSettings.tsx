// The settings and history tabs of the zone page. Settings: the SOA values, the serial policy,
// the description and, for a stub, secondary or forward zone, the servers of `source` (one PATCH
// with the zone's revision) and the NS RRset of the apex (one batch change), saved together.
// WP6.1 adds the zone transfers (every kind but stub and forward): who may transfer the zone,
// the NOTIFY targets, TSIG and XoT, the catalog flag, and for a secondary zone its primaries as
// rows and the transfer state with "Transfer now"; a secondary zone keeps its SOA and name
// servers from the primary, so they are shown and never sent. History: the serial served now,
// the last change, and the newest audit records of the zone for those who read the audit log
// (until a journal route exists, the lead's decision for WP4.5).
// WP6.2 adds the dynamic updates of a primary zone: the access lists that may update it, TSIG,
// whether updates may replace what IPAM manages, and the profile's rule beside them.
import { A } from "@solidjs/router";
import { createEffect, createMemo, createResource, createSignal, For, Index, onCleanup, onMount, Show, untrack } from "solid-js";
import { ApiError, errorMessage } from "../api/problem";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { formatDateTime, t, type MessageKey } from "../i18n";
import { parseIp } from "../ipam/ip";
import {
  changeRecords,
  getZoneTransfer,
  listAcls,
  listRecords,
  SERIAL_POLICIES,
  serialPolicy,
  servedSerial,
  triggerZoneTransfer,
  updateZone,
  zoneAudit,
  type Acl,
  type NotifyTarget,
  type PrimaryServer,
  type SerialPolicy,
  type SoaDefaults,
  type TransferPolicy,
  type TransferStatus,
  type Zone,
  type ZonePatch,
} from "./api";
import { mayWriteDns } from "./access";
import { canonical, hasSource, parseTtl, splitList, targetName, validName } from "./model";
import { parseUpstream, upstreamText } from "./forwarders/model";
import { describedBy, Field, fieldErrors } from "./Parts";
import { paths } from "../app/paths";
import { session } from "../auth/session";

const SOA_NUMBERS = ["refresh", "retry", "expire", "minimum", "ttl"] as const;
type SoaNumber = (typeof SOA_NUMBERS)[number];

/**
 * The typed servers as the zone keeps them; a server that was there before keeps its other
 * settings (key, TLS name, XoT). Null when an entry does not parse.
 */
function sourceServers(text: string, before: readonly PrimaryServer[]): PrimaryServer[] | null {
  const out: PrimaryServer[] = [];
  for (const entry of splitList(text)) {
    const parsed = parseUpstream(entry, "plain");
    if (!parsed.ok) return null;
    const port = parsed.upstream.port ?? 53;
    const kept = before.find((p) => p.address === parsed.upstream.address && (p.port || 53) === port);
    out.push(kept ? { ...kept, port } : { address: parsed.upstream.address, port });
  }
  return out;
}

// ---------------------------------------------------------------------------------
// Zone transfers (WP6.1)

const DNS_PORT = 53;

/** A port as typed: empty is the DNS port, otherwise a whole number from 1 to 65535. */
function parsePort(text: string): number | null {
  const s = text.trim();
  if (s === "") return DNS_PORT;
  if (!/^\d{1,5}$/.test(s)) return null;
  const n = Number(s);
  return n >= 1 && n <= 65_535 ? n : null;
}

interface NotifyRow {
  address: string;
  port: string;
  key: string;
}

interface PrimaryRow extends NotifyRow {
  xot: boolean;
  tls_name: string;
}

/** The policy as the form edits it: every default filled in, so two policies compare as text. */
function policyOf(policy: TransferPolicy | undefined) {
  return {
    allow: [...(policy?.allow ?? [])],
    notify: (policy?.notify ?? []).map((n) => ({ address: n.address, port: n.port ?? DNS_PORT, key: n.key ?? "" })),
    require_tsig: policy?.require_tsig ?? true,
    xot: policy?.xot ?? false,
  };
}

function primariesOf(primaries: readonly PrimaryServer[]) {
  return primaries.map((p) => ({ address: p.address, port: p.port ?? DNS_PORT, key: p.key ?? "", xot: p.xot ?? false, tls_name: p.tls_name ?? "" }));
}

const rowOf = (n: { address: string; port: number; key: string }): NotifyRow => ({ address: n.address, port: String(n.port), key: n.key });

/**
 * The transfer part of the settings form: the policy, the catalog flag and, for a secondary zone,
 * its primaries, as signals, with the local checks and the part of the PATCH that changed.
 * `rebase` takes the saved zone as the new state to compare against.
 */
function createTransferDraft(zone: Zone) {
  let policy0 = policyOf(zone.transfer);
  let catalog0 = zone.catalog ?? false;
  let primaries0 = primariesOf(zone.source?.primaries ?? []);
  const [allow, setAllow] = createSignal<string[]>(policy0.allow);
  const [notify, setNotify] = createSignal<NotifyRow[]>(policy0.notify.map(rowOf));
  const [requireTsig, setRequireTsig] = createSignal(policy0.require_tsig);
  const [xot, setXot] = createSignal(policy0.xot);
  const [catalog, setCatalog] = createSignal(catalog0);
  const [primaries, setPrimaries] = createSignal<PrimaryRow[]>(primaries0.map((p) => ({ ...rowOf(p), xot: p.xot, tls_name: p.tls_name })));

  const checkRow = (kind: "notify" | "primaries", i: number, row: NotifyRow, errors: Record<string, string>) => {
    if (parseIp(row.address) === null) errors[`${kind}.${i}.address`] = t("dns.transfer.check.address");
    if (parsePort(row.port) === null) errors[`${kind}.${i}.port`] = t("dns.transfer.check.port");
    const key = canonical(row.key);
    if (key !== "" && !validName(key)) errors[`${kind}.${i}.key`] = t("dns.transfer.check.key");
  };

  /** The errors by field id; empty when the form may be sent. */
  const check = (secondary: boolean, transferable: boolean): Record<string, string> => {
    const errors: Record<string, string> = {};
    if (transferable) notify().forEach((row, i) => checkRow("notify", i, row, errors));
    if (secondary) {
      if (primaries().length === 0) errors.primaries = t("dns.zone.create.primaries_required");
      primaries().forEach((row, i) => {
        checkRow("primaries", i, row, errors);
        const tls = canonical(row.tls_name);
        if (tls !== "" && !validName(tls)) errors[`primaries.${i}.tls_name`] = t("dns.transfer.check.tls_name");
      });
    }
    return errors;
  };

  const notifyTargets = (): NotifyTarget[] =>
    notify().map((row) => {
      const key = canonical(row.key);
      return { address: row.address.trim(), port: parsePort(row.port) ?? DNS_PORT, ...(key ? { key } : {}) };
    });

  const primaryServers = (): PrimaryServer[] =>
    primaries().map((row) => {
      const key = canonical(row.key);
      const tls = canonical(row.tls_name);
      return { address: row.address.trim(), port: parsePort(row.port) ?? DNS_PORT, ...(key ? { key } : {}), xot: row.xot, ...(tls ? { tls_name: tls } : {}) };
    });

  /** Adds what changed to `patch`: `transfer`, `catalog` and, for a secondary zone, `source`; call after `check`. */
  const fill = (patch: ZonePatch, secondary: boolean, transferable: boolean) => {
    if (transferable) {
      const targets = notifyTargets();
      const now = policyOf({ allow: allow(), notify: targets, require_tsig: requireTsig(), xot: xot() });
      if (JSON.stringify(now) !== JSON.stringify(policy0)) {
        patch.transfer = { allow: now.allow, notify: targets, require_tsig: now.require_tsig, xot: now.xot };
      }
      if (catalog() !== catalog0) patch.catalog = catalog();
    }
    if (secondary) {
      const servers = primaryServers();
      if (JSON.stringify(primariesOf(servers)) !== JSON.stringify(primaries0)) patch.source = { primaries: servers };
    }
  };

  const rebase = (saved: Zone) => {
    policy0 = policyOf(saved.transfer);
    catalog0 = saved.catalog ?? false;
    primaries0 = primariesOf(saved.source?.primaries ?? []);
  };

  return {
    allow,
    addAllow: (id: string) => setAllow((ids) => (ids.includes(id) ? ids : [...ids, id])),
    removeAllow: (id: string) => setAllow((ids) => ids.filter((x) => x !== id)),
    notify,
    addNotify: () => setNotify((rows) => [...rows, { address: "", port: "", key: "" }]),
    editNotify: (i: number, change: Partial<NotifyRow>) => setNotify((rows) => rows.map((row, j) => (j === i ? { ...row, ...change } : row))),
    removeNotify: (i: number) => setNotify((rows) => rows.filter((_, j) => j !== i)),
    requireTsig,
    setRequireTsig,
    xot,
    setXot,
    catalog,
    setCatalog,
    primaries,
    addPrimary: () => setPrimaries((rows) => [...rows, { address: "", port: "", key: "", xot: false, tls_name: "" }]),
    editPrimary: (i: number, change: Partial<PrimaryRow>) => setPrimaries((rows) => rows.map((row, j) => (j === i ? { ...row, ...change } : row))),
    removePrimary: (i: number) => setPrimaries((rows) => rows.filter((_, j) => j !== i)),
    check,
    fill,
    rebase,
  };
}

type TransferDraft = ReturnType<typeof createTransferDraft>;

/** The text of the stable code a transfer failed with. */
const TRANSFER_ERRORS: Readonly<Record<string, MessageKey>> = {
  "dns.transfer.failed": "dns.transfer.error.failed",
  "dns.transfer.tsig": "dns.transfer.error.tsig",
  "dns.transfer.refused": "dns.transfer.error.refused",
};

/** One labelled text input of a row (a NOTIFY target, a primary). */
function RowInput(props: {
  id: string;
  label: string;
  value: string;
  error: string | undefined;
  disabled: boolean;
  placeholder?: string;
  onInput: (value: string) => void;
}) {
  return (
    <Field id={props.id} label={props.label} error={props.error}>
      <input
        id={`dns-f-${props.id}`}
        class="input mono"
        value={props.value}
        disabled={props.disabled}
        spellcheck={false}
        placeholder={props.placeholder}
        aria-invalid={props.error ? "true" : undefined}
        aria-describedby={describedBy(props.id, props.error)}
        data-testid={`field-${props.id}`}
        onInput={(e) => props.onInput(e.currentTarget.value)}
      />
    </Field>
  );
}

/** A checkbox with its help line. */
function Check(props: { id: string; label: string; help: string; checked: boolean; disabled: boolean; onChange: (value: boolean) => void }) {
  return (
    <div class="field">
      <label class="choice">
        <input
          type="checkbox"
          id={`dns-f-${props.id}`}
          checked={props.checked}
          disabled={props.disabled}
          aria-describedby={`dns-f-${props.id}-help`}
          data-testid={`field-${props.id}`}
          onChange={(e) => props.onChange(e.currentTarget.checked)}
        />{" "}
        <span>{props.label}</span>
      </label>
      <span class="help" id={`dns-f-${props.id}-help`}>
        {props.help}
      </span>
    </div>
  );
}

/** The primaries of a secondary zone, one row each. */
function PrimaryRows(props: { draft: TransferDraft; errors: Record<string, string>; disabled: boolean }) {
  return (
    <div class="field" role="group" aria-labelledby="dns-primaries-label" data-testid="zone-primaries">
      <span id="dns-primaries-label" class="label">
        {t("dns.zone.field.primaries")}
      </span>
      <Show when={props.errors.primaries}>
        {(message) => (
          <span class="help bad" data-testid="field-error" data-field="primaries">
            {message()}
          </span>
        )}
      </Show>
      <Index each={props.draft.primaries()}>
        {(row, i) => (
          <div class="field-row" data-testid="transfer-primary-row" data-index={i}>
            <RowInput
              id={`primaries.${i}.address`}
              label={t("dns.transfer.address")}
              value={row().address}
              error={props.errors[`primaries.${i}.address`]}
              disabled={props.disabled}
              placeholder="192.0.2.53"
              onInput={(address) => props.draft.editPrimary(i, { address })}
            />
            <RowInput
              id={`primaries.${i}.port`}
              label={t("dns.transfer.port")}
              value={row().port}
              error={props.errors[`primaries.${i}.port`]}
              disabled={props.disabled}
              placeholder="53"
              onInput={(port) => props.draft.editPrimary(i, { port })}
            />
            <RowInput
              id={`primaries.${i}.key`}
              label={t("dns.transfer.key")}
              value={row().key}
              error={props.errors[`primaries.${i}.key`]}
              disabled={props.disabled}
              onInput={(key) => props.draft.editPrimary(i, { key })}
            />
            <RowInput
              id={`primaries.${i}.tls_name`}
              label={t("dns.transfer.tls_name")}
              value={row().tls_name}
              error={props.errors[`primaries.${i}.tls_name`]}
              disabled={props.disabled}
              onInput={(tls_name) => props.draft.editPrimary(i, { tls_name })}
            />
            <div class="field">
              <label class="choice">
                <input
                  type="checkbox"
                  checked={row().xot}
                  disabled={props.disabled}
                  data-testid={`field-primaries.${i}.xot`}
                  onChange={(e) => props.draft.editPrimary(i, { xot: e.currentTarget.checked })}
                />{" "}
                <span>{t("dns.transfer.xot_short")}</span>
              </label>
            </div>
            <Show when={!props.disabled}>
              <button
                type="button"
                class="icon-btn"
                aria-label={t("dns.transfer.primary_remove", { n: i + 1 })}
                data-testid="transfer-primary-remove"
                data-index={i}
                onClick={() => props.draft.removePrimary(i)}
              >
                <Icon name="x" size="xs" />
              </button>
            </Show>
          </div>
        )}
      </Index>
      <Show when={!props.disabled}>
        <div>
          <button type="button" class="btn sm" data-testid="transfer-primary-add" onClick={() => props.draft.addPrimary()}>
            <Icon name="plus" size="sm" />
            {t("dns.transfer.primary_add")}
          </button>
        </div>
      </Show>
    </div>
  );
}

/** The access lists that may transfer the zone, as chips by name, and a select that adds one. */
function AllowChips(props: { draft: TransferDraft; disabled: boolean }) {
  const [acls] = createResource(() => listAcls().then((all) => all.items).catch((): Acl[] => []));
  const known = (): Acl[] => (acls.state === "ready" ? acls() ?? [] : []);
  const nameOf = (id: string) => known().find((a) => a.id === id)?.name ?? id;
  const free = () => known().filter((a) => !props.draft.allow().includes(a.id));
  return (
    <div class="field" role="group" aria-labelledby="dns-allow-label" data-testid="transfer-allow-list">
      <span id="dns-allow-label" class="label">
        {t("dns.transfer.allow")}
      </span>
      <Show
        when={props.draft.allow().length > 0}
        fallback={
          <p class="muted" data-testid="transfer-allow-none">
            {t("dns.transfer.allow_none")}
          </p>
        }
      >
        <ul class="dns-draft" aria-label={t("dns.transfer.allow")}>
          <For each={props.draft.allow()}>
            {(id) => (
              <li data-testid="transfer-allow" data-key={id}>
                <span>{nameOf(id)}</span>
                <button
                  type="button"
                  class="icon-btn"
                  aria-label={t("dns.transfer.allow_remove", { name: nameOf(id) })}
                  data-testid="transfer-allow-remove"
                  disabled={props.disabled}
                  onClick={() => props.draft.removeAllow(id)}
                >
                  <Icon name="x" size="xs" />
                </button>
              </li>
            )}
          </For>
        </ul>
      </Show>
      <select
        class="select"
        aria-label={t("dns.transfer.allow_add")}
        aria-describedby="dns-f-allow-help"
        value=""
        disabled={props.disabled || free().length === 0}
        data-testid="field-allow-add"
        onChange={(e) => {
          if (e.currentTarget.value) props.draft.addAllow(e.currentTarget.value);
          e.currentTarget.value = "";
        }}
      >
        <option value="">{t("dns.transfer.allow_add")}</option>
        <For each={free()}>{(a) => <option value={a.id}>{a.name}</option>}</For>
      </select>
      <span class="help" id="dns-f-allow-help">
        {t("dns.transfer.allow_help")}
      </span>
    </div>
  );
}

/** The transfer section of a zone that is not a stub or forward zone. */
function TransferSection(props: { zone: Zone; draft: TransferDraft; errors: Record<string, string>; disabled: boolean }) {
  return (
    <section class="page-section" aria-labelledby="dns-transfer-title" data-testid="zone-transfer">
      <h2 id="dns-transfer-title">{t("dns.transfer.title")}</h2>
      <p>{t("dns.transfer.body")}</p>
      <Show when={props.zone.kind === "secondary"}>
        <TransferState zone={props.zone} />
      </Show>
      <AllowChips draft={props.draft} disabled={props.disabled} />
      <div class="field" role="group" aria-labelledby="dns-notify-label" data-testid="transfer-notify-list">
        <span id="dns-notify-label" class="label">
          {t("dns.transfer.notify")}
        </span>
        <Show when={props.draft.notify().length === 0}>
          <p class="muted" data-testid="transfer-notify-none">
            {t("dns.transfer.notify_none")}
          </p>
        </Show>
        <Index each={props.draft.notify()}>
          {(row, i) => (
            <div class="field-row" data-testid="transfer-notify" data-index={i}>
              <RowInput
                id={`notify.${i}.address`}
                label={t("dns.transfer.address")}
                value={row().address}
                error={props.errors[`notify.${i}.address`]}
                disabled={props.disabled}
                placeholder="192.0.2.54"
                onInput={(address) => props.draft.editNotify(i, { address })}
              />
              <RowInput
                id={`notify.${i}.port`}
                label={t("dns.transfer.port")}
                value={row().port}
                error={props.errors[`notify.${i}.port`]}
                disabled={props.disabled}
                placeholder="53"
                onInput={(port) => props.draft.editNotify(i, { port })}
              />
              <RowInput
                id={`notify.${i}.key`}
                label={t("dns.transfer.key")}
                value={row().key}
                error={props.errors[`notify.${i}.key`]}
                disabled={props.disabled}
                  onInput={(key) => props.draft.editNotify(i, { key })}
              />
              <Show when={!props.disabled}>
                <button
                  type="button"
                  class="icon-btn"
                  aria-label={t("dns.transfer.notify_remove", { n: i + 1 })}
                  data-testid="transfer-notify-remove"
                  data-index={i}
                  onClick={() => props.draft.removeNotify(i)}
                >
                  <Icon name="x" size="xs" />
                </button>
              </Show>
            </div>
          )}
        </Index>
        <Show when={!props.disabled}>
          <div>
            <button type="button" class="btn sm" data-testid="transfer-notify-add" onClick={() => props.draft.addNotify()}>
              <Icon name="plus" size="sm" />
              {t("dns.transfer.notify_add")}
            </button>
          </div>
        </Show>
      </div>
      <Check
        id="require_tsig"
        label={t("dns.transfer.require_tsig")}
        help={t("dns.transfer.require_tsig_help")}
        checked={props.draft.requireTsig()}
        disabled={props.disabled}
        onChange={props.draft.setRequireTsig}
      />
      <Check id="xot" label={t("dns.transfer.xot")} help={t("dns.transfer.xot_help")} checked={props.draft.xot()} disabled={props.disabled} onChange={props.draft.setXot} />
      <Check
        id="catalog"
        label={t("dns.transfer.catalog")}
        help={t(`dns.transfer.catalog_help_${props.zone.kind === "primary" || props.zone.kind === "secondary" ? props.zone.kind : "other"}`)}
        checked={props.draft.catalog()}
        disabled={props.disabled}
        onChange={props.draft.setCatalog}
      />
    </section>
  );
}

/** The transfer state of a secondary zone: the serial held, the timers, each primary, and "Transfer now". */
function TransferState(props: { zone: Zone }) {
  const id = untrack(() => props.zone.id);
  const [status, setStatus] = createSignal<TransferStatus>();
  const [problem, setProblem] = createSignal<unknown>();
  const [loading, setLoading] = createSignal(true);
  const [busy, setBusy] = createSignal(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let polls = 0;
  onCleanup(() => clearTimeout(timer));
  onMount(() => {
    getZoneTransfer(id)
      .then(setStatus)
      .catch(setProblem)
      .finally(() => setLoading(false));
  });
  // While a transfer runs, read the state again every second, at most half a minute.
  createEffect(() => {
    clearTimeout(timer);
    if (status()?.running && polls < 30) {
      timer = setTimeout(() => {
        polls += 1;
        getZoneTransfer(id).then(setStatus).catch(setProblem);
      }, 1000);
    }
  });
  const quiet = () => {
    const err = problem();
    return err instanceof ApiError && (err.status === 404 || err.status === 501);
  };
  const transferNow = async () => {
    setBusy(true);
    try {
      polls = 0;
      setProblem(undefined);
      setStatus(await triggerZoneTransfer(id));
      toast({ kind: "ok", title: t("dns.transfer.queued", { name: props.zone.name }) });
    } catch (err) {
      toast({ kind: "bad", title: t("dns.transfer.not_queued"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div data-testid="zone-transfer-status" aria-live="polite">
      <h3>{t("dns.transfer.status")}</h3>
      <Show
        when={status()}
        fallback={
          <Show when={problem()} fallback={<p class="muted">{loading() ? t("common.loading") : ""}</p>}>
            {(err) => (
              <Show when={quiet()} fallback={<ErrorNotice error={err()} />}>
                <Notice kind="info" role="status" testid="zone-transfer-unavailable">
                  {t("dns.transfer.unavailable")}
                </Notice>
              </Show>
            )}
          </Show>
        }
      >
        {(s) => (
          <>
            <dl class="kv">
              <dt>{t("dns.transfer.serial")}</dt>
              <dd class="mono" data-testid="transfer-serial" data-key={String(s().serial ?? "")}>
                {s().serial ?? "–"}
              </dd>
              <dt>{t("dns.transfer.next_refresh")}</dt>
              <dd data-testid="transfer-next-refresh">
                <TimeAgo at={s().next_refresh} />
              </dd>
              <dt>{t("dns.transfer.expires")}</dt>
              <dd data-testid="transfer-expires">
                <TimeAgo at={s().expires} />
              </dd>
              <dt>{t("dns.transfer.state")}</dt>
              <dd data-testid="transfer-running" data-state={s().running ? "running" : "idle"}>
                {s().running ? t("dns.transfer.state_running") : t("dns.transfer.state_idle")}
              </dd>
            </dl>
            <div class="table-wrap">
              <table class="plain">
                <thead>
                  <tr>
                    <th>{t("dns.transfer.primary")}</th>
                    <th>{t("dns.transfer.last_success")}</th>
                    <th>{t("dns.transfer.last_error")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={s().primaries}>
                    {(p) => (
                      <tr data-testid="transfer-primary" data-key={p.address}>
                        <td class="mono">{p.address}</td>
                        <td data-testid="transfer-last-success">
                          <TimeAgo at={p.last_success} />
                        </td>
                        <td data-testid="transfer-last-error" data-code={p.last_error ?? ""}>
                          <Show when={p.last_error} fallback={<span class="muted">–</span>}>
                            {(code) => (
                              <>
                                <code>{code()}</code>
                                <Show when={TRANSFER_ERRORS[code()]}>{(key) => <> {t(key())}</>}</Show>
                              </>
                            )}
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </>
        )}
      </Show>
      <Show when={mayWriteDns() && !quiet()}>
        <div class="form-row">
          <button type="button" class="btn" data-testid="transfer-now" disabled={busy() || status()?.running === true} onClick={() => void transferNow()}>
            {t("dns.transfer.now")}
          </button>
        </div>
      </Show>
    </div>
  );
}

// ---------------------------------------------------------------------------------
// WP6.2: dynamic updates (RFC 2136). Who may update a primary zone: the access lists of
// `update.allowed` (none means nobody), whether a TSIG key is required, and whether updates may
// replace the records IPAM manages; the profile's rule (TGL-09) is explained beside them.

type UpdatePolicy = NonNullable<ZonePatch["update"]>;

/** The update policy as the form edits it, every default filled in. */
function updatePolicyOf(policy: UpdatePolicy | null | undefined) {
  return {
    allowed: [...(policy?.allowed ?? [])],
    require_tsig: policy?.require_tsig ?? true,
    may_replace_ipam: policy?.may_replace_ipam ?? false,
  };
}

/** The update part of the settings form, with the part of the PATCH that changed. */
function createUpdateDraft(zone: Zone) {
  let policy0 = updatePolicyOf(zone.update);
  const [allowed, setAllowed] = createSignal<string[]>(policy0.allowed);
  const [requireTsig, setRequireTsig] = createSignal(policy0.require_tsig);
  const [mayReplaceIpam, setMayReplaceIpam] = createSignal(policy0.may_replace_ipam);
  const fill = (patch: ZonePatch) => {
    const now = updatePolicyOf({ allowed: allowed(), require_tsig: requireTsig(), may_replace_ipam: mayReplaceIpam() });
    if (JSON.stringify(now) !== JSON.stringify(policy0)) patch.update = now;
  };
  return {
    allowed,
    addAllowed: (id: string) => setAllowed((ids) => (ids.includes(id) ? ids : [...ids, id])),
    removeAllowed: (id: string) => setAllowed((ids) => ids.filter((x) => x !== id)),
    requireTsig,
    setRequireTsig,
    mayReplaceIpam,
    setMayReplaceIpam,
    fill,
    rebase: (saved: Zone) => {
      policy0 = updatePolicyOf(saved.update);
    },
  };
}

type UpdateDraft = ReturnType<typeof createUpdateDraft>;

/** The profile in force, as TGL-09 names it. */
function profileInForce(): "home" | "standard" | "hardened" | "lab" {
  const p = session()?.profile;
  return p === "standard" || p === "hardened" || p === "lab" ? p : "home";
}

/** The update section of a primary zone. */
function UpdateSection(props: { draft: UpdateDraft; disabled: boolean }) {
  const [acls] = createResource(() => listAcls().then((all) => all.items).catch((): Acl[] => []));
  const known = (): Acl[] => (acls.state === "ready" ? acls() ?? [] : []);
  const nameOf = (id: string) => known().find((a) => a.id === id)?.name ?? id;
  const free = () => known().filter((a) => !props.draft.allowed().includes(a.id));
  const profile = profileInForce;
  const profileName = () => t(`profile.${profile()}.name`);
  // Hardened and Lab hold their rule for the signature whatever the zone says (TGL-09).
  const signatureHelp = () => {
    const p = profile();
    const rule = p === "hardened" ? t("dns.update.require_tsig_hardened", { profile: profileName() }) : p === "lab" ? t("dns.update.require_tsig_lab", { profile: profileName() }) : "";
    return rule ? `${t("dns.update.require_tsig_help")} ${rule}` : t("dns.update.require_tsig_help");
  };
  return (
    <section class="page-section" aria-labelledby="dns-update-title" data-testid="zone-update" data-key={profile()}>
      <h2 id="dns-update-title">{t("dns.update.title")}</h2>
      <p>{t("dns.update.body")}</p>
      <div class="field" role="group" aria-labelledby="dns-update-allow-label" data-testid="update-allow-list">
        <span id="dns-update-allow-label" class="label">
          {t("dns.update.allow")}
        </span>
        <Show
          when={props.draft.allowed().length > 0}
          fallback={
            <p class="muted" data-testid="update-allow-none">
              {t("dns.update.allow_none")} {t(`dns.update.default_${profile()}`, { profile: profileName() })}
            </p>
          }
        >
          <ul class="dns-draft" aria-label={t("dns.update.allow")}>
            <For each={props.draft.allowed()}>
              {(id) => (
                <li data-testid="update-allow" data-key={id}>
                  <span>{nameOf(id)}</span>
                  <button
                    type="button"
                    class="icon-btn"
                    aria-label={t("dns.update.allow_remove", { name: nameOf(id) })}
                    data-testid="update-allow-remove"
                    disabled={props.disabled}
                    onClick={() => props.draft.removeAllowed(id)}
                  >
                    <Icon name="x" size="xs" />
                  </button>
                </li>
              )}
            </For>
          </ul>
        </Show>
        <select
          class="select"
          aria-label={t("dns.update.allow_add")}
          aria-describedby="dns-f-update-allow-help"
          value=""
          disabled={props.disabled || free().length === 0}
          data-testid="field-update-allow-add"
          onChange={(e) => {
            if (e.currentTarget.value) props.draft.addAllowed(e.currentTarget.value);
            e.currentTarget.value = "";
          }}
        >
          <option value="">{t("dns.update.allow_add")}</option>
          <For each={free()}>{(a) => <option value={a.id}>{a.name}</option>}</For>
        </select>
        <span class="help" id="dns-f-update-allow-help">
          {t("dns.update.allow_help")}
        </span>
      </div>
      <Check
        id="update.require_tsig"
        label={t("dns.update.require_tsig")}
        help={signatureHelp()}
        checked={props.draft.requireTsig()}
        disabled={props.disabled}
        onChange={props.draft.setRequireTsig}
      />
      <Check
        id="update.may_replace_ipam"
        label={t("dns.update.may_replace_ipam")}
        help={t("dns.update.may_replace_ipam_help")}
        checked={props.draft.mayReplaceIpam()}
        disabled={props.disabled}
        onChange={props.draft.setMayReplaceIpam}
      />
    </section>
  );
}

export function SettingsTab(props: { zone: Zone; onSaved: (zone: Zone) => void }) {
  const zone = untrack(() => props.zone);
  const readOnly = () => !mayWriteDns();
  // WP6.1: a secondary zone takes its SOA and name servers from the primary (shown, never sent);
  // a stub and a forward zone have no transfers.
  const secondary = zone.kind === "secondary";
  const transferable = zone.kind !== "stub" && zone.kind !== "forward";
  const textSource = hasSource(zone.kind) && !secondary;
  const draft = createTransferDraft(zone);
  // WP6.2: dynamic updates, for a primary zone.
  const updatable = zone.kind === "primary";
  const updateDraft = createUpdateDraft(zone);
  const [mname, setMname] = createSignal(zone.soa.mname);
  const [rname, setRname] = createSignal(zone.soa.rname);
  const [numbers, setNumbers] = createSignal<Record<SoaNumber, string>>({
    refresh: String(zone.soa.refresh ?? 3600),
    retry: String(zone.soa.retry ?? 900),
    expire: String(zone.soa.expire ?? 1_209_600),
    minimum: String(zone.soa.minimum ?? 300),
    ttl: String(zone.soa.ttl ?? 3600),
  });
  const [policy, setPolicy] = createSignal<SerialPolicy>(serialPolicy(zone));
  const [description, setDescription] = createSignal(zone.description ?? "");
  // The servers a stub zone asks for its NS set (or a secondary zone transfers from), as typed.
  const sourceBefore = (zone.source?.primaries ?? []).map((p) => upstreamText({ address: p.address, port: p.port || null })).join(", ");
  const [source, setSource] = createSignal(sourceBefore);
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  // The NS RRset of the apex, edited as a list of host names.
  const [apexNs] = createResource(() => listRecords(zone.id, { name: zone.name, type: "NS" }).then((sets) => sets.find((s) => s.name === zone.name && s.type === "NS")));
  const [servers, setServers] = createSignal<string | null>(null);
  const serverText = createMemo(() => servers() ?? (apexNs.latest?.records ?? []).map((r) => (r.type === "NS" ? r.host : "")).join(", "));

  const save = async (event: Event) => {
    event.preventDefault();
    if (busy() || readOnly()) return;
    const e: Record<string, string> = {};
    const hosts = splitList(serverText()).map((h) => targetName(h, zone.name));
    if (!secondary) {
      if (!validName(canonical(mname()))) e["soa.mname"] = t("dns.check.name");
      if (!validName(canonical(rname()))) e["soa.rname"] = t("dns.check.name");
      for (const key of SOA_NUMBERS) if (parseTtl(numbers()[key]) === null) e[`soa.${key}`] = t("dns.check.number");
      if (hosts.length === 0 || hosts.some((h) => !validName(h))) e.name_servers = t("dns.settings.ns_required");
    }
    const servers = textSource ? sourceServers(source(), zone.source?.primaries ?? []) : [];
    if (textSource && servers === null) e.source = t("dns.settings.source_invalid");
    else if (textSource && servers?.length === 0) e.source = t("dns.zone.create.primaries_required");
    Object.assign(e, draft.check(secondary, transferable));
    setErrors(e);
    if (Object.keys(e).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      const n = (k: SoaNumber) => parseTtl(numbers()[k]) ?? 0;
      const soa: SoaDefaults = {
        mname: canonical(mname()),
        rname: canonical(rname()),
        refresh: n("refresh"),
        retry: n("retry"),
        expire: n("expire"),
        minimum: n("minimum"),
        ttl: n("ttl"),
      };
      const text = description().trim() || null;
      const patch: ZonePatch = secondary ? { description: text } : { soa, serial: policy(), description: text };
      if (textSource && servers && source() !== sourceBefore) patch.source = { primaries: servers };
      draft.fill(patch, secondary, transferable);
      if (updatable) updateDraft.fill(patch);
      let saved = await updateZone(props.zone, patch);
      draft.rebase(saved);
      updateDraft.rebase(saved);
      const before = (apexNs.latest?.records ?? []).map((r) => (r.type === "NS" ? r.host : "")).sort().join(",");
      if (!secondary && [...hosts].sort().join(",") !== before) {
        const result = await changeRecords(
          zone.id,
          [{ op: "set", name: zone.name, type: "NS", ttl: apexNs.latest?.ttl ?? soa.ttl ?? null, records: hosts.map((host) => ({ type: "NS", host })) }],
          false,
        );
        if (typeof result.serial === "number") saved = { ...saved, soa_serial: result.serial };
        setServers(null);
      }
      toast({ kind: "ok", title: t("dns.settings.saved", { name: zone.name }) });
      props.onSaved(saved);
    } catch (err) {
      const fields = fieldErrors(err);
      if (Object.keys(fields).length > 0) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const input = (id: string, label: string, value: () => string, set: (v: string) => void, help?: string, locked = false) => (
    <Field id={id} label={label} error={errors()[id]} help={help}>
      <input
        id={`dns-f-${id}`}
        class="input mono"
        value={value()}
        disabled={readOnly() || locked}
        spellcheck={false}
        aria-invalid={errors()[id] ? "true" : undefined}
        aria-describedby={describedBy(id, errors()[id], help)}
        data-testid={`field-${id}`}
        onInput={(e) => set(e.currentTarget.value)}
      />
    </Field>
  );

  return (
    <form class="page-body dns-form" data-testid="zone-settings" onSubmit={(e) => void save(e)} novalidate>
      <Show when={secondary}>
        <Notice kind="info" testid="zone-from-primary">
          {t("dns.transfer.from_primary")}
        </Notice>
      </Show>
      <section class="page-section" aria-labelledby="dns-soa-title">
        <h2 id="dns-soa-title">{t("dns.settings.soa")}</h2>
        <p>{t("dns.settings.soa_body")}</p>
        <div class="field-row">
          {input("soa.mname", t("dns.zone.field.mname"), mname, setMname, undefined, secondary)}
          {input("soa.rname", t("dns.zone.field.rname"), rname, setRname, t("dns.settings.rname_help"), secondary)}
        </div>
        <div class="field-row">
          <For each={SOA_NUMBERS}>
            {(key) =>
              input(
                `soa.${key}`,
                t(`dns.settings.${key}`),
                () => numbers()[key],
                (v) => setNumbers({ ...numbers(), [key]: v }),
                undefined,
                secondary,
              )
            }
          </For>
        </div>
      </section>
      <Show when={hasSource(zone.kind)}>
        <section class="page-section" aria-labelledby="dns-source-title" data-testid="zone-source">
          <h2 id="dns-source-title">{t(`dns.settings.source_${zone.kind === "stub" ? "stub" : "primaries"}`)}</h2>
          <p>{t(`dns.settings.source_${zone.kind === "stub" ? "stub" : "primaries"}_body`)}</p>
          <Show
            when={secondary}
            fallback={input("source", t("dns.zone.field.primaries"), source, setSource, t("dns.zone.field.primaries_help"))}
          >
            <PrimaryRows draft={draft} errors={errors()} disabled={readOnly()} />
          </Show>
        </section>
      </Show>
      <section class="page-section" aria-labelledby="dns-ns-title">
        <h2 id="dns-ns-title">{t("dns.settings.ns")}</h2>
        {input("name_servers", t("dns.zone.field.name_servers"), serverText, setServers, t("dns.zone.field.name_servers_help"), secondary)}
      </section>
      <section class="page-section" aria-labelledby="dns-serial-title">
        <h2 id="dns-serial-title">{t("dns.settings.serial")}</h2>
        <Field id="serial" label={t("dns.zone.field.serial")} help={t(`dns.serial.${policy()}_help`)}>
          <select
            id="dns-f-serial"
            class="select"
            value={policy()}
            disabled={readOnly() || secondary}
            data-testid="field-serial"
            aria-describedby="dns-f-serial-help"
            onChange={(e) => setPolicy(e.currentTarget.value as SerialPolicy)}
          >
            <For each={SERIAL_POLICIES}>{(p) => <option value={p}>{t(`dns.serial.${p}`)}</option>}</For>
          </select>
        </Field>
        {input("description", t("dns.zone.field.description"), description, setDescription)}
      </section>
      <Show when={transferable}>
        <TransferSection zone={props.zone} draft={draft} errors={errors()} disabled={readOnly()} />
      </Show>
      <Show when={updatable}>
        <UpdateSection draft={updateDraft} disabled={readOnly()} />
      </Show>
      <ErrorNotice error={error()} />
      <Show when={!readOnly()}>
        <div class="form-row">
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dns.settings.save")}
          </button>
        </div>
      </Show>
    </form>
  );
}

export function HistoryTab(props: { zone: Zone }) {
  const [records] = createResource(
    () => `${props.zone.id}:${props.zone.revision}`,
    () => zoneAudit(props.zone.id),
  );
  const refused = () => records.error instanceof ApiError && records.error.status === 403;
  return (
    <div class="page-body" data-testid="zone-history">
      <section class="page-section" aria-labelledby="dns-hist-serial">
        <h2 id="dns-hist-serial">{t("dns.history.serial_title")}</h2>
        <dl class="kv">
          <dt>{t("dns.history.serial")}</dt>
          <dd class="mono" data-testid="zone-serial">
            {servedSerial(props.zone) ?? "–"}
          </dd>
          <dt>{t("dns.zone.field.serial")}</dt>
          <dd>{t(`dns.serial.${serialPolicy(props.zone)}`)}</dd>
          <dt>{t("dns.history.updated")}</dt>
          <dd>
            <TimeAgo at={props.zone.updated.at} />
          </dd>
          <dt>{t("dns.history.revision")}</dt>
          <dd class="mono">{props.zone.revision}</dd>
        </dl>
      </section>
      <section class="page-section" aria-labelledby="dns-hist-changes">
        <h2 id="dns-hist-changes">{t("dns.history.changes")}</h2>
        <Show when={!refused()} fallback={<Notice kind="info" testid="zone-history-refused">{t("dns.history.no_audit")}</Notice>}>
          <Show when={!records.error} fallback={<ErrorNotice error={records.error} />}>
            <Show when={(records.latest ?? []).length > 0} fallback={<p class="muted">{records.loading ? t("common.loading") : t("dns.history.empty")}</p>}>
              <div class="table-wrap">
                <table class="plain">
                  <thead>
                    <tr>
                      <th>{t("dns.history.when")}</th>
                      <th>{t("dns.history.action")}</th>
                      <th>{t("dns.history.result")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={records.latest}>
                      {(r) => (
                        <tr data-testid="history-entry" data-kind={r.draft.action} data-key={String(r.seq)}>
                          <td title={formatDateTime(r.at)}>
                            <A href={paths.auditRecord(r.seq)}>
                              <TimeAgo at={r.at} />
                            </A>
                          </td>
                          <td>
                            <code>{r.draft.action}</code>
                          </td>
                          <td>{t(`dns.history.outcome.${r.draft.outcome.kind}`)}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </Show>
        </Show>
      </section>
    </div>
  );
}
