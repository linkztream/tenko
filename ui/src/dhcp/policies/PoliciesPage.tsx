// The DHCP policies (/dhcp/policies): rules in evaluation order, those of each scope first (the
// scopes by network) and then those of the server, with whether they apply, the condition in words
// and the action in words. Create and edit with a condition editor (the join and terms over
// classes and matches) and the four actions of docs/dhcp.md section 16.1: options (the option set
// of the policy, edited once the policy exists), an address range inside the scope, lease times and
// DDNS settings; delete. The DHCP engine matches clients to these classes and policies.
import { A } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, Index, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { DataGrid } from "../../grid/DataGrid";
import type { Column, RowAction } from "../../grid/types";
import { formatNumber, t } from "../../i18n";
import { compareIp, containsIp, parseIp } from "../../ipam/ip";
import { MatchRow, matchProblem } from "../classes/MatchEditor";
import { mayWriteDhcp } from "../access";
import { createPolicy, deletePolicy, getSettings, listClasses, listPolicies, listPolicyOptionSets, listScopes, updatePolicy, type DhcpClass, type Join, type Policy, type PolicyAction, type Scope, type Term } from "../api";
import { createZoneChoices, DdnsFields, startingDraft, zoneNameIn } from "../ddns/DdnsFields";
import { ddnsFieldErrors, ddnsOfDraft, draftOfDdns, namesDdns, type DdnsDraft, type DdnsField } from "../ddns/model";
import { DhcpNav } from "../DhcpNav";
import { LeaseChoice, leaseProblem } from "../LeaseFields";
import { OptionSetEditor } from "../options/OptionSetEditor";
import {
  draftOfLease,
  draftOfTerm,
  emptyTerm,
  leaseOfDraft,
  networkOf,
  policyOrder,
  termOfDraft,
  TERM_KINDS,
  validDhcpName,
  type LeaseDraft,
  type LeaseField,
  type TermDraft,
  type TermKind,
} from "../model";
import { Check, describedBy, DhcpProblem, errorFor, Field, fieldErrors, hasField, unavailable } from "../Parts";
import { dhcpPaths } from "../paths";
import { actionWords, conditionWords } from "../words";
import "../dhcp.css";
import "./policies.css";

const SERVER_LEASE = { default_secs: 86_400, min_secs: 3600, max_secs: 604_800 };

function TermEditor(props: { index: number; value: TermDraft; classes: readonly DhcpClass[]; onChange: (next: TermDraft) => void; onRemove?: (() => void) | undefined; error?: string | undefined }) {
  const isClass = () => props.value.kind === "class" || props.value.kind === "not_class";
  return (
    <div class="dhcp-term" role="group" aria-label={t("dhcp.term.row", { n: props.index + 1 })} data-testid="term-row" data-kind={props.value.kind}>
      <select
        class="select"
        aria-label={t("dhcp.term.kind_label")}
        value={props.value.kind}
        data-testid="term-kind"
        onChange={(e) => props.onChange({ ...props.value, kind: e.currentTarget.value as TermKind })}
      >
        <For each={TERM_KINDS}>{(kind) => <option value={kind}>{t(`dhcp.term.kind.${kind}`)}</option>}</For>
      </select>
      <Show
        when={isClass()}
        fallback={
          <MatchRow
            id={`term-${props.index}`}
            label={t("dhcp.term.row", { n: props.index + 1 })}
            value={props.value.match}
            error={props.error}
            onChange={(match) => props.onChange({ ...props.value, match })}
          />
        }
      >
        <select
          class="select"
          aria-label={t("dhcp.term.class_label")}
          value={props.value.class_id}
          aria-invalid={props.error ? "true" : undefined}
          data-testid="term-class"
          onChange={(e) => props.onChange({ ...props.value, class_id: e.currentTarget.value })}
        >
          <option value="">{t("dhcp.term.class_pick")}</option>
          <For each={props.classes}>{(c) => <option value={c.id}>{c.name}</option>}</For>
        </select>
        <Show when={props.error}>
          <span class="help bad dhcp-match-error" data-testid="field-error" data-field={`term-${props.index}`}>
            {props.error}
          </span>
        </Show>
      </Show>
      <Show when={props.onRemove}>
        <button type="button" class="icon-btn" aria-label={t("dhcp.term.remove", { n: props.index + 1 })} data-testid="term-remove" onClick={() => props.onRemove?.()}>
          <Icon name="trash" />
        </button>
      </Show>
    </div>
  );
}

function PolicyDialog(props: {
  item?: Policy;
  scopes: readonly Scope[];
  classes: readonly DhcpClass[];
  onClose: () => void;
  onDone: () => void;
  /** A new policy exists: the dialog continues with it, so that its options can be added. */
  onCreated: (policy: Policy) => void;
  /** The option set of the policy was saved. */
  onOptionsSaved: () => void;
}) {
  let nameInput!: HTMLInputElement;
  const item = untrack(() => props.item);
  const [settings] = createResource(() => getSettings());
  const zones = createZoneChoices();
  const serverLease = () => (settings.error ? SERVER_LEASE : (settings.latest?.lease ?? SERVER_LEASE));
  const [name, setName] = createSignal(item?.name ?? "");
  const [scope, setScope] = createSignal(item?.scope ?? "");
  const [order, setOrder] = createSignal(item ? String(item.order) : "");
  const [enabled, setEnabled] = createSignal(item?.enabled ?? true);
  const [join, setJoin] = createSignal<Join>(item?.condition.join ?? "and");
  const [terms, setTerms] = createSignal<TermDraft[]>(item ? item.condition.terms.map(draftOfTerm) : [emptyTerm()]);
  const [rangeFirst, setRangeFirst] = createSignal(item?.action?.range?.first ?? "");
  const [rangeLast, setRangeLast] = createSignal(item?.action?.range?.last ?? "");
  const [inherit, setInherit] = createSignal(!item?.action?.lease);
  const [lease, setLease] = createSignal<LeaseDraft>(draftOfLease(item?.action?.lease ?? SERVER_LEASE));
  const [ddnsOn, setDdnsOn] = createSignal(item?.action?.ddns !== undefined && item.action.ddns !== null);
  const [ddns, setDdns] = createSignal<DdnsDraft>(item?.action?.ddns ? draftOfDdns(item.action.ddns) : startingDraft(undefined));
  const [ddnsTouched, setDdnsTouched] = createSignal(false);
  const [description, setDescription] = createSignal(item?.description ?? "");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [termErrors, setTermErrors] = createSignal<Record<number, string>>({});
  const [leaseErrors, setLeaseErrors] = createSignal<Partial<Record<LeaseField, string>>>({});
  const [ddnsErrors, setDdnsErrors] = createSignal<Partial<Record<DdnsField, string>>>({});
  const editDdns = (next: DdnsDraft) => {
    setDdnsTouched(true);
    setDdns(next);
  };
  const toggleDdns = (on: boolean) => {
    setDdnsOn(on);
    // A DDNS action that is new starts from the settings of the server, with DDNS on.
    if (on && !item?.action?.ddns && !ddnsTouched() && !settings.error && settings.latest) setDdns(startingDraft(settings.latest.ddns));
  };
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const replaceTerm = (i: number, next: TermDraft) => setTerms((list) => list.map((x, j) => (j === i ? next : x)));
  const scopeNetwork = () => {
    const s = props.scopes.find((x) => x.prefix === scope());
    return s ? networkOf(s.cidr) : null;
  };

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    const te: Record<number, string> = {};
    const le: Partial<Record<LeaseField, string>> = {};
    if (!validDhcpName(name().trim())) e.name = t("dhcp.check.name");
    if (order().trim() !== "" && !/^\d{1,9}$/.test(order().trim())) e.order = t("dhcp.check.order");
    const built: Term[] = [];
    terms().forEach((draft, i) => {
      const parsed = termOfDraft(draft);
      if (parsed.ok) built.push(parsed.term);
      else te[i] = parsed.problem === "class" ? t("dhcp.check.term_class") : matchProblem(parsed.problem);
    });
    const de: Partial<Record<DdnsField, string>> = {};
    const action: PolicyAction = {};
    if (ddnsOn()) {
      const parsed = ddnsOfDraft(ddns());
      if (parsed.ok) action.ddns = parsed.ddns;
      else de.ttl = t("dhcp.ddns.check.ttl");
    }
    if (rangeFirst().trim() !== "" || rangeLast().trim() !== "") {
      const a = parseIp(rangeFirst());
      const b = parseIp(rangeLast());
      const net = scopeNetwork();
      if (!a || a.version !== 4 || !b || b.version !== 4) e.range = t("dhcp.check.range_address");
      else if (compareIp(a, b) > 0) e.range = t("dhcp.check.range_order");
      else if (net && (!containsIp(net, a) || !containsIp(net, b))) e.range = t("dhcp.check.range_outside");
      else action.range = { first: rangeFirst().trim(), last: rangeLast().trim() };
    }
    if (!inherit()) {
      const parsed = leaseOfDraft(lease(), item?.action?.lease);
      if (parsed.ok) action.lease = parsed.lease;
      else le[parsed.field] = leaseProblem(parsed.problem);
    }
    setErrors(e);
    setTermErrors(te);
    setLeaseErrors(le);
    setDdnsErrors(de);
    if (Object.keys(e).length > 0 || Object.keys(te).length > 0 || Object.keys(le).length > 0 || Object.keys(de).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      const condition = { join: join(), terms: built };
      const text = description().trim();
      if (item) {
        await updatePolicy(item, { name: name().trim(), order: Number(order() || item.order), enabled: enabled(), condition, action, description: text });
        toast({ kind: "ok", title: t("dhcp.policy.saved", { name: name().trim() }) });
        props.onDone();
      } else {
        const made = await createPolicy({
          name: name().trim(),
          ...(scope() !== "" ? { scope: scope() } : {}),
          ...(order().trim() !== "" ? { order: Number(order()) } : {}),
          enabled: enabled(),
          condition,
          action,
          ...(text !== "" ? { description: text } : {}),
        });
        toast({ kind: "ok", title: t("dhcp.policy.created", { name: name().trim() }) });
        props.onCreated(made);
      }
    } catch (err) {
      const fields = fieldErrors(err);
      if (namesDdns(fields, "action.ddns")) setDdnsErrors(ddnsFieldErrors(fields, "action.ddns"));
      if (hasField(fields, ["name", "order", "condition", "action.range"])) {
        setErrors(fields);
        const rows: Record<number, string> = {};
        for (const key of Object.keys(fields)) {
          const m = /^condition\.terms\[(\d+)\]/.exec(key);
          if (m) rows[Number(m[1])] = fields[key] ?? "";
        }
        setTermErrors(rows);
      } else if (!namesDdns(fields, "action.ddns")) setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = () => (item ? t("dhcp.policy.edit_title", { name: item.name }) : t("dhcp.policy.create_title"));
  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog wide dhcp-dialog" testid="dialog-policy-form" initialFocus={() => nameInput}>
      <h2 class="dialog-title">{title()}</h2>
      <div class="dialog-body dhcp-form">
        <form id="dhcp-policy-form" class="dhcp-form" onSubmit={(ev) => void submit(ev)} novalidate>
          <div class="field-row">
            <Field id="name" label={t("dhcp.policy.field.name")} error={errorFor(errors(), "name")} help={t("dhcp.field.name_help")}>
              <input
                ref={nameInput}
                id="dhcp-f-name"
                class="input mono"
                value={name()}
                spellcheck={false}
                autocomplete="off"
                aria-invalid={errors().name ? "true" : undefined}
                aria-describedby={describedBy("name", errors().name, "help")}
                data-testid="field-name"
                onInput={(ev) => setName(ev.currentTarget.value)}
              />
            </Field>
            <Field id="scope" label={t("dhcp.policy.field.scope")} help={item ? t("dhcp.policy.field.scope_fixed") : undefined}>
              <select id="dhcp-f-scope" class="select" value={scope()} disabled={item !== undefined} data-testid="field-scope" onChange={(ev) => setScope(ev.currentTarget.value)}>
                <option value="">{t("dhcp.policy.scope_server")}</option>
                <For each={props.scopes}>{(s) => <option value={s.prefix}>{s.cidr}</option>}</For>
              </select>
            </Field>
          </div>
          <div class="field-row">
            <Field id="order" label={t("dhcp.policy.field.order")} error={errorFor(errors(), "order")} help={t("dhcp.policy.field.order_help")}>
              <input
                id="dhcp-f-order"
                class="input mono"
                inputmode="numeric"
                value={order()}
                aria-invalid={errors().order ? "true" : undefined}
                aria-describedby={describedBy("order", errors().order, "help")}
                data-testid="field-order"
                onInput={(ev) => setOrder(ev.currentTarget.value)}
              />
            </Field>
            <Check id="enabled" label={t("dhcp.policy.field.enabled")} checked={enabled()} onChange={setEnabled} />
          </div>
          <fieldset class="dhcp-matches-field" data-testid="policy-condition">
            <legend>{t("dhcp.policy.field.condition")}</legend>
            <Field id="join" label={t("dhcp.policy.field.join")}>
              <select id="dhcp-f-join" class="select" value={join()} data-testid="field-join" onChange={(ev) => setJoin(ev.currentTarget.value as Join)}>
                <option value="and">{t("dhcp.join.and")}</option>
                <option value="or">{t("dhcp.join.or")}</option>
              </select>
            </Field>
            {/* By position, so that typing in a term does not rebuild it. */}
            <Index each={terms()}>
              {(term, i) => (
                <TermEditor
                  index={i}
                  value={term()}
                  classes={props.classes}
                  error={termErrors()[i]}
                  onChange={(next) => replaceTerm(i, next)}
                  onRemove={terms().length > 1 ? () => setTerms((list) => list.filter((_, j) => j !== i)) : undefined}
                />
              )}
            </Index>
            <Show when={errorFor(errors(), "condition.terms") && Object.keys(termErrors()).length === 0}>
              <span class="help bad" data-testid="field-error" data-field="terms">
                {errorFor(errors(), "condition.terms")}
              </span>
            </Show>
            <button type="button" class="btn" data-testid="term-add" onClick={() => setTerms((list) => [...list, emptyTerm()])}>
              <Icon name="plus" />
              {t("dhcp.term.add")}
            </button>
          </fieldset>
          <fieldset class="dhcp-matches-field" data-testid="policy-action">
            <legend>{t("dhcp.policy.field.action")}</legend>
            <div class="field-row">
              <Field id="range-first" label={t("dhcp.policy.field.range_first")} error={errors().range}>
                <input id="dhcp-f-range-first" class="input mono" value={rangeFirst()} spellcheck={false} data-testid="field-range-first" onInput={(ev) => setRangeFirst(ev.currentTarget.value)} />
              </Field>
              <Field id="range-last" label={t("dhcp.policy.field.range_last")}>
                <input id="dhcp-f-range-last" class="input mono" value={rangeLast()} spellcheck={false} data-testid="field-range-last" onInput={(ev) => setRangeLast(ev.currentTarget.value)} />
              </Field>
            </div>
            <Show when={errorFor(errors(), "action.range")}>
              <span class="help bad" data-testid="field-error" data-field="action.range">
                {errorFor(errors(), "action.range")}
              </span>
            </Show>
            <LeaseChoice
              id="lease"
              inherit={inherit()}
              onInherit={(on) => {
                setInherit(on);
                if (!on && !item?.action?.lease) setLease(draftOfLease(serverLease()));
              }}
              value={lease()}
              onChange={setLease}
              errors={leaseErrors()}
              serverWords={t("dhcp.policy.lease_inherit_help")}
            />
          </fieldset>
          <fieldset class="dhcp-matches-field" data-testid="policy-ddns">
            <legend>{t("dhcp.policy.ddns.legend")}</legend>
            <Check id="policy-ddns-on" label={t("dhcp.policy.ddns.on")} checked={ddnsOn()} onChange={toggleDdns} help={t("dhcp.policy.ddns.help")} />
            <Show when={ddnsOn()}>
              <DdnsFields value={ddns()} onChange={editDdns} zones={zones} errors={ddnsErrors()} />
            </Show>
          </fieldset>
          <Field id="description" label={t("dhcp.field.description")}>
            <input id="dhcp-f-description" class="input" value={description()} data-testid="field-description" onInput={(ev) => setDescription(ev.currentTarget.value)} />
          </Field>
          <ErrorNotice error={error()} />
        </form>
        {/* The option set has its own save button and sits outside the form, so that Enter in it never submits the policy. */}
        <fieldset class="dhcp-policy-options" data-testid="policy-options">
          <legend>{t("dhcp.policy.options.title")}</legend>
          {item ? (
            <>
              <p class="muted">{t("dhcp.policy.options.help")}</p>
              <OptionSetEditor
                owner={`policy:${item.id}`}
                label={t("dhcp.policy.options.label", { name: item.name })}
                canWrite={mayWriteDhcp()}
                testid="policy-optset"
                onSaved={() => props.onOptionsSaved()}
              />
            </>
          ) : (
            <p class="muted" data-testid="policy-options-new">
              {t("dhcp.policy.options.new")}
            </p>
          )}
        </fieldset>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" form="dhcp-policy-form" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {item ? t("dhcp.policy.save") : t("dhcp.policy.create")}
          </button>
        </div>
      </div>
    </Dialog>
  );
}

function DeletePolicyDialog(props: { item: Policy; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dhcp.policy.delete_title", { name: props.item.name })}
      testid="dialog-policy-delete"
      danger
      busy={busy()}
      confirmLabel={t("dhcp.policy.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deletePolicy(props.item)
          .then(() => {
            toast({ kind: "ok", title: t("dhcp.policy.deleted", { name: props.item.name }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dhcp.policy.delete_body")}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

export default function PoliciesPage() {
  const [dialog, setDialog] = createSignal<{ kind: "edit"; item?: Policy } | { kind: "delete"; item: Policy } | null>(null);
  const query = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const page = await listPolicies(signal);
      return { value: page.items, revision: page.revision };
    },
  });
  // The option sets of the policies in one read: the words of a policy say "options" when its set has values.
  const optionSets = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => ({ value: await listPolicyOptionSets(signal) }),
  });
  const withOptions = createMemo(() => new Set((latest(optionSets) ?? []).filter((s) => s.values.length > 0).map((s) => s.path)));
  const zones = createZoneChoices();
  const actionText = (p: Policy) => actionWords(p.action, { zoneName: zoneNameIn(zones()), options: withOptions().has(`policy:${p.id}`) });
  const [classes] = createResource(async () => (await listClasses()).items);
  const [scopes] = createResource(async () => (await listScopes()).items);
  const classList = () => (classes.error ? [] : (classes.latest ?? []));
  const scopeList = () => (scopes.error ? [] : (scopes.latest ?? []));
  const className = (id: string) => classList().find((c) => c.id === id)?.name ?? id;
  const cidrOf = (prefix: string) => scopeList().find((s) => s.prefix === prefix)?.cidr ?? prefix;
  const blocked = () => unavailable(query.value.error);
  const ordered = createMemo(() => policyOrder(latest(query) ?? [], cidrOf));
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };

  const columns: Column<Policy>[] = [
    { id: "order", header: () => t("dhcp.col.order"), width: 70, align: "right", text: (p) => String(p.order), render: (p) => <span class="num" data-testid="policy-order">{formatNumber(p.order)}</span> },
    { id: "name", header: () => t("dhcp.col.name"), width: 200, fixed: true, text: (p) => p.name, render: (p) => <span class="mono">{p.name}</span> },
    {
      id: "scope",
      header: () => t("dhcp.col.scope"),
      width: 170,
      text: (p) => (p.scope ? cidrOf(p.scope) : t("dhcp.policy.scope_server")),
      render: (p) => (
        <Show when={p.scope} fallback={<span class="tag" data-testid="policy-scope" data-key="server">{t("dhcp.policy.scope_server")}</span>}>
          {(prefix) => (
            <A class="mono" href={dhcpPaths.scope(prefix())} data-testid="policy-scope" data-key={cidrOf(prefix())}>
              {cidrOf(prefix())}
            </A>
          )}
        </Show>
      ),
    },
    {
      id: "enabled",
      header: () => t("dhcp.col.enabled"),
      width: 110,
      text: (p) => (p.enabled === false ? t("dhcp.scope.disabled") : t("dhcp.scope.enabled")),
      render: (p) => (
        <span class={p.enabled === false ? "tag" : "tag accent"} data-testid="policy-enabled" data-key={p.enabled === false ? "off" : "on"}>
          {p.enabled === false ? t("dhcp.scope.disabled") : t("dhcp.scope.enabled")}
        </span>
      ),
    },
    { id: "condition", header: () => t("dhcp.col.condition"), text: (p) => conditionWords(p.condition, className), render: (p) => <span data-testid="policy-condition-words">{conditionWords(p.condition, className)}</span> },
    { id: "action", header: () => t("dhcp.col.action"), width: 320, text: actionText, render: (p) => <span data-testid="policy-action-words">{actionText(p)}</span> },
  ];
  const actions: RowAction<Policy>[] = [
    { id: "edit", label: () => t("dhcp.do.edit"), hidden: () => !mayWriteDhcp(), run: (p) => setDialog({ kind: "edit", item: p }) },
    { id: "delete", label: () => t("dhcp.do.delete"), danger: true, hidden: () => !mayWriteDhcp(), run: (p) => setDialog({ kind: "delete", item: p }) },
  ];

  return (
    <div class="page dhcp-page list-page" data-testid="page-dhcp-policies">
      <DhcpNav />
      <PageHead
        title={t("dhcp.policies.title")}
        sub={t("dhcp.policies.sub")}
        actions={
          <Show when={mayWriteDhcp() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dhcp-policy-create" onClick={() => setDialog({ kind: "edit" })}>
              <Icon name="plus" />
              {t("dhcp.policy.create")}
            </button>
          </Show>
        }
      />
      <Show
        when={!blocked()}
        fallback={
          <div class="page-body">
            <DhcpProblem error={query.value.error} />
          </div>
        }
      >
        <Notice kind="info" testid="policies-note">
          {t("dhcp.policies.note_live")}
        </Notice>
        <div class="dhcp-list-body">
          <DataGrid
            id="dhcp-policies"
            label={t("dhcp.policies.title")}
            noSelection
            columns={columns}
            rows={ordered()}
            rowId={(p) => p.id}
            rowKey={(p) => p.name}
            rowLabel={(p) => p.name}
            loading={query.value.loading}
            initial={latest(query) === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(p) => (mayWriteDhcp() ? setDialog({ kind: "edit", item: p }) : undefined)}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dhcp-policies-empty">
                <h3>{t("dhcp.policies.empty")}</h3>
                <p>{t("dhcp.policies.empty_body")}</p>
              </div>
            }
          />
        </div>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "edit" ? (
            <PolicyDialog
              item={d.item}
              scopes={scopeList()}
              classes={classList()}
              onClose={() => close(false)}
              onDone={() => close(true)}
              onCreated={(made) => {
                setDialog({ kind: "edit", item: made });
                query.refetch();
              }}
              onOptionsSaved={() => optionSets.refetch()}
            />
          ) : (
            <DeletePolicyDialog item={d.item} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
