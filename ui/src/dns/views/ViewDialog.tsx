// The dialogs of a view: create and edit (the name; the rules, one editor per test: a list of
// prefixes, addresses, types or names, the transports, or a time window in UTC; the scope map
// of zone, scope and weight with the share each weight gives; the recursion access list or
// the profile's default; the position of a new view; the description) and delete. The form
// checks what it can before it sends; a refusal of the server (`dns.view.invalid` with
// `field`) lands under the field it names, a refusal of a delete (`dns.view.in_use`) says
// what still names the view.
import { createSignal, For, Index, Match, Show, Switch, untrack } from "solid-js";
import { ApiError } from "../../api/problem";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { describedBy, Field } from "../Parts";
import type { Acl, Zone } from "../types";
import { createView, deleteView, updateView, type ViewItem, type ViewPatch } from "./api";
import {
  checkView,
  draftOf,
  emptyDraft,
  MAX_RULES,
  MAX_SCOPES,
  QUERY_TRANSPORTS,
  RULE_KINDS,
  shares,
  type RuleDraft,
  type RuleKind,
  type ScopeDraft,
  type ViewField,
  type ViewProblem,
} from "./model";

/** The message of a local problem of the form. */
function problemText(p: ViewProblem): string {
  switch (p.field) {
    case "name":
      return p.problem === "required" ? t("dns.view.check.name_required") : t("dns.view.check.name_long");
    case "description":
      return t("dns.view.check.description");
    case "rules":
      switch (p.problem) {
        case "too_many_rules":
          return t("dns.view.check.too_many_rules");
        case "empty":
          return t("dns.view.check.rule_empty", { n: p.index + 1 });
        case "too_many":
          return t("dns.view.check.rule_too_many", { n: p.index + 1 });
        case "time":
          return t("dns.view.check.time", { n: p.index + 1, entry: p.entry });
        default:
          return t(`dns.view.check.${p.problem}`, { n: p.index + 1, entry: p.entry });
      }
    case "scope_map":
      switch (p.problem) {
        case "too_many_scopes":
          return t("dns.view.check.too_many_scopes");
        case "zone":
          return t("dns.view.check.scope_zone", { n: p.index + 1 });
        case "weight":
          return t("dns.view.check.scope_weight", { n: p.index + 1 });
        case "twice":
          return t("dns.view.check.scope_twice", { n: p.index + 1 });
      }
  }
}

/** The form field a refusal of the server names (`field` of `dns.view.invalid`). */
export function refusedField(err: unknown): ViewField | "recursion" | undefined {
  if (!(err instanceof ApiError) || err.code !== "dns.view.invalid") return undefined;
  const field = err.params.field ?? "";
  return field === "name" || field === "rules" || field === "scope_map" || field === "recursion" || field === "description" ? field : undefined;
}

function refusedText(err: ApiError, field: string): string {
  if (field === "name" && /exists/.test(err.params.reason ?? "")) return t("dns.view.check.taken");
  if (field === "scope_map" && err.params.scope) return t("dns.view.check.no_scope", { zone: err.params.zone ?? "", scope: err.params.scope });
  if (field === "scope_map" && /zone/.test(err.params.reason ?? "")) return t("dns.view.check.no_zone");
  if (field === "recursion") return t("dns.view.check.no_acl");
  return t("errors.dns.view.invalid");
}

/** The help line of a list rule's editor. */
function valuesHelp(kind: RuleKind): string {
  return t(`dns.view.rule.help.${kind}`);
}

export function ViewDialog(props: {
  view?: ViewItem;
  /** The number of views, for the position of a new one. */
  count: number;
  zones: readonly Zone[];
  acls: readonly Acl[];
  onClose: () => void;
  onDone: () => void;
}) {
  let nameInput!: HTMLInputElement;
  const view = untrack(() => props.view);
  const [name, setName] = createSignal(view?.name ?? "");
  const [rules, setRules] = createSignal<RuleDraft[]>((view?.rules ?? []).map(draftOf));
  const [scopes, setScopes] = createSignal<ScopeDraft[]>((view?.scope_map ?? []).map((s) => ({ zone: s.zone, scope: s.scope, weight: String(s.weight) })));
  const [recursion, setRecursion] = createSignal(view?.recursion ?? "");
  const [order, setOrder] = createSignal(untrack(() => props.count) + 1);
  const [description, setDescription] = createSignal(view?.description ?? "");
  const [nextKind, setNextKind] = createSignal<RuleKind>("client_subnet");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const zoneOf = (id: string) => props.zones.find((z) => z.id === id);
  const zoneScopes = (id: string) => zoneOf(id)?.scopes?.map((s) => s.name) ?? ["default"];
  const editRule = (index: number, change: Partial<RuleDraft>) => setRules((list) => list.map((r, i) => (i === index ? { ...r, ...change } : r)));
  const editScope = (index: number, change: Partial<ScopeDraft>) => setScopes((list) => list.map((s, i) => (i === index ? { ...s, ...change } : s)));
  const addScope = () => {
    const zone = props.zones[0];
    setScopes((list) => [...list, { zone: zone?.id ?? "", scope: zone ? (zoneScopes(zone.id)[0] ?? "default") : "", weight: "1" }]);
  };
  /** The shares of the weights typed so far (a weight that is not a number counts 0). */
  const typedShares = () =>
    shares(scopes().map((s) => ({ zone: s.zone, scope: s.scope, weight: /^\d+$/.test(s.weight.trim()) ? Number(s.weight.trim()) : 0 })));

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const checked = checkView({ name: name(), rules: rules(), scopes: scopes(), description: description() });
    if (!checked.ok) {
      const e: Record<string, string> = {};
      for (const p of checked.problems) e[p.field] ??= problemText(p);
      setErrors(e);
      return;
    }
    setErrors({});
    setBusy(true);
    setError(undefined);
    try {
      if (view) {
        const patch: ViewPatch = { name: checked.name, rules: checked.rules, scope_map: checked.scopeMap, description: checked.description };
        if (recursion()) patch.recursion = recursion();
        else patch.default_recursion = true;
        await updateView(view, patch);
        toast({ kind: "ok", title: t("dns.view.saved", { name: checked.name }) });
      } else {
        await createView({
          name: checked.name,
          rules: checked.rules,
          scope_map: checked.scopeMap,
          order: order(),
          recursion: recursion() || null,
          description: checked.description || null,
        });
        toast({ kind: "ok", title: t("dns.view.created", { name: checked.name }) });
      }
      props.onDone();
    } catch (err) {
      const field = refusedField(err);
      if (field && err instanceof ApiError) setErrors({ [field]: refusedText(err, field) });
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = () => (view ? t("dns.view.edit_title", { name: view.name }) : t("dns.view.create_title"));
  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-view-form" initialFocus={() => nameInput}>
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        <div class="field-row">
          <Field id="name" label={t("dns.view.field.name")} error={errors().name}>
            <input
              ref={nameInput}
              id="dns-f-name"
              class="input"
              value={name()}
              autocomplete="off"
              aria-invalid={errors().name ? "true" : undefined}
              aria-describedby={describedBy("name", errors().name)}
              data-testid="field-name"
              onInput={(ev) => setName(ev.currentTarget.value)}
            />
          </Field>
          <Show when={!view}>
            <Field id="order" label={t("dns.view.field.order")} help={t("dns.view.field.order_help")}>
              <select id="dns-f-order" class="select" aria-describedby="dns-f-order-help" data-testid="field-order" onChange={(ev) => setOrder(Number(ev.currentTarget.value))}>
                <For each={Array.from({ length: props.count + 1 }, (_, i) => i + 1)}>
                  {(n) => (
                    <option value={n} selected={n === order()}>
                      {n === props.count + 1 ? t("dns.view.field.order_last", { n }) : t("dns.view.field.order_at", { n })}
                    </option>
                  )}
                </For>
              </select>
            </Field>
          </Show>
        </div>

        <fieldset class="dns-view-group" data-testid="view-rules" aria-describedby={errors().rules ? "dns-f-rules-error" : "dns-f-rules-help"}>
          <legend>{t("dns.view.field.rules")}</legend>
          <span class="help" id="dns-f-rules-help">
            {rules().length === 0 ? t("dns.view.field.rules_none") : t("dns.view.field.rules_help")}
          </span>
          <Index each={rules()}>
            {(rule, i) => (
              <div class="dns-view-rule" data-testid="view-rule-editor" data-index={i} data-kind={rule().kind}>
                <span class="dns-view-rule-kind">{t(`dns.view.rule.kind.${rule().kind}`)}</span>
                <Switch>
                  <Match when={rule().kind === "transport"}>
                    <span class="dns-modes" role="group" aria-label={t("dns.view.rule.kind.transport")}>
                      <For each={QUERY_TRANSPORTS}>
                        {(tr) => (
                          <label class="choice">
                            <input
                              type="checkbox"
                              checked={rule().transports.includes(tr)}
                              data-testid={`field-rule-transport-${tr}`}
                              onChange={(ev) =>
                                editRule(i, {
                                  transports: ev.currentTarget.checked ? [...rule().transports, tr] : rule().transports.filter((x) => x !== tr),
                                })
                              }
                            />
                            <span>{t(`dns.view.transport.${tr}`)}</span>
                          </label>
                        )}
                      </For>
                    </span>
                  </Match>
                  <Match when={rule().kind === "time_of_day"}>
                    <span class="dns-view-time">
                      <label>
                        <span>{t("dns.view.rule.from")}</span>
                        <input
                          type="time"
                          class="input mono"
                          value={rule().from}
                          data-testid="field-rule-from"
                          onInput={(ev) => editRule(i, { from: ev.currentTarget.value })}
                        />
                      </label>
                      <label>
                        <span>{t("dns.view.rule.to")}</span>
                        <input type="time" class="input mono" value={rule().to} data-testid="field-rule-to" onInput={(ev) => editRule(i, { to: ev.currentTarget.value })} />
                      </label>
                      <span class="help">{t("dns.view.rule.help.time_of_day")}</span>
                    </span>
                  </Match>
                  <Match when={true}>
                    <span class="dns-view-values">
                      <textarea
                        class="input mono"
                        rows={2}
                        value={rule().text}
                        spellcheck={false}
                        aria-label={t(`dns.view.rule.kind.${rule().kind}`)}
                        data-testid="field-rule-values"
                        onInput={(ev) => editRule(i, { text: ev.currentTarget.value })}
                      />
                      <span class="help">{valuesHelp(rule().kind)}</span>
                    </span>
                  </Match>
                </Switch>
                <button
                  type="button"
                  class="icon-btn"
                  aria-label={t("dns.view.rule.remove", { n: i + 1 })}
                  data-testid="view-rule-remove"
                  onClick={() => setRules((list) => list.filter((_, j) => j !== i))}
                >
                  <Icon name="x" size="sm" />
                </button>
              </div>
            )}
          </Index>
          <Show when={errors().rules}>
            <span class="help bad" id="dns-f-rules-error" data-testid="field-error" data-field="rules">
              {errors().rules}
            </span>
          </Show>
          <div class="dns-view-add">
            <select
              class="select"
              aria-label={t("dns.view.rule.kind_label")}
              data-testid="field-rule-kind"
              onChange={(ev) => setNextKind(ev.currentTarget.value as RuleKind)}
            >
              <For each={RULE_KINDS}>
                {(kind) => (
                  <option value={kind} selected={kind === nextKind()}>
                    {t(`dns.view.rule.kind.${kind}`)}
                  </option>
                )}
              </For>
            </select>
            <button
              type="button"
              class="btn sm"
              disabled={rules().length >= MAX_RULES}
              data-testid="view-rule-add"
              onClick={() => setRules((list) => [...list, emptyDraft(nextKind())])}
            >
              <Icon name="plus" size="sm" />
              {t("dns.view.rule.add")}
            </button>
          </div>
        </fieldset>

        <fieldset class="dns-view-group" data-testid="view-scopes" aria-describedby={errors().scope_map ? "dns-f-scope_map-error" : "dns-f-scope_map-help"}>
          <legend>{t("dns.view.field.scopes")}</legend>
          <span class="help" id="dns-f-scope_map-help">
            {t("dns.view.field.scopes_help")}
          </span>
          <Index each={scopes()}>
            {(entry, i) => (
              <div class="dns-view-scope" data-testid="view-scope-editor" data-index={i}>
                <select
                  class="select"
                  aria-label={t("dns.view.field.zone", { n: i + 1 })}
                  data-testid="field-scope-zone"
                  onChange={(ev) => {
                    const zone = ev.currentTarget.value;
                    editScope(i, { zone, scope: zoneScopes(zone)[0] ?? "default" });
                  }}
                >
                  <For each={props.zones}>
                    {(z) => (
                      <option value={z.id} selected={z.id === entry().zone}>
                        {z.name}
                      </option>
                    )}
                  </For>
                </select>
                <select class="select mono" aria-label={t("dns.view.field.scope", { n: i + 1 })} data-testid="field-scope-scope" onChange={(ev) => editScope(i, { scope: ev.currentTarget.value })}>
                  <For each={zoneScopes(entry().zone)}>
                    {(s) => (
                      <option value={s} selected={s === entry().scope}>
                        {s}
                      </option>
                    )}
                  </For>
                </select>
                <input
                  class="input mono dns-view-weight"
                  inputmode="numeric"
                  value={entry().weight}
                  aria-label={t("dns.view.field.weight", { n: i + 1 })}
                  data-testid="field-scope-weight"
                  onInput={(ev) => editScope(i, { weight: ev.currentTarget.value })}
                />
                <span class="muted" data-testid="view-share" data-key={String(typedShares()[i] ?? 0)}>
                  {t("dns.view.share", { share: typedShares()[i] ?? 0 })}
                </span>
                <button
                  type="button"
                  class="icon-btn"
                  aria-label={t("dns.view.scope.remove", { n: i + 1 })}
                  data-testid="view-scope-remove"
                  onClick={() => setScopes((list) => list.filter((_, j) => j !== i))}
                >
                  <Icon name="x" size="sm" />
                </button>
              </div>
            )}
          </Index>
          <Show when={errors().scope_map}>
            <span class="help bad" id="dns-f-scope_map-error" data-testid="field-error" data-field="scope_map">
              {errors().scope_map}
            </span>
          </Show>
          <div class="dns-view-add">
            <button type="button" class="btn sm" disabled={props.zones.length === 0 || scopes().length >= MAX_SCOPES} data-testid="view-scope-add" onClick={addScope}>
              <Icon name="plus" size="sm" />
              {t("dns.view.scope.add")}
            </button>
            <Show when={props.zones.length === 0}>
              <span class="help">{t("dns.view.scope.no_zones")}</span>
            </Show>
          </div>
        </fieldset>

        <Field id="recursion" label={t("dns.view.field.recursion")} error={errors().recursion} help={t("dns.view.field.recursion_help")}>
          <select
            id="dns-f-recursion"
            class="select"
            aria-invalid={errors().recursion ? "true" : undefined}
            aria-describedby={describedBy("recursion", errors().recursion, "help")}
            data-testid="field-recursion"
            onChange={(ev) => setRecursion(ev.currentTarget.value)}
          >
            <option value="" selected={recursion() === ""}>
              {t("dns.view.recursion.default")}
            </option>
            <For each={props.acls}>
              {(acl) => (
                <option value={acl.id} selected={acl.id === recursion()}>
                  {acl.name}
                </option>
              )}
            </For>
          </select>
        </Field>
        <Field id="description" label={t("dns.zone.field.description")} error={errors().description}>
          <input id="dns-f-description" class="input" value={description()} data-testid="field-description" onInput={(ev) => setDescription(ev.currentTarget.value)} />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {view ? t("dns.view.save") : t("dns.view.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/** What names a view, from the `by` of `dns.view.in_use` (`forwarder:example.net,...`). */
export function namedBy(err: unknown): string[] {
  if (!(err instanceof ApiError) || err.code !== "dns.view.in_use") return [];
  return (err.params.by ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function DeleteViewDialog(props: { view: ViewItem; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dns.view.delete_title", { name: props.view.name })}
      testid="dialog-view-delete"
      danger
      busy={busy()}
      confirmLabel={t("dns.view.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteView(props.view)
          .then(() => {
            toast({ kind: "ok", title: t("dns.view.deleted", { name: props.view.name }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dns.view.delete_body")}</p>
          <Show when={namedBy(error()).length > 0} fallback={<ErrorNotice error={error()} />}>
            <div class="note bad" role="alert" data-testid="view-in-use" data-code="dns.view.in_use">
              <p>{t("dns.view.in_use")}</p>
              <ul>
                <For each={namedBy(error())}>
                  {(by) => (
                    <li class="mono" data-testid="view-in-use-by" data-key={by}>
                      {by}
                    </li>
                  )}
                </For>
              </ul>
            </div>
          </Show>
        </>
      }
    />
  );
}
