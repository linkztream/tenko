// The name authority section of the reconciler settings page (docs/reconciliation.md): the
// order of the kinds of source that decides which name a host takes when the sources disagree.
// The global order (the default one until a rule is stored), the rules of sites, and the hosts
// that prefer a source. Every change is its own request; a refused one (422 for an empty order
// or a duplicate, 404 for a site that is gone) shows as the page shows its other errors.
import { A } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { latest } from "../../api/live";
import { fetchAll } from "../../api/paginate";
import type { Site } from "../../api/types";
import { paths } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { PrincipalLabel } from "../../components/Principal";
import { toast } from "../../components/toast";
import { nameSourceWord } from "../../discovery/model";
import { TimeAgo } from "../../grid/cells";
import { t } from "../../i18n";
import { moveSource, removeSourceAt, sameOrder, sourcesLeft, type HostPreference, type NameAuthorityView, type NameSource, type StoredAuthority } from "./model";

const BASE = "/api/v1/settings/reconciler/name-authority";

function loadView(): Promise<NameAuthorityView> {
  return api.get(BASE);
}

/** The ordered list of kinds with its buttons: move up, move down, remove, and an add select. */
function OrderEditor(props: { id: string; order: readonly NameSource[]; sources: readonly NameSource[]; disabled: boolean; onChange: (order: NameSource[]) => void }) {
  let list: HTMLOListElement | undefined;
  const left = () => sourcesLeft(props.sources, props.order);
  const [adding, setAdding] = createSignal("");

  // Moving a row re-inserts its element, which drops the focus: put it back on the button that
  // was used, or on the other one when that button is disabled now at the end of the list.
  const focusAfter = (source: NameSource, button: "up" | "down") => {
    queueMicrotask(() => {
      const row = list?.querySelector<HTMLElement>(`[data-source="${source}"]`);
      const wanted = row?.querySelector<HTMLButtonElement>(`[data-testid="move-${button}"]`);
      const other = row?.querySelector<HTMLButtonElement>(`[data-testid="move-${button === "up" ? "down" : "up"}"]`);
      (wanted && !wanted.disabled ? wanted : other)?.focus();
    });
  };
  const move = (index: number, delta: -1 | 1) => {
    const source = props.order[index] as NameSource;
    props.onChange(moveSource(props.order, index, delta));
    focusAfter(source, delta < 0 ? "up" : "down");
  };
  const add = () => {
    const source = left().find((s) => s === adding());
    if (!source) return;
    props.onChange([...props.order, source]);
    setAdding("");
  };

  return (
    <div class="rc-editor">
      <ol class="rc-order" ref={list} aria-label={t("reconciler.names.order_label")} data-testid={`${props.id}-order`}>
        <For each={props.order}>
          {(source, index) => (
            <li data-testid="name-source" data-source={source}>
              <span class="rc-source-name">{nameSourceWord(source)}</span>
              <button
                type="button"
                class="icon-btn"
                data-testid="move-up"
                aria-label={t("reconciler.names.move_up", { source: nameSourceWord(source) })}
                title={t("reconciler.names.move_up", { source: nameSourceWord(source) })}
                disabled={props.disabled || index() === 0}
                onClick={() => move(index(), -1)}
              >
                <Icon name="chev-u" />
              </button>
              <button
                type="button"
                class="icon-btn"
                data-testid="move-down"
                aria-label={t("reconciler.names.move_down", { source: nameSourceWord(source) })}
                title={t("reconciler.names.move_down", { source: nameSourceWord(source) })}
                disabled={props.disabled || index() === props.order.length - 1}
                onClick={() => move(index(), 1)}
              >
                <Icon name="chev-d" />
              </button>
              <button
                type="button"
                class="icon-btn"
                data-testid="remove-source"
                aria-label={t("reconciler.names.remove_source", { source: nameSourceWord(source) })}
                title={t("reconciler.names.remove_source", { source: nameSourceWord(source) })}
                disabled={props.disabled}
                onClick={() => props.onChange(removeSourceAt(props.order, index()))}
              >
                <Icon name="x" />
              </button>
            </li>
          )}
        </For>
      </ol>
      <Show when={props.order.length === 0}>
        <p class="help bad" role="status" data-testid="order-empty">
          {t("reconciler.names.empty_order")}
        </p>
      </Show>
      <Show when={left().length > 0}>
        <div class="form-row">
          <label class="sr-only" for={`${props.id}-add`}>
            {t("reconciler.names.add_label")}
          </label>
          <select id={`${props.id}-add`} class="select" data-testid="add-source" value={adding()} disabled={props.disabled} onChange={(e) => setAdding(e.currentTarget.value)}>
            <option value="">{t("reconciler.names.add_choose")}</option>
            <For each={left()}>{(source) => <option value={source}>{nameSourceWord(source)}</option>}</For>
          </select>
          <button type="button" class="btn" data-testid="add-source-button" disabled={props.disabled || adding() === ""} onClick={add}>
            <Icon name="plus" />
            {t("common.action.add")}
          </button>
        </div>
      </Show>
    </div>
  );
}

/**
 * One rule: the editor with Save and a second button that removes the rule (the global rule
 * falls back to the default order, a site's rule goes). A rule that is not stored yet starts
 * from `initial`; `onCancel` takes the place of removing for one that was just added.
 */
function RuleBlock(props: {
  id: string;
  title: string;
  stored: StoredAuthority | null;
  /** The order the editor starts from while nothing is stored. */
  initial: readonly NameSource[];
  sources: readonly NameSource[];
  /** The order is the default one (nothing stored): it is marked so. */
  isDefault?: boolean;
  removeLabel: string;
  save: (order: NameSource[]) => Promise<void>;
  remove?: () => Promise<void>;
  onCancel?: () => void;
}) {
  // The editor starts from the stored order, or from the one to start with; it is a copy to work on.
  const [draft, setDraft] = createSignal<NameSource[]>(untrack(() => [...(props.stored?.order ?? props.initial)]));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const changed = () => !sameOrder(draft(), props.stored?.order ?? props.initial);
  // A rule that is not stored yet can be stored as it stands; a stored one only when it changed.
  const canSave = () => !busy() && draft().length > 0 && (props.stored === null || changed());

  const run = async (action: () => Promise<void>) => {
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="card rc-rule" aria-labelledby={`${props.id}-title`} data-testid={props.id}>
      <h3 id={`${props.id}-title`}>
        {props.title}
        <Show when={props.isDefault && props.stored === null}>
          <span class="tag" data-testid="default-tag">
            {t("reconciler.names.default_tag")}
          </span>
        </Show>
      </h3>
      <Show when={props.isDefault && props.stored === null}>
        <p class="help">{t("reconciler.names.default_help")}</p>
      </Show>
      <ErrorNotice error={error()} />
      <OrderEditor id={props.id} order={draft()} sources={props.sources} disabled={busy()} onChange={setDraft} />
      <div class="form-row">
        <button type="button" class="btn primary" data-testid="save-rule" disabled={!canSave()} onClick={() => void run(() => props.save(draft()))}>
          {t("common.action.save")}
        </button>
        <Show
          when={props.onCancel && props.stored === null}
          fallback={
            <Show when={props.remove && props.stored !== null}>
              <button
                type="button"
                class="btn"
                data-testid="remove-rule"
                disabled={busy()}
                onClick={() =>
                  void run(async () => {
                    await props.remove?.();
                    setDraft([...props.initial]);
                  })
                }
              >
                {props.removeLabel}
              </button>
            </Show>
          }
        >
          <button type="button" class="btn ghost" data-testid="cancel-rule" disabled={busy()} onClick={() => props.onCancel?.()}>
            {t("common.action.cancel")}
          </button>
        </Show>
      </div>
    </section>
  );
}

export function NameAuthority() {
  const [loaded, { refetch }] = createResource(loadView);
  const [siteList] = createResource(() => fetchAll<Site>("/api/v1/sites").then((r) => r.items));
  const view = () => latest(loaded);

  // Sites whose rule is being written and is not stored yet, with the name to show.
  const [added, setAdded] = createSignal<{ id: string; name: string }[]>([]);
  const [pick, setPick] = createSignal("");
  const [forgetError, setForgetError] = createSignal<unknown>(null);

  const sources = () => view()?.sources ?? [];
  const storedSites = () => view()?.sites ?? [];
  const ruleSiteIds = createMemo(() => [...storedSites().map((s) => s.site as string), ...added().map((a) => a.id)].filter((id, i, all) => all.indexOf(id) === i));
  const siteName = (id: string): string =>
    storedSites().find((s) => s.site === id)?.site_name ?? added().find((a) => a.id === id)?.name ?? siteList()?.find((s) => s.id === id)?.name ?? id;
  const siteChoices = () => (siteList() ?? []).filter((s) => !ruleSiteIds().includes(s.id));

  const globalOrder = () => view()?.global?.order ?? view()?.default_order ?? [];

  const saveGlobal = async (order: NameSource[]) => {
    await api.put(BASE, { body: { order } });
    toast({ kind: "ok", title: t("reconciler.names.saved") });
    await refetch();
  };
  const resetGlobal = async () => {
    await api.delete(BASE);
    toast({ kind: "ok", title: t("reconciler.names.reset_done") });
    await refetch();
  };
  const saveSite = async (id: string, order: NameSource[]) => {
    await api.put(`${BASE}/sites/{site}`, { path: { site: id }, body: { order } });
    toast({ kind: "ok", title: t("reconciler.names.site_saved", { site: siteName(id) }) });
    await refetch();
    setAdded((list) => list.filter((a) => a.id !== id));
  };
  const removeSite = async (id: string) => {
    await api.delete(`${BASE}/sites/{site}`, { path: { site: id } });
    toast({ kind: "ok", title: t("reconciler.names.site_removed", { site: siteName(id) }) });
    await refetch();
  };
  const addSite = () => {
    const site = siteChoices().find((s) => s.id === pick());
    if (!site) return;
    setAdded((list) => [...list, { id: site.id, name: site.name }]);
    setPick("");
  };
  const forget = async (p: HostPreference) => {
    setForgetError(null);
    try {
      await api.delete(`${BASE}/hosts/{host}`, { path: { host: p.host } });
      toast({ kind: "ok", title: t("reconciler.names.forgotten", { host: p.host_name }) });
      await refetch();
    } catch (err) {
      setForgetError(err);
    }
  };

  return (
    <section class="rc-names" aria-labelledby="rc-names-title" data-testid="name-authority">
      <h2 id="rc-names-title">{t("reconciler.names.title")}</h2>
      <p class="muted">{t("reconciler.names.lede")}</p>
      <ErrorNotice error={loaded.error} />
      <Show when={view()} fallback={<Show when={!loaded.error}><p class="muted" role="status">{t("common.loading")}</p></Show>}>
        {(current) => (
          <>
            <RuleBlock
              id="name-global"
              title={t("reconciler.names.global_title")}
              stored={current().global ?? null}
              initial={current().default_order}
              sources={sources()}
              isDefault
              removeLabel={t("reconciler.names.reset")}
              save={saveGlobal}
              remove={resetGlobal}
            />

            <div class="rc-sites" data-testid="name-sites">
              <h3>{t("reconciler.names.sites_title")}</h3>
              <Show when={ruleSiteIds().length === 0}>
                <p class="muted" data-testid="name-sites-empty">
                  {t("reconciler.names.sites_empty")}
                </p>
              </Show>
              <For each={ruleSiteIds()}>
                {(id) => (
                  <RuleBlock
                    id={`name-site-${id}`}
                    title={t("reconciler.names.site_rule", { site: siteName(id) })}
                    stored={(view()?.sites ?? []).find((s) => s.site === id) ?? null}
                    initial={globalOrder()}
                    sources={sources()}
                    removeLabel={t("reconciler.names.remove_rule")}
                    save={(order) => saveSite(id, order)}
                    remove={() => removeSite(id)}
                    onCancel={() => setAdded((list) => list.filter((a) => a.id !== id))}
                  />
                )}
              </For>
              <Show when={siteChoices().length > 0} fallback={<Show when={siteList() && ruleSiteIds().length > 0}><p class="help">{t("reconciler.names.site_none_left")}</p></Show>}>
                <div class="form-row">
                  <label class="sr-only" for="name-site-pick">
                    {t("reconciler.names.site_add_label")}
                  </label>
                  <select id="name-site-pick" class="select" data-testid="add-site" value={pick()} onChange={(e) => setPick(e.currentTarget.value)}>
                    <option value="">{t("reconciler.names.site_add_choose")}</option>
                    <For each={siteChoices()}>{(site) => <option value={site.id}>{site.name}</option>}</For>
                  </select>
                  <button type="button" class="btn" data-testid="add-site-button" disabled={pick() === ""} onClick={addSite}>
                    <Icon name="plus" />
                    {t("reconciler.names.site_add")}
                  </button>
                </div>
              </Show>
            </div>

            <div class="rc-prefs" data-testid="name-preferences">
              <h3>{t("reconciler.names.prefs_title")}</h3>
              <p class="help">{t("reconciler.names.prefs_help")}</p>
              <ErrorNotice error={forgetError()} />
              <Show when={current().preferences.length > 0} fallback={<p class="muted" data-testid="name-preferences-empty">{t("reconciler.names.prefs_empty")}</p>}>
                <div class="table-wrap">
                  <table class="plain" aria-label={t("reconciler.names.prefs_title")}>
                    <thead>
                      <tr>
                        <th scope="col">{t("reconciler.names.col_host")}</th>
                        <th scope="col">{t("reconciler.names.col_source")}</th>
                        <th scope="col">{t("reconciler.names.col_name")}</th>
                        <th scope="col">{t("reconciler.names.col_decided")}</th>
                        <th scope="col">
                          <span class="sr-only">{t("reconciler.names.forget")}</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={current().preferences}>
                        {(p) => (
                          <tr data-testid="name-preference" data-host={p.host}>
                            <td>
                              <A href={paths.host(p.host_name)}>{p.host_name}</A>
                            </td>
                            <td>{nameSourceWord(p.source)}</td>
                            <td class="mono">{p.name}</td>
                            <td>
                              <PrincipalLabel principal={p.decided.by} /> <TimeAgo at={p.decided.at} />
                            </td>
                            <td>
                              <button
                                type="button"
                                class="btn"
                                data-testid="forget-preference"
                                aria-label={t("reconciler.names.forget_label", { host: p.host_name })}
                                onClick={() => void forget(p)}
                              >
                                {t("reconciler.names.forget")}
                              </button>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
              </Show>
            </div>
          </>
        )}
      </Show>
    </section>
  );
}
