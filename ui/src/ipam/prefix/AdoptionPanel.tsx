// The adoption policy of a prefix (IPAM-15, docs/reconciliation.md section 6): the policy in
// force with where it comes from (its own, inherited from a containing prefix, or the default
// "manual"), and the form that sets the prefix's own policy or clears it so that it inherits
// again. Writes carry the revision of the own policy the person saw (`If-Match`; 0 when the
// prefix has none). Administrators and operators edit; everyone else reads.
import { A } from "@solidjs/router";
import { createEffect, createSignal, For, on, Show } from "solid-js";
import { createLiveQuery } from "../../api/live";
import { ApiError, isApiError } from "../../api/problem";
import type { AssignmentMode, Prefix } from "../../api/types";
import { ASSIGNMENT_MODES } from "../../api/types";
import { paths } from "../../app/paths";
import { may } from "../../auth/gate";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PrincipalLabel } from "../../components/Principal";
import { toast } from "../../components/toast";
import { TimeAgo } from "../../grid/cells";
import { formatList, t, tDynamic } from "../../i18n";
import {
  ADOPTION_MODES,
  clearAdoptionPolicy,
  getAdoptionPolicy,
  setAdoptionPolicy,
  type AdoptionMode,
  type AdoptionPolicy,
  type PolicyView,
} from "../../discovery/api";
import { PrefixRef } from "../../discovery/refs";
import { Field, FieldRow, SelectInput } from "../formKit";
import { modeWord } from "../words";
import "./adoption.css";

const MAX_VENDORS = 32;
const MAX_SIGHTINGS = 1000;

export function modeText(mode: AdoptionMode): string {
  return t(`ipam.adoption.mode.${mode}`);
}

/** The vendors of the text field: one per line or comma, trimmed, without duplicates. */
export function parseVendors(text: string): string[] {
  return [...new Set(text.split(/[\n,]/).map((v) => v.trim()).filter(Boolean))];
}

/** A problem of the form that the server would refuse too, by field. */
export function checkPolicy(policy: AdoptionPolicy): { field: string; message: string } | null {
  const vendors = policy.vendors ?? [];
  if (vendors.length > MAX_VENDORS) return { field: "vendors", message: t("ipam.adoption.error.vendors_count", { max: MAX_VENDORS }) };
  if (vendors.some((v) => [...v].length > 64)) return { field: "vendors", message: t("ipam.adoption.error.vendor_length") };
  const n = policy.min_sightings ?? 1;
  if (!Number.isInteger(n) || n < 1 || n > MAX_SIGHTINGS) return { field: "min_sightings", message: t("ipam.adoption.error.sightings", { max: MAX_SIGHTINGS }) };
  return null;
}

/** The constraints of a policy in words, for the summary of the policy in force. */
function constraints(policy: AdoptionPolicy): string[] {
  const out: string[] = [];
  if (policy.mode === "manual") return out;
  if (policy.only_dhcp_pools) out.push(t("ipam.adoption.only_pools_on"));
  if ((policy.vendors ?? []).length > 0) out.push(t("ipam.adoption.vendors_on", { vendors: formatList(policy.vendors ?? []) }));
  if ((policy.min_sightings ?? 1) > 1) out.push(t("ipam.adoption.sightings_on", { count: policy.min_sightings ?? 1 }));
  out.push(t("ipam.adoption.host_mode_on", { mode: modeWord(policy.host_mode ?? "dynamic") }));
  return out;
}

export function AdoptionPanel(props: { prefix: Prefix }) {
  const live = createLiveQuery<PolicyView>({
    topics: ["ipam"],
    relevant: (e) => {
      const tables = e.data.tables;
      return (Array.isArray(tables) && tables.includes("ipam.adoption")) || e.objects.some((o) => o.kind === "prefix");
    },
    fetch: async (signal) => {
      const view = await getAdoptionPolicy(props.prefix.id, signal);
      return { value: view };
    },
  });
  // `latest` rethrows the error of a failed read; the error is shown below instead.
  const view = () => (live.value.error ? undefined : live.value.latest);

  const [editing, setEditing] = createSignal(false);
  const [mode, setMode] = createSignal<AdoptionMode>("manual");
  const [pools, setPools] = createSignal(false);
  const [vendors, setVendors] = createSignal("");
  const [sightings, setSightings] = createSignal("1");
  const [hostMode, setHostMode] = createSignal<AssignmentMode>("dynamic");
  const [error, setError] = createSignal<unknown>(null);
  const [local, setLocal] = createSignal<{ field: string; message: string } | null>(null);
  const [busy, setBusy] = createSignal(false);

  /** Starts the form from the own policy, or from the one in force when the prefix inherits. */
  const fill = (v: PolicyView) => {
    const p = v.policy ?? v.effective;
    setMode(p.mode);
    setPools(!!p.only_dhcp_pools);
    setVendors((p.vendors ?? []).join("\n"));
    setSightings(String(p.min_sightings ?? 1));
    setHostMode(p.host_mode ?? "dynamic");
    setError(null);
    setLocal(null);
  };
  createEffect(on(view, (v) => v && !editing() && fill(v)));

  const policy = (): AdoptionPolicy => ({
    mode: mode(),
    only_dhcp_pools: pools(),
    vendors: parseVendors(vendors()),
    min_sightings: Number(sightings()),
    host_mode: hostMode(),
  });

  /** The field an error is about: a local check, or the `field` parameter of `ipam.adoption.invalid`. */
  const fieldError = (name: string): string | undefined => {
    const l = local();
    if (l?.field === name) return l.message;
    const e = error();
    if (e instanceof ApiError && e.is("ipam.adoption.invalid") && e.params.field === name) {
      return tDynamic(`errors.${e.code}`, e.params) ?? e.detail;
    }
    return undefined;
  };
  const generalError = () => {
    const e = error();
    return e instanceof ApiError && e.is("ipam.adoption.invalid") && ["mode", "only_dhcp_pools", "vendors", "min_sightings", "host_mode"].includes(e.params.field ?? "")
      ? null
      : e;
  };

  const save = async (e: Event) => {
    e.preventDefault();
    const v = view();
    if (!v || busy()) return;
    const body = policy();
    const problem = checkPolicy(body);
    setLocal(problem);
    if (problem) return;
    setBusy(true);
    setError(null);
    try {
      await setAdoptionPolicy(props.prefix.id, body, v.revision);
      setEditing(false);
      toast({ kind: "ok", title: t("ipam.adoption.saved", { prefix: props.prefix.cidr }) });
      live.refetch();
    } catch (err) {
      setError(err);
      if (isApiError(err, "ipam.revision_mismatch")) live.refetch();
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    const v = view();
    if (!v || busy()) return;
    setBusy(true);
    setError(null);
    try {
      await clearAdoptionPolicy(props.prefix.id, v.revision);
      setEditing(false);
      toast({ kind: "ok", title: t("ipam.adoption.cleared", { prefix: props.prefix.cidr }) });
      live.refetch();
    } catch (err) {
      setError(err);
      if (isApiError(err, "ipam.revision_mismatch")) live.refetch();
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="adoption" aria-labelledby="adoption-title" data-testid="prefix-adoption">
      <h3 id="adoption-title" class="sr-only">
        {t("ipam.adoption.title")}
      </h3>
      <Show when={live.value.error && !view()}>
        <ErrorNotice error={live.value.error} />
      </Show>
      <Show when={view()} fallback={<Show when={!live.value.error}><p class="muted" role="status">{t("common.loading")}</p></Show>}>
        {(v) => (
          <>
            <div class="adoption-effective" data-testid="adoption-effective" data-mode={v().effective.mode}>
              <p>
                <strong>{modeText(v().effective.mode)}</strong>
              </p>
              <p class="muted" data-testid="adoption-source" data-source={v().policy ? "own" : v().source ? "inherited" : "default"}>
                <Show when={v().policy}>{t("ipam.adoption.source_own")}</Show>
                <Show when={!v().policy && v().source}>
                  {(source) => (
                    <>
                      {t("ipam.adoption.source_inherited")} <PrefixRef id={source() as string} />
                    </>
                  )}
                </Show>
                <Show when={!v().policy && !v().source}>{t("ipam.adoption.source_default")}</Show>
                <Show when={v().policy && v().updated}>
                  {(u) => (
                    <>
                      {" · "}
                      {t("ipam.adoption.updated_by")} <PrincipalLabel principal={u().by} /> <TimeAgo at={u().at} />
                    </>
                  )}
                </Show>
              </p>
              <Show when={constraints(v().effective).length > 0}>
                <ul class="adoption-constraints">
                  <For each={constraints(v().effective)}>{(c) => <li>{c}</li>}</For>
                </ul>
              </Show>
              <p class="muted">{t("ipam.adoption.never")}</p>
              <p>
                <A href={paths.discovery({ prefix: props.prefix.id })} data-testid="adoption-proposals">
                  <Icon name="proposal" size="sm" /> {t("ipam.adoption.proposals")}
                </A>
              </p>
            </div>

            {/* Changing or clearing a policy is an update of the prefix (docs/access.md section 3). */}
            <Show when={may.prefix(props.prefix.id) && !props.prefix.meta.deleted}>
              <Show
                when={editing()}
                fallback={
                  <>
                    {/* A refused clear has no form to show its problem in. */}
                    <ErrorNotice error={error()} />
                    <div class="row-actions">
                      <button
                        type="button"
                        class="btn"
                        data-testid="adoption-edit"
                        onClick={() => {
                          setError(null);
                          setEditing(true);
                        }}
                      >
                        <Icon name="settings" />
                        {v().policy ? t("ipam.adoption.edit") : t("ipam.adoption.set")}
                      </button>
                      <Show when={v().policy}>
                        <button type="button" class="btn ghost" data-testid="adoption-clear" disabled={busy()} onClick={() => void clear()}>
                          {t("ipam.adoption.clear")}
                        </button>
                      </Show>
                    </div>
                  </>
                }
              >
                <form class="adoption-form" data-testid="dialog-adoption-form" onSubmit={(e) => void save(e)} novalidate>
                  <fieldset class="adoption-modes">
                    <legend>{t("ipam.adoption.mode_label")}</legend>
                    <For each={ADOPTION_MODES}>
                      {(m) => (
                        <label class="radio-row">
                          <input type="radio" name="adoption-mode" value={m} checked={mode() === m} data-testid={`field-mode-${m}`} onChange={() => setMode(m)} />
                          <span>
                            {modeText(m)}
                            <small class="help">{t(`ipam.adoption.mode_hint.${m}`)}</small>
                          </span>
                        </label>
                      )}
                    </For>
                  </fieldset>
                  <Show when={mode() !== "manual"}>
                    <label class="check-row">
                      <input type="checkbox" class="cb" checked={pools()} data-testid="field-only_dhcp_pools" onChange={(e) => setPools(e.currentTarget.checked)} />
                      {t("ipam.adoption.only_pools")}
                    </label>
                    <FieldRow>
                      <Field name="min_sightings" label={t("ipam.adoption.min_sightings")} help={t("ipam.adoption.min_sightings_help")} error={fieldError("min_sightings")}>
                        {(c) => (
                          <input
                            {...c}
                            class="input num"
                            type="number"
                            min="1"
                            max={MAX_SIGHTINGS}
                            step="1"
                            value={sightings()}
                            onInput={(e) => setSightings(e.currentTarget.value)}
                          />
                        )}
                      </Field>
                      <Field name="host_mode" label={t("ipam.adoption.host_mode")} help={t("ipam.adoption.host_mode_help")} error={fieldError("host_mode")}>
                        {(c) => (
                          <SelectInput
                            {...c}
                            value={hostMode()}
                            options={ASSIGNMENT_MODES.map((m) => ({ value: m, label: modeWord(m) }))}
                            onChange={setHostMode}
                          />
                        )}
                      </Field>
                    </FieldRow>
                    <Field name="vendors" label={t("ipam.adoption.vendors")} help={t("ipam.adoption.vendors_help")} error={fieldError("vendors")}>
                      {(c) => (
                        <textarea {...c} class="input mono" rows={3} spellcheck={false} value={vendors()} onInput={(e) => setVendors(e.currentTarget.value)} />
                      )}
                    </Field>
                  </Show>
                  <Show when={isApiError(error(), "ipam.revision_mismatch")}>
                    <Notice kind="warn">{t("ipam.adoption.stale")}</Notice>
                  </Show>
                  <Show when={!isApiError(error(), "ipam.revision_mismatch")}>
                    <ErrorNotice error={generalError()} />
                  </Show>
                  <div class="dialog-actions">
                    <button
                      type="button"
                      class="btn ghost"
                      onClick={() => {
                        setEditing(false);
                        const current = view();
                        if (current) fill(current);
                      }}
                    >
                      {t("common.action.cancel")}
                    </button>
                    <button type="submit" class="btn primary" disabled={busy()} data-testid="form-submit">
                      {t("ipam.adoption.save")}
                    </button>
                  </div>
                </form>
              </Show>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}
