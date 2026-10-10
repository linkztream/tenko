// Creates a VLAN with its network, or puts an existing VLAN onto the network (docs/topology.md,
// section 8): a form, then the preview of the provision job (the IPAM plan, the network step with
// the controller's read-back diff, the steps of the job and the warnings to acknowledge), then
// the start. Nothing is written before "Start"; Back returns to the form with its values. A
// retry of one confirmation keeps its Idempotency-Key, so a repeated start answers the first job.
import { createMemo, createResource, createSignal, createUniqueId, For, Show, untrack } from "solid-js";
import { createStore } from "solid-js/store";
import { ApiError, isApiError } from "../../api/problem";
import type { Vlan } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { ErrorNotice, Notice } from "../../components/Notice";
import { StatusBadge, TimeAgo } from "../../grid/cells";
import { t } from "../../i18n";
import { Field, FieldRow, SelectInput, type Option } from "../formKit";
import { codesToAcknowledge } from "../plan/describe";
import { useWriteToast } from "../plan/PlanDialog";
import { PlanPreview } from "../plan/PlanPreview";
import {
  listSites,
  listVrfs,
  newIdempotencyKey,
  previewProvision,
  submitProvision,
  type ControllerInfo,
  type VlanProvisionPreview,
  type VlanProvisionSubmitted,
} from "./api";
import {
  buildRequest,
  confirmKey,
  emptyForm,
  modeHint,
  modeWord,
  networkWarningText,
  problemText,
  reasonText,
  splitWarnings,
  stepText,
  validateForm,
  type ConfirmKey,
  type FormErrors,
  type ProvisionForm,
} from "./model";
import { createVlanStyles } from "./palette";
import { VlanChip } from "./VlanChip";
import "../forms.css";
import "../plan/plan.css";
import "./provision.css";

type Phase = "form" | "preview";

/** The general error of the dialog: the translated text, its code, and the way out of a controller error. */
function ErrorBlock(props: { error: unknown; byHand: boolean }) {
  const code = () => (props.error instanceof ApiError ? props.error.code : undefined);
  return (
    <Show when={props.error}>
      <div class="provision-error" data-testid="vlan-provision-error" data-code={code()}>
        <ErrorNotice error={props.error} />
        <Show when={props.byHand && (code() ?? "").startsWith("connect.")}>
          <p class="muted" data-testid="vlan-provision-hint">
            {t("ipam.vlan.provision.hint.by_hand")}
          </p>
        </Show>
      </div>
    </Show>
  );
}

export function ProvisionDialog(props: {
  /** An existing VLAN to put onto the network; absent for a new VLAN. */
  vlan?: Vlan | undefined;
  onClose: () => void;
  /** The job started (202); the page reloads its list. */
  onDone: (result: VlanProvisionSubmitted) => void;
}) {
  const existing = untrack(() => props.vlan);
  const writeToast = useWriteToast();
  const [form, setForm] = createStore<ProvisionForm>(
    emptyForm(existing ? { id: existing.id, vid: existing.vid, name: existing.name } : undefined),
  );
  const [sites] = createResource(async () => {
    try {
      return await listSites();
    } catch {
      return [];
    }
  });
  const [vrfs] = createResource(async () => {
    try {
      return await listVrfs();
    } catch {
      return [];
    }
  });
  const [phase, setPhase] = createSignal<Phase>("form");
  const [preview, setPreview] = createSignal<VlanProvisionPreview | null>(null);
  const [candidates, setCandidates] = createSignal<ControllerInfo[]>([]);
  const [errors, setErrors] = createSignal<FormErrors>({});
  const [error, setError] = createSignal<unknown>(null);
  const [note, setNote] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [acked, setAcked] = createSignal<ReadonlySet<string>>(new Set());
  const ids = createUniqueId();
  let key: ConfirmKey | null = null;
  let formRoot: HTMLFormElement | undefined;
  let previewRoot: HTMLDivElement | undefined;
  let startButton: HTMLButtonElement | undefined;

  const styles = createVlanStyles(() => {
    const p = preview();
    return p ? [p.vlan.vid] : [];
  });
  const title = () =>
    existing ? t("ipam.vlan.provision.title_existing", { vid: existing.vid }) : t("ipam.vlan.provision.title_new");

  const siteOptions = createMemo<Option[]>(() => [
    { value: "", label: t("ipam.field.none") },
    ...[...(sites() ?? [])].sort((a, b) => a.name.localeCompare(b.name)).map((s) => ({ value: s.id, label: s.name })),
  ]);
  const vrfOptions = createMemo<Option[]>(() => [
    { value: "", label: t("ipam.vlan.provision.vrf_default") },
    ...[...(vrfs() ?? [])].sort((a, b) => a.name.localeCompare(b.name)).map((v) => ({ value: v.id, label: v.name })),
  ]);
  const connectorOptions = createMemo<Option[]>(() => [
    { value: "", label: t("ipam.vlan.provision.connector_any") },
    ...candidates().map((c) => ({ value: c.id, label: c.name })),
  ]);
  const vrfName = (id: string) => vrfs()?.find((v) => v.id === id)?.name;
  const problem = (name: keyof FormErrors) => {
    const found = errors()[name];
    return found ? problemText(found) : undefined;
  };

  const split = createMemo(() => splitWarnings(preview()?.warnings ?? []));
  const networkBlocking = () => split().network.filter((w) => w.requires_ack && !w.acknowledged);
  const networkPlain = () => split().network.filter((w) => !(w.requires_ack && !w.acknowledged));
  const blocking = () => codesToAcknowledge(preview()?.warnings ?? []).filter((c) => !acked().has(c));

  const acknowledge = (code: string, on: boolean) => {
    const next = new Set(acked());
    if (on) next.add(code);
    else next.delete(code);
    setAcked(next);
  };

  const focusPreview = () => {
    if (startButton && !startButton.disabled) startButton.focus();
    else previewRoot?.querySelector<HTMLElement>('[data-testid="plan-ack"]')?.focus();
  };

  const runPreview = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await previewProvision(buildRequest(form, [...acked()]));
      setPreview(result);
      setCandidates(result.controller.candidates ?? []);
      setPhase("preview");
      queueMicrotask(focusPreview);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const submitForm = async () => {
    const found = validateForm(form);
    setErrors(found);
    if (Object.keys(found).length > 0) {
      queueMicrotask(() => formRoot?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      return;
    }
    setAcked(new Set<string>());
    setNote(null);
    await runPreview();
  };

  const back = () => {
    setError(null);
    setNote(null);
    setPhase("form");
    queueMicrotask(() => formRoot?.querySelector<HTMLElement>('[data-testid="form-submit"]')?.focus());
  };

  const start = async () => {
    setBusy(true);
    setError(null);
    const request = buildRequest(form, [...acked()]);
    key = confirmKey(key, request, newIdempotencyKey);
    try {
      const result = await submitProvision(request, key.key);
      writeToast(t("ipam.vlan.provision.started", { vid: result.preview.vlan.vid }), {
        dry_run: false,
        warnings: [],
        job_id: result.job_id,
      });
      props.onDone(result);
    } catch (err) {
      if (isApiError(err, "ipam.plan.stale") || isApiError(err, "ipam.plan.unacknowledged")) {
        // The data changed since the preview: a new preview, which the person reads again.
        setNote(t("ipam.plan.stale"));
        await runPreview();
        return;
      }
      setError(err);
      setBusy(false);
    }
  };

  const formView = () => (
    <form
      ref={(el) => (formRoot = el)}
      class="form-fields provision-form"
      data-testid="vlan-provision-form"
      novalidate
      onSubmit={(e) => {
        e.preventDefault();
        void submitForm();
      }}
    >
      <h2 class="dialog-title">{title()}</h2>
      <p class="muted">{existing ? t("ipam.vlan.provision.intro_existing") : t("ipam.vlan.provision.intro_new")}</p>

      <FieldRow>
        <Field name="vid" label={t("ipam.col.vid")} required={!existing} error={problem("vid")}>
          {(c) => (
            <input
              class="input"
              type={existing ? "text" : "number"}
              min="1"
              max="4094"
              autocomplete="off"
              readOnly={!!existing}
              {...c}
              value={form.vid}
              onInput={(e) => setForm("vid", e.currentTarget.value)}
            />
          )}
        </Field>
        <Field name="name" label={t("ipam.col.name")} required={!existing} error={problem("name")}>
          {(c) => (
            <input
              class="input"
              type="text"
              autocomplete="off"
              spellcheck={false}
              readOnly={!!existing}
              {...c}
              value={form.name}
              onInput={(e) => setForm("name", e.currentTarget.value)}
            />
          )}
        </Field>
      </FieldRow>
      <Show when={!existing}>
        <FieldRow>
          <Field name="site" label={t("ipam.col.site")}>
            {(c) => <SelectInput {...c} value={form.site} options={siteOptions()} onChange={(v) => setForm("site", v)} />}
          </Field>
          <Field name="vni" label={t("ipam.col.vni")} help={t("ipam.vlan.vni_help")} error={problem("vni")}>
            {(c) => (
              <input
                class="input"
                type="number"
                min="0"
                autocomplete="off"
                {...c}
                value={form.vni}
                onInput={(e) => setForm("vni", e.currentTarget.value)}
              />
            )}
          </Field>
        </FieldRow>
        <Field name="description" label={t("ipam.col.description")}>
          {(c) => (
            <input
              class="input"
              type="text"
              autocomplete="off"
              {...c}
              value={form.description}
              onInput={(e) => setForm("description", e.currentTarget.value)}
            />
          )}
        </Field>
      </Show>

      <div class="provision-prefix">
        <div class="check-field">
          <input
            id={`${ids}-with-prefix`}
            type="checkbox"
            class="cb"
            data-testid="field-with-prefix"
            aria-describedby={`${ids}-with-prefix-help`}
            checked={form.withPrefix}
            onChange={(e) => setForm("withPrefix", e.currentTarget.checked)}
          />
          <label for={`${ids}-with-prefix`}>{t("ipam.vlan.provision.with_prefix")}</label>
        </div>
        <span class="help" id={`${ids}-with-prefix-help`}>
          {t("ipam.vlan.provision.with_prefix_help")}
        </span>
        <Show when={form.withPrefix}>
          <FieldRow>
            <Field name="cidr" label={t("ipam.field.cidr")} help={t("ipam.field.cidr_help")} required error={problem("cidr")}>
              {(c) => (
                <input
                  class="input mono"
                  type="text"
                  autocomplete="off"
                  spellcheck={false}
                  {...c}
                  value={form.cidr}
                  onInput={(e) => setForm("cidr", e.currentTarget.value)}
                />
              )}
            </Field>
            <Field name="vrf" label={t("ipam.col.vrf")}>
              {(c) => <SelectInput {...c} value={form.vrf} options={vrfOptions()} onChange={(v) => setForm("vrf", v)} />}
            </Field>
          </FieldRow>
        </Show>
      </div>

      <fieldset class="provision-group">
        <legend>{t("ipam.vlan.provision.network_legend")}</legend>
        <label class="provision-choice">
          <input
            type="radio"
            name={`${ids}-controller`}
            value="auto"
            data-testid="field-controller-auto"
            checked={form.controller === "auto"}
            onChange={() => setForm("controller", "auto")}
          />
          <span>
            {t("ipam.vlan.provision.controller_auto")}
            <small class="help">{t("ipam.vlan.provision.controller_auto_help")}</small>
          </span>
        </label>
        <label class="provision-choice">
          <input
            type="radio"
            name={`${ids}-controller`}
            value="manual"
            data-testid="field-controller-manual"
            checked={form.controller === "manual"}
            onChange={() => setForm("controller", "manual")}
          />
          <span>
            {t("ipam.vlan.provision.controller_manual")}
            <small class="help">{t("ipam.vlan.provision.controller_manual_help")}</small>
          </span>
        </label>
      </fieldset>
      <Show when={form.controller === "auto" && candidates().length > 1}>
        <Field name="connector" label={t("ipam.vlan.provision.connector")} help={t("ipam.vlan.provision.connector_help")}>
          {(c) => <SelectInput {...c} value={form.connector} options={connectorOptions()} onChange={(v) => setForm("connector", v)} />}
        </Field>
      </Show>
      <FieldRow>
        <Field name="network-name" label={t("ipam.vlan.provision.network_name")} help={t("ipam.vlan.provision.network_name_help")} error={problem("network-name")}>
          {(c) => (
            <input
              class="input"
              type="text"
              autocomplete="off"
              spellcheck={false}
              {...c}
              placeholder={form.name.trim() || t("ipam.vlan.provision.network_name_placeholder")}
              value={form.networkName}
              onInput={(e) => setForm("networkName", e.currentTarget.value)}
            />
          )}
        </Field>
        <Show when={form.controller === "auto"}>
          <Field name="dhcp-relay" label={t("ipam.vlan.provision.dhcp_relay")} help={t("ipam.vlan.provision.dhcp_relay_help")} error={problem("dhcp-relay")}>
            {(c) => (
              <input
                class="input mono"
                type="text"
                autocomplete="off"
                spellcheck={false}
                {...c}
                value={form.dhcpRelay}
                onInput={(e) => setForm("dhcpRelay", e.currentTarget.value)}
              />
            )}
          </Field>
        </Show>
      </FieldRow>

      <ErrorBlock error={error()} byHand={form.controller === "auto"} />
      <Show when={busy()}>
        <p class="muted" role="status">
          {t("ipam.plan.previewing")}
        </p>
      </Show>
      <div class="dialog-actions">
        <button type="button" class="btn ghost" onClick={() => props.onClose()}>
          {t("common.action.cancel")}
        </button>
        <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
          {t("ipam.vlan.provision.preview")}
        </button>
      </div>
    </form>
  );

  const previewView = (p: VlanProvisionPreview) => {
    const controller = p.controller;
    const context = () => ({ vlan: { vid: p.vlan.vid, name: p.vlan.name }, existing: p.vlan.existing, mode: controller.mode });
    const diff = () => controller.diff ?? [];
    const notes = () => controller.warnings ?? [];
    const relays = () => controller.network.dhcp_relay ?? [];
    return (
      <div ref={(el) => (previewRoot = el)} class="provision-preview" data-testid="vlan-provision-preview">
        <h2 class="dialog-title">{title()}</h2>
        <p class="muted">{t("ipam.vlan.provision.preview_intro")}</p>
        <Show when={note()}>
          <Notice kind="info" role="status">
            {note()}
          </Notice>
        </Show>

        <section class="provision-section" aria-labelledby={`${ids}-exist`}>
          <h3 class="provision-heading" id={`${ids}-exist`}>
            {t("ipam.vlan.provision.will_exist")}
          </h3>
          <dl class="provision-facts">
            <div>
              <dt>{p.vlan.existing ? t("ipam.vlan.provision.vlan_existing") : t("ipam.vlan.provision.vlan_new")}</dt>
              <dd data-testid="vlan-provision-vlan">
                <VlanChip vid={p.vlan.vid} name={p.vlan.name} style={styles().get(p.vlan.vid)} /> <StatusBadge status={p.vlan.status} />
              </dd>
            </div>
            <Show when={p.prefix}>
              {(prefix) => (
                <div>
                  <dt>{t("ipam.field.cidr")}</dt>
                  <dd data-testid="vlan-provision-prefix" data-key={prefix().cidr}>
                    <span class="mono">{prefix().cidr}</span> <StatusBadge status="planned" />
                    <Show when={prefix().vrf && vrfName(prefix().vrf as string)}>
                      {(name) => <span class="muted"> {t("ipam.col.vrf")} {name()}</span>}
                    </Show>
                  </dd>
                </div>
              )}
            </Show>
          </dl>
        </section>

        <Show when={p.plan}>
          <PlanPreview plan={p.plan} warnings={split().plan} acknowledged={acked()} onAcknowledge={acknowledge} />
        </Show>

        <section
          class="provision-section"
          data-testid="vlan-provision-controller"
          data-mode={controller.mode}
          aria-labelledby={`${ids}-network`}
        >
          <h3 class="provision-heading" id={`${ids}-network`}>
            {t("ipam.vlan.provision.network_legend")}
          </h3>
          <p class="provision-mode">
            <span class={controller.mode === "automatic" ? "tag ok" : controller.mode === "manual" ? "tag accent" : "tag"} data-testid="vlan-provision-mode">
              {modeWord(controller.mode)}
            </span>{" "}
            <span class="muted">{modeHint(controller.mode)}</span>
          </p>
          <Show when={controller.reason}>
            {(reason) => (
              <p data-testid="vlan-provision-reason" data-code={reason()}>
                {reasonText(reason())}
              </p>
            )}
          </Show>
          <dl class="provision-facts">
            <div>
              <dt>{t("ipam.vlan.provision.controller_label")}</dt>
              <dd data-testid="vlan-provision-connector">
                <Show when={controller.connector} fallback={<span class="muted">{t("ipam.vlan.provision.controller_none")}</span>}>
                  {(c) => (
                    <>
                      <span>{c().name}</span> <span class="tag">{c().plugin}</span>
                      <Show when={!c().writes_enabled}>
                        {" "}
                        <span class="tag conflict">{t("ipam.vlan.provision.read_only")}</span>
                      </Show>
                    </>
                  )}
                </Show>
              </dd>
            </div>
            <div>
              <dt>{t("ipam.vlan.provision.network_name")}</dt>
              <dd class="mono" data-testid="vlan-provision-network">
                {controller.network.name}
              </dd>
            </div>
            <div>
              <dt>{t("ipam.vlan.provision.dhcp_relay")}</dt>
              <dd class="mono" data-testid="vlan-provision-relays">
                <Show when={relays().length > 0} fallback={<span class="muted">{t("ipam.vlan.provision.dhcp_off")}</span>}>
                  {relays().join(", ")}
                </Show>
              </dd>
            </div>
          </dl>
          <Show
            when={diff().length > 0}
            fallback={
              <Show when={controller.mode === "unchanged"}>
                <p class="muted" data-testid="vlan-provision-unchanged">
                  {t("ipam.vlan.provision.diff_none")}
                </p>
              </Show>
            }
          >
            <div class="table-wrap provision-diff">
              <table class="plain" data-testid="vlan-provision-diff" aria-label={t("ipam.vlan.provision.diff_heading")}>
                <thead>
                  <tr>
                    <th scope="col">{t("ipam.vlan.provision.diff.setting")}</th>
                    <th scope="col">{t("ipam.vlan.provision.diff.now")}</th>
                    <th scope="col">{t("ipam.vlan.provision.diff.planned")}</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={diff()}>
                    {(line) => (
                      <tr data-testid="diff-line" data-key={line.path}>
                        <td class="mono">{line.path}</td>
                        <td>
                          <Show when={line.before != null} fallback={<span class="muted">{t("ipam.vlan.provision.diff.absent")}</span>}>
                            <del class="mono">{line.before}</del>
                          </Show>
                        </td>
                        <td>
                          <Show when={line.after != null} fallback={<span class="muted">{t("ipam.vlan.provision.diff.removed")}</span>}>
                            <ins class="mono">{line.after}</ins>
                          </Show>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
          <Show when={notes().length > 0}>
            <div class="provision-notes" data-testid="vlan-provision-notes">
              <h4 class="provision-subheading">{t("ipam.vlan.provision.notes_heading")}</h4>
              <ul class="muted">
                <For each={notes()}>{(text) => <li>{text}</li>}</For>
              </ul>
            </div>
          </Show>
          <Show when={controller.read_at}>
            {(at) => (
              <p class="muted provision-read">
                {t("ipam.vlan.provision.read_at")} <TimeAgo at={at()} />
              </p>
            )}
          </Show>
        </section>

        <Show when={networkBlocking().length > 0}>
          <div class="plan-warnings" data-testid="vlan-provision-warnings">
            <For each={networkBlocking()}>
              {(w) => (
                <Notice kind="warn">
                  <p>{networkWarningText(w)}</p>
                  <label class="ackrow">
                    <input
                      type="checkbox"
                      class="cb"
                      checked={acked().has(w.code)}
                      data-testid="plan-ack"
                      data-code={w.code}
                      onChange={(e) => acknowledge(w.code, e.currentTarget.checked)}
                    />
                    {t("ipam.plan.ack")}
                  </label>
                </Notice>
              )}
            </For>
          </div>
        </Show>
        <Show when={networkPlain().length > 0}>
          <div class="plan-warnings">
            <For each={networkPlain()}>{(w) => <Notice kind="info">{networkWarningText(w)}</Notice>}</For>
          </div>
        </Show>

        <section class="provision-section" aria-labelledby={`${ids}-steps`}>
          <h3 class="provision-heading" id={`${ids}-steps`}>
            {t("ipam.vlan.provision.steps_heading")}
          </h3>
          <ol class="provision-steps">
            <For each={p.steps}>
              {(step) => (
                <li
                  data-testid="vlan-provision-step"
                  data-kind={step.kind}
                  data-step-kind={step.step_kind}
                  data-mode={step.automatic ? "automatic" : "manual"}
                >
                  <span class={step.automatic ? "tag ok" : "tag accent"}>{modeWord(step.automatic ? "automatic" : "manual")}</span>
                  <span>{stepText(step, context())}</span>
                </li>
              )}
            </For>
          </ol>
        </section>

        <ErrorBlock error={error()} byHand={form.controller === "auto"} />
        <Show when={blocking().length > 0}>
          <p class="muted">{t("ipam.plan.ack_needed")}</p>
        </Show>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="button" class="btn" data-testid="vlan-provision-back" disabled={busy()} onClick={back}>
            {t("common.action.back")}
          </button>
          <button
            ref={(el) => (startButton = el)}
            type="button"
            class="btn primary"
            data-testid="vlan-provision-confirm"
            disabled={busy() || blocking().length > 0}
            onClick={() => void start()}
          >
            {t("ipam.vlan.provision.start")}
          </button>
        </div>
      </div>
    );
  };

  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog provision-dialog" testid="dialog-vlan-provision">
      <Show when={phase() === "preview" ? preview() : null} fallback={formView()} keyed>
        {(p) => previewView(p)}
      </Show>
    </Dialog>
  );
}
