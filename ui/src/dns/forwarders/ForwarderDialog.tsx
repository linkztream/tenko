// The dialogs of a forwarding rule: create and edit (suffix, transport, upstreams, the TLS name
// of DoT and DoH, the description; an edit of a rule bound to one view can make it apply in
// every view again) and delete. The form checks what it can before it sends; a refusal of the
// server (`dns.forwarder.invalid` with `field`) lands under the field it names.
//
// WP10.4: a rule's mode. `forward` asks the upstreams (with `validate` as the escape hatch for an
// upstream that strips DNSSEC signatures); `recurse` resolves the names under the suffix from the
// root servers and has no upstreams, no transport and no TLS name (and always validates). The
// preset "Forward everything to a DoT resolver" opens the form as a root rule over DoT, with the
// privacy sentence of the recursion plan's section 2.8 and the well-known resolvers to pick from.
import { createMemo, createSignal, For, Show, untrack } from "solid-js";
import { ApiError } from "../../api/problem";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { describedBy, Field } from "../Parts";
import { createForwarder, deleteForwarder, updateForwarder, type ForwarderItem, type ForwarderPatch } from "./api";
import {
  checkRule,
  isRoot,
  KNOWN_RESOLVERS,
  knownResolver,
  needsTlsName,
  splitUpstreams,
  TRANSPORTS,
  upstreamText,
  type ForwardTransport,
  type RuleProblem,
} from "./model";

/** The message of a local problem of the form. */
function problemText(p: RuleProblem): string {
  switch (p.field) {
    case "suffix":
      return t("dns.fwd.check.suffix");
    case "tls_name":
      return p.problem === "required" ? t("dns.fwd.check.tls_required") : t("dns.fwd.check.tls_name");
    case "upstreams":
      switch (p.problem) {
        case "none":
          return t("dns.fwd.check.none");
        case "too_many":
          return t("dns.fwd.check.too_many");
        case "duplicate":
          return t("dns.fwd.check.duplicate");
        case "address":
          return t("dns.fwd.check.address", { entry: p.entry });
        case "port":
          return t("dns.fwd.check.port", { entry: p.entry });
        case "path":
          return t("dns.fwd.check.path", { entry: p.entry });
        case "path_transport":
          return t("dns.fwd.check.path_transport", { entry: p.entry });
      }
  }
}

/** The form field a refusal of the server names (`field` of `dns.forwarder.invalid`). */
export function refusedField(err: unknown): string | undefined {
  if (!(err instanceof ApiError)) return undefined;
  if (err.code === "dns.forwarder.invalid") {
    const field = err.params.field ?? "";
    if (field === "suffix" || field === "tls_name" || field === "description" || field === "view") return field;
    // WP10.4: the rule's mode and its validation.
    if (field === "mode" || field === "validate") return "mode";
    if (field.startsWith("upstream") || field === "port" || field === "path" || field === "transport") return "upstreams";
    return undefined;
  }
  if (err.code === "sys.invalid_value" && err.params.name) return err.params.name.startsWith("upstream") ? "upstreams" : err.params.name;
  return undefined;
}

function refusedText(err: ApiError, field: string): string {
  if (field === "suffix" && /exists/.test(err.params.reason ?? "")) return t("dns.fwd.check.taken");
  if (field === "view") return t("dns.fwd.check.view");
  return t("errors.dns.forwarder.invalid");
}

export function ForwarderDialog(props: { rule?: ForwarderItem; preset?: "dot"; onClose: () => void; onDone: () => void }) {
  let suffixInput!: HTMLInputElement;
  const rule = untrack(() => props.rule);
  // WP10.4: the preset of a root rule over DoT.
  const preset = untrack(() => props.preset);
  const [suffix, setSuffix] = createSignal(rule?.suffix ?? (preset === "dot" ? "." : ""));
  const [transport, setTransport] = createSignal<ForwardTransport>(preset === "dot" ? "dot" : (rule?.transport ?? "plain"));
  // WP10.4: forward to the upstreams, or recurse from the root servers; validation of forwarded answers.
  const [mode, setMode] = createSignal<"forward" | "recurse">(preset ? "forward" : (rule?.mode ?? "forward"));
  const [validate, setValidate] = createSignal(rule?.validate ?? true);
  const [upstreams, setUpstreams] = createSignal((rule?.upstreams ?? []).map(upstreamText).join("\n"));
  const [tlsName, setTlsName] = createSignal(rule?.tls_name ?? "");
  const [description, setDescription] = createSignal(rule?.description ?? "");
  const [allViews, setAllViews] = createSignal(false);
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  // The known resolver the typed upstreams belong to, offered with DoT while the rule is plain.
  const known = createMemo(() => (transport() === "plain" ? knownResolver(splitUpstreams(upstreams())) : undefined));

  // WP10.4: a recurse rule: only the suffix and the description are sent.
  const submitRecurse = async () => {
    const checked = checkRule({ suffix: suffix(), upstreams: "192.0.2.1", transport: "plain", tlsName: "" });
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
      if (rule) {
        const patch: ForwarderPatch = { suffix: checked.suffix, mode: "recurse", upstreams: [], transport: "plain", tls_name: "", validate: true, description: description().trim() };
        if (allViews()) patch.all_views = true;
        await updateForwarder(rule, patch);
        toast({ kind: "ok", title: t("dns.fwd.saved", { suffix: checked.suffix }) });
      } else {
        await createForwarder({ suffix: checked.suffix, mode: "recurse", description: description().trim() || null });
        toast({ kind: "ok", title: t("dns.fwd.created", { suffix: checked.suffix }) });
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

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    if (mode() === "recurse") return submitRecurse();
    const checked = checkRule({ suffix: suffix(), upstreams: upstreams(), transport: transport(), tlsName: tlsName() });
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
      if (rule) {
        const patch: ForwarderPatch = {
          suffix: checked.suffix,
          transport: checked.transport,
          upstreams: checked.upstreams,
          tls_name: checked.tlsName ?? "",
          description: description().trim(),
          // WP10.4
          mode: "forward",
          validate: validate(),
        };
        if (allViews()) patch.all_views = true;
        await updateForwarder(rule, patch);
        toast({ kind: "ok", title: t("dns.fwd.saved", { suffix: checked.suffix }) });
      } else {
        await createForwarder({
          suffix: checked.suffix,
          transport: checked.transport,
          upstreams: checked.upstreams,
          tls_name: checked.tlsName,
          description: description().trim() || null,
          // WP10.4
          mode: "forward",
          validate: validate(),
        });
        toast({ kind: "ok", title: t("dns.fwd.created", { suffix: checked.suffix }) });
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

  const title = () => (rule ? t("dns.fwd.edit_title", { suffix: rule.suffix }) : preset === "dot" ? t("dns.fwd.preset.dot_title") : t("dns.fwd.create_title"));
  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-forwarder-form" initialFocus={() => suffixInput}>
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        {/* WP10.4: the preset's privacy sentence and the resolvers to pick from (examples, never a default). */}
        <Show when={preset === "dot"}>
          <div class="note info" data-testid="fwd-preset-privacy">
            <span class="grow">{t("dns.fwd.preset.privacy")}</span>
          </div>
          <div class="dns-chips" data-testid="fwd-preset-resolvers">
            <For each={KNOWN_RESOLVERS}>
              {(resolver) => (
                <button
                  type="button"
                  class="btn sm"
                  data-testid="fwd-preset-resolver"
                  data-key={resolver.tlsName}
                  onClick={() => {
                    setUpstreams(resolver.addresses.filter((a) => !a.includes(":")).join("\n"));
                    setTlsName(resolver.tlsName);
                    setTransport("dot");
                  }}
                >
                  {resolver.name}
                </button>
              )}
            </For>
          </div>
        </Show>
        <Field id="suffix" label={t("dns.fwd.field.suffix")} error={errors().suffix} help={t("dns.fwd.field.suffix_help")}>
          <input
            ref={suffixInput}
            id="dns-f-suffix"
            class="input mono"
            value={suffix()}
            placeholder={t("dns.fwd.field.suffix_placeholder")}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().suffix ? "true" : undefined}
            aria-describedby={describedBy("suffix", errors().suffix, "help")}
            data-testid="field-suffix"
            onInput={(ev) => setSuffix(ev.currentTarget.value)}
          />
        </Field>
        {/* WP10.4: the rule's mode. */}
        <fieldset class="dns-modes" data-testid="fwd-mode">
          <legend>{t("dns.fwd.field.mode")}</legend>
          <For each={["forward", "recurse"] as const}>
            {(m) => (
              <label class="choice">
                <input type="radio" name="dns-fwd-mode" value={m} checked={mode() === m} disabled={preset !== undefined} data-testid={`field-mode-${m}`} onChange={() => setMode(m)} />
                <span>{m === "forward" ? t("dns.fwd.mode.forward") : t("dns.fwd.mode.recurse_long")}</span>
              </label>
            )}
          </For>
        </fieldset>
        <Show when={mode() === "recurse"}>
          <p class="help" data-testid="fwd-recurse-note">
            {t("dns.fwd.mode.recurse_help")}
          </p>
        </Show>
        <Show when={mode() === "forward"}>
          <fieldset class="dns-modes">
            <legend>{t("dns.fwd.field.transport")}</legend>
            <For each={TRANSPORTS}>
              {(tr) => (
                <label class="choice">
                  <input
                    type="radio"
                    name="dns-fwd-transport"
                    value={tr}
                    checked={transport() === tr}
                    data-testid={`field-transport-${tr}`}
                    onChange={() => setTransport(tr)}
                  />
                  <span>{t(`dns.fwd.transport.${tr}`)}</span>
                </label>
              )}
            </For>
          </fieldset>
          <Field id="upstreams" label={t("dns.fwd.field.upstreams")} error={errors().upstreams} help={t(`dns.fwd.field.upstreams_help_${transport()}`)}>
            <textarea
              id="dns-f-upstreams"
              class="input mono"
              rows={4}
              value={upstreams()}
              spellcheck={false}
              aria-invalid={errors().upstreams ? "true" : undefined}
              aria-describedby={describedBy("upstreams", errors().upstreams, "help")}
              data-testid="field-upstreams"
              onInput={(ev) => setUpstreams(ev.currentTarget.value)}
            />
          </Field>
          <Show when={known()}>
            {(resolver) => (
              <div class="note info dns-fwd-known" data-testid="fwd-known" data-key={resolver().tlsName}>
                <span class="grow">{t("dns.fwd.known", { name: resolver().name, tls: resolver().tlsName })}</span>
                <button
                  type="button"
                  class="btn sm"
                  data-testid="fwd-use-dot"
                  onClick={() => {
                    // Read the resolver first: switching to DoT ends the offer and its accessor.
                    const name = resolver().tlsName;
                    setTlsName(name);
                    setTransport("dot");
                  }}
                >
                  {t("dns.fwd.use_dot")}
                </button>
              </div>
            )}
          </Show>
          <Show when={needsTlsName(transport()) || tlsName() !== ""}>
            <Field id="tls_name" label={t("dns.fwd.field.tls_name")} error={errors().tls_name} help={t("dns.fwd.field.tls_name_help")}>
              <input
                id="dns-f-tls_name"
                class="input mono"
                value={tlsName()}
                spellcheck={false}
                autocomplete="off"
                aria-invalid={errors().tls_name ? "true" : undefined}
                aria-describedby={describedBy("tls_name", errors().tls_name, "help")}
                data-testid="field-tls_name"
                onInput={(ev) => setTlsName(ev.currentTarget.value)}
              />
            </Field>
          </Show>
          {/* WP10.4: validation of the upstreams' answers, the escape hatch for one that strips signatures. */}
          <div class="field">
            <label class="choice">
              <input type="checkbox" checked={validate()} data-testid="field-validate" onChange={(e) => setValidate(e.currentTarget.checked)} />
              <span>{t("dns.fwd.field.validate")}</span>
            </label>
            <span class="help" classList={{ bad: !validate() }}>
              {validate() ? t("dns.fwd.field.validate_help") : t("dns.fwd.field.validate_off")}
            </span>
          </div>
        </Show>
        <Show when={errors().mode}>
          <span class="help bad" data-testid="field-error" data-field="mode">
            {errors().mode}
          </span>
        </Show>
        <Show when={rule?.view}>
          <div class="field">
            <label class="choice">
              <input type="checkbox" checked={allViews()} data-testid="field-all_views" onChange={(e) => setAllViews(e.currentTarget.checked)} />
              <span>{t("dns.fwd.field.all_views")}</span>
            </label>
            <span class="help">{t("dns.fwd.field.all_views_help", { view: rule?.view ?? "" })}</span>
          </div>
        </Show>
        <Field id="description" label={t("dns.zone.field.description")} error={errors().description}>
          <input id="dns-f-description" class="input" value={description()} data-testid="field-description" onInput={(ev) => setDescription(ev.currentTarget.value)} />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {rule ? t("dns.fwd.save") : t("dns.fwd.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function DeleteForwarderDialog(props: { rule: ForwarderItem; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dns.fwd.delete_title", { suffix: props.rule.suffix })}
      testid="dialog-forwarder-delete"
      danger
      busy={busy()}
      confirmLabel={t("dns.fwd.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteForwarder(props.rule)
          .then(() => {
            toast({ kind: "ok", title: t("dns.fwd.deleted", { suffix: props.rule.suffix }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{isRoot(props.rule) ? t("dns.fwd.delete_root") : t("dns.fwd.delete_body")}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}
