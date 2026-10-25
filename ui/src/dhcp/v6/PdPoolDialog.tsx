// The dialog that adds a delegation pool to a DHCPv6 scope (WP9.2): the first and last address and
// the length of the prefixes handed to routers. The pool is made as an IPAM range of the scope's
// network. The form checks the lengths and boundaries before it sends; what the server still
// refuses (`ipam.validation` names the field) shows under the field it names.
import { createSignal, Show } from "solid-js";
import { Dialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { parseCidr } from "../../ipam/ip";
import type { Scope } from "../api";
import { describedBy, errorFor, Field, fieldErrors, hasField } from "../Parts";
import { checkPdDraft, createPdPool } from "./pdModel";

export function PdPoolDialog(props: { scope: Scope; onClose: () => void; onDone: () => void }) {
  let firstInput!: HTMLInputElement;
  const [first, setFirst] = createSignal("");
  const [last, setLast] = createSignal("");
  const [len, setLen] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const networkLength = () => parseCidr(props.scope.cidr)?.length ?? 0;

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const checked = checkPdDraft({ first: first(), last: last(), len: len() }, props.scope.cidr);
    if (!checked.ok) {
      setErrors(checked.problems);
      return;
    }
    setErrors({});
    setError(undefined);
    setBusy(true);
    try {
      const made = await createPdPool(props.scope.prefix, checked.body);
      toast({ kind: "ok", title: t("dhcp.pd.created", { first: made.first, last: made.last }) });
      props.onDone();
    } catch (err) {
      const fields = fieldErrors(err);
      // A refused role is shown with the length: the form has no role field to put it under.
      if (fields.role && !fields.delegated_len) fields.delegated_len = fields.role;
      if (hasField(fields, ["first", "last", "delegated_len"])) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = t("dhcp.pd.add");
  return (
    <Dialog label={title} onClose={props.onClose} class="dialog dhcp-dialog" testid="dialog-pd-pool-form" initialFocus={() => firstInput}>
      <h2 class="dialog-title">{title}</h2>
      <form class="dialog-body dhcp-form" onSubmit={(e) => void submit(e)} novalidate>
        <p class="muted">{t("dhcp.pd.help", { network: props.scope.cidr })}</p>
        <div class="field-row">
          <Field id="first" label={t("dhcp.pd.field.first")} error={errorFor(errors(), "first")}>
            <input
              ref={firstInput}
              id="dhcp-f-first"
              class="input mono"
              value={first()}
              spellcheck={false}
              autocomplete="off"
              aria-invalid={errors().first ? "true" : undefined}
              aria-describedby={describedBy("first", errors().first)}
              data-testid="field-first"
              onInput={(e) => setFirst(e.currentTarget.value)}
            />
          </Field>
          <Field id="last" label={t("dhcp.pd.field.last")} error={errorFor(errors(), "last")}>
            <input
              id="dhcp-f-last"
              class="input mono"
              value={last()}
              spellcheck={false}
              autocomplete="off"
              aria-invalid={errors().last ? "true" : undefined}
              aria-describedby={describedBy("last", errors().last)}
              data-testid="field-last"
              onInput={(e) => setLast(e.currentTarget.value)}
            />
          </Field>
        </div>
        <Field id="delegated_len" label={t("dhcp.pd.field.delegated")} error={errorFor(errors(), "delegated_len")} help={t("dhcp.pd.field.delegated_help", { length: networkLength() })}>
          <input
            id="dhcp-f-delegated_len"
            class="input mono"
            value={len()}
            inputmode="numeric"
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().delegated_len ? "true" : undefined}
            aria-describedby={describedBy("delegated_len", errors().delegated_len, "help")}
            data-testid="field-delegated_len"
            onInput={(e) => setLen(e.currentTarget.value)}
          />
        </Field>
        <Show when={error()}>
          <ErrorNotice error={error()} />
        </Show>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dhcp.pd.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
