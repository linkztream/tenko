// Creating an enrollment code for an integration (ADR 0035, decision 5): the service account,
// how long the code lives and, optionally, the one network it may be used from; then the code,
// shown this once, with the fingerprint of the root it pins and what to do with it. Nothing
// here keeps the code: closing the dialog forgets it. The enrollment itself runs on the
// automation host with `openssl` and `curl` (docs/integrations.md); the code's secret never
// leaves that host, only a proof made with it does.
import { createSignal, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDateTime, t } from "../../i18n";
import { Field, FieldRow, SelectInput } from "../../ipam/formKit";
import { fingerprintPairs } from "../../nodes/model";
import { copyValue } from "../../secrets/clipboard";
import { unreachableListener, type CreatedCode } from "./integrations";
import type { UserInfo } from "./model";
// The dialog width and the code blocks are the node enrollment dialog's.
import "../../nodes/nodes.css";

/** The lifetimes offered, in seconds: the server takes 60 to 3600. */
const LIFETIMES = [900, 3600] as const;

/** An address with a prefix length, IPv4 or IPv6; the server checks it exactly. */
const NETWORK = /^[0-9a-fA-F:.]+\/\d{1,3}$/;

export function EnrollmentCodeDialog(props: { accounts: UserInfo[]; onCreated: () => void; onClose: () => void }) {
  // The first account until the person picks one; the list is read once, when the dialog opens.
  const [account, setAccount] = createSignal(untrack(() => props.accounts[0]?.id ?? ""));
  const [lifetime, setLifetime] = createSignal("3600");
  const [source, setSource] = createSignal("");
  const [tried, setTried] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [created, setCreated] = createSignal<CreatedCode | null>(null);
  // Esc and a click outside must not lose a code the server shows once: close after the box.
  const [stored, setStored] = createSignal(false);
  const guardedClose = () => {
    if (!created() || stored()) props.onClose();
  };

  const sourceError = () => (source().trim() !== "" && !NETWORK.test(source().trim()) ? t("integrations.code.source_rule") : undefined);

  const submit = async (e: Event) => {
    e.preventDefault();
    setTried(true);
    if (!account() || sourceError() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const answer = await api.post("/api/v1/integrations/enrollments", {
        // No idempotency key: the answer carries the code, which no replay could return.
        body: { account: account(), lifetime_secs: Number(lifetime()), source: source().trim() || null },
        idempotencyKey: null,
      });
      setCreated(answer);
      props.onCreated();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const copy = async (text: string) => {
    const outcome = await copyValue(text);
    toast(outcome === "copied" ? { kind: "ok", title: t("integrations.code.copied") } : { kind: "bad", title: t("integrations.code.copy_blocked") });
  };

  return (
    <Dialog label={t("integrations.code.title")} onClose={guardedClose} class="dialog nodes-dialog">
      <Show
        when={created()}
        fallback={
          <form class="dialog-form" data-testid="dialog-integration-code" onSubmit={(e) => void submit(e)} novalidate>
            <h2 class="dialog-title">{t("integrations.code.title")}</h2>
            <div class="dialog-body">
              <p class="muted">{t("integrations.code.intro")}</p>
              <Show when={props.accounts.length > 0} fallback={<Notice kind="warn">{t("integrations.code.no_accounts")}</Notice>}>
                <Field name="account" label={t("integrations.code.account")}>
                  {(c) => (
                    <SelectInput {...c} value={account()} options={props.accounts.map((a) => ({ value: a.id, label: a.name }))} onChange={setAccount} />
                  )}
                </Field>
                <FieldRow>
                  <Field name="lifetime" label={t("integrations.code.lifetime")}>
                    {(c) => (
                      <SelectInput
                        {...c}
                        value={lifetime()}
                        options={LIFETIMES.map((s) => ({ value: String(s), label: t(`integrations.code.lifetime_${s}`) }))}
                        onChange={setLifetime}
                      />
                    )}
                  </Field>
                  <Field
                    name="source"
                    label={t("integrations.code.source")}
                    help={t("integrations.code.source_help")}
                    error={tried() ? sourceError() : undefined}
                  >
                    {(c) => (
                      <input
                        {...c}
                        class="input mono"
                        autocomplete="off"
                        spellcheck={false}
                        placeholder="192.0.2.0/24"
                        value={source()}
                        onInput={(e) => setSource(e.currentTarget.value)}
                      />
                    )}
                  </Field>
                </FieldRow>
              </Show>
              <ErrorNotice error={error()} />
            </div>
            <div class="dialog-actions">
              <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
                {t("common.action.cancel")}
              </button>
              <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy() || props.accounts.length === 0}>
                {t("integrations.code.create")}
              </button>
            </div>
          </form>
        }
      >
        {(c) => (
          <div class="dialog-form" data-testid="dialog-integration-code-once">
            <h2 class="dialog-title">{t("integrations.code.created_title")}</h2>
            <div class="dialog-body">
              <Notice kind="warn" testid="integration-code-once">
                {t("integrations.code.once", { expires: formatDateTime(c().enrollment.expires_at) })}
              </Notice>
              <Show when={unreachableListener(c().listen)}>
                {(why) => (
                  <Notice kind="bad" testid="integration-listener-unreachable">
                    {why() === "closed"
                      ? t("integrations.code.listener_closed")
                      : t("integrations.code.listener_loopback", { addresses: (c().listen ?? []).join(", ") })}
                  </Notice>
                )}
              </Show>
              <div class="field">
                <span class="label">{t("integrations.code.code")}</span>
                <code class="enroll-token mono" data-testid="integration-code-text">
                  {c().code}
                </code>
                <div class="row-actions">
                  <button type="button" class="btn primary" data-testid="integration-code-copy" onClick={() => void copy(c().code)}>
                    <Icon name="copy" />
                    {t("integrations.code.copy")}
                  </button>
                </div>
              </div>
              <div class="field">
                <span class="label">{t("integrations.code.fingerprint")}</span>
                <code class="enroll-fingerprint mono" data-testid="integration-code-fingerprint">
                  {fingerprintPairs(c().server_root_sha256)}
                </code>
                <small class="help">{t("integrations.code.fingerprint_help")}</small>
              </div>
              <ol>
                <li>{t("integrations.code.step_save")}</li>
                <li>{t("integrations.code.step_run")}</li>
                <li>{t("integrations.code.step_list")}</li>
              </ol>
              <label class="ackrow">
                <input
                  type="checkbox"
                  class="cb"
                  checked={stored()}
                  data-testid="integration-code-stored"
                  onChange={(e) => setStored(e.currentTarget.checked)}
                />
                {t("integrations.code.stored")}
              </label>
            </div>
            <div class="dialog-actions">
              <button type="button" class="btn primary" data-testid="integration-code-done" disabled={!stored()} onClick={guardedClose}>
                {t("integrations.code.done")}
              </button>
            </div>
          </div>
        )}
      </Show>
    </Dialog>
  );
}
