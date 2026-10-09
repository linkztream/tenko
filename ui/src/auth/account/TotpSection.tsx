import { createSignal, Show } from "solid-js";
import { api } from "../../api/client";
import { isApiError } from "../../api/problem";
import type { FactorEnrolled, TotpEnrolment } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { QrCode } from "../../components/QrCode";
import { toast } from "../../components/toast";
import { formatNumber, t } from "../../i18n";
import type { MethodsData } from "./data";
import { copyText, describeError, isLastFactorRefusal } from "./shared";

/** The secret in blocks of four characters, easier to read and to type. */
export function groupSecret(secret: string): string {
  return (secret.replace(/\s+/g, "").match(/.{1,4}/g) ?? []).join(" ");
}

/** Only an `otpauth:` link is offered to the device; anything else is not a provisioning URI. */
function provisioningLink(uri: string): string | undefined {
  return uri.startsWith("otpauth://") ? uri : undefined;
}

/** The authenticator app (TOTP): status, set-up with the key and a first code, removal (IAM-06). */
export function TotpSection(props: {
  data: MethodsData;
  onCodes: (codes: string[]) => void;
  onReauthenticate: () => void;
}) {
  const [enrolment, setEnrolment] = createSignal<TotpEnrolment | null>(null);
  const [code, setCode] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [removing, setRemoving] = createSignal(false);
  const [removeError, setRemoveError] = createSignal<string | null>(null);
  let codeInput: HTMLInputElement | undefined;
  let startButton: HTMLButtonElement | undefined;

  const start = async () => {
    setError(null);
    setBusy(true);
    try {
      setEnrolment(await api.post("/api/v1/auth/totp/enroll/start"));
      setCode("");
    } catch (err) {
      if (isApiError(err, "auth.totp.already_enrolled")) props.data.setTotp(true);
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  };

  const cancel = () => {
    setEnrolment(null);
    setError(null);
    setCode("");
    queueMicrotask(() => startButton?.focus());
  };

  const verify = async (e: Event) => {
    e.preventDefault();
    const current = enrolment();
    if (!current) return;
    const digits = code().replace(/\s+/g, "");
    if (!digits) {
      codeInput?.focus();
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const res: FactorEnrolled = await api.post("/api/v1/auth/totp/enroll/finish", {
        body: { enrolment_id: current.enrolment_id, code: digits },
      });
      setEnrolment(null);
      setCode("");
      props.data.setTotp(true);
      toast({ title: t("account.totp.enabled"), kind: "ok" });
      if (res.recovery_codes?.length) props.onCodes(res.recovery_codes);
      if (res.reauthenticate) props.onReauthenticate();
    } catch (err) {
      if (isApiError(err, "auth.challenge_invalid")) {
        setEnrolment(null);
        setError(t("account.totp.expired"));
      } else {
        setError(describeError(err));
        setCode("");
        codeInput?.focus();
      }
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setRemoveError(null);
    setBusy(true);
    try {
      await api.delete("/api/v1/auth/totp");
      setRemoving(false);
      props.data.setTotp(false);
      toast({ title: t("account.totp.removed"), kind: "ok" });
    } catch (err) {
      if (isApiError(err, "auth.totp.not_enrolled")) props.data.setTotp(false);
      setRemoveError(isLastFactorRefusal(err) ? t("account.totp.remove_refused") : describeError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page-section" aria-label={t("account.totp.title")}>
      <div class="factor">
        <div class="info">
          <h2>
            {t("account.totp.name")}
            <Show when={props.data.totp() !== undefined}>
              <span classList={{ tag: true, ok: props.data.totp() === true }}>
                <Icon name={props.data.totp() ? "check" : "x"} size="xs" />
                {props.data.totp() ? t("account.totp.status_on") : t("account.totp.status_off")}
              </span>
            </Show>
          </h2>
          <p class="help12">{t("account.totp.lede")}</p>
        </div>
        <div class="act">
          <Show
            when={props.data.totp() === true}
            fallback={
              <Show when={enrolment() === null}>
                <button
                  ref={startButton}
                  type="button"
                  class="btn"
                  disabled={busy()}
                  onClick={() => void start()}
                >
                  {t("account.totp.setup")}
                </button>
              </Show>
            }
          >
            <button type="button" class="btn sm" onClick={() => setRemoving(true)}>
              {t("common.action.remove")}
            </button>
          </Show>
        </div>
      </div>

      <Show when={error() && enrolment() === null}>
        <Notice kind="bad" role="alert">
          {error()}
        </Notice>
      </Show>

      <Show when={enrolment()}>
        {(enrol) => (
          <div class="acct-panel" role="group" aria-labelledby="acct-totp-setup">
            <h3 id="acct-totp-setup">{t("account.totp.setup_title")}</h3>
            <p>{t("account.totp.scan_or_key")}</p>
            <div class="acct-qr">
              <QrCode text={enrol().otpauth_uri} label={t("account.totp.qr_label")} />
            </div>

            <div class="field">
              <span class="label" id="acct-totp-key-label">
                {t("account.totp.key")}
              </span>
              <div class="form-row" role="group" aria-labelledby="acct-totp-key-label">
                <code class="secret acct-secret">
                  {groupSecret(enrol().secret)}
                </code>
                <button type="button" class="btn sm" onClick={() => void copyText(enrol().secret)}>
                  <Icon name="copy" size="sm" />
                  {t("common.action.copy")}
                </button>
              </div>
              <span class="help">
                {t("account.totp.params", {
                  digits: formatNumber(enrol().params.digits),
                  period: formatNumber(enrol().params.period),
                  algorithm: enrol().params.algorithm.toUpperCase(),
                })}
              </span>
            </div>

            <Show when={provisioningLink(enrol().otpauth_uri)}>
              {(link) => (
                <p>
                  <a class="acct-link" href={link()}>
                    <Icon name="link" size="sm" />
                    {t("account.totp.open_link")}
                  </a>
                </p>
              )}
            </Show>

            <form class="form" onSubmit={(e) => void verify(e)} novalidate>
              <div class="field">
                <label for="acct-totp-code">{t("account.totp.code")}</label>
                <input
                  ref={codeInput}
                  id="acct-totp-code"
                  class="input mono acct-code"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  spellcheck={false}
                  aria-invalid={error() ? "true" : undefined}
                  aria-describedby={error() ? "acct-totp-error" : undefined}
                  value={code()}
                  onInput={(e) => setCode(e.currentTarget.value)}
                />
              </div>
              <Show when={error()}>
                <div class="note bad" role="alert" id="acct-totp-error">
                  <Icon name="alert" size="sm" />
                  <span class="grow">{error()}</span>
                </div>
              </Show>
              <div class="form-row">
                <button type="submit" class="btn primary" disabled={busy()}>
                  {t("account.totp.verify")}
                </button>
                <button type="button" class="btn ghost" onClick={cancel}>
                  {t("common.action.cancel")}
                </button>
              </div>
            </form>
          </div>
        )}
      </Show>

      <Show when={removing()}>
        <ConfirmDialog
          title={t("account.totp.remove_title")}
          body={
            <>
              <p>{t("account.totp.remove_body")}</p>
              <Show when={removeError()}>
                <Notice kind="bad" role="alert">
                  {removeError()}
                </Notice>
              </Show>
            </>
          }
          confirmLabel={t("common.action.remove")}
          cancelLabel={t("common.action.cancel")}
          danger
          busy={busy()}
          onConfirm={() => void remove()}
          onClose={() => setRemoving(false)}
        />
      </Show>
    </section>
  );
}
