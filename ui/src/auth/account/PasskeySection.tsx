import { createSignal, For, onCleanup, Show } from "solid-js";
import { api } from "../../api/client";
import type { CredentialInfo, FactorEnrolled } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { Icon, type IconName } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDate, formatRelative, t } from "../../i18n";
import { registerPasskey, webauthnAvailable } from "../webauthn";
import type { MethodsData } from "./data";
import { describeError, isLastFactorRefusal } from "./shared";

type Kind = "synced" | "hardware" | "device";

function kindOf(c: CredentialInfo): Kind {
  if (c.hardware_key) return "hardware";
  return c.backup_eligible ? "synced" : "device";
}

const KIND_ICON: Record<Kind, IconName> = { synced: "refresh", hardware: "key", device: "lock" };

/** Passkeys and security keys: the list, removal and enrolment (IAM-06). */
export function PasskeySection(props: {
  data: MethodsData;
  onCodes: (codes: string[]) => void;
  onReauthenticate: () => void;
}) {
  const [label, setLabel] = createSignal("");
  const [waiting, setWaiting] = createSignal<"passkey" | "key" | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [removing, setRemoving] = createSignal<CredentialInfo | null>(null);
  const [removeError, setRemoveError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);
  let controller: AbortController | undefined;
  onCleanup(() => controller?.abort());

  const available = webauthnAvailable();
  const unavailableReason = () => (typeof window !== "undefined" && window.isSecureContext === false ? "insecure" : "unsupported");

  const add = async (securityKey: boolean) => {
    if (waiting()) return;
    setError(null);
    setWaiting(securityKey ? "key" : "passkey");
    controller = new AbortController();
    try {
      const name = label().trim();
      const res: FactorEnrolled = await registerPasskey({
        ...(name ? { label: name } : {}),
        securityKey,
        signal: controller.signal,
      });
      setLabel("");
      toast({ title: securityKey ? t("account.passkey.added_key") : t("account.passkey.added"), kind: "ok" });
      props.data.refetch();
      if (res.recovery_codes?.length) props.onCodes(res.recovery_codes);
      if (res.reauthenticate) props.onReauthenticate();
    } catch (err) {
      setError(describeError(err));
    } finally {
      setWaiting(null);
    }
  };

  const remove = async (c: CredentialInfo) => {
    setRemoveError(null);
    setBusy(true);
    try {
      await api.delete("/api/v1/auth/webauthn/credentials/{id}", { path: { id: c.id } });
      setRemoving(null);
      toast({ title: t("account.passkey.removed", { name: c.label }), kind: "ok" });
      props.data.refetch();
    } catch (err) {
      setRemoveError(isLastFactorRefusal(err) ? t("account.passkey.remove_refused") : describeError(err));
    } finally {
      setBusy(false);
    }
  };

  const loadError = () => props.data.credentials.value.error;

  return (
    <section class="page-section" aria-labelledby="acct-passkeys">
      <h2 id="acct-passkeys">{t("account.passkey.title")}</h2>
      <p>{t("account.passkey.lede")}</p>

      <Show when={loadError()}>
        <div class="note bad" role="alert">
          <Icon name="alert" size="sm" />
          <span class="grow">{describeError(loadError())}</span>
          <button type="button" class="btn sm" onClick={() => props.data.credentials.refetch()}>
            {t("common.action.retry")}
          </button>
        </div>
      </Show>

      <Show when={props.data.keys()}>
        {(keys) => (
          <Show when={keys().length > 0} fallback={<p class="muted">{t("account.passkey.none")}</p>}>
            <ul class="list">
              <For each={keys()}>
                {(c) => (
                  <li class="factor">
                    <div class="info">
                      <h3>
                        {c.label}
                        <span class="tag">
                          <Icon name={KIND_ICON[kindOf(c)]} size="xs" />
                          {t(`account.passkey.kind.${kindOf(c)}`)}
                        </span>
                      </h3>
                      <p class="help12 acct-meta">
                        <span>{t("account.passkey.created", { date: formatDate(c.created_at) })}</span>
                        <span>
                          {c.last_used_at
                            ? t("account.passkey.last_used", { when: formatRelative(c.last_used_at) })
                            : t("account.passkey.never_used")}
                        </span>
                      </p>
                    </div>
                    <div class="act">
                      <button
                        type="button"
                        class="btn sm"
                        aria-label={t("account.passkey.remove_named", { name: c.label })}
                        onClick={() => {
                          setRemoveError(null);
                          setRemoving(c);
                        }}
                      >
                        {t("common.action.remove")}
                      </button>
                    </div>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        )}
      </Show>

      <form
        class="form acct-add"
        onSubmit={(e) => {
          e.preventDefault();
          void add(false);
        }}
      >
        <div class="field">
          <label for="acct-pk-label">{t("account.passkey.label")}</label>
          <input
            id="acct-pk-label"
            class="input"
            maxlength={64}
            autocomplete="off"
            aria-describedby="acct-pk-label-help"
            value={label()}
            onInput={(e) => setLabel(e.currentTarget.value)}
          />
          <span class="help" id="acct-pk-label-help">
            {t("account.passkey.label_help")}
          </span>
        </div>
        <div class="form-row">
          <button type="submit" class="btn" disabled={!available || waiting() !== null}>
            <Icon name="key" size="sm" />
            {t("account.passkey.add")}
          </button>
          <button type="button" class="btn" disabled={!available || waiting() !== null} onClick={() => void add(true)}>
            <Icon name="key" size="sm" />
            {t("account.passkey.add_key")}
          </button>
        </div>
        <Show when={!available}>
          <p class="help12">{t(`auth.signin.ceremony.${unavailableReason()}`)}</p>
        </Show>
        <Show when={waiting()}>
          {(kind) => (
            <div class="wait" role="status">
              <span class="jstate waiting">
                {kind() === "key" ? t("account.passkey.waiting_key") : t("account.passkey.waiting_passkey")}
              </span>
              <button type="button" class="btn ghost sm" onClick={() => controller?.abort()}>
                {t("common.action.cancel")}
              </button>
            </div>
          )}
        </Show>
        <Show when={error()}>
          <Notice kind="bad" role="alert">
            {error()}
          </Notice>
        </Show>
      </form>

      <Show when={removing()}>
        {(c) => (
          <ConfirmDialog
            title={t("account.passkey.remove_title", { name: c().label })}
            body={
              <>
                <p>{t("account.passkey.remove_body")}</p>
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
            onConfirm={() => void remove(c())}
            onClose={() => setRemoving(null)}
          />
        )}
      </Show>
    </section>
  );
}
