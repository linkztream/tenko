import { createSignal, Show } from "solid-js";
import { api } from "../../api/client";
import { ConfirmDialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { t } from "../../i18n";
import type { MethodsData } from "./data";
import { describeError } from "./shared";

/** Recovery codes (IAM-06): what they are and how to replace them; the old ones stop working. */
export function RecoverySection(props: { data: MethodsData; onCodes: (codes: string[]) => void }) {
  const [asking, setAsking] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // Codes only make sense next to a passkey or an authenticator app (the server says the same).
  const possible = () => props.data.totp() === true || (props.data.keys()?.length ?? 0) > 0 || props.data.totp() === undefined;

  const generate = async () => {
    setError(null);
    setBusy(true);
    try {
      const res = await api.post("/api/v1/auth/recovery-codes");
      setAsking(false);
      props.data.refetch();
      props.onCodes(res.codes);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page-section" aria-label={t("account.recovery.title")}>
      <div class="factor">
        <div class="info">
          <h2>
            {t("account.recovery.name")}
            <Show when={props.data.codesLeft() !== undefined}>
              <span classList={{ tag: true, discrepancy: props.data.codesLeft() === 0 }}>
                <Show when={props.data.codesLeft() === 0}>
                  <Icon name="alert" size="xs" />
                </Show>
                {t("account.recovery.left", { count: props.data.codesLeft() ?? 0 })}
              </span>
            </Show>
          </h2>
          <p class="help12">{t("account.recovery.lede")}</p>
          <Show when={!possible()}>
            <p class="help12">{t("account.recovery.needs_factor")}</p>
          </Show>
        </div>
        <div class="act">
          <button
            type="button"
            class="btn"
            disabled={!possible()}
            onClick={() => {
              setError(null);
              setAsking(true);
            }}
          >
            {t("account.recovery.generate")}
          </button>
        </div>
      </div>

      <Show when={asking()}>
        <ConfirmDialog
          title={t("account.recovery.confirm_title")}
          body={
            <>
              <p>{t("account.recovery.confirm_body")}</p>
              <Show when={error()}>
                <Notice kind="bad" role="alert">
                  {error()}
                </Notice>
              </Show>
            </>
          }
          confirmLabel={t("account.recovery.generate")}
          cancelLabel={t("common.action.cancel")}
          danger
          busy={busy()}
          onConfirm={() => void generate()}
          onClose={() => setAsking(false)}
        />
      </Show>
    </section>
  );
}
