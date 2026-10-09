// Pieces the account pages share: error wording, reading live lists, copying a secret and
// the dialog that shows recovery codes exactly once.
import { createSignal } from "solid-js";
import { api } from "../../api/client";
import type { LiveQuery } from "../../api/live";
import { errorMessage, isApiError } from "../../api/problem";
import { Dialog } from "../../components/Dialog";
import { RecoveryCodes } from "../../components/RecoveryCodes";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { establish } from "../session";
import { CeremonyError } from "../webauthn";

/** The translated message of any error of the account pages, including passkey ceremonies. */
export function describeError(err: unknown): string {
  if (err instanceof CeremonyError) return t(`auth.signin.ceremony.${err.reason}`);
  return errorMessage(err);
}

/**
 * The server refuses to remove a factor the profile requires and that is the only one left:
 * `auth.factor.last_required` from the backend (`auth.conflict` in older answers).
 */
export function isLastFactorRefusal(err: unknown): boolean {
  return isApiError(err, "auth.factor.last_required") || isApiError(err, "auth.conflict");
}

/**
 * The newest value of a live query without suspending the page on a refetch;
 * undefined during the first load and after a failed load.
 */
export function latest<T>(query: LiveQuery<T>): T | undefined {
  return query.value.error ? undefined : query.value.latest;
}

/** Copies a secret to the clipboard and says whether it worked. */
export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast({ title: t("common.action.copied"), kind: "ok" });
  } catch {
    toast({ title: t("account.copy_failed"), kind: "bad" });
  }
}

/**
 * Reads the session again so the flags and the banner follow a change made here (a new
 * password clears `password_change_required`). Best effort: the page works without it.
 */
export async function refreshSession(): Promise<void> {
  try {
    await establish(await api.get("/api/v1/auth/session"));
  } catch {
    // The next navigation reads the session again.
  }
}

/**
 * Recovery codes, shown once (IAM-06). The dialog does not close, not even with Esc, until
 * the person confirms the codes are saved.
 */
export function CodesDialog(props: { codes: readonly string[]; fileBase: string; onClose: () => void }) {
  const [saved, setSaved] = createSignal(false);
  const close = () => {
    if (saved()) props.onClose();
  };
  return (
    <Dialog label={t("account.codes.title")} onClose={close} class="dialog wide">
      <h2 class="dialog-title">{t("account.codes.title")}</h2>
      <div class="dialog-body">
        <p>{t("account.codes.lede")}</p>
        <RecoveryCodes codes={props.codes} fileBase={props.fileBase} saved={saved()} onSavedChange={setSaved} />
      </div>
      <div class="dialog-actions">
        <button type="button" class="btn primary" disabled={!saved()} onClick={close}>
          {t("common.action.close")}
        </button>
      </div>
    </Dialog>
  );
}
