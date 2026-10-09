// The scheduled check of the release source: where it looks, when it last did, what went
// wrong, why it is off, and "Check now". An uploaded release list is named here too.
import { A } from "@solidjs/router";
import { createSignal, Show } from "solid-js";
import { paths } from "../app/paths";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { checkUpdates, type UpdateStatus } from "./api";
import { codeText, offReasonText, whenText } from "./words";

export function CheckPanel(props: {
  status: UpdateStatus;
  onStatus: (status: UpdateStatus) => void;
  /** Reads the status again (a failed check leaves its error in it). */
  onReload: () => void;
}) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const check = () => props.status.check;
  const manifest = () => props.status.manifest;

  const checkNow = async () => {
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      const next = await checkUpdates();
      props.onStatus(next);
      toast({ kind: "ok", title: next.update_available ? t("updates.check.found") : t("updates.check.none") });
    } catch (err) {
      setError(err);
      props.onReload();
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page-section" aria-labelledby="upd-check" data-testid="updates-check-panel">
      <h2 id="upd-check">{t("updates.check.heading")}</h2>
      <div class="card upd-card">
        <dl class="kv upd-kv">
          <dt>{t("updates.check.source")}</dt>
          <dd class="mono" data-testid="updates-source">
            {check().source}
          </dd>
          <dt>{t("updates.check.state")}</dt>
          <dd data-testid="updates-check-state" data-key={check().enabled ? "on" : "off"}>
            <Show when={check().enabled} fallback={offReasonText(check().off_reason)}>
              {t("updates.check.on", { hours: check().interval_hours })}
            </Show>
          </dd>
          <dt>{t("updates.check.last")}</dt>
          <dd data-testid="updates-last-checked">
            <Show when={check().last_checked} fallback={t("updates.check.never")}>
              {whenText(check().last_checked)}
            </Show>
          </dd>
          <Show when={check().last_error}>
            {(code) => (
              <>
                <dt>{t("updates.check.error")}</dt>
                <dd data-testid="updates-last-error" data-code={code()}>
                  {codeText(code())}
                </dd>
              </>
            )}
          </Show>
          <Show when={manifest()}>
            {(m) => (
              <>
                <dt>{t("updates.manifest.heading")}</dt>
                <dd data-testid="updates-manifest-info" data-key={m().origin}>
                  {t(m().origin === "uploaded" ? "updates.manifest.uploaded" : "updates.manifest.fetched", {
                    when: whenText(m().at),
                    count: m().releases,
                  })}
                </dd>
              </>
            )}
          </Show>
        </dl>
        <Show when={!check().enabled && check().off_reason === "setting"}>
          <p class="muted">
            <A href={paths.settings("security")}>{t("updates.check.settings_link")}</A>
          </p>
        </Show>
        <ErrorNotice error={error()} />
        <div class="upd-actions">
          <button
            type="button"
            class="btn"
            disabled={busy() || !check().enabled}
            onClick={() => void checkNow()}
            data-testid="updates-check"
          >
            {busy() ? t("updates.check.checking") : t("updates.check.now")}
          </button>
        </div>
      </div>
    </section>
  );
}
