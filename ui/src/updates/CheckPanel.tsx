// The scheduled check of the release source: where it looks, when it last did, what went
// wrong, why it is off, and "Check now". An uploaded release list is named here too, and the
// pre-release switch (TGL-45, OPS-30).
import { A } from "@solidjs/router";
import { createEffect, createSignal, Show } from "solid-js";
import { isApiError } from "../api/problem";
import { paths } from "../app/paths";
import { ErrorNotice, Notice } from "../components/Notice";
import { Switch } from "../components/Switch";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { checkUpdates, setPrereleases, type UpdateStatus } from "./api";
import { StepUpNotice } from "./StepUpNotice";
import { codeText, offReasonText, prereleaseNoticeText, whenText } from "./words";

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

  // The switch shows the stored value while tenko.toml allows it; a refused change flips it back.
  const [prereleases, setPrereleasesShown] = createSignal(false);
  createEffect(() => setPrereleasesShown(check().prereleases && check().prereleases_allowed));
  const [switching, setSwitching] = createSignal(false);
  const [switchError, setSwitchError] = createSignal<unknown>(null);
  const switchPrereleases = async (on: boolean) => {
    setPrereleasesShown(on);
    setSwitching(true);
    setSwitchError(null);
    try {
      await setPrereleases(on);
      // Ask the source at once, so that a release candidate shows now, not at the next check.
      const next = on && check().enabled ? await checkUpdates().catch(() => null) : null;
      if (next) props.onStatus(next);
      else props.onReload();
    } catch (err) {
      setPrereleasesShown(!on);
      setSwitchError(err);
    } finally {
      setSwitching(false);
    }
  };
  const prereleaseHint = () => {
    if (!check().prereleases_allowed) return t("updates.prerelease.locked");
    if (!check().enabled) return t("updates.prerelease.uploads_only");
    // The server searches a source of this form only (docs/upgrades.md section 8.13).
    if (!check().source.includes("/releases/latest/download/")) return t("updates.prerelease.mirror");
    return t("updates.prerelease.hint");
  };

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
        <div data-testid="updates-prereleases">
          <Switch
            id="upd-prereleases"
            checked={prereleases()}
            disabled={switching() || !check().prereleases_allowed}
            onChange={(on) => void switchPrereleases(on)}
            label={t("toggles.update_prereleases.name")}
            hint={prereleaseHint()}
          />
        </div>
        <Show when={check().prerelease_notice}>
          {(notice) => (
            <Notice kind="warn" testid="updates-prerelease-notice" code={notice().code}>
              <span data-key={notice().params?.turn_on}>
                {prereleaseNoticeText(notice().params?.turn_on, props.status.running)}
              </span>
            </Notice>
          )}
        </Show>
        <Show when={isApiError(switchError(), "auth.step_up_required")} fallback={<ErrorNotice error={switchError()} />}>
          <StepUpNotice body={t("updates.prerelease.stepup")} />
        </Show>
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
