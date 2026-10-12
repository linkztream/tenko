// "Scan now" (SCAN-09): a button that opens a dialog to start an on-demand scan of a prefix, a
// host, an address or a network. The prefix pane and the host page mount it lazily with the
// `scans` pack, so it imports its own styles and needs nothing from the scans page. It shows
// only while the Discovery module runs and only for operators and administrators, who have the
// right to execute on a target; the server decides again.
import { A } from "@solidjs/router";
import { createSignal, For, Show } from "solid-js";
import { ErrorNotice, Notice } from "../components/Notice";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { hasRole, isAdmin } from "../auth/session";
import { formatDuration, t } from "../i18n";
import { moduleRunning } from "../updates/modules";
import { createScan } from "./api";
import { SCAN_KINDS, type ScanKind, type ScanNowTarget, type ScanView, scanPath } from "./model";
import { kindWord, noteText } from "./text";
import "./scans.css";

/** The waits the dialog offers, in seconds; the server takes 30 to 3,600 and defaults to ten minutes. */
const DEADLINES: readonly number[] = [60, 300, 600, 1800, 3600];
const DEFAULT_DEADLINE = 600;

function ScanNowDialog(props: ScanNowTarget & { onClose: () => void }) {
  const [kinds, setKinds] = createSignal<readonly ScanKind[]>(["passive_refresh"]);
  const [deadline, setDeadline] = createSignal(DEFAULT_DEADLINE);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [started, setStarted] = createSignal<ScanView | null>(null);

  const toggle = (kind: ScanKind, on: boolean) => {
    setKinds((list) => (on ? [...list, kind] : list.filter((k) => k !== kind)));
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    if (busy() || kinds().length === 0) return;
    setBusy(true);
    setError(null);
    try {
      // In the order of the document, whatever order they were ticked in.
      const chosen = SCAN_KINDS.filter((k) => kinds().includes(k));
      setStarted(await createScan({ target: { kind: props.kind, value: props.value }, kinds: chosen, deadline_secs: deadline() }));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("scans.now.title", { target: props.label })} onClose={props.onClose} class="dialog scans-dialog" testid="dialog-scan-now">
      <Show
        when={started()}
        fallback={
          <form class="scans-form" onSubmit={(e) => void submit(e)}>
            <h2 class="dialog-title">{t("scans.now.title", { target: props.label })}</h2>
            <p class="muted">{t("scans.now.intro")}</p>
            <fieldset class="scans-kinds" aria-describedby={kinds().length === 0 ? "scan-now-kinds-error" : undefined}>
              <legend>{t("scans.now.kinds")}</legend>
              <For each={SCAN_KINDS}>
                {(kind) => (
                  <label class="scans-kind">
                    <input
                      type="checkbox"
                      data-testid={`scan-now-kind-${kind}`}
                      checked={kinds().includes(kind)}
                      onChange={(e) => toggle(kind, e.currentTarget.checked)}
                    />
                    <span>
                      {kindWord(kind)}
                      <small class="help">{t(`scans.now.kind.${kind}`)}</small>
                    </span>
                  </label>
                )}
              </For>
              <Show when={kinds().length === 0}>
                <small id="scan-now-kinds-error" class="help bad" role="alert">
                  {t("scans.now.kinds_required")}
                </small>
              </Show>
            </fieldset>
            <div class="field">
              <label for="scan-now-deadline">{t("scans.now.deadline")}</label>
              <select id="scan-now-deadline" class="select" data-testid="scan-now-deadline" aria-describedby="scan-now-deadline-help" onChange={(e) => setDeadline(Number(e.currentTarget.value))}>
                <For each={DEADLINES}>
                  {(secs) => (
                    <option value={secs} selected={deadline() === secs}>
                      {formatDuration(secs)}
                    </option>
                  )}
                </For>
              </select>
              <small id="scan-now-deadline-help" class="help">
                {t("scans.now.deadline_hint")}
              </small>
            </div>
            <ErrorNotice error={error()} />
            <div class="dialog-actions">
              <button type="button" class="btn ghost" data-testid="scan-now-cancel" onClick={() => props.onClose()}>
                {t("common.action.cancel")}
              </button>
              <button type="submit" class="btn primary" data-testid="scan-now-start" disabled={busy() || kinds().length === 0}>
                {busy() ? t("scans.now.starting") : t("scans.now.start")}
              </button>
            </div>
          </form>
        }
      >
        {(scan) => (
          <div class="scans-form">
            <h2 class="dialog-title">{t("scans.now.title", { target: props.label })}</h2>
            {/* A scan every probe refused (the kill switch is on) is created already failed. */}
            <Show
              when={scan().state !== "failed"}
              fallback={
                <Notice kind="bad" role="alert" title={t("scans.now.refused_title")} testid="scan-now-started">
                  {noteText(scan().error ?? "")}
                </Notice>
              }
            >
              <Notice kind="ok" role="status" title={t("scans.now.started_title")} testid="scan-now-started">
                {t("scans.now.started", { probes: scan().probes.length })}
              </Notice>
            </Show>
            <div class="dialog-actions">
              <A href={scanPath(scan().id)} class="btn" data-testid="scan-now-follow" onClick={() => props.onClose()}>
                {t("scans.now.follow")}
              </A>
              <button type="button" class="btn primary" data-testid="scan-now-close" onClick={() => props.onClose()}>
                {t("common.action.close")}
              </button>
            </div>
          </div>
        )}
      </Show>
    </Dialog>
  );
}

/** The "Scan now" button of a target and its dialog; nothing for an account that may not scan. */
export default function ScanNow(props: ScanNowTarget) {
  const allowed = () => moduleRunning("discovery") && (isAdmin() || hasRole("operator"));
  const [open, setOpen] = createSignal(false);
  return (
    <Show when={allowed()}>
      <button type="button" class="btn" data-testid="scan-now" onClick={() => setOpen(true)}>
        <Icon name="scan" />
        {t("scans.now.action")}
      </button>
      <Show when={open()}>
        <ScanNowDialog kind={props.kind} value={props.value} label={props.label} onClose={() => setOpen(false)} />
      </Show>
    </Show>
  );
}
