// "What is new in <version>": after an upgrade, once for each user, the release notes since
// the version that user last saw. Closing the dialog tells the server the notes were seen. A
// user who has never seen any starts from the running version without a dialog. The same
// component serves the "What is new" command, which opens the notes again on request.
import { createEffect, createSignal, For, on, onMount, Show } from "solid-js";
import { session } from "../auth/session";
import { Dialog } from "../components/Dialog";
import { t } from "../i18n";
import { markWhatsNewSeen, readWhatsNew, type Release, type WhatsNewNotes } from "./api";
import { ReleaseCard } from "./ReleaseCard";
import "./marks.css";
import "./updates.css";

/** The sign-in session the dialog was already shown for: once per session, however often the shell mounts. */
let shownFor: string | null = null;
/** The notes the user was shown in this session, to reopen them later. */
let lastNotes: { running: string; last: string | null; releases: Release[] } | null = null;

/** For tests: forget that a dialog was shown. */
export function forgetWhatsNew(): void {
  shownFor = null;
  lastNotes = null;
}

export default function WhatsNew(props: {
  /** Opens the notes on request (the command), whether or not they are new. */
  open?: boolean;
  onClose?: () => void;
}) {
  const [notes, setNotes] = createSignal<WhatsNewNotes | null>(null);
  const [mode, setMode] = createSignal<"auto" | "manual" | null>(null);
  let closeButton: HTMLButtonElement | undefined;

  const load = async (): Promise<WhatsNewNotes | null> => {
    try {
      const data = await readWhatsNew();
      setNotes(data);
      return data;
    } catch {
      return null;
    }
  };

  const seen = () => void markWhatsNewSeen().catch(() => undefined);

  onMount(() => {
    void (async () => {
      const data = await load();
      if (!data) return;
      const key = session()?.session_id ?? "";
      if (data.show && shownFor !== key) {
        shownFor = key;
        lastNotes = { running: data.running, last: data.last_seen ?? null, releases: data.releases };
        setMode("auto");
      } else if (!data.show && (data.last_seen ?? null) === null) {
        // A new user starts from the running version.
        seen();
      }
    })();
  });

  createEffect(
    on(
      () => props.open === true,
      (open) => {
        if (!open || mode() !== null) return;
        void (async () => {
          const data = notes() ?? (await load());
          if (data && data.releases.length > 0) lastNotes = { running: data.running, last: data.last_seen ?? null, releases: data.releases };
          setMode("manual");
        })();
      },
      { defer: true },
    ),
  );

  const shown = () => {
    const data = notes();
    const releases = data && data.releases.length > 0 ? data.releases : (lastNotes?.releases ?? []);
    return { running: data?.running ?? lastNotes?.running ?? "", last: data?.last_seen ?? lastNotes?.last ?? null, releases };
  };

  const close = () => {
    const was = mode();
    setMode(null);
    if (was === "auto") seen();
    props.onClose?.();
  };

  return (
    <Show when={mode()}>
      <Dialog
        label={t("updates.whatsnew.title", { version: shown().running })}
        onClose={close}
        class="dialog upd-whatsnew"
        testid="dialog-whats-new"
        initialFocus={() => closeButton}
      >
        <h2 class="dialog-title">{t("updates.whatsnew.title", { version: shown().running })}</h2>
        <div class="dialog-body">
          <Show
            when={shown().releases.length > 0}
            fallback={<p data-testid="whats-new-empty">{t("updates.whatsnew.empty", { version: shown().running })}</p>}
          >
            <p class="muted">
              {shown().last ? t("updates.whatsnew.lead", { last: shown().last ?? "" }) : t("updates.whatsnew.lead_first")}
            </p>
            <div class="upd-notes" data-testid="whats-new-notes">
              <For each={shown().releases}>{(release) => <ReleaseCard release={release} />}</For>
            </div>
          </Show>
        </div>
        <div class="dialog-actions">
          <button
            ref={closeButton}
            type="button"
            class="btn primary"
            onClick={close}
            data-testid="whats-new-close"
          >
            {t("updates.whatsnew.close")}
          </button>
        </div>
      </Dialog>
    </Show>
  );
}
