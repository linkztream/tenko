// One release: its version and date, the marks (security fixes, action required), the action
// the operator must take (shown first and prominently), and the release notes.
import { createUniqueId, Show } from "solid-js";
import { Notice } from "../components/Notice";
import { t } from "../i18n";
import type { Release } from "./api";
import { Markdown } from "./markdown";
import { Marks } from "./Marks";
import { releaseDate } from "./words";

/** A link to the public release notes of a version, in a new tab. */
export function ReleaseNotesLink(props: { version: string; href: string }) {
  return (
    <a
      class="upd-notes-link"
      href={props.href}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={t("updates.release.notes_link_label", { version: props.version })}
      data-testid="release-notes-link"
      data-key={props.version}
    >
      {t("updates.release.notes_link")}
    </a>
  );
}

export function ReleaseCard(props: { release: Release; newest?: boolean; notesUrl?: string | null }) {
  const titleId = createUniqueId();
  const r = () => props.release;
  return (
    <article class="card upd-release" aria-labelledby={titleId} data-testid="update-release" data-key={r().version}>
      <header class="upd-release-head">
        <h3 id={titleId}>{t("updates.release.title", { version: r().version })}</h3>
        <span class="muted">{releaseDate(r().date)}</span>
        <Show when={props.newest}>
          <span class="tag accent">{t("updates.release.newest")}</span>
        </Show>
        <Show when={r().format != null}>
          <span class="muted">{t("updates.release.format", { format: r().format ?? 0 })}</span>
        </Show>
        <Show when={props.notesUrl}>{(href) => <ReleaseNotesLink version={r().version} href={href()} />}</Show>
        <Marks
          security={r().security}
          action={r().requires_action}
          securityLabel={t("updates.mark.security")}
          actionLabel={t("updates.mark.action")}
        />
      </header>
      <Show when={r().requires_action}>
        <div class="upd-action" data-testid="update-action">
          <Notice kind="warn" title={t("updates.release.action_title")}>
            <Show when={r().action} fallback={t("updates.release.action_unspecified")}>
              {(action) => <Markdown source={action()} />}
            </Show>
          </Notice>
        </div>
      </Show>
      <Show when={r().notes.trim() !== ""} fallback={<p class="muted">{t("updates.release.no_notes")}</p>}>
        <Markdown source={r().notes} />
      </Show>
    </article>
  );
}
