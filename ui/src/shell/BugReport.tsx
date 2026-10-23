// "Report a bug" (the account menu): the diagnostics of GET /system/diagnostics, shown in
// full before anything leaves the browser, with two actions. "Open on GitHub" opens the
// repository's new-issue page in a new tab with the bug-report template's fields prefilled
// from the document, under the person's own GitHub account; nothing is sent by the node and
// the product holds no GitHub token. "Copy diagnostics" puts the same text on the clipboard,
// for installations without outbound links: under the Hardened profile it is the only
// action.
import { createResource, Show } from "solid-js";
import { api } from "../api/client";
import type { SystemDiagnostics } from "../api/types";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { toast } from "../components/toast";
import { t } from "../i18n";

/** The new-issue page of the repository. */
export const ISSUE_URL = "https://github.com/linkztream/tenko/issues/new";

/** The issue template whose fields are prefilled (`.github/ISSUE_TEMPLATE/bug-report.yml`). */
export const ISSUE_TEMPLATE = "bug-report.yml";

/** The diagnostics in the issue's log field end here; the rest is pasted by hand. */
export const DIAGNOSTICS_LIMIT = 6000;

/** The note that closes a truncated log field. */
export const TRUNCATION_NOTE =
  "[truncated: paste the rest of the diagnostics from the dialog or from `tenko system diagnostics`]";

/** The template's security-profile options, by the API's profile names. */
const PROFILE_OPTIONS: Record<string, string> = {
  home: "Home",
  standard: "Standard",
  hardened: "Hardened",
  lab: "Lab",
};

/** Whether the dialog may open a link to GitHub: not under the Hardened profile. */
export function linkAllowed(document: Pick<SystemDiagnostics, "profile">): boolean {
  return document.profile !== "hardened";
}

/**
 * `text` cut to at most `limit` characters at a line boundary, with the truncation note at
 * the end when anything was cut.
 */
export function truncateDiagnostics(text: string, limit = DIAGNOSTICS_LIMIT): string {
  if (text.length <= limit) return text;
  const room = limit - TRUNCATION_NOTE.length - 1;
  let cut = text.lastIndexOf("\n", room);
  if (cut <= 0) cut = room;
  return `${text.slice(0, cut)}\n${TRUNCATION_NOTE}`;
}

/** The new-issue URL with the template's fields prefilled from the document. */
export function issueUrl(document: SystemDiagnostics): string {
  const params = new URLSearchParams({
    template: ISSUE_TEMPLATE,
    version: `tenko ${document.version}`,
    profile: PROFILE_OPTIONS[document.profile] ?? "Not sure",
    platform: `${document.os} ${document.arch}`,
    logs: truncateDiagnostics(document.text),
  });
  return `${ISSUE_URL}?${params.toString()}`;
}

async function copyDiagnostics(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast({ title: t("common.action.copied"), kind: "ok" });
  } catch {
    toast({ title: t("shell.report.copy_failed"), kind: "bad" });
  }
}

/** The "Report a bug" dialog. */
export function BugReportDialog(props: { onClose: () => void }) {
  const [document] = createResource(() => api.get("/api/v1/system/diagnostics"));
  const failure = () => {
    const error = document.error as unknown;
    if (!error) return null;
    return error instanceof Error ? error.message : String(error);
  };

  return (
    <Dialog label={t("shell.report.title")} onClose={props.onClose} class="dialog wide" testid="dialog-bug-report">
      <h2 class="dialog-title">{t("shell.report.title")}</h2>
      <div class="dialog-body">
        <p>{t("shell.report.intro")}</p>
        <Show when={document.loading}>
          <p class="report-loading" data-testid="report-loading">
            {t("shell.report.loading")}
          </p>
        </Show>
        <Show when={failure()}>
          {(detail) => (
            <p class="report-failed" role="alert" data-testid="report-failed">
              {t("shell.report.failed", { detail: detail() })}
            </p>
          )}
        </Show>
        <Show when={document()}>
          {(d) => (
            <>
              <pre class="report-text mono" data-testid="report-text" tabIndex={0}>
                {d().text}
              </pre>
              <Show
                when={linkAllowed(d())}
                fallback={
                  <p class="report-note" data-testid="report-hardened">
                    {t("shell.report.hardened")}
                  </p>
                }
              >
                <p class="report-note" data-testid="report-account">
                  {t("shell.report.account")}
                </p>
              </Show>
            </>
          )}
        </Show>
      </div>
      <div class="dialog-actions">
        <button type="button" class="btn" onClick={() => props.onClose()} data-testid="report-close">
          {t("common.action.close")}
        </button>
        <Show when={document()}>
          {(d) => (
            <>
              <button
                type="button"
                class={linkAllowed(d()) ? "btn" : "btn primary"}
                onClick={() => void copyDiagnostics(d().text)}
                data-testid="report-copy"
              >
                <Icon name="copy" size="sm" />
                {t("shell.report.copy")}
              </button>
              <Show when={linkAllowed(d())}>
                <a
                  class="btn primary"
                  href={issueUrl(d())}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid="report-open"
                >
                  <Icon name="ext" size="sm" />
                  {t("shell.report.open")}
                </a>
              </Show>
            </>
          )}
        </Show>
      </div>
    </Dialog>
  );
}
