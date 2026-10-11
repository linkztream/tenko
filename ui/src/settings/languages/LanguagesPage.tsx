// The languages page (/settings/languages, administrators; API-21): the languages of the user
// interface with their packs, the upload of a pack with its validation report, the preview in
// this tab, activation for everyone, discarding an uploaded version, removing a language or
// reverting a built-in one, and the templates for translators. The list follows the `i18n.*`
// tables live (topic `system`), so a change made on another controller shows here too.
import { createSignal, For, Show } from "solid-js";
import { createLiveQuery } from "../../api/live";
import { ConfirmDialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { currentPreview, endPreview, isPackEvent, startPreview } from "../../i18n/remote";
import { SettingsNav } from "../SettingsNav";
import {
  activatePack,
  discardCandidate,
  listPacks,
  packReport,
  previewPack,
  removePack,
  templateUrl,
  type PackInfo,
  type PackReport,
  type PackUpload,
} from "./api";
import { ReportView, StatusBadge, UploadForm, VersionSummary } from "./parts";
import "./languages.css";

type Confirm = { kind: "activate" | "discard" | "remove"; pack: PackInfo };

export default function LanguagesPage() {
  const packs = createLiveQuery({
    topics: ["system"],
    relevant: isPackEvent,
    fetch: async (signal) => ({ value: await listPacks(signal) }),
  });
  const [report, setReport] = createSignal<{ report: PackReport; name: string } | null>(null);
  const [confirm, setConfirm] = createSignal<Confirm | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [confirmError, setConfirmError] = createSignal<unknown>(null);

  const rows = () => packs.latest()?.packs ?? [];

  const uploaded = (upload: PackUpload) => {
    packs.refetch();
    setReport({ report: upload.report, name: upload.pack.name });
    toast({ kind: "ok", title: t("languages.upload.done", { name: upload.pack.name, percent: upload.report.percent }) });
  };

  const showReport = async (pack: PackInfo) => {
    setError(null);
    try {
      setReport({ report: await packReport(pack.tag), name: pack.name });
    } catch (err) {
      setError(err);
    }
  };

  const preview = async (pack: PackInfo) => {
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      const info = await previewPack(pack.tag);
      await startPreview({ tag: info.tag, name: info.candidate?.display_name ?? info.name });
      packs.refetch();
      toast({ kind: "info", title: t("languages.toast.preview", { name: info.candidate?.display_name ?? info.name }) });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const confirmed = async () => {
    const pending = confirm();
    if (!pending || busy()) return;
    const { kind, pack } = pending;
    setBusy(true);
    setConfirmError(null);
    try {
      if (kind === "activate") {
        await activatePack(pack.tag);
        // What was previewed is now what everyone sees.
        if (currentPreview()?.tag === pack.tag) await endPreview();
        toast({ kind: "ok", title: t("languages.toast.activated", { name: pack.candidate?.display_name ?? pack.name }) });
      } else if (kind === "discard") {
        await discardCandidate(pack.tag);
        if (currentPreview()?.tag === pack.tag) await endPreview();
        toast({ kind: "ok", title: t("languages.toast.discarded", { name: pack.name }) });
      } else {
        await removePack(pack.tag);
        if (currentPreview()?.tag === pack.tag) await endPreview();
        toast({
          kind: "ok",
          title: pack.built_in ? t("languages.toast.reverted", { name: pack.name }) : t("languages.toast.removed", { name: pack.name }),
        });
      }
      if (report()?.report.tag === pack.tag) setReport(null);
      setConfirm(null);
      packs.refetch();
    } catch (err) {
      setConfirmError(err);
    } finally {
      setBusy(false);
    }
  };

  const ask = (kind: Confirm["kind"], pack: PackInfo) => {
    setConfirmError(null);
    setConfirm({ kind, pack });
  };

  const confirmText = (c: Confirm) => {
    const name = c.kind === "activate" ? (c.pack.candidate?.display_name ?? c.pack.name) : c.pack.name;
    if (c.kind === "activate") {
      return {
        title: t("languages.confirm.activate.title", { name }),
        body: t("languages.confirm.activate.body", { name }),
        ok: t("languages.confirm.activate.ok", { name }),
      };
    }
    if (c.kind === "discard") {
      return {
        title: t("languages.confirm.discard.title", { name }),
        body: t("languages.confirm.discard.body"),
        ok: t("languages.confirm.discard.ok"),
      };
    }
    if (c.pack.built_in) {
      return {
        title: t("languages.confirm.revert.title", { name }),
        body: t("languages.confirm.revert.body", { name }),
        ok: t("languages.confirm.revert.ok", { name }),
      };
    }
    return {
      title: t("languages.confirm.remove.title", { name }),
      body: t("languages.confirm.remove.body", { name }),
      ok: t("languages.confirm.remove.ok", { name }),
    };
  };

  return (
    <div class="page" data-testid="page-languages">
      <PageHead
        title={t("languages.title")}
        sub={t("languages.sub")}
        actions={
          <a class="btn" href={templateUrl()} download="tenko-en.xlf" data-testid="languages-template">
            {t("languages.action.template")}
          </a>
        }
      />
      <SettingsNav />
      <div class="page-body">
        <section class="page-section" aria-labelledby="lang-upload-head">
          <h2 id="lang-upload-head">{t("languages.upload.heading")}</h2>
          <p>{t("languages.lead")}</p>
          <UploadForm onUploaded={uploaded} />
        </section>

        <Show when={report()}>
          {(shown) => <ReportView report={shown().report} name={shown().name} onClose={() => setReport(null)} />}
        </Show>

        <section class="page-section" aria-labelledby="lang-list-head">
          <h2 id="lang-list-head">{t("languages.list.heading")}</h2>
          <ErrorNotice error={error() ?? packs.value.error} />
          <div class="table-wrap">
            <table class="plain lang-table" aria-labelledby="lang-list-head" data-testid="grid-languages">
              <thead>
                <tr>
                  <th scope="col">{t("languages.col.language")}</th>
                  <th scope="col">{t("languages.col.status")}</th>
                  <th scope="col">{t("languages.col.active")}</th>
                  <th scope="col">{t("languages.col.candidate")}</th>
                  <th scope="col">
                    <span class="sr-only">{t("languages.col.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                <For each={rows()}>
                  {(pack) => (
                    <tr data-testid="row" data-id={pack.tag} data-key={pack.tag} data-status={pack.status}>
                      <td data-col="language">
                        <div class="lang-name">{pack.name}</div>
                        <code class="mono muted">{pack.tag}</code>
                      </td>
                      <td data-col="status">
                        <StatusBadge status={pack.status} />
                      </td>
                      <td data-col="active">
                        <Show
                          when={pack.active}
                          fallback={<span class="muted">{pack.built_in ? t("languages.built_in_texts") : t("languages.none")}</span>}
                        >
                          {(active) => <VersionSummary version={active()} />}
                        </Show>
                      </td>
                      <td data-col="candidate">
                        <Show when={pack.candidate} fallback={<span class="muted">{t("languages.none")}</span>}>
                          {(candidate) => <VersionSummary version={candidate()} candidate />}
                        </Show>
                      </td>
                      <td data-col="actions">
                        <div class="lang-actions">
                          <Show when={pack.candidate}>
                            {(candidate) => (
                              <>
                                <button
                                  type="button"
                                  class="btn sm"
                                  disabled={busy()}
                                  onClick={() => void preview(pack)}
                                  data-testid="languages-preview"
                                >
                                  {t("languages.action.preview")}
                                </button>
                                <button
                                  type="button"
                                  class="btn sm primary"
                                  disabled={busy() || !candidate().previewed_at}
                                  title={candidate().previewed_at ? undefined : t("languages.activate.hint")}
                                  onClick={() => ask("activate", pack)}
                                  data-testid="languages-activate"
                                >
                                  {t("languages.action.activate")}
                                </button>
                                <button type="button" class="btn sm ghost" onClick={() => ask("discard", pack)} data-testid="languages-discard">
                                  {t("languages.action.discard")}
                                </button>
                              </>
                            )}
                          </Show>
                          <Show when={pack.active || pack.candidate}>
                            <button type="button" class="btn sm ghost" onClick={() => void showReport(pack)} data-testid="languages-report-open">
                              {t("languages.action.report")}
                            </button>
                          </Show>
                          <Show when={pack.active}>
                            <button
                              type="button"
                              class="btn sm ghost danger"
                              onClick={() => ask("remove", pack)}
                              data-testid={pack.built_in ? "languages-revert" : "languages-remove"}
                            >
                              {pack.built_in ? t("languages.action.revert") : t("languages.action.remove")}
                            </button>
                          </Show>
                          <a
                            class="btn sm ghost"
                            href={templateUrl(pack.tag)}
                            download={`tenko-${pack.tag}.xlf`}
                            aria-label={t("languages.action.template_of", { name: pack.name })}
                            data-testid="languages-template-language"
                          >
                            {t("languages.action.template_short")}
                          </a>
                        </div>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <Show when={confirm()}>
        {(c) => (
          <ConfirmDialog
            title={confirmText(c()).title}
            testid={`dialog-${c().kind}`}
            body={
              <>
                <p>{confirmText(c()).body}</p>
                <ErrorNotice error={confirmError()} />
              </>
            }
            confirmLabel={confirmText(c()).ok}
            cancelLabel={t("common.action.cancel")}
            danger={c().kind !== "activate"}
            busy={busy()}
            onConfirm={() => void confirmed()}
            onClose={() => setConfirm(null)}
          />
        )}
      </Show>
    </div>
  );
}
