// The import wizard (/ipam/import, IPAM-11): upload a spreadsheet or CSV, check how its
// sheets and columns are read, preview every change as a full page with the loss report
// and the warnings, then apply it as a job and follow it to the result. The import id is
// kept in the URL (`?id=`), so a reload or a link resumes where the import stands.
import { useSearchParams } from "@solidjs/router";
import { createEffect, createSignal, For, Match, on, Show, Switch } from "solid-js";
import { createLiveQuery } from "../api/live";
import { api, newIdempotencyKey } from "../api/client";
import { isApiError } from "../api/problem";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import { IpamNav } from "../ipam/IpamNav";
import { applyImport, discardImport, MAX_PREVIEW_ROWS, previewImport, readImport, saveMapping, uploadImport } from "./api";
import { allRowsListed, INITIAL, nextRows, reduce, STEPS, type Step, type WizardEvent, type WizardState } from "./model";
import { ExportPanel } from "./steps/ExportPanel";
import { MappingStep } from "./steps/MappingStep";
import { PreviewStep } from "./steps/PreviewStep";
import { ResultStep } from "./steps/ResultStep";
import { UploadStep } from "./steps/UploadStep";
import "./import.css";

const FINAL = new Set(["succeeded", "failed", "rolled_back", "cancelled"]);

export default function Wizard() {
  const [params, setParams] = useSearchParams();
  const [state, setState] = createSignal<WizardState>(INITIAL);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  let applyKey = newIdempotencyKey();
  const send = (event: WizardEvent) => setState((s) => reduce(s, event));

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await work();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  // Resume an import named in the URL.
  const idParam = () => (typeof params.id === "string" ? params.id : undefined);
  createEffect(
    on(idParam, (id) => {
      if (!id || state().view?.id === id) return;
      void run(async () => {
        try {
          send({ type: "resumed", view: await readImport(id) });
        } catch (err) {
          setParams({ id: undefined });
          if (isApiError(err, "import.expired") || isApiError(err, "import.not_found")) send({ type: "reset" });
          throw err;
        }
      });
    }),
  );

  const upload = (files: File[]) =>
    void run(async () => {
      const view = await uploadImport(files);
      send({ type: "uploaded", view });
      setParams({ id: view.id });
    });

  const save = () =>
    // eslint-disable-next-line solid/reactivity -- an event handler: reads the state when it runs
    void run(async () => {
      const s = state();
      if (!s.view || !s.mapping) return;
      send({ type: "saved", view: await saveMapping(s.view.id, s.mapping) });
      send({ type: "previewed", preview: await previewImport(s.view.id) });
    });

  // A mapping edit on the preview page (a proposal) saves and previews again at once.
  const saveAndPreview = (event: WizardEvent) => {
    send(event);
    save();
  };

  // The next page of the row list: the preview again, with more rows listed.
  const [loadingRows, setLoadingRows] = createSignal(false);
  const [rowsError, setRowsError] = createSignal<unknown>(null);
  const moreRows = async () => {
    const s = state();
    const rows = nextRows(s);
    if (!s.view || rows === 0 || loadingRows()) return;
    setLoadingRows(true);
    setRowsError(null);
    try {
      send({ type: "rows", preview: await previewImport(s.view.id, rows) });
    } catch (err) {
      setRowsError(err);
    } finally {
      setLoadingRows(false);
    }
  };

  const apply = () =>
    // eslint-disable-next-line solid/reactivity -- an event handler: reads the state when it runs
    void run(async () => {
      let s = state();
      if (!s.view) return;
      // List every row first, so the result links to everything the import creates.
      if (!allRowsListed(s)) {
        const full = await previewImport(s.view.id, Math.min(s.preview?.total_rows ?? 0, MAX_PREVIEW_ROWS));
        const before = s.preview?.base_revision;
        send({ type: "rows", preview: full });
        // The store changed meanwhile: the person checks the new preview before applying.
        if (full.base_revision !== before) return;
        s = state();
      }
      const jobId = await applyImport(s.view!.id, s.acknowledged, applyKey);
      applyKey = newIdempotencyKey();
      send({ type: "applying", jobId });
    });

  const discard = () =>
    // eslint-disable-next-line solid/reactivity -- an event handler: reads the state when it runs
    void run(async () => {
      const id = state().view?.id;
      if (id) await discardImport(id).catch(() => undefined);
      send({ type: "reset" });
      setParams({ id: undefined });
    });

  // Follow the apply job until it ends.
  const job = createLiveQuery({
    topics: ["jobs"],
    relevant: (e) => e.objects.some((o) => o.kind === "job" && o.id === state().jobId),
    fetch: async (signal) => {
      const id = state().jobId;
      if (!id) return { value: null };
      const detail = await api.get("/api/v1/jobs/{id}", { path: { id }, signal });
      return { value: detail, revision: detail.revision };
    },
  });
  createEffect(on(() => state().jobId, () => job.refetch(), { defer: true }));
  createEffect(() => {
    const d = job.value.latest;
    if (d && state().step === "apply" && FINAL.has(d.job.state)) send({ type: "finished", succeeded: d.job.state === "succeeded" });
  });

  const stepIndex = (s: Step) => STEPS.indexOf(s);

  return (
    <div class="page import-page" data-testid="page-import">
      <IpamNav />
      <div class="page-head">
        <div>
          <h1 tabIndex={-1}>
            {t("import.title")}
            <span class="sub">{t("import.sub")}</span>
          </h1>
        </div>
      </div>
      <ol class="import-steps" aria-label={t("import.steps")} data-testid="import-steps">
        <For each={STEPS}>
          {(s, i) => (
            <li
              classList={{ done: stepIndex(state().step) > i(), current: state().step === s }}
              aria-current={state().step === s ? "step" : undefined}
              data-step={s}
              data-testid="import-step"
              data-key={s}
            >
              <span class="n">{i() + 1}</span>
              {t(`import.step.${s}`)}
            </li>
          )}
        </For>
      </ol>
      <div class="import-body">
        <ErrorNotice error={error()} />
        <Switch>
          <Match when={state().step === "upload"}>
            <UploadStep busy={busy()} onUpload={upload} />
            <ExportPanel />
          </Match>
          <Match when={state().step === "mapping" && state().view}>
            <MappingStep
              view={state().view!}
              mapping={state().mapping!}
              busy={busy()}
              onChange={(mapping) => send({ type: "edit", mapping })}
              onSave={save}
              onDiscard={discard}
            />
          </Match>
          <Match when={state().step === "preview"}>
            <PreviewStep
              state={state()}
              busy={busy()}
              onAcknowledge={(code, on) => send({ type: "acknowledge", code, on })}
              onMappingChange={(mapping) => saveAndPreview({ type: "edit", mapping })}
              onBack={() => send({ type: "back" })}
              onApply={apply}
              rowsLoading={loadingRows()}
              rowsError={rowsError()}
              onMoreRows={() => void moreRows()}
            />
          </Match>
          <Match when={state().step === "apply" || state().step === "done"}>
            <ResultStep
              state={state()}
              job={job.value.latest ?? null}
              onAgain={() => {
                send({ type: "reset" });
                setParams({ id: undefined });
              }}
              onBack={() => send({ type: "back" })}
            />
          </Match>
        </Switch>
        <Show when={busy()}>
          <p class="muted" role="status">
            {t("common.loading")}
          </p>
        </Show>
      </div>
    </div>
  );
}
