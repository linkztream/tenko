// The zone file import (/dns/import/:id), in the steps of the spreadsheet import
// (ui/src/import/**): choose or paste an RFC 1035 zone file, preview it (a dry run: RRsets
// added, replaced and removed, the records per type, and the loss report of what the file
// brings that the zone will not keep), then apply it as a job whose progress follows the
// `jobs` topic and whose last step keeps the final report.
import { A, useParams } from "@solidjs/router";
import { createEffect, createMemo, createSignal, For, Match, on, Show, Switch } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery, latest } from "../api/live";
import { ApiError } from "../api/problem";
import { decodeSegment, paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { formatNumber, t, tDynamic } from "../i18n";
import { JobStateChip } from "../jobs/StateChip";
import { applyImport, getZone, importReportOf, previewImport, type ImportReport } from "./api";
import { DnsNav } from "./DnsNav";
import { DnsProblem, unavailable } from "./Parts";
import { dnsPaths } from "./paths";
import "../import/import.css";
import "./dns.css";

type Step = "upload" | "preview" | "apply" | "done";
const STEPS: readonly Step[] = ["upload", "preview", "apply", "done"];
const FINAL = new Set(["succeeded", "failed", "cancelled", "rolled_back"]);
/** The largest zone file the browser reads into the request (the server has its own limit). */
export const MAX_ZONE_FILE_BYTES = 64 * 1024 * 1024;

export default function ImportWizard() {
  const params = useParams<{ id: string }>();
  const id = () => decodeSegment(params.id);
  const zoneQuery = createLiveQuery({
    topics: ["dns"],
    relevant: (e) => e.objects.some((o) => o.kind === "zone" && o.id === id()),
    fetch: async (signal) => {
      const zone = await getZone(id(), signal);
      return { value: zone, revision: zone.revision };
    },
  });
  const zone = () => latest(zoneQuery);
  const zoneError = () => zoneQuery.value.error as unknown;
  const [step, setStep] = createSignal<Step>("upload");
  const [text, setText] = createSignal("");
  const [fileName, setFileName] = createSignal<string | null>(null);
  const [replace, setReplace] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  const [tooLarge, setTooLarge] = createSignal(false);
  const [preview, setPreview] = createSignal<ImportReport | null>(null);
  const [jobId, setJobId] = createSignal<string | null>(null);
  const [final, setFinal] = createSignal<ImportReport | null>(null);
  const [failed, setFailed] = createSignal(false);
  const [over, setOver] = createSignal(false);
  let fileInput!: HTMLInputElement;

  const read = async (file: File | undefined) => {
    if (!file) return;
    setTooLarge(file.size > MAX_ZONE_FILE_BYTES);
    if (file.size > MAX_ZONE_FILE_BYTES) return;
    setFileName(file.name);
    setText(await file.text());
  };

  const runPreview = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setPreview(await previewImport(id(), { zoneFile: text(), replace: replace() }));
      setStep("preview");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const runApply = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const answer = await applyImport(id(), { zoneFile: text(), replace: replace() });
      if ("jobId" in answer) {
        setJobId(answer.jobId);
        setStep("apply");
      } else {
        setFinal(answer.report);
        setStep("done");
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const job = createLiveQuery({
    topics: ["jobs"],
    relevant: (e) => e.objects.some((o) => o.kind === "job" && o.id === jobId()),
    fetch: async (signal) => {
      const jid = jobId();
      if (!jid) return { value: null };
      const detail = await api.get("/api/v1/jobs/{id}", { path: { id: jid }, signal });
      return { value: detail, revision: detail.revision };
    },
  });
  createEffect(on(jobId, () => job.refetch(), { defer: true }));
  createEffect(() => {
    const detail = latest(job);
    if (!detail || step() !== "apply" || !FINAL.has(detail.job.state)) return;
    setFailed(detail.job.state !== "succeeded");
    setFinal(importReportOf(detail.job) ?? null);
    setStep("done");
  });
  const jobDone = () => latest(job)?.job.steps.filter((s) => s.state.state === "done" || s.state.state === "skipped").length ?? 0;
  const jobTotal = () => latest(job)?.job.steps.length ?? 0;
  const pct = () => (jobTotal() ? Math.round((jobDone() / jobTotal()) * 100) : 0);

  const again = () => {
    setStep("upload");
    setText("");
    setFileName(null);
    setPreview(null);
    setFinal(null);
    setJobId(null);
    setFailed(false);
    setError(undefined);
  };

  const zoneFileError = () => {
    const err = error();
    return err instanceof ApiError && err.code === "dns.zonefile.invalid" ? err : null;
  };

  return (
    <div class="page import-page dns-page" data-testid="page-dns-import" data-id={id()}>
      <DnsNav />
      <PageHead
        crumbs={
          <Show when={zone()} fallback={<A href={dnsPaths.zones()}>{t("dns.zones.title")}</A>}>
            {(z) => (
              <>
                <A href={dnsPaths.zones()}>{t("dns.zones.title")}</A> / <A href={dnsPaths.zone(z().id)} class="mono">{z().name}</A>
              </>
            )}
          </Show>
        }
        title={t("dns.import.title")}
        sub={zone()?.name}
      />
      <Show when={!unavailable(zoneError())} fallback={<div class="page-body"><DnsProblem error={zoneError()} /></div>}>
        <ol class="import-steps" aria-label={t("dns.import.steps")} data-testid="import-steps">
          <For each={STEPS}>
            {(s, i) => (
              <li
                classList={{ done: STEPS.indexOf(step()) > i(), current: step() === s }}
                aria-current={step() === s ? "step" : undefined}
                data-testid="import-step"
                data-key={s}
              >
                <span class="n">{i() + 1}</span>
                {t(`dns.import.step.${s}`)}
              </li>
            )}
          </For>
        </ol>
        <div class="import-body">
          <Show when={zoneFileError()} fallback={<ErrorNotice error={error()} />}>
            {(err) => (
              <Notice kind="bad" role="alert" testid="error-notice" code={err().code}>
                {t("dns.import.parse_error", { line: err().params.line ?? "?" })}
              </Notice>
            )}
          </Show>
          <Switch>
            <Match when={step() === "upload"}>
              <section class="import-card" aria-labelledby="dns-import-upload" data-testid="import-upload">
                <h2 id="dns-import-upload">{t("dns.import.upload.title")}</h2>
                <p class="muted">{t("dns.import.upload.body")}</p>
                <div
                  class="dropzone"
                  classList={{ over: over() }}
                  data-testid="import-dropzone"
                  onDragOver={(e) => {
                    e.preventDefault();
                    setOver(true);
                  }}
                  onDragLeave={() => setOver(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setOver(false);
                    void read(e.dataTransfer?.files[0]);
                  }}
                >
                  <Icon name="export" />
                  <span>{t("dns.import.upload.drop")}</span>
                  <button type="button" class="btn" onClick={() => fileInput.click()} data-testid="import-choose">
                    {t("dns.import.upload.choose")}
                  </button>
                  <input
                    ref={fileInput}
                    type="file"
                    class="sr-only"
                    accept=".zone,.db,.txt,text/plain,text/dns"
                    aria-label={t("dns.import.upload.choose")}
                    data-testid="import-file-input"
                    onChange={(e) => {
                      void read(e.currentTarget.files?.[0]);
                      e.currentTarget.value = "";
                    }}
                  />
                </div>
                <Show when={fileName()}>
                  {(name) => (
                    <p data-testid="import-file" data-key={name()}>
                      <span class="mono">{name()}</span>{" "}
                      <span class="muted">{t("dns.import.upload.lines", { count: text().split("\n").length })}</span>
                    </p>
                  )}
                </Show>
                <Show when={tooLarge()}>
                  <Notice kind="bad">{t("dns.import.upload.too_large")}</Notice>
                </Show>
                <div class="field">
                  <label for="dns-f-zone_file">{t("dns.import.upload.paste")}</label>
                  <textarea
                    id="dns-f-zone_file"
                    class="input mono dns-zonefile"
                    rows={10}
                    value={text()}
                    spellcheck={false}
                    data-testid="field-zone_file"
                    onInput={(e) => {
                      setText(e.currentTarget.value);
                      setFileName(null);
                    }}
                  />
                </div>
                <label class="ackrow">
                  <input type="checkbox" class="cb" checked={replace()} data-testid="field-replace" onChange={(e) => setReplace(e.currentTarget.checked)} />
                  {t("dns.import.upload.replace")}
                </label>
                <p class="muted">{t("dns.import.upload.replace_help")}</p>
                <div class="import-actions">
                  <button type="button" class="btn primary" data-testid="import-preview" disabled={busy() || text().trim() === ""} onClick={() => void runPreview()}>
                    {t("dns.import.upload.preview")}
                  </button>
                </div>
              </section>
            </Match>
            <Match when={step() === "preview" && preview()}>
              {(report) => (
                <section class="import-card" aria-labelledby="dns-import-preview" data-testid="import-preview-report">
                  <h2 id="dns-import-preview">{t("dns.import.preview.title")}</h2>
                  <ReportFacts report={report()} />
                  <TypeCounts report={report()} />
                  <Losses report={report()} />
                  <div class="import-actions">
                    <button type="button" class="btn" data-testid="import-back" onClick={() => setStep("upload")}>
                      {t("dns.import.preview.back")}
                    </button>
                    <button type="button" class="btn primary" data-testid="import-apply" disabled={busy()} onClick={() => void runApply()}>
                      {t("dns.import.preview.apply")}
                    </button>
                  </div>
                </section>
              )}
            </Match>
            <Match when={step() === "apply"}>
              <section class="import-card import-result" data-testid="import-result" aria-live="polite">
                <h2>{t("dns.import.apply.running")}</h2>
                <div class="meter progress" aria-hidden="true">
                  <span class="bar">
                    <i style={{ "--v": `${pct()}%` }} />
                  </span>
                </div>
                <p class="muted" role="status">
                  {t("dns.import.apply.progress", { done: jobDone(), total: jobTotal() })}
                </p>
                <Show when={latest(job)}>{(d) => <JobStateChip state={d().job.state} />}</Show>
              </section>
            </Match>
            <Match when={step() === "done"}>
              <section class="import-card import-result" data-testid="import-result" data-state={failed() ? "failed" : "done"} aria-live="polite">
                <Show
                  when={!failed()}
                  fallback={
                    <Notice kind="bad" role="alert" title={t("dns.import.apply.failed")}>
                      {(() => {
                        const err = latest(job)?.job.error;
                        return err ? (tDynamic(`errors.${err.code}`, err.params ?? {}) ?? t("dns.import.apply.rolled_back")) : t("dns.import.apply.rolled_back");
                      })()}
                    </Notice>
                  }
                >
                  <h2>
                    <Icon name="check" /> {t("dns.import.apply.done")}
                  </h2>
                  <Show when={final()}>
                    {(report) => (
                      <>
                        <ReportFacts report={report()} />
                        <Show when={typeof report().serial === "number"}>
                          <p data-testid="import-serial" data-key={String(report().serial)}>
                            {t("dns.import.apply.serial", { serial: String(report().serial) })}
                          </p>
                        </Show>
                        <Losses report={report()} />
                      </>
                    )}
                  </Show>
                </Show>
                <div class="import-actions">
                  <Show when={jobId()}>
                    {(jid) => (
                      <A class="btn" href={paths.job(jid())} data-testid="import-open-job">
                        {t("dns.import.apply.open_job")}
                      </A>
                    )}
                  </Show>
                  <button type="button" class="btn" data-testid="import-again" onClick={again}>
                    {t("dns.import.apply.again")}
                  </button>
                  <A class="btn primary" href={dnsPaths.zone(id())} data-testid="import-open-zone">
                    {t("dns.import.apply.open_zone")}
                  </A>
                </div>
              </section>
            </Match>
          </Switch>
        </div>
      </Show>
    </div>
  );
}

function ReportFacts(props: { report: ImportReport }) {
  const facts = createMemo(() => [
    { key: "added", value: props.report.added },
    { key: "replaced", value: props.report.replaced },
    { key: "removed", value: props.report.removed },
  ] as const);
  return (
    <div class="import-facts" data-testid="import-facts">
      <For each={facts()}>
        {(f) => (
          <div data-testid="import-fact" data-key={f.key} data-count={f.value}>
            <div class="big num">{formatNumber(f.value)}</div>
            {t(`dns.import.fact.${f.key}`, { count: f.value })}
          </div>
        )}
      </For>
    </div>
  );
}

function TypeCounts(props: { report: ImportReport }) {
  return (
    <Show when={props.report.types}>
      {(types) => (
        <div class="table-wrap import-counts">
          <table class="plain" data-testid="import-types">
            <caption class="sr-only">{t("dns.import.types.caption")}</caption>
            <thead>
              <tr>
                <th>{t("dns.col.type")}</th>
                <th class="r">{t("dns.import.types.records")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={types()}>
                {(row) => (
                  <tr data-testid="import-type" data-key={row.rtype} data-count={row.records}>
                    <td class="mono">{row.rtype}</td>
                    <td class="r num">{formatNumber(row.records)}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      )}
    </Show>
  );
}

/** The message of a loss code: `dns.import.unsupported_type` is `dns.loss.unsupported_type`. */
function lossKey(code: string): string {
  return `dns.loss.${code.replace(/^dns\.import\./, "").replace(/\./g, "_")}`;
}

function Losses(props: { report: ImportReport }) {
  return (
    <Show
      when={props.report.losses.length > 0}
      fallback={
        <p class="muted" data-testid="import-no-losses">
          {t("dns.import.losses.none")}
        </p>
      }
    >
      <h3>{t("dns.import.losses.title", { count: props.report.losses.length })}</h3>
      <div class="table-wrap">
        <table class="plain" data-testid="import-losses">
          <thead>
            <tr>
              <th class="r">{t("dns.import.losses.line")}</th>
              <th>{t("dns.import.losses.what")}</th>
            </tr>
          </thead>
          <tbody>
            <For each={props.report.losses}>
              {(loss, i) => (
                <tr data-testid="import-loss" data-index={i()} data-code={loss.code}>
                  <td class="r num">{loss.line > 0 ? loss.line : "–"}</td>
                  <td>{tDynamic(lossKey(loss.code)) ?? <code>{loss.code}</code>}</td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>
    </Show>
  );
}
