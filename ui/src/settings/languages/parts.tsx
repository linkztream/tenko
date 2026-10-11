// The parts of the languages page: the status of a language, a version's summary, the upload
// form with the problems of a refused pack, and the validation report of a pack.
import { createSignal, createUniqueId, For, Show } from "solid-js";
import { ApiError, fieldErrorMessage, type FieldError } from "../../api/problem";
import { principalText } from "../../components/Principal";
import { ErrorNotice, Notice } from "../../components/Notice";
import { Icon } from "../../components/Icon";
import { formatDateTime, formatNumber, t } from "../../i18n";
import { MAX_PACK_BYTES, uploadPack, type PackProblem, type PackReport, type PackStatus, type PackUpload, type PackVersion } from "./api";

/** The longest list of keys the report shows; the rest is counted. */
const MAX_LISTED = 200;

const STATUS_ICON: Record<PackStatus, "globe" | "clock" | "eye" | "check"> = {
  built_in: "globe",
  uploaded: "clock",
  previewed: "eye",
  active: "check",
};

/** The life cycle state of a language: a glyph and a word, never color alone. */
export function StatusBadge(props: { status: PackStatus }) {
  return (
    <span class={`lang-status ${props.status}`} data-testid="status-badge" data-status={props.status}>
      <Icon name={STATUS_ICON[props.status]} size="xs" />
      {t(`languages.status.${props.status}`)}
    </span>
  );
}

/** One uploaded version: completeness, version, who uploaded it and when, and whether it was previewed. */
export function VersionSummary(props: { version: PackVersion; candidate?: boolean }) {
  const v = () => props.version;
  return (
    <div class="lang-version">
      <span class="meter" style={{ "--v": `${Math.min(100, Math.max(0, v().percent))}%` }}>
        <span class="bar">
          <i />
        </span>
        <span class="val">{t("languages.version.percent", { percent: v().percent })}</span>
      </span>
      <Show when={v().version}>{(version) => <span class="muted">{t("languages.version.label", { version: version() })}</span>}</Show>
      <span class="muted lang-version-by">
        {t("languages.version.by", { when: formatDateTime(v().uploaded_at), who: principalText(v().uploaded_by) })}
      </span>
      <Show when={v().origin === "data_dir"}>
        <span class="muted">{t("languages.origin.data_dir")}</span>
      </Show>
      <Show when={props.candidate}>
        <span class="muted" data-testid="languages-previewed" data-state={v().previewed_at ? "previewed" : "waiting"}>
          {v().previewed_at ? t("languages.version.previewed") : t("languages.version.not_previewed")}
        </span>
      </Show>
    </div>
  );
}

/** The problems of a refused upload, one per entry of the problem's `errors`. */
function RefusalProblems(props: { errors: readonly FieldError[] }) {
  return (
    <ul class="lang-problems" data-testid="languages-refusal">
      <For each={props.errors}>
        {(error, index) => (
          <li data-testid="languages-refusal-problem" data-index={index()} data-code={error.code} data-key={error.field}>
            <span>{fieldErrorMessage(error)}</span>
            <Show when={error.params?.["line"]}>
              {(line) => <span class="muted">{t("languages.report.at_line", { line: Number(line()) })}</span>}
            </Show>
            <Show when={error.field !== "file"}>
              <code class="mono">{error.field}</code>
            </Show>
            <Show when={error.params?.["detail"]}>{(detail) => <code class="mono muted lang-detail">{detail()}</code>}</Show>
          </li>
        )}
      </For>
    </ul>
  );
}

/** The upload of a pack: a file and a button; a refused pack lists its problems. */
export function UploadForm(props: { onUploaded: (upload: PackUpload) => void }) {
  const id = createUniqueId();
  let input!: HTMLInputElement;
  const [file, setFile] = createSignal<File | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const send = async (event: Event) => {
    event.preventDefault();
    const chosen = file();
    if (!chosen || busy()) return;
    setError(null);
    if (chosen.size > MAX_PACK_BYTES) {
      setError(new ApiError({ status: 413, code: "i18n.pack.too_large", title: "", detail: "" }));
      return;
    }
    setBusy(true);
    try {
      const upload = await uploadPack(chosen);
      setFile(null);
      input.value = "";
      props.onUploaded(upload);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const fieldErrors = () => {
    const err = error();
    return err instanceof ApiError ? err.fieldErrors : [];
  };

  return (
    <form class="field lang-upload" onSubmit={(e) => void send(e)} data-testid="languages-upload-form">
      <label for={id}>{t("languages.upload.file")}</label>
      <div class="form-row">
        <input
          ref={input}
          id={id}
          type="file"
          class="input"
          accept=".xlf,.xliff,application/xliff+xml,application/xml,text/xml"
          data-testid="field-file"
          onChange={(e) => {
            setError(null);
            setFile(e.currentTarget.files?.[0] ?? null);
          }}
        />
        <button type="submit" class="btn primary" disabled={!file() || busy()} data-testid="languages-upload">
          {t("languages.upload.submit")}
        </button>
      </div>
      <span class="help">{t("languages.upload.help")}</span>
      <ErrorNotice error={error()} />
      <Show when={fieldErrors().length > 0}>
        <RefusalProblems errors={fieldErrors()} />
      </Show>
    </form>
  );
}

function KeyList(props: { keys: readonly string[]; testid: string }) {
  const shown = () => props.keys.slice(0, MAX_LISTED);
  return (
    <ul class="lang-keys" data-testid={props.testid}>
      <For each={shown()}>
        {(key) => (
          <li>
            <code class="mono">{key}</code>
          </li>
        )}
      </For>
      <Show when={props.keys.length > MAX_LISTED}>
        <li class="muted">{t("languages.report.more", { count: props.keys.length - MAX_LISTED })}</li>
      </Show>
    </ul>
  );
}

/** A list of keys behind its count, opened on demand. */
function KeyGroup(props: { keys: readonly string[]; label: string; testid: string }) {
  return (
    <Show when={props.keys.length > 0}>
      <details class="lang-group" data-testid={props.testid} data-count={props.keys.length}>
        <summary>{props.label}</summary>
        <KeyList keys={props.keys} testid={`${props.testid}-keys`} />
      </details>
    </Show>
  );
}

function problemText(problem: PackProblem): string {
  return fieldErrorMessage({ field: problem.key ?? "file", code: problem.code });
}

/** The validation report of a pack: completeness, the keys in English, unused and stale keys, problems. */
export function ReportView(props: { report: PackReport; name: string; onClose: () => void }) {
  const r = () => props.report;
  const errors = () => r().problems.filter((p) => p.severity === "error").length;
  return (
    <section class="page-section lang-report" aria-labelledby="lang-report-head" data-testid="languages-report" data-key={r().tag}>
      <h2 id="lang-report-head">
        {t("languages.report.heading", { name: props.name })}
        <span class="aside">
          <button type="button" class="btn sm ghost" onClick={() => props.onClose()} data-testid="languages-report-close">
            {t("common.action.close")}
          </button>
        </span>
      </h2>
      <div class="card lang-report-body">
        <p class="lang-report-meta">
          <code class="mono">{r().tag}</code>
          <Show when={r().version}>
            <span class="muted">{t("languages.version.label", { version: r().version })}</span>
          </Show>
          <Show when={r().author}>
            <span class="muted">{t("languages.report.author", { author: r().author })}</span>
          </Show>
        </p>
        <p data-testid="languages-report-complete" data-percent={r().percent} data-translated={r().translated} data-total={r().total}>
          <span class="meter" style={{ "--v": `${Math.min(100, Math.max(0, r().percent))}%` }}>
            <span class="bar">
              <i />
            </span>
            <span class="val">{t("languages.version.percent", { percent: r().percent })}</span>
          </span>{" "}
          {t("languages.report.complete", { translated: r().translated, total: r().total })}
        </p>
        <KeyGroup keys={r().missing} label={t("languages.report.missing", { count: r().missing.length })} testid="languages-report-missing" />
        <KeyGroup keys={r().extra} label={t("languages.report.extra", { count: r().extra.length })} testid="languages-report-extra" />
        <KeyGroup keys={r().stale} label={t("languages.report.stale", { count: r().stale.length })} testid="languages-report-stale" />
        <Show
          when={r().problems.length > 0}
          fallback={
            <Notice kind="ok" testid="languages-report-clean">
              {t("languages.report.none")}
            </Notice>
          }
        >
          <h3 class="lang-subhead">{t("languages.report.problems", { count: r().problems.length, errors: errors() })}</h3>
          <div class="table-wrap">
            <table class="plain" aria-label={t("languages.report.problems_label")}>
              <thead>
                <tr>
                  <th scope="col">{t("languages.report.col.severity")}</th>
                  <th scope="col">{t("languages.report.col.problem")}</th>
                  <th scope="col">{t("languages.report.col.key")}</th>
                  <th scope="col" class="r">
                    {t("languages.report.col.line")}
                  </th>
                </tr>
              </thead>
              <tbody>
                <For each={r().problems}>
                  {(problem, index) => (
                    <tr data-testid="languages-problem" data-index={index()} data-code={problem.code} data-key={problem.key ?? ""}>
                      <td>
                        <span class={`lang-severity ${problem.severity}`}>
                          <Icon name={problem.severity === "error" ? "alert" : "info"} size="xs" />
                          {t(`languages.severity.${problem.severity}`)}
                        </span>
                      </td>
                      <td>
                        <div>{problemText(problem)}</div>
                        <code class="mono muted lang-detail">{problem.detail}</code>
                      </td>
                      <td>
                        <Show when={problem.key}>{(key) => <code class="mono">{key()}</code>}</Show>
                      </td>
                      <td class="r">{problem.line == null ? "" : formatNumber(problem.line)}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </div>
    </section>
  );
}
