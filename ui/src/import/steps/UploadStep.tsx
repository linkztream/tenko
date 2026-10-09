// Step 1: pick the spreadsheet or CSV files (button or drop), checked for type and size
// before anything is sent.
import { createSignal, For, Show } from "solid-js";
import { Icon } from "../../components/Icon";
import { Notice } from "../../components/Notice";
import { formatNumber, t } from "../../i18n";
import { ACCEPTED, MAX_UPLOAD_BYTES } from "../api";
import { checkFiles } from "../model";

export function UploadStep(props: { busy: boolean; onUpload: (files: File[]) => void }) {
  let input!: HTMLInputElement;
  const [files, setFiles] = createSignal<File[]>([]);
  const [over, setOver] = createSignal(false);
  const check = () => checkFiles(files(), MAX_UPLOAD_BYTES, ACCEPTED);

  const add = (list: FileList | null | undefined) => {
    if (!list) return;
    const names = new Set(files().map((f) => f.name));
    setFiles([...files(), ...Array.from(list).filter((f) => !names.has(f.name))]);
  };

  return (
    <section class="import-card" aria-labelledby="import-upload-title" data-testid="import-upload">
      <h2 id="import-upload-title">{t("import.upload.title")}</h2>
      <p class="muted">{t("import.upload.body")}</p>
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
          add(e.dataTransfer?.files);
        }}
      >
        <Icon name="export" />
        <span>{t("import.upload.drop")}</span>
        <button type="button" class="btn" onClick={() => input.click()} data-testid="import-choose">
          {t("import.upload.choose")}
        </button>
        <input
          ref={input}
          type="file"
          class="sr-only"
          multiple
          accept={ACCEPTED.join(",")}
          aria-label={t("import.upload.choose")}
          data-testid="import-file-input"
          onChange={(e) => {
            add(e.currentTarget.files);
            e.currentTarget.value = "";
          }}
        />
      </div>
      <Show when={files().length > 0}>
        <ul class="import-files" aria-label={t("import.upload.files")}>
          <For each={files()}>
            {(file) => (
              <li data-key={file.name}>
                <span class="mono">{file.name}</span>
                <span class="muted">{t("import.upload.size", { kb: formatNumber(Math.ceil(file.size / 1024)) })}</span>
                <button
                  type="button"
                  class="icon-btn"
                  aria-label={t("import.upload.remove", { name: file.name })}
                  onClick={() => setFiles(files().filter((f) => f !== file))}
                >
                  <Icon name="x" size="sm" />
                </button>
              </li>
            )}
          </For>
        </ul>
      </Show>
      <Show when={check().unsupported.length > 0}>
        <Notice kind="warn">{t("import.upload.unsupported", { names: check().unsupported.join(", ") })}</Notice>
      </Show>
      <Show when={check().tooLarge}>
        <Notice kind="bad">{t("import.upload.too_large")}</Notice>
      </Show>
      <div class="form-row">
        <button
          type="button"
          class="btn primary"
          data-testid="import-upload-start"
          disabled={props.busy || check().ok.length === 0 || check().tooLarge}
          onClick={() => props.onUpload(check().ok)}
        >
          {t("import.upload.start", { count: check().ok.length })}
        </button>
      </div>
    </section>
  );
}
