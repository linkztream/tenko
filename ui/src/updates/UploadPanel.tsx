// Installing from files, for a server that cannot reach the release source: first the
// release list (`releases.json`) of the release, then the release file for this platform.
// The release list is optional when the server already knows the release; the file is the
// executable as published with the release, and the server checks its size and SHA-256
// against the list.
import { createSignal, createUniqueId, For, Show } from "solid-js";
import { ApiError } from "../api/problem";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { uploadManifest, uploadRelease, type InstallStarted, type UpdateStatus } from "./api";
import { InstallConfirm } from "./InstallConfirm";
import { formatFileSize } from "./words";

/** The largest release list the server accepts. */
export const MAX_MANIFEST_BYTES = 1024 * 1024;

function readText(file: Blob): Promise<string> {
  if (typeof file.text === "function") return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.readAsText(file);
  });
}

export function UploadPanel(props: {
  status: UpdateStatus;
  /** Whether a release file can be installed now (`install.upload`). */
  canInstall: boolean;
  onStatus: (status: UpdateStatus) => void;
  onStarted: (started: InstallStarted) => void;
  /** Step-up and the other failures of the install are shown by the panel above. */
  onFailure: (err: unknown) => void;
}) {
  const ids = { manifest: createUniqueId(), version: createUniqueId(), file: createUniqueId() };
  const [manifestFile, setManifestFile] = createSignal<File | null>(null);
  const [manifestBusy, setManifestBusy] = createSignal(false);
  const [manifestError, setManifestError] = createSignal<unknown>(null);
  const [version, setVersion] = createSignal<string>("");
  const [file, setFile] = createSignal<File | null>(null);
  const [confirming, setConfirming] = createSignal(false);
  const [busy, setBusy] = createSignal(false);

  const releases = () => props.status.releases;
  const chosen = () => version() || releases()[0]?.version || "";
  const asset = () =>
    releases()
      .find((r) => r.version === chosen())
      ?.assets?.find((a) => a.platform === props.status.platform);

  const sendManifest = async () => {
    const chosenFile = manifestFile();
    if (!chosenFile || manifestBusy()) return;
    setManifestBusy(true);
    setManifestError(null);
    try {
      if (chosenFile.size > MAX_MANIFEST_BYTES) {
        throw new ApiError({ status: 400, code: "update.manifest.too_large", title: "", detail: "" });
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(await readText(chosenFile));
      } catch {
        throw new ApiError({ status: 400, code: "update.manifest.json", title: "", detail: "" });
      }
      const next = await uploadManifest(parsed);
      props.onStatus(next);
      setManifestFile(null);
      setVersion("");
      toast({ kind: "ok", title: t("updates.upload.manifest_done", { count: next.manifest?.releases ?? next.releases.length }) });
    } catch (err) {
      setManifestError(err);
    } finally {
      setManifestBusy(false);
    }
  };

  const sendRelease = async () => {
    const chosenFile = file();
    if (!chosenFile || busy()) return;
    setBusy(true);
    try {
      const started = await uploadRelease(chosenFile, chosen());
      setConfirming(false);
      props.onStarted(started);
    } catch (err) {
      setConfirming(false);
      props.onFailure(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page-section" aria-labelledby="upd-upload" data-testid="updates-upload-panel">
      <h2 id="upd-upload">{t("updates.upload.heading")}</h2>
      <div class="card upd-card">
        <p class="muted">{t("updates.upload.lead")}</p>

        <div class="field">
          <label for={ids.manifest}>{t("updates.upload.manifest_label")}</label>
          <div class="form-row">
            <input
              id={ids.manifest}
              type="file"
              class="input"
              accept=".json,application/json"
              data-testid="updates-manifest-file"
              onChange={(e) => setManifestFile(e.currentTarget.files?.[0] ?? null)}
            />
            <button
              type="button"
              class="btn"
              disabled={!manifestFile() || manifestBusy()}
              onClick={() => void sendManifest()}
              data-testid="updates-manifest-upload"
            >
              {t("updates.upload.manifest_button")}
            </button>
          </div>
          <span class="help">{t("updates.upload.manifest_help")}</span>
          <ErrorNotice error={manifestError()} />
        </div>

        <Show
          when={props.canInstall && releases().length > 0}
          fallback={<p class="muted" data-testid="updates-upload-wait">{t("updates.upload.need_manifest")}</p>}
        >
          <div class="field">
            <label for={ids.version}>{t("updates.upload.version_label")}</label>
            <select
              id={ids.version}
              class="select"
              data-testid="updates-upload-version"
              value={chosen()}
              onChange={(e) => setVersion(e.currentTarget.value)}
            >
              <For each={releases()}>{(r) => <option value={r.version}>{r.version}</option>}</For>
            </select>
          </div>
          <div class="field">
            <label for={ids.file}>{t("updates.upload.file_label", { platform: props.status.platform })}</label>
            <input
              id={ids.file}
              type="file"
              class="input"
              data-testid="updates-release-file"
              onChange={(e) => setFile(e.currentTarget.files?.[0] ?? null)}
            />
            <Show when={asset()}>
              {(a) => (
                <span class="help" data-testid="updates-expected-file">
                  {t("updates.upload.expected", { name: a().name, size: formatFileSize(a().size) })}
                </span>
              )}
            </Show>
            <Show when={file()}>
              {(f) => (
                <span class="help" data-testid="updates-chosen-file">
                  {t("updates.upload.chosen", { name: f().name, size: formatFileSize(f().size) })}
                </span>
              )}
            </Show>
          </div>
          <div class="upd-actions">
            <button
              type="button"
              class="btn primary"
              disabled={!file() || busy()}
              onClick={() => setConfirming(true)}
              data-testid="updates-upload"
            >
              {busy() ? t("updates.upload.uploading") : t("updates.upload.button", { version: chosen() })}
            </button>
          </div>
        </Show>
      </div>

      <Show when={confirming()}>
        <InstallConfirm
          status={props.status}
          version={chosen()}
          kind="upload"
          busy={busy()}
          onConfirm={() => void sendRelease()}
          onClose={() => setConfirming(false)}
        />
      </Show>
    </section>
  );
}
