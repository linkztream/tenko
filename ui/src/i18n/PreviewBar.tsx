// The bar of a language preview (remote.ts): while an administrator previews the uploaded
// candidate of a language, this tab says so on every page, with the way back to the languages
// page and the way out. It is loaded and mounted only when a preview starts, outside the
// application tree, so neither the first page load nor the shell carries it.
import { createSignal, Show } from "solid-js";
import { render } from "solid-js/web";
import { Icon } from "../components/Icon";
import { loadPacks, t } from ".";
import { currentPreview, endPreview } from "./remote";
import "./preview.css";

const LANGUAGES_PAGE = "/settings/languages";

let mounted = false;

function PreviewBar() {
  const [busy, setBusy] = createSignal(false);
  const end = async () => {
    setBusy(true);
    try {
      await endPreview();
    } finally {
      setBusy(false);
    }
  };
  return (
    <Show when={currentPreview()}>
      {(preview) => (
        <div class="preview-bar" role="status" data-testid="languages-preview-bar" data-key={preview().tag}>
          <Icon name="info" size="sm" />
          <span class="preview-bar-text">{t("languages.preview.bar", { name: preview().name })}</span>
          <a class="btn sm ghost" href={LANGUAGES_PAGE} data-testid="languages-preview-open">
            {t("languages.preview.open")}
          </a>
          <button type="button" class="btn sm" disabled={busy()} onClick={() => void end()} data-testid="languages-preview-end">
            {t("languages.preview.end")}
          </button>
        </div>
      )}
    </Show>
  );
}

/** Shows the bar of the preview in progress (once mounted, it follows the preview). */
export async function showPreviewBar(): Promise<void> {
  await loadPacks(["languages"]);
  if (mounted || typeof document === "undefined") return;
  mounted = true;
  const host = document.createElement("div");
  host.className = "preview-bar-host";
  document.body.append(host);
  render(() => <PreviewBar />, host);
}
