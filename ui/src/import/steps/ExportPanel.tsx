// CSV export in the import vocabulary (MIG-14): three files that import back unchanged. The
// links download straight from the server, which streams the files.
import { For } from "solid-js";
import { Icon } from "../../components/Icon";
import { t } from "../../i18n";
import { EXPORT_KINDS, exportUrl } from "../api";

export function ExportPanel() {
  return (
    <section class="import-card" aria-labelledby="import-export-title" data-testid="import-export">
      <h2 id="import-export-title">{t("import.export.title")}</h2>
      <p class="muted">{t("import.export.body")}</p>
      <div class="form-row">
        <For each={EXPORT_KINDS}>
          {(kind) => (
            <a class="btn" href={exportUrl(kind)} download={`${kind}.csv`} data-testid={`export-${kind}`}>
              <Icon name="download" size="sm" />
              {t(`import.export.${kind}`)}
            </a>
          )}
        </For>
      </div>
    </section>
  );
}
