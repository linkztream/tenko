// "Download CA root": the root certificate of the internal CA (TLS mode a), to install on
// admin clients so their browsers trust this installation (Q5). The link exists only in
// the internal CA mode; without a known mode the system status tells.
// GET /api/v1/system/ca-root (public, application/x-pem-file) is added by WP1.8b.
import { createResource, Show } from "solid-js";
import { api } from "../api/client";
import type { TlsMode } from "../api/types";
import { t } from "../i18n";
import { Icon } from "./Icon";

export const CA_ROOT_PATH = "/api/v1/system/ca-root";

export function CaRootLink(props: { mode?: TlsMode | null; withHelp?: boolean }) {
  const [status] = createResource(
    () => props.mode === undefined,
    () => api.get("/api/v1/system/status").catch(() => null),
  );
  const internal = () => (props.mode !== undefined ? props.mode === "internal_ca" : status()?.tls?.mode === "internal_ca");
  return (
    <Show when={internal()}>
      <div class="ca-root">
        <a class="btn sm" href={CA_ROOT_PATH} download="tenko-ca-root.pem" data-testid="ca-root-download">
          <Icon name="download" size="sm" />
          {t("common.ca_root.download")}
        </a>
        <Show when={props.withHelp}>
          <span class="muted">{t("common.ca_root.help")}</span>
        </Show>
      </div>
    </Show>
  );
}
