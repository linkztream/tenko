// What uses a secret: the hosts that bind it (with the role) and the connector instances
// that reference it. Shown in the detail and in the dialog that refuses a delete.
import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { t } from "../i18n";
import type { SecretReferences } from "./api";
import { roleText } from "./model";

/** How many hosts and connectors use the secret. */
export function referenceCount(references: SecretReferences): number {
  return references.hosts.length + references.connectors.length;
}

export function ReferenceLists(props: { references: SecretReferences }) {
  return (
    <div class="ref-lists" data-testid="secret-references">
      <Show when={props.references.hosts.length > 0}>
        <div class="ref-group">
          <strong>{t("secrets.refs.hosts")}</strong>
          <ul class="ref-list" aria-label={t("secrets.refs.hosts")}>
            <For each={props.references.hosts}>
              {(host) => (
                <li data-testid="secret-host" data-id={host.host} data-key={host.name ?? ""}>
                  <Show
                    when={!host.deleted && host.name}
                    fallback={<span class="mono">{host.name ?? t("secrets.refs.unknown_host")}</span>}
                  >
                    {(name) => (
                      <A class="mono" href={paths.host(name())}>
                        {name()}
                      </A>
                    )}
                  </Show>
                  <span class="muted">{t("secrets.refs.role", { role: roleText(host.role) })}</span>
                  <Show when={host.deleted}>
                    <span class="tag conflict">
                      <Icon name="alert" size="xs" /> {t("secrets.refs.deleted")}
                    </span>
                  </Show>
                </li>
              )}
            </For>
          </ul>
        </div>
      </Show>
      <Show when={props.references.connectors.length > 0}>
        <div class="ref-group">
          <strong>{t("secrets.refs.connectors")}</strong>
          <ul class="ref-list" aria-label={t("secrets.refs.connectors")}>
            <For each={props.references.connectors}>
              {(connector) => (
                <li data-testid="secret-connector" data-id={connector.connector} data-key={connector.name}>
                  <span class="mono">{connector.name}</span>
                  <span class="muted">
                    {t("secrets.refs.connector", { plugin: connector.plugin, purpose: connector.purpose })}
                  </span>
                </li>
              )}
            </For>
          </ul>
        </div>
      </Show>
    </div>
  );
}
