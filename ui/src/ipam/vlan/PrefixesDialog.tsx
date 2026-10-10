// The prefixes linked to a VLAN (GET /api/v1/vlans/{id}/prefixes): each with a link to its
// prefix page, its status and role. A prefix is linked to a VLAN by editing the prefix, which
// the dialog says; it only reads.
import { A } from "@solidjs/router";
import { createResource, createSignal, For, onCleanup, onMount, Show, untrack } from "solid-js";
import { paths } from "../../app/paths";
import type { Prefix, Vlan } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { ErrorNotice } from "../../components/Notice";
import { StatusBadge } from "../../grid/cells";
import { t } from "../../i18n";
import { prefixRoleWord } from "../words";
import { listVlanPrefixes, listVrfs } from "./api";
import "./provision.css";

type State = { items: Prefix[] } | { error: unknown } | null;

export function PrefixesDialog(props: { vlan: Vlan; onClose: () => void }) {
  const vlan = untrack(() => props.vlan);
  const title = t("ipam.vlan.prefixes.title", { vid: vlan.vid, name: vlan.name });
  const [state, setState] = createSignal<State>(null);
  const [vrfs] = createResource(async () => {
    try {
      return await listVrfs();
    } catch {
      return [];
    }
  });
  const controller = new AbortController();
  onCleanup(() => controller.abort());
  onMount(() => {
    listVlanPrefixes(vlan.id, controller.signal).then(
      (items) => setState({ items }),
      (error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) setState({ error });
      },
    );
  });

  const items = () => {
    const s = state();
    return s && "items" in s ? s.items : null;
  };
  const failure = () => {
    const s = state();
    return s && "error" in s ? s.error : null;
  };
  const vrfName = (id: string) => vrfs()?.find((v) => v.id === id)?.name;

  return (
    <Dialog label={title} onClose={props.onClose} class="dialog prefixes-dialog" testid="dialog-vlan-prefixes">
      <div class="prefixes-body">
        <h2 class="dialog-title">{title}</h2>
        <p class="muted">{t("ipam.vlan.prefixes.intro")}</p>
        <Show when={failure()}>
          <ErrorNotice error={failure()} />
        </Show>
        <Show
          when={items()}
          fallback={
            <Show when={!failure()}>
              <p class="muted" role="status">
                {t("ipam.vlan.prefixes.loading")}
              </p>
            </Show>
          }
        >
          {(list) => (
            <Show
              when={list().length > 0}
              fallback={
                <p class="muted" data-testid="vlan-prefixes-empty">
                  {t("ipam.vlan.prefixes.empty")}
                </p>
              }
            >
              <ul class="vlan-prefix-list" aria-label={t("ipam.vlan.prefixes.list_label")}>
                <For each={list()}>
                  {(prefix) => (
                    <li class="vlan-prefix" data-testid="vlan-prefix" data-key={prefix.cidr}>
                      <A href={paths.prefix(prefix.cidr, prefix.vrf)} class="mono vlan-prefix-cidr">
                        {prefix.cidr}
                      </A>
                      <StatusBadge status={prefix.status} />
                      <span class="vlan-prefix-meta">{prefixRoleWord(prefix.role)}</span>
                      <Show when={vrfName(prefix.vrf)}>
                        {(name) => (
                          <span class="vlan-prefix-meta">
                            {t("ipam.col.vrf")} {name()}
                          </span>
                        )}
                      </Show>
                      <Show when={prefix.meta.description}>
                        <span class="vlan-prefix-meta">{prefix.meta.description}</span>
                      </Show>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          )}
        </Show>
        <div class="dialog-actions">
          <button type="button" class="btn" data-testid="vlan-prefixes-close" onClick={() => props.onClose()}>
            {t("common.action.close")}
          </button>
        </div>
      </div>
    </Dialog>
  );
}
