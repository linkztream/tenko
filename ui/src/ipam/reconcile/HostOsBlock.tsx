// The operating system and the vendors of a host, from the reconciliation view
// (GET /api/v1/ipam/reconcile?host=<id>&limit=1): the OS field that wins by precedence (an
// inventory's statement, then an active scan's guess, then the DHCP fingerprint's) with its
// confidence, source and truth, the other guesses, and the vendors of the MAC addresses and the
// DHCP vendor class. It sits in the observation section of the host page. When the view cannot
// be read the block shows a quiet note, and nothing at all for a principal who may not read it.
import { A } from "@solidjs/router";
import { createEffect, For, on, Show } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery } from "../../api/live";
import { ApiError } from "../../api/problem";
import { formatList, t } from "../../i18n";
import { reconcilePath } from "./links";
import type { HostTruths } from "./model";
import { OsGuess } from "./OsGuess";
import "./reconcile.css";

export function HostOsBlock(props: { host: string }) {
  const live = createLiveQuery<HostTruths | null>({
    topics: ["discovery", "ipam"],
    debounceMs: 400,
    fetch: async (signal) => {
      const page = await api.get("/api/v1/ipam/reconcile", { query: { host: props.host, limit: 1 }, signal });
      return { value: page.host ?? null, revision: page.revision };
    },
  });
  createEffect(on(() => props.host, () => live.refetch(), { defer: true }));

  const truths = () => live.latest() ?? null;
  const forbidden = () => live.value.error instanceof ApiError && live.value.error.status === 403;
  const others = () => (truths()?.os_guesses ?? []).filter((g) => g.source !== truths()?.os?.source);

  return (
    <Show when={!forbidden()}>
      <div class="host-os" data-testid="host-os-block">
        <Show when={live.value.error}>
          <p class="muted" data-testid="host-os-unavailable">
            {t("ipam.reconcile.host_unavailable")}
          </p>
        </Show>
        <Show when={!live.value.error && truths()}>
          {(truth) => (
            <>
              <dl class="kv">
                <dt>{t("ipam.reconcile.os")}</dt>
                <dd data-testid="host-reconcile-os">
                  <Show when={truth().os} fallback="–">
                    {(os) => <OsGuess os={os()} />}
                  </Show>
                  <For each={others()}>
                    {(guess) => (
                      <div class="muted" data-testid="host-reconcile-os-other">
                        <OsGuess os={guess} />
                      </div>
                    )}
                  </For>
                </dd>
                <dt>{t("ipam.reconcile.vendors")}</dt>
                <dd data-testid="host-reconcile-vendors">{(truth().vendors ?? []).length > 0 ? formatList(truth().vendors ?? []) : "–"}</dd>
              </dl>
              <p>
                <A href={reconcilePath({ host: props.host })} data-testid="host-reconcile-link">
                  {t("ipam.reconcile.host_open")}
                </A>
              </p>
            </>
          )}
        </Show>
      </div>
    </Show>
  );
}
