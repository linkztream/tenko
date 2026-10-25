// A note on the address page: the address is configured on a stopped guest, so nothing uses it
// now. It reads the observations of the address and stays quiet when they cannot be read.
import { createEffect, For, on, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import { t } from "../i18n";
import { getSubject } from "./api";
import { dormantClaims, type DormantClaim } from "./dormant";

export function AddressDormantNote(props: { ip: string }) {
  const live = createLiveQuery<DormantClaim[]>({
    topics: ["discovery"],
    debounceMs: 400,
    fetch: async (signal) => {
      const view = await getSubject(props.ip, signal);
      return { value: dormantClaims(view?.facts ?? []) };
    },
  });
  createEffect(on(() => props.ip, () => live.refetch(), { defer: true }));
  const names = () => [...new Set((live.value.error ? [] : (live.latest() ?? [])).map((c) => c.name))];
  return (
    <Show when={names().length > 0}>
      <div data-testid="address-dormant">
        <For each={names()}>{(name) => <p class="muted">{t("ipam.address.dormant", { name })}</p>}</For>
      </div>
    </Show>
  );
}
