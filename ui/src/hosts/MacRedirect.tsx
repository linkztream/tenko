// /ipam/macs/<mac>: the host that has an interface with this MAC address (a search hit or a
// link from elsewhere). One match opens the host; several are listed; none says so.
import { A, Navigate, useParams } from "@solidjs/router";
import { createResource, For, Match, Switch } from "solid-js";
import { api } from "../api/client";
import type { Host } from "../api/types";
import { decodeSegment, paths } from "../app/paths";
import { Mac } from "../components/Addr";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import { IpamNav } from "../ipam/IpamNav";
import { readHost } from "../ipam/resolve";
import { normalizeMac } from "./HostForm";

export default function MacRedirect() {
  const params = useParams();
  const mac = () => normalizeMac(decodeSegment(params.mac)) ?? decodeSegment(params.mac);
  const [hosts] = createResource(mac, async (m) => {
    const hits = await api.get("/api/v1/search", { query: { q: m, limit: 50 } });
    const ids = hits.items.filter((h) => h.item.kind === "interface" && h.item.data.mac === m).map((h) => (h.item.data as { host: string }).host);
    const found = await Promise.all([...new Set(ids)].map((id) => readHost(id)));
    return found.filter((h): h is Host => !!h);
  });
  return (
    <div class="page" data-testid="page-mac">
      <IpamNav />
      <div class="page-body">
        <ErrorNotice error={hosts.error} />
        <Switch>
          <Match when={hosts()?.length === 1}>
            <Navigate href={paths.host(hosts()![0]!.name)} />
          </Match>
          <Match when={(hosts()?.length ?? 0) > 1}>
            <p>{t("hosts.mac.several")}</p>
            <ul class="list">
              <For each={hosts() ?? []}>{(h) => <li><A href={paths.host(h.name)}>{h.name}</A></li>}</For>
            </ul>
          </Match>
          <Match when={hosts()?.length === 0}>
            <p class="muted">
              {t("hosts.mac.none")} <Mac value={mac()} />
            </p>
          </Match>
        </Switch>
      </div>
    </div>
  );
}
