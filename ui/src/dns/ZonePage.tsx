// One zone (/dns/zones/:id/:tab?): its name, kind and serving state and the serial it serves,
// the actions (import a zone file, export one, delete the zone) and three tabs: the records,
// the settings (SOA, apex NS, serial policy) and the history. The zone follows the `dns`
// topic; a 501 of the API (WP4.2 not landed) or the module switched off shows the notice.
import { A, useNavigate, useParams } from "@solidjs/router";
import { createSignal, For, Match, Show, Switch } from "solid-js";
import { createLiveQuery, latest } from "../api/live";
import { decodeSegment } from "../app/paths";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { exportZoneFile, getZone, servedSerial, type Zone } from "./api";
import { mayWriteDns } from "./access";
import { DnsNav } from "./DnsNav";
import { DnsProblem, downloadText, unavailable, ZoneChips } from "./Parts";
import { dnsPaths, type ZoneTab } from "./paths";
import { RecordsTab } from "./RecordsTab";
import { DeleteZoneDialog } from "./ZoneDialogs";
import { HistoryTab, SettingsTab } from "./ZoneSettings";
import { errorMessage } from "../api/problem";
import "./dns.css";

const TABS: readonly ZoneTab[] = ["records", "settings", "history"];

export default function ZonePage() {
  const params = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const id = () => decodeSegment(params.id);
  const tab = (): ZoneTab => (TABS.includes(params.tab as ZoneTab) ? (params.tab as ZoneTab) : "records");
  const [deleting, setDeleting] = createSignal(false);
  const [exporting, setExporting] = createSignal(false);

  const query = createLiveQuery({
    topics: ["dns"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => o.kind === "zone" && o.id === id()),
    fetch: async (signal) => {
      const zone = await getZone(id(), signal);
      return { value: zone, revision: zone.revision };
    },
  });
  const zone = () => latest(query);
  const [saved, setSaved] = createSignal<Zone | null>(null);
  // A save answers the new zone before the event arrives; show it at once.
  const current = () => {
    const z = zone();
    const s = saved();
    return s && z && s.id === z.id && s.revision >= z.revision ? s : z;
  };

  const doExport = async (z: Zone) => {
    setExporting(true);
    try {
      downloadText(`${z.name}.zone`, await exportZoneFile(z.id));
    } catch (err) {
      toast({ kind: "bad", title: t("dns.export.failed"), body: errorMessage(err) });
    } finally {
      setExporting(false);
    }
  };

  return (
    <div class="page dns-page" data-testid="page-dns-zone" data-id={id()}>
      <DnsNav />
      <Show
        when={current()}
        fallback={
          <>
            <PageHead title={t("dns.zones.title")} />
            <div class="page-body">
              <Show when={query.value.error} fallback={<p class="muted">{t("common.loading")}</p>}>
                {(err) => (
                  <Show when={unavailable(err())} fallback={<ErrorNotice error={err()} />}>
                    <DnsProblem error={err()} />
                  </Show>
                )}
              </Show>
            </div>
          </>
        }
      >
        {(z) => (
          <>
            <PageHead
              crumbs={<A href={dnsPaths.zones()}>{t("dns.zones.title")}</A>}
              title={<span class="mono" data-testid="zone-name">{z().name}</span>}
              sub={
                <>
                  <ZoneChips zone={z()} />{" "}
                  <span class="muted" data-testid="zone-header-serial" data-key={String(servedSerial(z()) ?? "")}>
                    {t("dns.zone.serial", { serial: String(servedSerial(z()) ?? "–") })}
                  </span>
                </>
              }
              actions={
                <>
                  <Show when={mayWriteDns()}>
                    <A class="btn" href={dnsPaths.zoneImport(z().id)} data-testid="dns-zone-import">
                      <Icon name="export" />
                      {t("dns.do.import")}
                    </A>
                  </Show>
                  <button type="button" class="btn" data-testid="dns-zone-export" disabled={exporting()} onClick={() => void doExport(z())}>
                    <Icon name="download" />
                    {t("dns.do.export")}
                  </button>
                  <Show when={mayWriteDns()}>
                    <button type="button" class="btn danger" data-testid="dns-zone-delete" onClick={() => setDeleting(true)}>
                      <Icon name="trash" />
                      {t("dns.do.delete")}
                    </button>
                  </Show>
                </>
              }
            />
            <div class="tabs" role="tablist" aria-label={t("dns.zone.tabs")}>
              <For each={TABS}>
                {(name) => (
                  <button
                    type="button"
                    role="tab"
                    aria-selected={tab() === name}
                    data-testid={`zone-tab-${name}`}
                    onClick={() => navigate(dnsPaths.zone(z().id, name))}
                  >
                    {t(`dns.zone.tab.${name}`)}
                  </button>
                )}
              </For>
            </div>
            <Switch>
              <Match when={tab() === "records"}>
                <RecordsTab zone={z()} onWritten={() => query.refetch()} />
              </Match>
              <Match when={tab() === "settings"}>
                <SettingsTab
                  zone={z()}
                  onSaved={(next) => {
                    setSaved(next);
                    query.refetch();
                  }}
                />
              </Match>
              <Match when={tab() === "history"}>
                <HistoryTab zone={z()} />
              </Match>
            </Switch>
            <Show when={deleting()}>
              <DeleteZoneDialog
                zone={z()}
                onClose={() => setDeleting(false)}
                onDone={() => {
                  setDeleting(false);
                  navigate(dnsPaths.zones());
                }}
              />
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}
