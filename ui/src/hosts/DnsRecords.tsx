// The read-only "DNS records" block of the host and address pages (WP4.5): for each address, the
// A (IPv4) or AAAA (IPv6) records of its DNS name in the zone with the longest matching suffix,
// and the PTR of its reverse name in the reverse zone that holds it; "no zone in Tenko" where
// none matches.
// The records appear once IPAM writes them (WP4.4). Nothing shows while the DNS module is off,
// or when the server does not answer the DNS routes (501 until WP4.2, 403 without `dns.read`).
import { A } from "@solidjs/router";
import { createResource, For, Show } from "solid-js";
import { listRecords, listZones, type RrSet, type Zone } from "../dns/api";
import { recordText, relativeName, reverseName, zoneFor } from "../dns/model";
import { dnsPaths } from "../dns/paths";
import { t } from "../i18n";
import { moduleRunning } from "../updates/modules";

export interface DnsAddress {
  ip: string;
  dns_name?: string | null | undefined;
}

interface Lookup {
  zone: Zone | undefined;
  /** The owner looked up: the DNS name, or the reverse name of the address. */
  owner: string | undefined;
  sets: RrSet[];
}

interface Row {
  ip: string;
  forward: Lookup;
  reverse: Lookup;
}

async function lookup(owner: string | undefined, zones: readonly Zone[], types: readonly string[]): Promise<Lookup> {
  const zone = owner ? zoneFor(owner, zones) : undefined;
  if (!zone || !owner) return { zone, owner, sets: [] };
  const sets = await listRecords(zone.id, { name: relativeName(owner, zone.name) });
  return { zone, owner, sets: sets.filter((s) => s.name === owner && types.includes(s.type)) };
}

async function load(addresses: readonly DnsAddress[]): Promise<Row[]> {
  const { items: zones } = await listZones();
  return Promise.all(
    addresses.map(async (a) => {
      const name = a.dns_name?.trim().toLowerCase().replace(/\.$/, "") || undefined;
      const [forward, reverse] = await Promise.all([lookup(name, zones, [a.ip.includes(":") ? "AAAA" : "A"]), lookup(reverseName(a.ip), zones, ["PTR"])]);
      return { ip: a.ip, forward, reverse };
    }),
  );
}

function Records(props: { lookup: Lookup; kind: "forward" | "reverse" }) {
  return (
    <Show when={props.lookup.owner} fallback={<span class="muted">–</span>}>
    <Show
      when={props.lookup.zone}
      fallback={
        <span class="muted" data-testid="host-dns-none" data-kind={props.kind}>
          {t("hosts.dns.no_zone")}
        </span>
      }
    >
      {(zone) => (
        <Show
          when={props.lookup.sets.length > 0}
          fallback={
            <span class="muted" data-testid="host-dns-empty" data-kind={props.kind}>
              {t("hosts.dns.no_records", { zone: zone().name })}
            </span>
          }
        >
          <div>
            <For each={props.lookup.sets}>
              {(set) => (
                <For each={set.records}>
                  {(r) => (
                    <div data-testid="host-dns-record" data-kind={props.kind} data-key={`${set.type} ${recordText(r)}`}>
                      <span class="mono">{set.type}</span> <span class="mono">{recordText(r)}</span>{" "}
                      <span class="muted">{t(`hosts.dns.origin.${set.origin}`)}</span>
                    </div>
                  )}
                </For>
              )}
            </For>
          </div>
          <A href={dnsPaths.zone(zone().id)} class="mono" data-testid="host-dns-zone" data-kind={props.kind}>
            {zone().name}
          </A>
        </Show>
      )}
    </Show>
    </Show>
  );
}

/** The block: shown only when the zones could be read. */
export function DnsRecords(props: { addresses: readonly DnsAddress[] }) {
  const [rows] = createResource(
    () => (moduleRunning("dns") && props.addresses.length > 0 ? props.addresses.map((a) => `${a.ip} ${a.dns_name ?? ""}`).join(",") : false),
    () => load(props.addresses),
  );
  return (
    <Show when={!rows.error && rows.latest}>
      {(list) => (
        <section class="page-section" aria-labelledby="host-dns-title" data-testid="host-dns">
          <h2 id="host-dns-title">{t("hosts.dns.title")}</h2>
          <div class="table-wrap">
            <table class="plain">
              <thead>
                <tr>
                  <th>{t("hosts.dns.col.address")}</th>
                  <th>{t("hosts.dns.col.forward")}</th>
                  <th>{t("hosts.dns.col.reverse")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={list()}>
                  {(row) => (
                    <tr data-testid="host-dns-row" data-key={row.ip}>
                      <td class="mono">{row.ip}</td>
                      <td>
                        <Records lookup={row.forward} kind="forward" />
                      </td>
                      <td>
                        <Records lookup={row.reverse} kind="reverse" />
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </section>
      )}
    </Show>
  );
}
