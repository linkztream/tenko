// The observation section of the host page: what the sources report about the host's MAC
// addresses, IP addresses and name, merged into one list of facts (one row per source and
// subject), with the last sighting, the open TCP ports and the operating system (SCAN-08), the
// open proposals about the host, and links to the picture of each subject. Live on the
// `discovery` topic and on proposal changes.
import { A } from "@solidjs/router";
import { createEffect, createMemo, For, on, Show } from "solid-js";
import { createLiveQuery } from "../api/live";
import type { Address, Host, Interface } from "../api/types";
import { paths } from "../app/paths";
import { Mac } from "../components/Addr";
import { ErrorNotice } from "../components/Notice";
import { TimeAgo } from "../grid/cells";
import { formatList, t } from "../i18n";
import { getSubject, listProposals, type ObservedFact, type Proposal } from "./api";
import { KindBadge } from "./columns";
import { FactTable } from "./FactTable";
import { isCurrent, isProposalEvent, ruleText, sourceText } from "./model";
import { useSourceNames } from "./refs";
import "./discovery.css";

interface HostPicture {
  facts: ObservedFact[];
  proposals: Proposal[];
  subjects: string[];
}

/** The subjects of a host: the MACs of its live interfaces, its live addresses and its name. */
export function hostSubjects(host: Host, interfaces: readonly Interface[], addresses: readonly Address[]): string[] {
  const macs = interfaces.filter((i) => !i.meta.deleted && i.mac).map((i) => i.mac as string);
  const ips = addresses.filter((a) => !a.meta.deleted).map((a) => a.ip);
  return [...new Set([...macs, ...ips, host.name])];
}

export function HostObservations(props: { host: Host; interfaces: readonly Interface[]; addresses: readonly Address[] }) {
  const names = useSourceNames();
  const subjects = createMemo(() => hostSubjects(props.host, props.interfaces, props.addresses), undefined, {
    equals: (a, b) => a.length === b.length && a.every((x, i) => x === b[i]),
  });

  const live = createLiveQuery<HostPicture>({
    topics: ["discovery", "ipam"],
    relevant: (e) => e.topic === "discovery" || isProposalEvent(e),
    debounceMs: 400,
    fetch: async (signal) => {
      const list = subjects();
      const [pictures, proposals] = await Promise.all([
        Promise.all(list.map((s) => getSubject(s, signal))),
        listProposals({ subject: props.host.id, state: ["open"] }, signal),
      ]);
      const byKey = new Map<string, ObservedFact>();
      for (const p of pictures) for (const f of p?.facts ?? []) byKey.set(`${f.source_key}|${f.subject_key}`, f);
      const facts = [...byKey.values()].sort((a, b) => {
        const ca = isCurrent(a);
        const cb = isCurrent(b);
        if (ca !== cb) return ca ? -1 : 1;
        return a.last_seen < b.last_seen ? 1 : a.last_seen > b.last_seen ? -1 : 0;
      });
      return { value: { facts, proposals, subjects: list.filter((_, i) => pictures[i] !== null) } };
    },
  });

  // Another interface or address of the host changes what to look up.
  createEffect(on(subjects, () => live.refetch(), { defer: true }));

  const picture = () => live.latest();
  const newest = () => picture()?.facts[0];
  const ports = () => [...new Set((picture()?.facts ?? []).flatMap((f) => (f.observed.type === "services" && isCurrent(f) ? f.observed.data.open_tcp : [])))].sort((a, b) => a - b);
  const os = () =>
    [
      ...new Set(
        (picture()?.facts ?? []).flatMap((f) =>
          f.observed.type === "os" ? [`${f.observed.data.guess} (${f.observed.data.confidence} %)`] : f.observed.type === "host" && f.observed.data.os ? [f.observed.data.os] : [],
        ),
      ),
    ];

  return (
    <div class="host-obs" data-testid="host-observations-body">
      <Show when={live.value.error}>
        <ErrorNotice error={live.value.error} />
      </Show>
      <Show when={picture()} fallback={<Show when={!live.value.error}><p class="muted" role="status">{t("common.loading")}</p></Show>}>
        {(p) => (
          <>
            <Show when={p().proposals.length > 0}>
              <ul class="proposal-list" data-testid="host-proposals">
                <For each={p().proposals}>
                  {(proposal) => (
                    <li data-testid="host-proposal" data-id={proposal.id}>
                      <KindBadge kind={proposal.kind} />
                      <A href={paths.proposal(proposal.id)}>{ruleText(proposal)}</A>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
            <Show when={p().facts.length > 0} fallback={<p class="muted">{t("hosts.observations.empty")}</p>}>
              <div class="host-obs-summary" data-testid="host-observations-summary">
                <div>
                  <span class="k">{t("discovery.col.last_seen")}</span>
                  <span>
                    <TimeAgo at={newest()?.last_seen} />{" "}
                    <span class="muted">{newest() ? sourceText(newest()!.source, names()) : ""}</span>
                  </span>
                </div>
                <div>
                  <span class="k">{t("discovery.subject.ports")}</span>
                  <span class="mono" data-testid="host-open-ports">
                    {ports().length > 0 ? ports().join(", ") : "–"}
                  </span>
                </div>
                <div>
                  <span class="k">{t("discovery.subject.os")}</span>
                  <span data-testid="host-os">{os().length > 0 ? formatList(os()) : "–"}</span>
                </div>
              </div>
              <FactTable facts={p().facts} names={names()} links label={t("hosts.observations.title")} />
            </Show>
            <Show when={p().subjects.length > 0}>
              <p class="muted host-obs-links">
                {t("hosts.observations.open")}{" "}
                <For each={p().subjects}>
                  {(s, i) => (
                    <>
                      {i() > 0 ? ", " : ""}
                      <A href={paths.observation(s)} data-testid="host-observation-link" data-key={s}>
                        {/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(s) ? <Mac value={s} /> : s}
                      </A>
                    </>
                  )}
                </For>
              </p>
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}
