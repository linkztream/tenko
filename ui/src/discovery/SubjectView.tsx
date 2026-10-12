// The picture of one subject across sources (/discovery/observations/<subject>): a MAC
// address, an IP address or a name (docs/reconciliation.md, section 2.5). The computed summary
// (first and last sighting, addresses, names, operating systems, open ports, attachments), the
// intent that matches, the proposals about it, every fact per source and the last sightings of
// the matching intent. Live on the `discovery` topic, and on proposal changes of `ipam`.
import { A, useParams } from "@solidjs/router";
import { For, Match, Show, Switch } from "solid-js";
import { createLiveQuery } from "../api/live";
import { decodeSegment, paths } from "../app/paths";
import { Addr, Mac } from "../components/Addr";
import { ErrorNotice, Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { Tags, TimeAgo } from "../grid/cells";
import { formatList, t } from "../i18n";
import { getSubject, listProposals, type Proposal, type SubjectView as Picture } from "./api";
import { KindBadge, StateBadge } from "./columns";
import { DiscoveryNav } from "./DiscoveryNav";
import { FactTable } from "./FactTable";
import { isProposalEvent, ruleText, sourceKeyText, subjectKind, type SourceNames } from "./model";
import { ObjectLink, useSourceNames } from "./refs";
import "./discovery.css";

interface Loaded {
  picture: Picture | null;
  proposals: Proposal[];
}

export default function SubjectView() {
  const params = useParams<{ subject: string }>();
  const subject = () => decodeSegment(params.subject).trim();
  const names = useSourceNames();

  const live = createLiveQuery<Loaded>({
    topics: ["discovery", "ipam"],
    relevant: (e) => e.topic === "discovery" || isProposalEvent(e),
    debounceMs: 400,
    fetch: async (signal) => {
      const value = subject();
      const [picture, proposals] = await Promise.all([getSubject(value, signal), listProposals({ subject: value }, signal)]);
      // Open proposals first, then the newest.
      proposals.sort((a, b) => (a.state === "open") === (b.state === "open") ? (a.created < b.created ? 1 : -1) : a.state === "open" ? -1 : 1);
      return { value: { picture, proposals }, revision: picture?.revision };
    },
  });

  const latest = () => live.latest();

  const kindLabel = () => t(`discovery.subject.kind_${subjectKind(subject())}`);
  const title = () => {
    const kind = subjectKind(subject());
    return kind === "mac" ? <Mac value={subject()} /> : kind === "ip" ? <Addr value={subject()} /> : subject();
  };

  return (
    <div class="page subject-page" data-testid="page-discovery-subject" data-key={subject()}>
      <PageHead
        title={title()}
        sub={
          <Show when={latest()?.picture} fallback={kindLabel()}>
            {(p) => `${kindLabel()} · ${p().summary.current ? t("discovery.subject.current") : t("discovery.subject.not_current")}`}
          </Show>
        }
        crumbs={<A href={paths.observations()}>{t("discovery.nav.observations")}</A>}
      />
      <DiscoveryNav />
      <div class="page-body wide">
        <Switch>
          <Match when={live.value.error}>
            <ErrorNotice error={live.value.error} />
          </Match>
          <Match when={latest() === undefined}>
            <p class="muted" role="status">
              {t("common.loading")}
            </p>
          </Match>
          <Match when={latest()}>
            {(loaded) => (
              <>
                <Show when={!loaded().picture}>
                  <Notice kind="info" testid="subject-unknown">
                    {t("discovery.subject.unknown", { subject: subject() })}
                  </Notice>
                </Show>
                <Show when={loaded().picture}>
                  {(p) => <PictureCards picture={p()} proposals={loaded().proposals} names={names()} />}
                </Show>
                <Show when={!loaded().picture && loaded().proposals.length > 0}>
                  <ProposalsCard proposals={loaded().proposals} />
                </Show>
              </>
            )}
          </Match>
        </Switch>
      </div>
    </div>
  );
}

function Values(props: { values: readonly (string | number)[]; mono?: boolean; testid: string }) {
  return (
    <Show when={props.values.length > 0} fallback={<span class="muted">–</span>}>
      <span class="value-list" data-testid={props.testid}>
        <For each={props.values}>{(v) => <span class={props.mono ? "mono" : undefined}>{String(v)}</span>}</For>
      </span>
    </Show>
  );
}

function PictureCards(props: { picture: Picture; proposals: Proposal[]; names: SourceNames }) {
  const s = () => props.picture.summary;
  // A summary without these members (an older server) has none.
  const tls = () => s().tls_tcp ?? [];
  const vendors = () => s().vendors ?? [];
  const intent = () => props.picture.intent;
  const intentRefs = () => [
    ...intent().hosts.map((id) => ({ kind: "host" as const, id })),
    ...intent().interfaces.map((id) => ({ kind: "interface" as const, id })),
    ...intent().addresses.map((id) => ({ kind: "address" as const, id })),
  ];
  return (
    <>
      <div class="subject-cards">
        <section class="card subject-card" aria-labelledby="subject-summary" data-testid="subject-summary">
          <h2 id="subject-summary">
            {t("discovery.subject.summary")}
            <span class="aside">{s().current ? t("discovery.subject.current") : t("discovery.subject.not_current")}</span>
          </h2>
          <dl class="kv">
            <dt>{t("discovery.col.first_seen")}</dt>
            <dd>
              <TimeAgo at={s().first_seen} />
            </dd>
            <dt>{t("discovery.col.last_seen")}</dt>
            <dd>
              <TimeAgo at={s().last_seen} />
            </dd>
            <dt>{t("discovery.subject.sources")}</dt>
            <dd>
              <Values values={s().sources.map((k) => sourceKeyText(k, props.names))} testid="subject-sources" />
            </dd>
            <dt>{t("discovery.subject.macs")}</dt>
            <dd>
              <Values values={s().macs} mono testid="subject-macs" />
            </dd>
            <dt>{t("discovery.subject.ips")}</dt>
            <dd>
              <Values values={s().ips} mono testid="subject-ips" />
            </dd>
            <dt>{t("discovery.subject.names")}</dt>
            <dd>
              <Values values={s().names} testid="subject-names" />
            </dd>
            <dt>{t("discovery.subject.os")}</dt>
            <dd>
              <Values values={s().os} testid="subject-os" />
            </dd>
            <dt>{t("discovery.subject.ports")}</dt>
            <dd>
              <Values values={s().open_tcp} mono testid="subject-ports" />
            </dd>
            <Show when={tls().length > 0}>
              <dt>{t("discovery.subject.tls")}</dt>
              <dd>
                <Values values={tls()} mono testid="subject-tls" />
              </dd>
            </Show>
            <Show when={vendors().length > 0}>
              <dt>{t("discovery.subject.vendors")}</dt>
              <dd>
                <Values values={vendors()} testid="subject-vendors" />
              </dd>
            </Show>
            <Show when={s().platforms.length > 0}>
              <dt>{t("discovery.subject.platforms")}</dt>
              <dd>{formatList(s().platforms)}</dd>
            </Show>
            <Show when={s().parents.length > 0}>
              <dt>{t("discovery.subject.parents")}</dt>
              <dd>{formatList(s().parents)}</dd>
            </Show>
            <Show when={s().tags.length > 0}>
              <dt>{t("discovery.subject.tags")}</dt>
              <dd>
                <Tags tags={s().tags} />
              </dd>
            </Show>
          </dl>
          <Show when={s().attachments.length > 0}>
            <h3 class="sub-h">{t("discovery.subject.attachments")}</h3>
            <ul class="proposal-list" data-testid="subject-attachments">
              <For each={s().attachments}>
                {(a) => (
                  <li data-key={a.source}>
                    <Mac value={a.mac} />
                    <span>
                      {[a.device, a.port ? t("discovery.fact.port", { port: a.port }) : null, a.ssid ? t("discovery.fact.ssid", { ssid: a.ssid }) : null]
                        .filter(Boolean)
                        .join(", ")}
                    </span>
                    <Show when={a.vlan != null}>
                      <span class="tag">{t("discovery.subject.vlan", { vlan: a.vlan ?? 0 })}</span>
                    </Show>
                    <span class="muted">{sourceKeyText(a.source, props.names)}</span>
                    <TimeAgo at={a.last_seen} />
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </section>

        <section class="card subject-card" aria-labelledby="subject-intent" data-testid="subject-intent">
          <h2 id="subject-intent">{t("discovery.subject.intent")}</h2>
          <Show when={intentRefs().length > 0} fallback={<p class="muted">{t("discovery.subject.no_intent")}</p>}>
            <ul class="proposal-list">
              <For each={intentRefs()}>
                {(o) => (
                  <li>
                    <ObjectLink object={o} />
                  </li>
                )}
              </For>
            </ul>
          </Show>
          <Show when={props.picture.sightings.length > 0}>
            <h3 class="sub-h">{t("discovery.subject.sightings")}</h3>
            <ul class="proposal-list" data-testid="subject-sightings">
              <For each={props.picture.sightings}>
                {(sg) => (
                  <li>
                    <ObjectLink object={sg.object} />
                    <TimeAgo at={sg.sighting.at} />
                    <span class="muted">{sourceKeyText(sg.sighting.source, props.names)}</span>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </section>

        <ProposalsCard proposals={props.proposals} />
      </div>

      <section class="page-section" aria-labelledby="subject-facts" data-testid="subject-facts">
        <h2 id="subject-facts">
          {t("discovery.subject.facts")}
          <span class="aside">{t("discovery.subject.fact_count", { count: props.picture.facts.length })}</span>
        </h2>
        <FactTable facts={props.picture.facts} names={props.names} label={t("discovery.subject.facts")} />
      </section>
    </>
  );
}

function ProposalsCard(props: { proposals: Proposal[] }) {
  return (
    <section class="card subject-card" aria-labelledby="subject-proposals" data-testid="subject-proposals">
      <h2 id="subject-proposals">{t("discovery.subject.proposals")}</h2>
      <Show when={props.proposals.length > 0} fallback={<p class="muted">{t("discovery.subject.no_proposals")}</p>}>
        <ul class="proposal-list">
          <For each={props.proposals}>
            {(p) => (
              <li data-testid="subject-proposal" data-id={p.id}>
                <KindBadge kind={p.kind} />
                <A href={paths.proposal(p.id)} data-testid="subject-proposal-link">{ruleText(p)}</A>
                <StateBadge state={p.state} />
              </li>
            )}
          </For>
        </ul>
      </Show>
    </section>
  );
}
