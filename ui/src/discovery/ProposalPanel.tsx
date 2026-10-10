// One proposal, docked beside the inbox (/discovery/<id>): what the reconciler suggests and
// why, the evidence (one line per observation behind it), the suggested change as the plan the
// planner would run, and the decision. Approve opens the plan dialog (dry run, acknowledge,
// apply); reject asks for an optional reason; a conflict cannot be approved and is dismissed
// once its cause is resolved. The panel follows the `ipam` topic, so a decision made elsewhere
// or a newer proposal that supersedes this one shows up at once.
import { A } from "@solidjs/router";
import { createResource, For, Match, onCleanup, onMount, Show, Switch } from "solid-js";
import { createLiveQuery } from "../api/live";
import { paths } from "../app/paths";
import { Addr, Mac } from "../components/Addr";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { ErrorNotice, Notice } from "../components/Notice";
import { PrincipalLabel } from "../components/Principal";
import { TimeAgo } from "../grid/cells";
import { t, tDynamic } from "../i18n";
import { PlanPreview } from "../ipam/plan/PlanPreview";
import { isTyping } from "../shell/keyboard";
import { approveProposal, getProposal, type Proposal } from "./api";
import { KindBadge, SeverityBadge, StateBadge } from "./columns";
import { canApprove, isOpen, ruleText, sourceText, type SourceNames } from "./model";
import { ObjectLink, PrefixRef } from "./refs";

export interface ProposalPanelProps {
  id: string;
  names: SourceNames;
  /** Whether this person may decide proposals (administrators and operators). */
  decider: boolean;
  onApprove: (proposal: Proposal) => void;
  onReject: (proposal: Proposal) => void;
  onClose: () => void;
}

export function ProposalPanel(props: ProposalPanelProps) {
  const live = createLiveQuery<Proposal>({
    topics: ["ipam"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => o.kind === "proposal" && o.id === props.id),
    fetch: async (signal) => {
      const p = await getProposal(props.id, signal);
      return { value: p, revision: p.revision };
    },
  });
  // `latest` rethrows the error of a failed read; the error is shown below instead.
  const proposal = () => (live.value.error ? undefined : live.value.latest);

  // The suggested change as the planner would run it now: a dry run of the approval. Read
  // once per revision, and only for a person who may approve.
  const [plan] = createResource(
    () => {
      const p = proposal();
      return p && props.decider && canApprove(p) ? { id: p.id, revision: p.revision } : false;
    },
    (p) => approveProposal(p, { dryRun: true, acknowledge: [] }),
  );

  // A and R decide the proposal in view; Esc closes the panel. Never while typing or in a dialog.
  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || isTyping(e) || e.ctrlKey || e.metaKey || e.altKey) return;
      if (document.querySelector("[aria-modal='true']")) return;
      const p = proposal();
      if (!p) return;
      const key = e.key.toLowerCase();
      if (key === "a" && props.decider && canApprove(p)) {
        e.preventDefault();
        props.onApprove(p);
      } else if (key === "r" && props.decider && isOpen(p)) {
        e.preventDefault();
        props.onReject(p);
      }
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  return (
    <aside
      class="panel proposal-panel"
      aria-label={t("discovery.panel.label")}
      data-testid="proposal-panel"
      data-id={props.id}
      onKeyDown={(e) => {
        if (e.key === "Escape" && !document.querySelector("[aria-modal='true']")) {
          e.stopPropagation();
          props.onClose();
        }
      }}
    >
      <Show
        when={proposal()}
        fallback={
          <div class="panel-body section">
            <Show when={live.value.error} fallback={<p class="muted" role="status">{t("common.loading")}</p>}>
              <ErrorNotice error={live.value.error} />
            </Show>
            <button type="button" class="btn" onClick={() => props.onClose()}>
              {t("common.action.close")}
            </button>
          </div>
        }
      >
        {(p) => (
          <>
            <div class="panel-head">
              <div class="grow">
                <div class="proposal-badges">
                  <KindBadge kind={p().kind} />
                  <SeverityBadge severity={p().severity} />
                  <StateBadge state={p().state} />
                </div>
                <h2 data-testid="proposal-summary">{ruleText(p())}</h2>
                <div class="meta">
                  {t("discovery.panel.opened", { rule: p().rule })} <TimeAgo at={p().created} />
                </div>
              </div>
              <div class="acts">
                <button type="button" class="icon-btn" aria-label={t("common.action.close")} title={t("common.action.close")} onClick={() => props.onClose()}>
                  <Icon name="x" />
                </button>
              </div>
            </div>
            <div class="panel-body">
              <Show when={props.decider && isOpen(p())}>
                <div class="section proposal-actions">
                  <Show
                    when={p().kind !== "conflict"}
                    fallback={<Notice kind="info">{t("discovery.panel.conflict_hint")}</Notice>}
                  >
                    <Show when={(p().commands?.length ?? 0) === 0}>
                      <Notice kind="info">{t("discovery.panel.nothing_hint")}</Notice>
                    </Show>
                  </Show>
                  <div class="row-actions">
                    <Show when={canApprove(p())}>
                      <button type="button" class="btn primary" data-testid="discovery-approve" onClick={() => props.onApprove(p())}>
                        <Icon name="check" />
                        {t("discovery.action.approve")}
                        <Kbd keys={["A"]} />
                      </button>
                    </Show>
                    <button type="button" class="btn" data-testid="discovery-reject" onClick={() => props.onReject(p())}>
                      <Icon name="x" />
                      {p().kind === "conflict" ? t("discovery.action.dismiss") : t("discovery.action.reject")}
                      <Kbd keys={["R"]} />
                    </button>
                  </div>
                </div>
              </Show>

              <Show when={p().adoption_error}>
                {(code) => (
                  <div class="section">
                    <Notice kind="warn" testid="proposal-adoption-error">
                      {t("discovery.panel.adoption_failed", { error: tDynamic(`errors.${code()}`) ?? code() })}
                    </Notice>
                  </div>
                )}
              </Show>

              <section class="section" aria-labelledby="proposal-subject">
                <h3 id="proposal-subject">{t("discovery.panel.subject")}</h3>
                <dl class="kv">
                  <Show when={p().subject.mac}>
                    {(mac) => (
                      <>
                        <dt>{t("discovery.panel.mac")}</dt>
                        <dd>
                          <A href={paths.observation(mac())} data-testid="proposal-subject-link">
                            <Mac value={mac()} />
                          </A>
                        </dd>
                      </>
                    )}
                  </Show>
                  <Show when={p().subject.ip}>
                    {(ip) => (
                      <>
                        <dt>{t("discovery.panel.ip")}</dt>
                        <dd>
                          <A href={paths.observation(ip())}>
                            <Addr value={ip()} />
                          </A>
                        </dd>
                      </>
                    )}
                  </Show>
                  <Show when={p().subject.cidr}>
                    {(cidr) => (
                      <>
                        <dt>{t("discovery.panel.network")}</dt>
                        <dd>
                          <Addr value={cidr()} />
                        </dd>
                      </>
                    )}
                  </Show>
                  <Show when={p().subject.name}>
                    {(name) => (
                      <>
                        <dt>{t("discovery.panel.name")}</dt>
                        <dd>{name()}</dd>
                      </>
                    )}
                  </Show>
                  <Show when={p().subject.prefix}>
                    {(prefix) => (
                      <>
                        <dt>{t("discovery.panel.prefix")}</dt>
                        <dd>
                          <PrefixRef id={prefix()} />
                        </dd>
                      </>
                    )}
                  </Show>
                  <Show when={(p().subject.objects?.length ?? 0) > 0}>
                    <dt>{t("discovery.panel.intent")}</dt>
                    <dd class="obj-list">
                      <For each={p().subject.objects ?? []}>{(o) => <ObjectLink object={o} />}</For>
                    </dd>
                  </Show>
                </dl>
              </section>

              <section class="section" aria-labelledby="proposal-evidence">
                <h3 id="proposal-evidence">
                  {t("discovery.panel.evidence")}
                  <span class="more muted">{t("discovery.panel.evidence_count", { count: p().evidence.length })}</span>
                </h3>
                <Show when={p().evidence.length > 0} fallback={<p class="muted">{t("discovery.panel.no_evidence")}</p>}>
                  <ul class="evidence-list" aria-label={t("discovery.panel.evidence")}>
                    <For each={p().evidence}>
                      {(e, i) => (
                        <li data-testid="evidence" data-index={i()} data-key={e.source_key}>
                          <strong>{sourceText(e.source, props.names)}</strong>
                          <span class="evidence-seen">
                            <Show when={e.mac}>{(mac) => <Mac value={mac()} />}</Show>
                            <Show when={e.ip}>{(ip) => <Addr value={ip()} />}</Show>
                            <Show when={e.name}>{(name) => <span class="muted">{name()}</span>}</Show>
                          </span>
                          <span class="muted evidence-times">
                            {t("discovery.panel.first_seen")} <TimeAgo at={e.first_seen} /> · {t("discovery.panel.last_seen")} <TimeAgo at={e.last_seen} /> ·{" "}
                            {t("discovery.panel.sightings", { count: e.sightings ?? 1 })}
                          </span>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </section>

              <section class="section" aria-labelledby="proposal-change" data-testid="proposal-change">
                <h3 id="proposal-change">{t("discovery.panel.change")}</h3>
                <Switch>
                  <Match when={(p().commands?.length ?? 0) === 0}>
                    <p class="muted">{p().kind === "conflict" ? t("discovery.panel.change_conflict") : t("discovery.panel.change_none")}</p>
                  </Match>
                  <Match when={!isOpen(p()) || !props.decider}>
                    <p class="muted">{t("discovery.panel.change_count", { count: p().commands?.length ?? 0 })}</p>
                  </Match>
                  <Match when={plan.error}>
                    <ErrorNotice error={plan.error} />
                  </Match>
                  <Match when={plan()}>
                    {(d) => (
                      <PlanPreview
                        plan={d().plan}
                        warnings={d().warnings.map((w) => ({ ...w, requires_ack: false }))}
                        acknowledged={new Set()}
                        onAcknowledge={() => undefined}
                      />
                    )}
                  </Match>
                  <Match when={plan.loading}>
                    <p class="muted" role="status">
                      {t("ipam.plan.previewing")}
                    </p>
                  </Match>
                </Switch>
              </section>

              <Show when={!isOpen(p())}>
                <section class="section" aria-labelledby="proposal-decision" data-testid="proposal-decision">
                  <h3 id="proposal-decision">{t("discovery.panel.decision")}</h3>
                  <dl class="kv">
                    <dt>{t("discovery.col.state")}</dt>
                    <dd>
                      <StateBadge state={p().state} />
                    </dd>
                    <Show when={p().decided}>
                      {(d) => (
                        <>
                          <dt>{t("discovery.panel.decided_by")}</dt>
                          <dd>
                            <PrincipalLabel principal={d().by} /> <TimeAgo at={d().at} />
                          </dd>
                        </>
                      )}
                    </Show>
                    <Show when={p().adopted_by}>
                      {(prefix) => (
                        <>
                          <dt>{t("discovery.panel.adopted_by")}</dt>
                          <dd>
                            <PrefixRef id={prefix()} />
                          </dd>
                        </>
                      )}
                    </Show>
                    <Show when={p().reason}>
                      {(reason) => (
                        <>
                          <dt>{t("discovery.panel.reason")}</dt>
                          <dd class="proposal-reason">{reason()}</dd>
                        </>
                      )}
                    </Show>
                    <Show when={p().superseded_by}>
                      {(next) => (
                        <>
                          <dt>{t("discovery.panel.superseded_by")}</dt>
                          <dd>
                            <A href={paths.proposal(next())} data-testid="proposal-superseded-by">
                              {t("discovery.panel.newer")}
                            </A>
                          </dd>
                        </>
                      )}
                    </Show>
                    <Show when={(p().results?.length ?? 0) > 0}>
                      <dt>{t("discovery.panel.results")}</dt>
                      <dd class="obj-list">
                        <For each={p().results ?? []}>{(o) => <ObjectLink object={o} />}</For>
                      </dd>
                    </Show>
                  </dl>
                </section>
              </Show>
            </div>
          </>
        )}
      </Show>
    </aside>
  );
}
