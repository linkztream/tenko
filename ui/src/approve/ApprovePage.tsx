// The approval of a takeover script (ADR 0038): the script on a Windows machine shows a code, an
// administrator signed in within the last five minutes types it here, reads what the script asks
// for and approves or denies it. Everything shown comes from the script's request except the
// source address, so every value renders as text, whole and wrapped, with the characters that
// could pose as another field replaced. The code is held in memory only, with the request.
import { useNavigate } from "@solidjs/router";
import { createSignal, For, onMount, Show, type JSX } from "solid-js";
import { api } from "../api/client";
import type { components } from "../api/generated/schema";
import { errorMessage, hasErrorMessage, isApiError } from "../api/problem";
import { paths } from "../app/paths";
import { signOut } from "../auth/session";
import { Notice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { formatDateTime, formatRelative, t } from "../i18n";
import "./approve.css";

type ApprovalView = components["schemas"]["ApprovalView"];
type PlanServer = components["schemas"]["PlanServer"];
/** A request found by its code, with the code that found it. */
type Found = { view: ApprovalView; code: string };

/** Refusals after which the request can no longer be decided. */
const FINAL = ["auth.approval.expired", "auth.approval.consumed", "auth.approval.denied", "auth.approval.not_found"];

/** A typed code as the server reads it (`canonical_code` in tenko-auth), `K7QD-M2XR-9FHA-T4WB`, or undefined. */
export function canonicalCode(typed: string): string | undefined {
  if (typed.length > 64) return undefined;
  // ASCII letters only: toUpperCase would turn ß or ı into letters the server never accepts.
  const chars = typed.replace(/[- ]/g, "").replace(/[a-z]/g, (c) => c.toUpperCase()).replace(/O/g, "0").replace(/[IL]/g, "1");
  return /^[0-9A-HJKMNP-TV-Z]{16}$/.test(chars) ? (chars.match(/.{4}/g) ?? []).join("-") : undefined;
}

/**
 * A value as text that cannot pose as another field: control, format (direction) and line or
 * paragraph separator characters become U+FFFD, and so does every combining mark past the second
 * on one character, so that stacked marks cannot draw over the rows around it.
 */
export function shown(value: string): string {
  return value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, "\uFFFD").replace(/(\p{M}{2})\p{M}+/gu, "$1\uFFFD");
}

/**
 * The text of a refusal, always one of the page's own (no pack replaces them): a code the page
 * has no words for gets its generic text, never a shared one.
 */
export function refusalText(err: unknown, denying = false): string {
  if (denying && isApiError(err, "auth.approval.consumed")) return t("approve.denied_late");
  const own = isApiError(err) && (err.is("auth.approval") || err.is("tls.no_internal_ca")) && hasErrorMessage(err.code);
  return own ? errorMessage(err) : t("approve.error.other");
}

function Value(props: { value: string }) {
  return <span class="mono">{shown(props.value)}</span>;
}

function List(props: { items: readonly string[] }) {
  return (
    <Show when={props.items.length > 0} fallback={t("approve.none")}>
      <ul class="ap-list">
        <For each={props.items}>
          {(item) => (
            <li>
              <Value value={item} />
            </li>
          )}
        </For>
      </ul>
    </Show>
  );
}

const named = (server: PlanServer) => `${server.name} (${server.address})`;

/** What the request asks for, in a fixed order (the test ids follow it). */
function Facts(props: { found: Found }) {
  const v = () => props.found.view;
  const plan = () => props.found.view.plan;
  const rows = (): [string, string, JSX.Element][] => [
    ["domain", t("approve.field.domain"), <Value value={plan().domain} />],
    ["code", t("approve.code.label"), <Value value={props.found.code} />],
    ["machine", t("approve.field.machine"), <Value value={v().reported.machine} />],
    ["user", t("approve.field.user"), <Value value={v().reported.user} />],
    ["version", t("approve.field.version"), <Value value={v().reported.version} />],
    ["source", t("approve.field.source"), <Value value={v().source} />],
    [
      "expires",
      t("approve.field.expires"),
      <>
        {formatDateTime(v().expires_at)} <span class="muted">({formatRelative(v().expires_at)})</span>
      </>,
    ],
    ["controllers", t("approve.field.controllers", { count: plan().controllers.length }), <List items={plan().controllers.map((c) => c.name)} />],
    ["zones", t("approve.field.zones", { count: plan().zones.length }), <List items={plan().zones} />],
    ["dhcp-servers", t("approve.field.dhcp_servers", { count: plan().dhcp_servers.length }), <List items={plan().dhcp_servers.map(named)} />],
    ["scopes", t("approve.field.scopes", { count: plan().scopes.length }), <List items={plan().scopes} />],
    ["mirror-host", t("approve.field.mirror_host"), <Value value={named(plan().mirror_host)} />],
    ["node-name", t("approve.field.node_name"), <Value value={`${plan().node_name}.${plan().domain}`} />],
    [
      "operations",
      t("approve.field.operations"),
      <ul class="ap-list">
        <For each={plan().operations}>{(op) => <li data-op={op}>{t(`approve.op.${op}`)}</li>}</For>
      </ul>,
    ],
    ["lifetime", t("approve.field.lifetime"), t("approve.lifetime")],
  ];
  return (
    <div class="card ap-facts">
      <dl class="kv">
        <For each={rows()}>
          {([id, label, value]) => (
            <>
              <dt data-testid={`approve-label-${id}`}>{label}</dt>
              <dd data-testid={`approve-${id}`}>{value}</dd>
            </>
          )}
        </For>
      </dl>
    </div>
  );
}

/** The answer to `auth.step_up_required`: sign in again and come back to this page. */
function StepUp() {
  const navigate = useNavigate();
  const signInAgain = async () => {
    await signOut();
    navigate(paths.signIn(paths.approve()), { replace: true });
  };
  return (
    <div data-testid="approve-step-up">
      <Notice kind="warn" role="alert" title={t("approve.step_up.title")}>
        <p>{t("approve.step_up.body")}</p>
        <button type="button" class="btn sm" data-testid="approve-sign-in-again" onClick={() => void signInAgain()}>
          {t("approve.step_up.sign_in")}
        </button>
      </Notice>
    </div>
  );
}

export default function ApprovePage() {
  const [typed, setTyped] = createSignal("");
  const [invalid, setInvalid] = createSignal(false);
  const [found, setFound] = createSignal<Found>();
  const [busy, setBusy] = createSignal(false);
  // A decision, or a refusal after which none is possible ("closed"): the buttons stay disabled.
  const [outcome, setOutcome] = createSignal<"approved" | "denied" | "closed">();
  const [error, setError] = createSignal<{ code: string | undefined; text: string }>();
  const [stepUp, setStepUp] = createSignal(false);
  let input!: HTMLInputElement;
  let heading!: HTMLHeadingElement;
  let result!: HTMLDivElement;
  onMount(() => input.focus());

  /** Runs one request in the busy state; false when it was refused. */
  const run = async (request: () => Promise<void>, denying = false): Promise<boolean> => {
    setBusy(true);
    setError(undefined);
    setStepUp(false);
    try {
      await request();
      return true;
    } catch (err) {
      if (isApiError(err, "auth.step_up_required")) setStepUp(true);
      else setError({ code: isApiError(err) ? err.code : undefined, text: refusalText(err, denying) });
      return false;
    } finally {
      setBusy(false);
    }
  };

  const lookUp = async (e: Event) => {
    e.preventDefault();
    const code = canonicalCode(typed());
    setInvalid(code === undefined);
    if (code === undefined || busy()) return;
    const ok = await run(async () => {
      setFound({ view: await api.post("/api/v1/auth/approvals/lookup", { body: { code } }), code });
    });
    if (ok) heading.focus();
    else input.focus();
  };

  const decide = async (approve: boolean) => {
    const current = found();
    if (!current || busy() || outcome()) return;
    const path = { id: current.view.id };
    const done = await run(async () => {
      if (approve) await api.post("/api/v1/auth/approvals/{id}/approve", { path, body: { code: current.code } });
      else await api.post("/api/v1/auth/approvals/{id}/deny", { path });
    }, !approve);
    if (done) setOutcome(approve ? "approved" : "denied");
    else if (FINAL.includes(error()?.code ?? "")) setOutcome("closed");
    result.focus();
  };

  const another = () => {
    setFound(undefined);
    setTyped("");
    setInvalid(false);
    setOutcome(undefined);
    setError(undefined);
    setStepUp(false);
    input.focus();
  };

  const locked = () => busy() || outcome() !== undefined;

  return (
    <div class="page" data-testid="page-approve">
      <PageHead title={t("approve.title")} />
      <div class="page-body">
        <p class="muted">{t("approve.lede")}</p>
        <div ref={result} tabIndex={-1} class="ap-result" data-testid="approve-result">
          <Show when={stepUp()}>
            <StepUp />
          </Show>
          <Show when={outcome() === "approved"}>
            <Notice kind="ok" role="status" testid="approve-approved" title={t("approve.approved.title")}>
              {t("approve.approved.body")}
            </Notice>
          </Show>
          <Show when={outcome() === "denied"}>
            <Notice kind="info" role="status" testid="approve-denied" title={t("approve.denied.title")}>
              {t("approve.denied.body")}
            </Notice>
          </Show>
          <Show when={error()}>
            {(e) => (
              <Notice kind="bad" role="alert" testid="error-notice" code={e().code}>
                {e().text}
              </Notice>
            )}
          </Show>
          <Show when={found() !== undefined && (outcome() !== undefined || error() !== undefined)}>
            <div class="form-row">
              <button type="button" class="btn sm" data-testid="approve-another" onClick={another}>
                {t("approve.action.another")}
              </button>
            </div>
          </Show>
        </div>
        <Show
          when={found()}
          keyed
          fallback={
            <form class="card ap-form" data-testid="approve-form" onSubmit={(e) => void lookUp(e)} novalidate>
              <div class="field">
                <label for="ap-code">{t("approve.code.label")}</label>
                <input
                  id="ap-code"
                  ref={input}
                  class="input mono"
                  type="text"
                  autocomplete="off"
                  autocapitalize="characters"
                  spellcheck={false}
                  maxlength={64}
                  data-testid="field-code"
                  aria-invalid={invalid() ? "true" : undefined}
                  aria-describedby="ap-code-help"
                  value={typed()}
                  onInput={(e) => setTyped(e.currentTarget.value)}
                />
                <span class={invalid() ? "help bad field-error" : "help"} id="ap-code-help">
                  {invalid() ? t("approve.code.invalid") : t("approve.code.hint")}
                </span>
              </div>
              <div class="form-row">
                <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
                  {t("approve.code.submit")}
                </button>
                <Show when={busy()}>
                  <span class="muted" role="status">
                    {t("approve.loading")}
                  </span>
                </Show>
              </div>
            </form>
          }
        >
          {(request) => (
            <section class="page-section" aria-labelledby="ap-domain" data-testid="approve-request">
              <h2 id="ap-domain" ref={heading} tabIndex={-1}>
                <Value value={request.view.plan.domain} />
              </h2>
              <Notice kind="warn" testid="approve-check">
                {t("approve.check")}
              </Notice>
              <Facts found={request} />
              <div class="form-row">
                <button type="button" class="btn" data-testid="approve-deny" disabled={locked()} onClick={() => void decide(false)}>
                  {t("approve.action.deny")}
                </button>
                <button type="button" class="btn primary" data-testid="approve-approve" disabled={locked()} onClick={() => void decide(true)}>
                  {t("approve.action.approve")}
                </button>
              </div>
            </section>
          )}
        </Show>
      </div>
    </div>
  );
}
