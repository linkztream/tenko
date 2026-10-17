// Small pieces of the DNS views: the state notices (the API is not built yet, the module is
// switched off), a form field with its error line, the chips of a zone and of an origin, the
// translated words, the field errors of a refused request, and the download of a text file.
import { A } from "@solidjs/router";
import { Match, Show, Switch, type JSX } from "solid-js";
import { ApiError, errorMessage } from "../api/problem";
import { paths } from "../app/paths";
import { ErrorNotice, Notice } from "../components/Notice";
import { t } from "../i18n";
import type { Origin, Zone, ZoneKind } from "./api";
import { isReverse, servedNow, type CheckCode } from "./model";

/** The server has no DNS service yet (501, WP4.2 builds it). */
export function notBuilt(err: unknown): boolean {
  return err instanceof ApiError && err.status === 501;
}

/** The DNS module is switched off: the server does not register the routes. */
export function moduleOff(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404 && err.code === "sys.route_not_found";
}

/** Whether an error means the DNS service cannot be used at all (the page shows a notice, no actions). */
export function unavailable(err: unknown): boolean {
  return notBuilt(err) || moduleOff(err);
}

/** The notice for an error of a DNS read: not built yet, switched off, or the error itself. */
export function DnsProblem(props: { error: unknown }) {
  return (
    <Switch fallback={<ErrorNotice error={props.error} />}>
      <Match when={notBuilt(props.error)}>
        <Notice kind="info" role="status" title={t("dns.state.not_built_title")} testid="dns-not-built">
          {t("dns.state.not_built_body")}
        </Notice>
      </Match>
      <Match when={moduleOff(props.error)}>
        <Notice kind="warn" role="status" title={t("dns.state.off_title")} testid="dns-off">
          {t("dns.state.off_body")}{" "}
          <A href={paths.settings()} data-testid="dns-modules-link">
            {t("dns.state.off_link")}
          </A>
        </Notice>
      </Match>
    </Switch>
  );
}

/** A labelled control with its error line (`field-error` with `data-field`) or its help. */
export function Field(props: { id: string; label: string; error?: string | undefined; help?: string | undefined; children: JSX.Element }) {
  return (
    <div class="field">
      <label for={`dns-f-${props.id}`}>{props.label}</label>
      {props.children}
      <Show when={props.error}>
        <span class="help bad" id={`dns-f-${props.id}-error`} data-testid="field-error" data-field={props.id}>
          {props.error}
        </span>
      </Show>
      <Show when={props.help && !props.error}>
        <span class="help" id={`dns-f-${props.id}-help`}>
          {props.help}
        </span>
      </Show>
    </div>
  );
}

/** The `aria-describedby` of a field's control. */
export function describedBy(id: string, error: string | undefined, help?: string): string | undefined {
  if (error) return `dns-f-${id}-error`;
  return help ? `dns-f-${id}-help` : undefined;
}

export function kindWord(kind: ZoneKind): string {
  return t(`dns.kind.${kind}`);
}

export function originWord(origin: Origin): string {
  return t(`dns.origin.${origin}`);
}

export function checkMessage(code: CheckCode): string {
  return t(`dns.check.${code}`);
}

/** The kind of a zone with its serving state: secondary and stub zones are not served yet. */
export function ZoneChips(props: { zone: Pick<Zone, "kind" | "name" | "reverse_of"> }) {
  return (
    <span class="dns-chips">
      <span class="tag" data-testid="zone-kind" data-kind={props.zone.kind}>
        {kindWord(props.zone.kind)}
      </span>
      <Show when={isReverse(props.zone)}>
        <span class="tag accent" data-testid="zone-reverse">
          {t("dns.zone.reverse")}
        </span>
      </Show>
      <Show when={!servedNow(props.zone.kind)}>
        <span class="tag discrepancy" data-testid="zone-not-served" title={t("dns.zone.not_served_hint")}>
          {t("dns.zone.not_served")}
        </span>
      </Show>
    </span>
  );
}

/** The origin of an RRset; anything but manual is shown as owned by its writer. */
export function OriginTag(props: { origin: Origin }) {
  return (
    <span class={props.origin === "manual" ? "tag" : "tag proposal"} data-testid="rrset-origin" data-kind={props.origin}>
      {originWord(props.origin)}
    </span>
  );
}

/** The request fields a refusal names, with the translated message (a zone, an ACL, a key). */
export function fieldErrors(err: unknown): Record<string, string> {
  if (!(err instanceof ApiError)) return {};
  const out: Record<string, string> = {};
  for (const e of err.fieldErrors) out[e.field] = errorMessage(err);
  const field =
    err.code === "dns.zone.exists" || err.code === "dns.key.exists"
      ? "name"
      : err.code === "dns.zone.invalid"
        ? err.params.field
        : err.code === "sys.invalid_value"
          ? err.params.name
          : undefined;
  if (field) out[field] = errorMessage(err);
  return out;
}

/** Offers a text as a file download. */
export function downloadText(name: string, text: string, type = "text/dns"): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
