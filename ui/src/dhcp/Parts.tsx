// Small pieces of the DHCP views: the state notices (the API is not built, the module is
// switched off), a form field with its error line, and the field errors of a refused request.
import { A } from "@solidjs/router";
import { Match, Show, Switch, type JSX } from "solid-js";
import { ApiError, errorMessage } from "../api/problem";
import { paths } from "../app/paths";
import { ErrorNotice, Notice } from "../components/Notice";
import { t } from "../i18n";

/** The server has no DHCP service (501). */
export function notBuilt(err: unknown): boolean {
  return err instanceof ApiError && err.status === 501;
}

/** The DHCP module is switched off: the server registers no route, or runs no configuration service. */
export function moduleOff(err: unknown): boolean {
  return err instanceof ApiError && ((err.status === 404 && err.code === "sys.route_not_found") || err.code === "dhcp.module.disabled");
}

/** Whether an error means the DHCP service cannot be used at all (the page shows a notice, no actions). */
export function unavailable(err: unknown): boolean {
  return notBuilt(err) || moduleOff(err);
}

/** The notice for an error of a DHCP read: not available, switched off, or the error itself. */
export function DhcpProblem(props: { error: unknown }) {
  return (
    <Switch fallback={<ErrorNotice error={props.error} />}>
      <Match when={notBuilt(props.error)}>
        <Notice kind="info" role="status" title={t("dhcp.state.not_built_title")} testid="dhcp-not-built">
          {t("dhcp.state.not_built_body")}
        </Notice>
      </Match>
      <Match when={moduleOff(props.error)}>
        <Notice kind="warn" role="status" title={t("dhcp.state.off_title")} testid="dhcp-off">
          {t("dhcp.state.off_body")}{" "}
          <A href={paths.settings()} data-testid="dhcp-modules-link">
            {t("dhcp.state.off_link")}
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
      <label for={`dhcp-f-${props.id}`}>{props.label}</label>
      {props.children}
      <Show when={props.error}>
        <span class="help bad" id={`dhcp-f-${props.id}-error`} data-testid="field-error" data-field={props.id}>
          {props.error}
        </span>
      </Show>
      <Show when={props.help && !props.error}>
        <span class="help" id={`dhcp-f-${props.id}-help`}>
          {props.help}
        </span>
      </Show>
    </div>
  );
}

/** The `aria-describedby` of a field's control. */
export function describedBy(id: string, error: string | undefined, help?: string): string | undefined {
  if (error) return `dhcp-f-${id}-error`;
  return help ? `dhcp-f-${id}-help` : undefined;
}

/** A checkbox with its label, the way the forms of the area write a switch. */
export function Check(props: { id: string; label: string; checked: boolean; onChange: (on: boolean) => void; disabled?: boolean | undefined; help?: string | undefined }) {
  return (
    <div class="field">
      <label class="choice">
        <input
          type="checkbox"
          id={`dhcp-f-${props.id}`}
          checked={props.checked}
          disabled={props.disabled}
          aria-describedby={props.help ? `dhcp-f-${props.id}-help` : undefined}
          data-testid={`field-${props.id}`}
          onChange={(e) => props.onChange(e.currentTarget.checked)}
        />{" "}
        <span>{props.label}</span>
      </label>
      <Show when={props.help}>
        <span class="help" id={`dhcp-f-${props.id}-help`}>
          {props.help}
        </span>
      </Show>
    </div>
  );
}

/**
 * The fields a refused request names, by the field the server names (`name`, `matches[0]`,
 * `lease.default_secs`), with the translated message of the refusal. A refusal that names no field
 * gives an empty record and the view shows it at the top.
 */
export function fieldErrors(err: unknown): Record<string, string> {
  if (!(err instanceof ApiError)) return {};
  const out: Record<string, string> = {};
  for (const e of err.fieldErrors) out[e.field] = errorMessage(err);
  const field = err.params.field;
  if (field && /\.(invalid)$/.test(err.code)) out[field] = errorMessage(err);
  return out;
}

/**
 * Whether a refusal names a field the form shows (`lease` covers `lease.min_secs`, `matches` covers
 * `matches[2]`). A refusal that names none is shown at the top, so it never goes unseen.
 */
export function hasField(fields: Readonly<Record<string, string>>, shown: readonly string[]): boolean {
  return Object.keys(fields).some((key) => shown.some((name) => key === name || key.startsWith(`${name}.`) || key.startsWith(`${name}[`)));
}

/** The message for a form field: an error of the server named `name` or one of its parts (`lease.min_secs` for `lease`). */
export function errorFor(errors: Readonly<Record<string, string>>, name: string): string | undefined {
  const direct = errors[name];
  if (direct) return direct;
  const key = Object.keys(errors).find((k) => k.startsWith(`${name}.`) || k.startsWith(`${name}[`));
  return key ? errors[key] : undefined;
}
