// The editor of a match on a client request (vendor class with exact or prefix, user class, MAC
// pattern, client identifier, circuit-id, remote-id, architecture code, host name with exact or
// prefix): `MatchRow` is one match, `MatchList` the rows of a class with "Add a match". The class
// and the terms of a policy share them.
import { For, Index, Show } from "solid-js";
import { Icon } from "../../components/Icon";
import { t } from "../../i18n";
import { emptyMatch, hasPrefix, MATCH_KINDS, type MatchDraft, type MatchKind, type MatchProblem } from "../model";

/** The translated message of a local check of a match. */
export function matchProblem(problem: MatchProblem): string {
  return t(`dhcp.check.match_${problem}`);
}

export function MatchRow(props: {
  id: string;
  value: MatchDraft;
  onChange: (next: MatchDraft) => void;
  disabled?: boolean | undefined;
  error?: string | undefined;
  onRemove?: (() => void) | undefined;
  /** The accessible name of the row ("Match 2"). */
  label: string;
}) {
  return (
    <div class="dhcp-match" role="group" aria-label={props.label} data-testid="match-row" data-kind={props.value.kind}>
      <select
        class="select"
        aria-label={t("dhcp.match.kind_label")}
        value={props.value.kind}
        disabled={props.disabled}
        data-testid="match-kind"
        onChange={(e) => props.onChange({ ...emptyMatch(e.currentTarget.value as MatchKind), value: "" })}
      >
        <For each={MATCH_KINDS}>{(kind) => <option value={kind}>{t(`dhcp.match.kind.${kind}`)}</option>}</For>
      </select>
      <input
        id={`dhcp-f-${props.id}`}
        class="input mono"
        aria-label={t("dhcp.match.value_label")}
        placeholder={t(`dhcp.match.example.${props.value.kind}`)}
        value={props.value.value}
        disabled={props.disabled}
        spellcheck={false}
        aria-invalid={props.error ? "true" : undefined}
        aria-describedby={props.error ? `dhcp-f-${props.id}-error` : undefined}
        data-testid="match-value"
        onInput={(e) => props.onChange({ ...props.value, value: e.currentTarget.value })}
      />
      <Show when={hasPrefix(props.value.kind)}>
        <label class="choice">
          <input
            type="checkbox"
            checked={props.value.prefix}
            disabled={props.disabled}
            data-testid="match-prefix"
            onChange={(e) => props.onChange({ ...props.value, prefix: e.currentTarget.checked })}
          />{" "}
          <span>{t("dhcp.match.prefix")}</span>
        </label>
      </Show>
      <Show when={props.onRemove && !props.disabled}>
        <button type="button" class="icon-btn" aria-label={t("dhcp.match.remove", { label: props.label })} data-testid="match-remove" onClick={() => props.onRemove?.()}>
          <Icon name="trash" />
        </button>
      </Show>
      <Show when={props.error}>
        <span class="help bad dhcp-match-error" id={`dhcp-f-${props.id}-error`} data-testid="field-error" data-field={props.id}>
          {props.error}
        </span>
      </Show>
    </div>
  );
}

/** The matches of a class: at least one, any of them holds. */
export function MatchList(props: {
  value: readonly MatchDraft[];
  onChange: (next: MatchDraft[]) => void;
  disabled?: boolean | undefined;
  errors?: Readonly<Record<number, string>> | undefined;
}) {
  const replace = (index: number, next: MatchDraft) => props.onChange(props.value.map((m, i) => (i === index ? next : m)));
  return (
    <div class="dhcp-matches" data-testid="match-list">
      {/* By position, so that typing in a row does not rebuild it. */}
      <Index each={props.value}>
        {(match, i) => (
          <MatchRow
            id={`match-${i}`}
            label={t("dhcp.match.row", { n: i + 1 })}
            value={match()}
            disabled={props.disabled}
            error={props.errors?.[i]}
            onChange={(next) => replace(i, next)}
            onRemove={props.value.length > 1 ? () => props.onChange(props.value.filter((_, j) => j !== i)) : undefined}
          />
        )}
      </Index>
      <Show when={!props.disabled}>
        <button type="button" class="btn" data-testid="match-add" onClick={() => props.onChange([...props.value, emptyMatch()])}>
          <Icon name="plus" />
          {t("dhcp.match.add")}
        </button>
      </Show>
    </div>
  );
}
