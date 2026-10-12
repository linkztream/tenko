// The scope of a grant or of a scoped token grant (IAM-01): a VRF, a site or a prefix, with or
// without what lies below it, or (for a token) the whole installation. The kind is a radio
// group, the object a select over the catalog, the subtree a check box; the picker reports a
// rule only once an object is chosen, and `null` for the whole installation.
import { createMemo, createSignal, For, Show, untrack } from "solid-js";
import { t } from "../../i18n";
import type { ScopeCatalog } from "./data";
import { GRANTABLE_KINDS, makeRule, ruleId, ruleSubtree, type GrantableKind, type ScopeRule } from "./model";

type Choice = GrantableKind | "everything";

interface Option {
  id: string;
  label: string;
}

/** The objects of one kind as select options: VRFs and sites by name, prefixes by VRF and network. */
export function scopeOptions(kind: GrantableKind, catalog: ScopeCatalog | undefined): Option[] {
  if (!catalog) return [];
  switch (kind) {
    case "vrf":
      return catalog.vrfs.map((v) => ({ id: v.id, label: v.name })).sort((a, b) => a.label.localeCompare(b.label));
    case "site":
      return catalog.sites.map((s) => ({ id: s.id, label: s.name })).sort((a, b) => a.label.localeCompare(b.label));
    case "prefix": {
      const vrfs = new Map(catalog.vrfs.map((v) => [v.id, v.name]));
      return catalog.prefixes
        .map((p) => ({ id: p.id, label: t("access.picker.prefix_option", { cidr: p.cidr, vrf: vrfs.get(p.vrf) ?? p.vrf }) }))
        .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
    }
  }
}

export function ScopePicker(props: {
  /** Prefix of the element ids, unique on the page. */
  id: string;
  catalog: ScopeCatalog | undefined;
  /** The rule to start from; `null` is the whole installation when `everything` is allowed. */
  initial?: ScopeRule | null | undefined;
  /** Offers "the whole installation" (a token grant without a scope). */
  everything?: boolean;
  onChange: (rule: ScopeRule | null | undefined) => void;
  /** The error of the field, from the server or the dialog's own check. */
  error?: string | undefined;
}) {
  const start = untrack(() => props.initial);
  const startKind: Choice =
    start && (start.kind === "vrf" || start.kind === "site" || start.kind === "prefix")
      ? start.kind
      : untrack(() => props.everything)
        ? "everything"
        : "prefix";
  const [kind, setKind] = createSignal<Choice>(startKind);
  const [object, setObject] = createSignal(start ? ruleId(start) : "");
  const [subtree, setSubtree] = createSignal(start ? ruleSubtree(start) : true);

  const options = createMemo(() => {
    const k = kind();
    return k === "everything" ? [] : scopeOptions(k, props.catalog);
  });
  const choices = (): Choice[] => (props.everything ? ["everything", ...GRANTABLE_KINDS] : [...GRANTABLE_KINDS]);

  // `undefined` while the rule is not complete, `null` for the whole installation.
  const report = () => {
    const k = kind();
    if (k === "everything") return props.onChange(null);
    const id = object();
    props.onChange(id ? makeRule(k, id, subtree()) : undefined);
  };

  const pickKind = (k: Choice) => {
    setKind(k);
    setObject("");
    report();
  };

  return (
    <div class="scope-picker" data-testid="scope-picker">
      <fieldset class="field">
        <legend class="label">{t("access.picker.kind")}</legend>
        <div class="segmented-choices" role="radiogroup" aria-label={t("access.picker.kind")}>
          <For each={choices()}>
            {(k) => (
              <label class="choice compact">
                <input
                  type="radio"
                  name={`${props.id}-kind`}
                  value={k}
                  checked={kind() === k}
                  onChange={() => pickKind(k)}
                  data-testid={`field-scope-kind-${k}`}
                />
                <span>{t(`access.picker.kind_${k}`)}</span>
              </label>
            )}
          </For>
        </div>
      </fieldset>

      <Show when={kind() !== "everything"}>
        <div class="field">
          <label for={`${props.id}-object`}>{t(`access.picker.object_${kind() as GrantableKind}`)}</label>
          <select
            id={`${props.id}-object`}
            class="select"
            data-testid="field-scope-object"
            aria-describedby={props.error ? `${props.id}-object-error` : undefined}
            aria-invalid={props.error ? "true" : undefined}
            onChange={(e) => {
              setObject(e.currentTarget.value);
              report();
            }}
          >
            <option value="" selected={object() === ""}>
              {t("access.picker.choose")}
            </option>
            <For each={options()}>
              {(o) => (
                <option value={o.id} selected={o.id === object()}>
                  {o.label}
                </option>
              )}
            </For>
          </select>
          <Show when={props.error}>
            <span class="help bad field-error" id={`${props.id}-object-error`}>
              {props.error}
            </span>
          </Show>
        </div>
        <Show when={kind() === "site" || kind() === "prefix"}>
          <label class="ackrow">
            <input
              type="checkbox"
              class="cb"
              checked={subtree()}
              data-testid="field-scope-subtree"
              onChange={(e) => {
                setSubtree(e.currentTarget.checked);
                report();
              }}
            />
            {kind() === "site" ? t("access.picker.subtree_site") : t("access.picker.subtree_prefix")}
          </label>
        </Show>
      </Show>
    </div>
  );
}
