import { si, siTitle } from "../app/format/si";
import { locale } from "../i18n";

/**
 * A number that can grow, with an SI suffix and at most three significant digits
 * (982, 1.0K, 48K, 1.3M); the exact value is in the tooltip (design decision 12).
 */
export function Si(props: { value: number | null | undefined; unit?: string; class?: string }) {
  return (
    <span class={props.class ?? "num"} title={siTitle(props.value, locale(), props.unit)}>
      {si(props.value, locale())}
    </span>
  );
}
