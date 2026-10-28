// The finding chip (design/README.md, component inventory): the glyph of a severity, a count and
// one word, as a link to the findings of that severity. Act now and Review carry their severity
// color; Info is plain ink, listed but never counted as a problem (ui-plan section 2.3).
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import type { FindingLevel } from "../shell/findings";
import { Icon, type IconName } from "./Icon";
import "./finding.css";

const GLYPH: Partial<Record<FindingLevel, IconName>> = { act: "conflict", review: "proposal" };

export function FindingChip(props: {
  level: FindingLevel;
  /** The text with its count ("1 act now", "5 to review"). */
  text: string;
  href: string;
  title?: string;
  testid?: string;
  class?: string;
}) {
  return (
    <A
      class={`finding-chip ${props.level}${props.class ? ` ${props.class}` : ""}`}
      href={props.href}
      title={props.title}
      data-level={props.level}
      data-testid={props.testid}
    >
      <Show when={GLYPH[props.level]}>{(glyph) => <Icon name={glyph()} size="sm" />}</Show>
      {props.text}
    </A>
  );
}
