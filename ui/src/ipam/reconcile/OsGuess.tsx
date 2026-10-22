// The operating system field of the reconciliation view: the guess, how sure the source is, and
// which source and truth it comes from. Used by the rows and by the host page.
import { t } from "../../i18n";
import type { OsField } from "./model";
import { TRUTH_WORD } from "./model";

export function OsGuess(props: { os: OsField }) {
  return (
    <span class="reconcile-os" data-testid="reconcile-os" data-source={props.os.source}>
      <span data-testid="reconcile-os-guess">{t("ipam.reconcile.os_guess", { guess: props.os.guess, confidence: props.os.confidence })}</span>{" "}
      <span class="muted" data-testid="reconcile-os-source">
        {t("ipam.reconcile.os_source", { source: props.os.source, truth: t(TRUTH_WORD[props.os.truth]) })}
      </span>
    </span>
  );
}
