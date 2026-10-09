// Accessibility checks with axe-core for component tests (WCAG 2.1 A and AA rules).
// jsdom cannot compute colors or layout, so color contrast is left to the token
// validation of the design (design/README.md) and to browser tests.
import axe from "axe-core";

export interface AxeOptions {
  /** Extra rule ids to switch off for this check, with a reason in the test. */
  disable?: readonly string[];
}

/** Runs axe on `root` and returns readable violations ("rule: target" lines). */
export async function axeViolations(root: Element = document.body, options: AxeOptions = {}): Promise<string[]> {
  const rules: Record<string, { enabled: boolean }> = { "color-contrast": { enabled: false } };
  for (const id of options.disable ?? []) rules[id] = { enabled: false };
  const result = await axe.run(root, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules,
    resultTypes: ["violations"],
  });
  return result.violations.flatMap((v) => v.nodes.map((n) => `${v.id}: ${n.target.join(" ")} (${v.help})`));
}
