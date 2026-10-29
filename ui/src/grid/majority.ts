// The "majority in the header" rule of the data grid (design/README.md, principle 7: aggregate
// before you repeat). A column that names the value of its cells (`Column.majority`) and whose
// rows all share one value says it once, in its header, and its cells stay empty; the DNS cache
// says "State · all insecure" instead of a badge on every row. Pure, so the rule is tested
// without a grid.
import type { Column } from "./types";

/** Fewest rows for which the header speaks for the column: one row says it in its own cell. */
export const MAJORITY_MIN_ROWS = 2;

/**
 * The value each column with a majority rule shares across `rows`, by column id. A column is
 * left out when fewer than {@link MAJORITY_MIN_ROWS} rows are given, when one row has no value,
 * or when two rows differ.
 */
export function columnMajorities<T>(columns: readonly Column<T>[], rows: readonly T[]): ReadonlyMap<string, string> {
  const out = new Map<string, string>();
  if (rows.length < MAJORITY_MIN_ROWS) return out;
  for (const column of columns) {
    const of = column.majority;
    if (!of) continue;
    let shared: string | undefined;
    let same = true;
    for (const row of rows) {
      const value = of(row);
      if (value === undefined || value === "" || (shared !== undefined && value !== shared)) {
        same = false;
        break;
      }
      shared = value;
    }
    if (same && shared !== undefined) out.set(column.id, shared);
  }
  return out;
}
