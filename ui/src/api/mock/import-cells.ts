// Cells, sheets and files of an upload (crates/tenko-ipam/src/import/read/mod.rs). A reader
// keeps the geometry of the source: rows[0] is row 1 and rows[r][0] is column A, so every
// location of the loss report points at the cell the person sees.

export type CellKind = "empty" | "text" | "number";

/** One cell: its kind and its text, trimmed; an empty cell has no text. */
export interface Cell {
  kind: CellKind;
  text: string;
}

export interface Sheet {
  name: string;
  /** From row 1, each from column A; ragged; trailing empty rows removed. */
  rows: Cell[][];
}

export type SourceFormat = "csv" | "xlsx" | "xls" | "ods";

/** How a CSV file was decoded. */
export interface TextInfo {
  encoding: string;
  bom: boolean;
  delimiter: string;
}

export interface SourceFile {
  name: string;
  format: SourceFormat;
  size: number;
  sheets: Sheet[];
  text?: TextInfo;
  /** The mock answered with the canned workbook (it cannot unpack a spreadsheet). */
  canned?: boolean;
}

export const EMPTY_CELL: Cell = { kind: "empty", text: "" };

export function textCell(text: string): Cell {
  const trimmed = text.trim();
  return trimmed === "" ? EMPTY_CELL : { kind: "text", text: trimmed };
}

export function numberCell(text: string): Cell {
  const trimmed = text.trim();
  return trimmed === "" ? EMPTY_CELL : { kind: "number", text: trimmed };
}

/** The text of a cell, null when it is empty. */
export function cellValue(cell: Cell | undefined): string | null {
  return cell && cell.kind !== "empty" && cell.text !== "" ? cell.text : null;
}

export function isBlank(cell: Cell | undefined): boolean {
  return cellValue(cell) === null;
}

/** The number of columns of the widest row. */
export function sheetWidth(sheet: Sheet): number {
  return sheet.rows.reduce((width, row) => Math.max(width, row.length), 0);
}

/** The cell at a 0-based row and column, empty outside the data. */
export function sheetCell(sheet: Sheet, row: number, column: number): Cell {
  return sheet.rows[row]?.[column] ?? EMPTY_CELL;
}

export function sheetIsEmpty(sheet: Sheet): boolean {
  return sheet.rows.every((row) => row.every(isBlank));
}

/** The letter of a 0-based column (0 is A, 26 is AA). */
export function columnLetter(column: number): string {
  let n = column + 1;
  let letters = "";
  while (n > 0) {
    const rem = (n - 1) % 26;
    letters = String.fromCharCode(65 + rem) + letters;
    n = Math.floor((n - 1) / 26);
  }
  return letters;
}

/** The 0-based index of a column letter, null for anything else. */
export function columnIndex(letter: string): number | null {
  if (letter.length === 0 || letter.length > 3 || !/^[A-Za-z]+$/.test(letter)) return null;
  let n = 0;
  for (const c of letter.toUpperCase()) n = n * 26 + (c.charCodeAt(0) - 64);
  return n - 1;
}

/** One sheet of an import with its unique name. */
export interface SheetRef {
  name: string;
  file: SourceFile;
  sheet: Sheet;
}

/** Unique sheet names across the files: a name that repeats gets ` (2)`, ` (3)`. */
export function sheetNames(files: readonly SourceFile[]): string[] {
  const seen = new Map<string, number>();
  const names: string[] = [];
  for (const file of files) {
    for (const sheet of file.sheets) {
      const count = (seen.get(sheet.name) ?? 0) + 1;
      seen.set(sheet.name, count);
      names.push(count === 1 ? sheet.name : `${sheet.name} (${count})`);
    }
  }
  return names;
}

export function sheetRefs(files: readonly SourceFile[]): SheetRef[] {
  const names = sheetNames(files);
  const refs: SheetRef[] = [];
  let index = 0;
  for (const file of files) {
    for (const sheet of file.sheets) {
      refs.push({ name: names[index] as string, file, sheet });
      index += 1;
    }
  }
  return refs;
}
