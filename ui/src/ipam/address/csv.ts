// CSV of selected addresses in the import vocabulary (MIG-14), the same format as the
// server's `GET /exports/addresses.csv` (crates/tenko-ipam/src/export): UTF-8 with a byte
// order mark, comma separated, CRLF line ends, tags joined with "; ", cells that a
// spreadsheet would read as a formula protected with a leading quote. The whole-VRF export
// is the server's; this one covers a selection from a grid.
import type { AddressRow } from "../../api/types";

export const ADDRESS_COLUMNS = [
  "address",
  "vrf",
  "status",
  "dns_name",
  "host",
  "interface",
  "mac",
  "duid",
  "description",
  "tags",
] as const;

/** The UTF-8 byte order mark, so spreadsheet programs open the file as UTF-8. */
const BOM = String.fromCharCode(0xfeff);
const FORMULA = /^'*[=+\-@\t\r]/;

/** Protects a cell against formula evaluation; a negative integer stays a number. */
export function protectCell(cell: string): string {
  if (/^-\d+$/.test(cell)) return cell;
  return FORMULA.test(cell) ? `'${cell}` : cell;
}

/** One CSV field: quoted when it holds a comma, a quote or a line break. */
export function csvField(cell: string): string {
  const safe = protectCell(cell);
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/** A CSV document with a byte order mark and CRLF line ends. */
export function toCsv(header: readonly string[], rows: readonly (readonly string[])[]): string {
  const lines = [header, ...rows].map((row) => row.map(csvField).join(","));
  return `${BOM}${lines.join("\r\n")}\r\n`;
}

/** The rows of `addresses` (read with `expand=host`) in the import vocabulary. */
export function addressesCsv(addresses: readonly AddressRow[], vrfName: (id: string) => string): string {
  const rows = addresses.map((a) => [
    a.ip,
    vrfName(a.vrf),
    a.status,
    a.dns_name ?? "",
    a.host?.name ?? "",
    a.interface_detail?.name ?? "",
    a.interface_detail?.mac ?? "",
    a.interface_detail?.duid ?? "",
    a.meta.description ?? "",
    (a.meta.tags ?? []).join("; "),
  ]);
  return toCsv(ADDRESS_COLUMNS, rows);
}
