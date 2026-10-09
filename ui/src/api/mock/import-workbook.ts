// The canned workbook the mock answers with for an xlsx, xls or ods upload, built after
// docs/plans/import-fixtures.md: ten sheets in the documentation ranges (RFC 5737 and RFC 3849)
// with invented names and test passwords. It carries every pattern the importer must handle
// and every loss report entry of rule 6:
//
//   Index          network list without a header; one single address; one empty sheet listed
//   192.0.2.0      pre-filled list of the /24 (255 rows), a login that is a model string
//   203.0.113.0    125 rows, sparse names, text in the IP column, a stray value in column E,
//                  a range cell and an IPv6 cell (both added, marked in their labels)
//   192.0.2.64     the network address used as a host address, one row with credentials
//   198.51.100.0   device layout: Nic1 to Nic4, one device with four NICs in four networks
//   192.0.2.128    no header row; the roles come from the layout of the other sheets
//   192.0.2.9      a single host named after its address, a numeric password
//   203.0.113.128  a network that Index does not list
//   192.0.2.192    another one, with one row
//   198.51.100.128 an empty sheet (Index lists it)
import { EMPTY_CELL, numberCell, textCell, type Cell, type Sheet } from "./import-cells";

/**
 * The VRF the canned workbook suggests importing into: its sheets describe the documentation
 * ranges the seeded IPAM state uses too, and a supernet over a network with ranges cannot be
 * planned there, so the suggestion keeps the preview applicable. Clearing the option imports
 * into the default VRF and shows the plan error.
 */
export const CANNED_VRF = "ip-plan";

type Value = string | Cell | null;

/** A row of cells from texts; null is an empty cell. */
function row(...values: Value[]): Cell[] {
  return values.map((v) => (v === null ? EMPTY_CELL : typeof v === "string" ? textCell(v) : v));
}

const HEADER = ["IP", "Beteckning", "Login", "Pass"] as const;

/** Name, login and password of a row of a pre-filled list. */
type Entry = readonly [name: string, login?: string, pass?: string];

function prefilled(
  name: string,
  header: readonly string[],
  count: number,
  base: string,
  entries: Readonly<Record<number, Entry>>,
): Sheet {
  const rows: Cell[][] = [row(...header)];
  for (let n = 1; n <= count; n += 1) {
    const [label, login, pass] = entries[n] ?? [];
    rows.push(row(`${base}.${n}`, label ?? null, login ?? null, pass ?? null));
  }
  return { name, rows };
}

const NETWORK_GEAR: Readonly<Record<number, Entry>> = {
  1: ["fw-main", "admin", "test-pass-fw"],
  2: ["SW_Rack", "HP v1810-48G"],
  4: ["SW_Attic"],
  5: ["Unifi Cloud Key", "ubnt", "test-pass-uck"],
  6: ["ap-hall"],
  7: ["ap-garage"],
  8: ["hyper1"],
  10: ["proxmox", "root", "test-pass-pve"],
  11: ["proxmox2"],
  12: ["hyper3"],
  14: ["dir01", "administrator", "test-pass-dir"],
  15: ["dir02"],
  16: ["files"],
  18: ["MX-9200"],
  20: ["ups41"],
  21: ["printer-lab"],
  22: ["backup-nas"],
  24: ["Wifi Controller Attic"],
  30: ["cam-recorder"],
  40: ["lab-pi"],
};

const SERVERS: Readonly<Record<number, Entry>> = {
  2: ["dc-a1"],
  4: ["dc-a2"],
  20: ["store7"],
  21: ["store8"],
  90: ["cam-nvr"],
};

function indexSheet(): Sheet {
  return {
    name: "Index",
    rows: [
      row("192.0.2.0/24", "Network gear, hypervisors"),
      row("203.0.113.0/24", "Servers"),
      row("192.0.2.64/26", "NAS"),
      row("198.51.100.0/26", "Alarm"),
      row("192.0.2.128/26", "DHCP"),
      row("192.0.2.9", "Management host"),
      row("198.51.100.128/26", "Printers"),
    ],
  };
}

function serversSheet(): Sheet {
  // 122 address rows, then a range cell, one more address and an IPv6 cell: 125 rows.
  const sheet = prefilled("203.0.113.0", HEADER, 122, "203.0.113", SERVERS);
  const rows = sheet.rows;
  // A text value where an address belongs; the row keeps a name.
  rows[50] = row("n/a", "old-switch", null, null);
  // A stray value in a column without a header.
  rows[8] = row("203.0.113.8", null, null, null, "rack B2");
  rows.push(row("203.0.113.123-124", "Spare range (added)"));
  rows.push(row("203.0.113.125"));
  rows.push(row("2001:db8::10", "v6-test"));
  return sheet;
}

/** The workbook as a fresh list of sheets (the importer never changes them). */
export function cannedWorkbook(): Sheet[] {
  return [
    indexSheet(),
    prefilled("192.0.2.0", HEADER, 255, "192.0.2", NETWORK_GEAR),
    serversSheet(),
    {
      name: "192.0.2.64",
      rows: [
        row(...HEADER),
        // The network address of the /26 used as a host address.
        row("192.0.2.64", "DS1819", "admin", "test-pass-nas"),
        row("192.0.2.65", "nas-backup"),
        row("192.0.2.66", "nas-media"),
        row("192.0.2.67", "nas-archive"),
        row("192.0.2.68", "nas-test"),
      ],
    },
    {
      name: "198.51.100.0",
      rows: [
        row("Enhet", "Nic1", "Nic2", "Nic3", "Nic4", "login", "pass"),
        // One device, four NICs, four networks (198.51.100.67 lies in no known network).
        row("fw-edge", "198.51.100.3", "198.51.100.67", "203.0.113.3", "192.0.2.3", "admin", "test-pass-edge"),
        row("nvr-1", "198.51.100.10"),
        row("alarm-panel", "198.51.100.11", null, null, null, "installer", "test-pass-alarm"),
        row("siren-1", "198.51.100.12"),
      ],
    },
    {
      // No header row: the first row is data.
      name: "192.0.2.128",
      rows: [
        row("192.0.2.130", "idrac - host1", "root", "test-pass-idrac"),
        row("192.0.2.131", "idrac - host2", "root", "test-pass-idrac"),
      ],
    },
    {
      name: "192.0.2.9",
      // A spreadsheet stored the password as a number.
      rows: [row(...HEADER), row("192.0.2.9", "files-mgmt", "admin", numberCell("4711"))],
    },
    {
      name: "203.0.113.128",
      rows: [
        row("IP", "Beteckning"),
        row("203.0.113.129", "dmz-web1"),
        row("203.0.113.130", "dmz-web2"),
        row("203.0.113.131", "dmz-db"),
        row("203.0.113.132", "dmz-mail"),
      ],
    },
    {
      name: "192.0.2.192",
      rows: [row(...HEADER), row("192.0.2.193", "Wifi Controller Hall")],
    },
    { name: "198.51.100.128", rows: [] },
  ];
}
