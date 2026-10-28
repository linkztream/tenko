import { afterEach, describe, expect, it } from "vitest";
import { paths } from "../app/paths";
import { setLocale } from "../i18n";
import { findingAction, findingEvidence, findingGlyph, findingKindWord, findingSubject, type Finding, type FindingKind } from "./findingWords";

afterEach(async () => {
  await setLocale("en");
});

function finding(part: Partial<Finding> & Pick<Finding, "kind">): Finding {
  return {
    id: "proposal:p-1",
    action: "none",
    area: "ipam",
    code: "ipam.reconcile.discovered_mac",
    evidence: { id: "p-1", path: "/proposals/p-1" },
    severity: "review",
    since: "2026-10-14T12:00:00Z",
    source: "proposal",
    subject: { kind: "address", label: "192.0.2.10" },
    summary: "the server's one-line summary",
    ...part,
  };
}

describe("findingGlyph", () => {
  it("gives the octagon to a conflict, the jobs glyph to a waiting job and the triangle to an alarm or a health condition", () => {
    expect(findingGlyph("conflict")).toBe("conflict");
    expect(findingGlyph("job_waiting")).toBe("jobs");
    expect(findingGlyph("utilization")).toBe("alert");
    expect(findingGlyph("health")).toBe("alert");
  });

  it("gives every other kind the proposal glyph", () => {
    const others: FindingKind[] = ["unknown_device", "orphaned_record", "orphaned_address", "ptr_mismatch", "intent_differs", "outside_prefixes", "vlan", "host_name", "dns", "ghost", "scan_artifact"];
    for (const kind of others) expect(findingGlyph(kind)).toBe("proposal");
  });
});

describe("findingKindWord", () => {
  it("names the kind in a word", () => {
    expect(findingKindWord("conflict")).toBe("Conflict");
    expect(findingKindWord("health")).toBe("Health");
  });
});

describe("findingSubject", () => {
  it("gives none for a health condition", () => {
    expect(findingSubject(finding({ kind: "health", subject: { kind: "node", label: "node.disk.low" } }))).toBeNull();
  });

  it("gives an address, a prefix and a device in the data font", () => {
    expect(findingSubject(finding({ kind: "conflict", subject: { kind: "address", label: "192.0.2.10" } }))).toEqual({ text: "192.0.2.10", mono: true });
    expect(findingSubject(finding({ kind: "utilization", subject: { kind: "prefix", label: "198.51.100.0/24" } }))).toEqual({ text: "198.51.100.0/24", mono: true });
    expect(findingSubject(finding({ kind: "unknown_device", subject: { kind: "device", label: "00:00:5e:00:53:01" } }))).toEqual({ text: "00:00:5e:00:53:01", mono: true });
  });

  it("gives a record or a host name in the text font", () => {
    expect(findingSubject(finding({ kind: "orphaned_record", subject: { kind: "record", label: "printer.example.test" } }))).toEqual({ text: "printer.example.test", mono: false });
    expect(findingSubject(finding({ kind: "intent_differs", subject: { kind: "host", label: "printer.example.test" } }))).toEqual({ text: "printer.example.test", mono: false });
  });

  it("gives a waiting job its title in the text font", () => {
    const job = finding({
      kind: "job_waiting",
      source: "job",
      code: "backup.create",
      subject: { kind: "job", label: "backup.create" },
      params: { job_kind: "backup.create", title: "jobs.title.backup.create", step: "2" },
    });
    expect(findingSubject(job)).toEqual({ text: "Create a backup", mono: false });
  });

  it("gives a waiting job with a title nobody translates the title as it is", () => {
    const job = finding({
      kind: "job_waiting",
      source: "job",
      code: "custom.kind",
      subject: { kind: "job", label: "custom.kind" },
      params: { job_kind: "custom.kind", title: "Move the printers", step: "0" },
    });
    expect(findingSubject(job)).toEqual({ text: "Move the printers", mono: false });
  });
});

describe("findingEvidence", () => {
  it("joins the MAC addresses of a conflict with a middle dot, in the data font", () => {
    const conflict = finding({ kind: "conflict", params: { macs: "00:00:5e:00:53:01, 00:00:5e:00:53:02" } });
    expect(findingEvidence(conflict)).toEqual({ text: "00:00:5e:00:53:01 · 00:00:5e:00:53:02", mono: true });
  });

  it("splits MAC addresses written without a space after the comma", () => {
    const conflict = finding({ kind: "conflict", params: { macs: "00:00:5e:00:53:01,00:00:5e:00:53:02,00:00:5e:00:53:03" } });
    expect(findingEvidence(conflict).text).toBe("00:00:5e:00:53:01 · 00:00:5e:00:53:02 · 00:00:5e:00:53:03");
  });

  it("falls back to the summary for a conflict without MAC addresses", () => {
    expect(findingEvidence(finding({ kind: "conflict" }))).toEqual({ text: "the server's one-line summary", mono: false });
  });

  it("names the share and the threshold of an alarm", () => {
    const alarm = finding({ kind: "utilization", source: "alarm", params: { percent: "92.4", threshold: "90" } });
    expect(findingEvidence(alarm)).toEqual({ text: "92.4 % in use, alarm at 90 %", mono: false });
  });

  it("names only the share of an alarm without a threshold", () => {
    const alarm = finding({ kind: "utilization", source: "alarm", params: { percent: "15.2" } });
    expect(findingEvidence(alarm).text).toBe("15.2 % in use");
  });

  it("rounds the share to one decimal in the language of the page", () => {
    const alarm = finding({ kind: "utilization", source: "alarm", params: { percent: "92.449", threshold: "90" } });
    expect(findingEvidence(alarm).text).toBe("92.4 % in use, alarm at 90 %");
  });

  it("says which step a job waits at, counting from one", () => {
    const job = finding({ kind: "job_waiting", source: "job", params: { step: "2" } });
    expect(findingEvidence(job)).toEqual({ text: "Step 3 waits for a person", mono: false });
  });

  it("says step 1 for a job whose step is missing", () => {
    expect(findingEvidence(finding({ kind: "job_waiting", source: "job" })).text).toBe("Step 1 waits for a person");
  });

  it("says how much room a low disk has, from the byte parameters", () => {
    const disk = finding({ kind: "health", source: "health", code: "node.disk.low", params: { available: "8000000000", total: "120000000000" } });
    expect(findingEvidence(disk)).toEqual({ text: "The data directory has 8 GB of 120 GB free", mono: false });
  });

  it("falls back to the summary for a low disk without the byte parameters", () => {
    const disk = finding({ kind: "health", source: "health", code: "node.disk.low", params: {} });
    expect(findingEvidence(disk).text).toBe("the server's one-line summary");
  });

  it("falls back to the summary for a health code the page has no words for", () => {
    const unknown = finding({ kind: "health", source: "health", code: "sys.unheard.of", params: { detail: "x" } });
    expect(findingEvidence(unknown)).toEqual({ text: "the server's one-line summary", mono: false });
  });

  it("gives the summary for any other kind", () => {
    expect(findingEvidence(finding({ kind: "ghost" }))).toEqual({ text: "the server's one-line summary", mono: false });
  });
});

describe("findingAction", () => {
  it("resolves a conflict of a proposal in the discovery view of that proposal", () => {
    const action = findingAction(finding({ kind: "conflict", action: "resolve", source: "proposal", evidence: { id: "p-17", path: "/proposals/p-17" } }));
    expect(action).toEqual({ label: "Resolve conflict", href: "/discovery/p-17" });
    expect(action?.href).toBe(paths.proposal("p-17"));
  });

  it("resolves a conflict of the reconciliation view in the reconciliation view", () => {
    const action = findingAction(finding({ kind: "conflict", action: "resolve", source: "reconcile", evidence: { id: "r-1", path: "/reconcile/r-1" } }));
    expect(action?.href).toBe("/ipam/reconcile");
  });

  it("opens the manual step of a job in the job's page", () => {
    const action = findingAction(finding({ kind: "job_waiting", action: "open_manual_step", source: "job", evidence: { id: "job-9", path: "/jobs/job-9" } }));
    expect(action?.href).toBe("/jobs/job-9");
    expect(action?.href).toBe(paths.job("job-9"));
  });

  it("opens the prefix of an alarm at its path, with the VRF when there is one", () => {
    const subject = { kind: "prefix" as const, label: "198.51.100.0/24", cidr: "198.51.100.0/24" };
    const plain = findingAction(finding({ kind: "utilization", action: "open_prefix", source: "alarm", subject }));
    expect(plain?.href).toBe(paths.prefix("198.51.100.0/24"));
    const inVrf = findingAction(finding({ kind: "utilization", action: "open_prefix", source: "alarm", subject: { ...subject, vrf: "vrf-lab" } }));
    expect(inVrf?.href).toBe(paths.prefix("198.51.100.0/24", "vrf-lab"));
  });

  it("opens the address space for an alarm whose subject has no network", () => {
    const action = findingAction(finding({ kind: "utilization", action: "open_prefix", source: "alarm", subject: { kind: "prefix", label: "x" } }));
    expect(action?.href).toBe(paths.ipam());
  });

  it("reviews an adopt, a decision, a record deletion and a PTR fix in the proposal", () => {
    for (const kind of ["adopt", "decide", "delete_record", "fix_ptr"] as const) {
      const action = findingAction(finding({ kind: "unknown_device", action: kind, evidence: { id: "p-3", path: "/proposals/p-3" } }));
      expect(action).toEqual({ label: "Review", href: "/discovery/p-3" });
    }
  });

  it("opens the host of a host subject, and the proposal for any other subject", () => {
    const host = findingAction(finding({ kind: "intent_differs", action: "open_host", subject: { kind: "host", label: "printer.example.test" } }));
    expect(host?.href).toBe(paths.host("printer.example.test"));
    const other = findingAction(finding({ kind: "intent_differs", action: "open_host", evidence: { id: "p-4", path: "/proposals/p-4" } }));
    expect(other?.href).toBe("/discovery/p-4");
  });

  it("words decommissioning differently from opening a host", () => {
    const subject = { kind: "host" as const, label: "printer.example.test" };
    const open = findingAction(finding({ kind: "ghost", action: "open_host", subject }));
    const decommission = findingAction(finding({ kind: "ghost", action: "decommission", subject }));
    expect(decommission?.href).toBe(open?.href);
    expect(decommission?.label).not.toBe(open?.label);
  });

  it("opens the page of the area of a health condition", () => {
    const status = (area: Finding["area"]) => findingAction(finding({ kind: "health", source: "health", action: "open_status", area }));
    expect(status("nodes")?.href).toBe("/nodes");
    expect(status("connectors")?.href).toBe("/connectors");
    expect(status("dns")?.href).toBe("/dns");
    expect(status("dhcp")?.href).toBe("/dhcp");
    expect(status("ipam")?.href).toBe("/ipam");
    expect(status("settings")?.href).toBe("/settings");
    expect(status("jobs")?.href).toBe("/settings");
  });

  it("gives no action for a finding that names none", () => {
    expect(findingAction(finding({ kind: "scan_artifact", action: "none" }))).toBeNull();
  });
});
