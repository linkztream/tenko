// Tests of scripts/label-catalog.mjs: the extraction of job kinds and audit actions from Rust
// source, and the completeness of the label catalog against the repository.
// Run with `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  auditUnit,
  catalogProblems,
  extractCodes,
  factsOf,
  jobUnit,
  matchArmNames,
  packUnits,
  scanRepository,
  stripRust,
  testRanges,
  unitsOf,
} from "./label-catalog.mjs";

/** The codes of one inline Rust file. */
function codesOf(source, file = "crates/tenko-x/src/lib.rs") {
  return extractCodes([{ file, source }]);
}

const sorted = (set) => [...set].sort();

describe("stripRust", () => {
  test("blanks comments and keeps the length and the line breaks", () => {
    const src = 'let a = "x"; // "no.code"\n/* "block.code" */ let b = 1;\n';
    const { code, masked } = stripRust(src);
    assert.equal(code.length, src.length);
    assert.equal(masked.length, src.length);
    assert.ok(!code.includes("no.code"));
    assert.ok(!code.includes("block.code"));
    assert.ok(code.includes('"x"'));
    assert.equal(code.split("\n").length, src.split("\n").length);
  });

  test("blanks the contents of strings and characters in the masked copy only", () => {
    const { code, masked } = stripRust(`let s = "a{b"; let c = '{'; let l: &'static str = r#"}"#;`);
    assert.ok(code.includes('"a{b"'));
    assert.ok(!masked.includes("a{b"));
    assert.equal([...masked].filter((c) => c === "{").length, 0);
    assert.equal([...masked].filter((c) => c === "}").length, 0);
  });
});

describe("testRanges", () => {
  test("covers a cfg(test) module, function and declaration", () => {
    const src = "fn a() {}\n#[cfg(test)]\nmod tests { fn x() { { } } }\n#[cfg(test)] mod more;\nfn b() {}\n";
    const { masked } = stripRust(src);
    const ranges = testRanges(masked);
    assert.equal(ranges.length, 2);
    const text = ranges.map(([from, to]) => src.slice(from, to));
    assert.ok(text[0].startsWith("#[cfg(test)]\nmod tests"));
    assert.ok(text[0].endsWith("}"));
    assert.ok(text[1].endsWith("mod more;"));
  });
});

describe("job kinds", () => {
  test("finds a literal and a constant resolved by name", () => {
    const found = codesOf(`
      pub const EDIT_JOB: &str = "demo.edit";
      fn a() { let _ = JobKind::from_static("demo.run"); }
      fn b() { let _ = JobKind::from_static(EDIT_JOB); }
      fn c() { let _ = JobKind::from_static(kinds::OTHER_JOB); }
      pub mod kinds { pub const OTHER_JOB: &str = "demo.other"; }
    `);
    assert.deepEqual(sorted(found.jobKinds), ["demo.edit", "demo.other", "demo.run"]);
  });

  test("resolves a constant in the same file before another file", () => {
    const found = extractCodes([
      { file: "crates/a/src/lib.rs", source: 'pub const JOB_KIND: &str = "a.job";\nfn f() { JobKind::from_static(JOB_KIND); }' },
      { file: "crates/b/src/lib.rs", source: 'pub const JOB_KIND: &str = "b.job";\nfn f() { JobKind::from_static(JOB_KIND); }' },
    ]);
    assert.deepEqual(sorted(found.jobKinds), ["a.job", "b.job"]);
  });

  test("ignores test-only kinds and comments", () => {
    const found = codesOf(`
      // JobKind::from_static("in.comment")
      fn real() { JobKind::from_static("real.kind"); }
      #[cfg(test)]
      mod tests {
        fn t() { JobKind::from_static("jobs.test"); }
        const TEST_JOB: &str = "only.test";
      }
    `);
    assert.deepEqual(sorted(found.jobKinds), ["real.kind"]);
  });

  test("ignores files of tests", () => {
    const sources = [
      { file: "crates/x/src/testing.rs", source: 'fn t() { JobKind::from_static("t.one"); }' },
    ];
    // The directory walk skips these files; extractCodes itself sees what it is given.
    assert.deepEqual(sorted(extractCodes(sources).jobKinds), ["t.one"]);
  });
});

describe("audit actions", () => {
  test("finds literals, from_static and new, over line breaks", () => {
    const found = codesOf(`
      fn a() { AuditAction::from_static("demo.thing.create"); }
      fn b() { AuditAction::new("demo.thing.update"); }
      fn c() {
        let _ = AuditAction::from_static(
          "demo.thing.delete",
        );
      }
    `);
    assert.deepEqual(sorted(found.auditActions), ["demo.thing.create", "demo.thing.delete", "demo.thing.update"]);
  });

  test("takes every constant of a pub mod actions block and the named action constants", () => {
    const found = codesOf(`
      pub mod actions {
        /// A thing was created.
        pub const CREATE: &str = "demo.thing.make";
        pub const REMOVE: AuditAction = AuditAction::from_static("demo.thing.remove");
      }
      pub const RUN_ACTION: &str = "demo.run";
      pub const INSTALL_AUDIT: &str = "demo.install";
      pub const PLAIN_CONSTANT: &str = "demo.plain.constant";
    `);
    assert.deepEqual(sorted(found.auditActions), ["demo.install", "demo.run", "demo.thing.make", "demo.thing.remove"]);
  });

  test("resolves a constant named in from_static", () => {
    const found = codesOf(`
      pub const UPDATE_ACTION: &str = "demo.settings.update";
      fn a() { AuditAction::from_static(UPDATE_ACTION); }
      fn b() { AuditAction::from_static(actions::APPROVE); }
      pub mod actions { pub const APPROVE: &str = "demo.proposal.approve"; }
    `);
    assert.deepEqual(sorted(found.auditActions), ["demo.proposal.approve", "demo.settings.update"]);
  });

  test("follows a helper that takes the action as a parameter", () => {
    const found = codesOf(`
      fn audit(cx: &Ctx, action: &'static str, tag: &str) -> AuditDraft { todo!() }
      fn use_it() {
        audit(cx, "demo.pack.preview", tag);
        other(cx, "demo.not.an.action", tag);
      }
    `);
    assert.deepEqual(sorted(found.auditActions), ["demo.pack.preview"]);
  });

  test("takes the code literals of a let action statement", () => {
    const found = codesOf(`
      fn f(origin: Origin) {
        let action = if origin == Origin::A { "demo.pack.import" } else { "demo.pack.upload" };
        let unrelated = "demo.not.counted";
      }
    `);
    assert.deepEqual(sorted(found.auditActions), ["demo.pack.import", "demo.pack.upload"]);
  });

  test("ignores test-only actions", () => {
    const found = codesOf(`
      fn real() { AuditAction::from_static("real.action.run"); }
      #[cfg(test)]
      mod tests {
        pub mod actions { pub const X: &str = "only.in.tests"; }
        fn t() { AuditAction::from_static("test.only.action"); }
      }
    `);
    assert.deepEqual(sorted(found.auditActions), ["real.action.run"]);
  });

  test("ignores a string that is not shaped like a code", () => {
    const found = codesOf('fn f() { AuditAction::from_static("NoDots"); }');
    assert.equal(found.auditActions.size, 0);
  });
});

describe("families built from enumerations", () => {
  const model = `
    impl JobAction {
      pub const fn as_str(self) -> &'static str {
        match self { JobAction::Start => "start", JobAction::Wait => "wait" }
      }
    }
    impl Other { fn as_str(&self) -> &str { match self { Other::X => "unrelated" } } }
  `;
  const persist = `
    fn action_name(row: &Transition) -> String {
      match row.event {
        TransitionEvent::Submitted => "jobs.job.submit".to_owned(),
        TransitionEvent::Claimed => "jobs.job.claim".to_owned(),
      }
    }
    pub(crate) const fn step_state_name(kind: StepStateKind) -> &'static str {
      match kind { StepStateKind::Pending => "pending", StepStateKind::Done => "done" }
    }
  `;
  const object = "entity!(Tenant, TenantId, Tenant, \"tenants\", TENANTS);\nentity!(CustomThing, X, Vrf, \"vrfs\", VRFS);\n";
  const history = `
    impl ChangeAction {
      pub const fn as_str(self) -> &'static str {
        match self {
          ChangeAction::Create => "create", ChangeAction::Update => "update", ChangeAction::Delete => "delete",
          ChangeAction::Restore => "restore", ChangeAction::Lock => "lock", ChangeAction::Unlock => "unlock",
          ChangeAction::Remove => "remove",
        }
      }
    }
  `;

  test("matchArmNames reads the arms of the function that holds the marker", () => {
    assert.deepEqual(matchArmNames(model, "as_str", "JobAction::Start"), ["start", "wait"]);
    assert.deepEqual(matchArmNames(model, "as_str", "Other::X"), ["unrelated"]);
    assert.deepEqual(matchArmNames(model, "as_str", "Missing::Marker"), []);
  });

  test("builds the job engine and planner actions", () => {
    const found = extractCodes([
      { file: "crates/tenko-jobs/src/model.rs", source: model },
      { file: "crates/tenko-jobs/src/persist.rs", source: persist },
      { file: "crates/tenko-ipam/src/object.rs", source: object },
      { file: "crates/tenko-ipam/src/history.rs", source: history },
    ]);
    const actions = sorted(found.auditActions);
    for (const code of [
      "jobs.job.start",
      "jobs.job.wait",
      "jobs.job.submit",
      "jobs.job.claim",
      "jobs.job.update",
      "jobs.step.pending",
      "jobs.step.done",
      "jobs.step.update",
      "ipam.tenant.create",
      "ipam.tenant.restore",
      "ipam.vrf.update",
      "ipam.host.lock",
      "ipam.custom_field.remove",
    ]) {
      assert.ok(actions.includes(code), `missing ${code}`);
    }
    assert.ok(!actions.includes("ipam.tenant.lock"), "only hosts are locked");
  });
});

describe("factsOf", () => {
  test("reads the crate from the display path", () => {
    assert.equal(factsOf("", "crates/tenko-ipam/src/lib.rs").crate, "tenko-ipam");
  });
});

describe("the catalog units", () => {
  test("unitsOf reads ids, sources and targets", () => {
    const xml = `<group>
      <unit id="a.b"><segment><source>One &amp; two</source><target>Ett</target></segment></unit>
      <unit id="c.d"><notes><note category="description">n</note></notes><segment><source>Two</source></segment></unit>
    </group>`;
    assert.deepEqual(unitsOf(xml), [
      { id: "a.b", source: "One &amp; two", target: "Ett" },
      { id: "c.d", source: "Two", target: "" },
    ]);
  });

  test("catalogProblems names every code without a unit or a Swedish target", () => {
    const codes = { jobKinds: new Set(["demo.job"]), auditActions: new Set(["demo.a", "demo.b", "demo.c"]) };
    const en = new Map([
      [jobUnit("demo.job"), { id: "", source: "Demo job", target: "" }],
      [auditUnit("demo.a"), { id: "", source: "Demo A", target: "" }],
      [auditUnit("demo.b"), { id: "", source: "Demo B", target: "" }],
    ]);
    const sv = new Map([
      [jobUnit("demo.job"), { id: "", source: "Demo job", target: "Demojobb" }],
      [auditUnit("demo.a"), { id: "", source: "Demo A", target: "  " }],
    ]);
    assert.deepEqual(catalogProblems(codes, en, sv), [
      "audit action demo.a: no Swedish target for audit.action.demo.a",
      "audit action demo.b: no Swedish target for audit.action.demo.b",
      "audit action demo.c: no English unit audit.action.demo.c",
      "audit action demo.c: no Swedish target for audit.action.demo.c",
    ]);
  });
});

describe("the repository", () => {
  const codes = scanRepository();

  test("the scan finds the well-known job kinds and audit actions", () => {
    for (const kind of ["ipam.edit", "ipam.move", "dns.edit", "dhcp.edit", "connect.run", "scan.run", "sys.update", "backup.create"]) {
      assert.ok(codes.jobKinds.has(kind), `job kind ${kind} not found`);
    }
    for (const code of [
      "ipam.reconcile.run",
      "ipam.proposal.open",
      "ipam.prefix.create",
      "ipam.host.decommission",
      "jobs.job.start",
      "jobs.step.running",
      "dns.zone.create",
      "dhcp.scope.create",
      "auth.login.password",
      "vault.secret.reveal",
      "connect.secret.inject",
      "sys.update.confirm",
      "i18n.pack.import",
    ]) {
      assert.ok(codes.auditActions.has(code), `audit action ${code} not found`);
    }
  });

  test("the scan does not take test-only kinds and actions", () => {
    assert.ok(!codes.jobKinds.has("jobs.test"));
    assert.ok(!codes.auditActions.has("vault.test.leak"));
    assert.ok(!codes.auditActions.has("ipam.raft_test.write"));
  });

  test("every job kind and audit action has a label in English and in Swedish", () => {
    const problems = catalogProblems(codes, packUnits("en"), packUnits("sv"));
    assert.deepEqual(problems, [], `the label catalog (ui/i18n/<language>.d/labels.xlf) is incomplete:\n${problems.join("\n")}`);
  });

  test("the catalog has no label for a code the Rust code does not write", () => {
    const stale = [];
    for (const id of packUnits("en").keys()) {
      if (id.startsWith("audit.action.") && !codes.auditActions.has(id.slice("audit.action.".length))) stale.push(id);
    }
    assert.deepEqual(stale, [], `labels without an audit action in the code:\n${stale.join("\n")}`);
  });
});
