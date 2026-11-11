# Standing rules for tests

A test must give the same result on a quiet machine, on a loaded one and on any date. These
rules come from the test review of November 2026 (`docs/testing/health-2026-11.md`, section 1
for the classes of host-dependent tests, section 8 for the rules). `node scripts/test-lint.mjs`
checks them over the Rust tests, the UI unit tests, the end-to-end tests and the test
configuration. Push CI runs it (job `spelling`, step "Test rules"), and the job `changelog`
checks that the baseline did not grow (`--grown-since`, below); the merge gate, whose script
lives outside the repository, runs the same two commands.

## The rules

Each rule has a lint rule name (used in exceptions and in the baseline), the reason, the
remedy this code base uses, and what the lint sees and does not see. The lint is lexical: it
blanks comments and string contents, matches brackets and recognizes functions, test
attributes, closures and loops; it does not resolve types, expand macros or follow calls. A
rule reports only what it can name precisely. Test code is a file under `crates/*/tests/`, a
module file reached through `#[cfg(test)] mod x;` (with what it declares), and in other source
files an item under `#[cfg(test)]` or a function marked `#[test]`; code under
`#[cfg(any(test, feature = "testing"))]` is shared test support and not checked. Tests that a
macro generates (`fn $name()`) are not seen.

### 1. No sleep as synchronization (`sleep`)

A sleep guesses how long another thread, task or process needs, and a loaded machine needs
longer.

- Remedy: wait until the named condition holds, with a generous limit (30 s), so a quiet
  machine pays nothing; when the code under test waits with `tokio::time`, use a paused clock
  (`#[tokio::test(start_paused = true)]` and `tokio::time::advance`, as
  `crates/tenko-scan/src/limit.rs` does). Where the product offers a signal, wait on it (for
  example `hub.subscribers_of` in `crates/tenko-api/src/sse/hub.rs` for "the watcher has
  subscribed"). In the UI, `waitFor`, `findBy*` or fake timers (`vi.useFakeTimers`,
  `vi.advanceTimersByTimeAsync`); end to end, `expect.poll` or an `expect(...)` with a limit,
  and `page.clock` for time itself. A sleep is allowed inside the shared wait helper and in a
  pacing loop (a load generator), each with an exception that says so.
- The lint reports: `thread::sleep`, `tokio::time::sleep` and `sleep_until`, a bare
  `sleep(...)` (an imported one); `new Promise((r) => setTimeout(r, ...))`,
  `page.waitForTimeout(...)` and the calls of a helper in the same file whose body is such a
  promise. Tokio sleeps in a test with `start_paused = true` or that calls `time::pause()` are
  not reported.
- It cannot see: a sleep inside a helper of another file or crate; a paused clock that a
  helper sets up (such a sleep is reported); `setTimeout` under fake timers (reported as a
  sleep when it is wrapped in a promise).

### 2. No wait limit under 10 s (`deadline`)

A limit is a bet on the machine's speed; under load an operation of milliseconds can take
seconds. A limit below 10 s is allowed only when the limit itself is what the test checks.

- Remedy: one wait helper with a 30 s limit that returns as soon as the condition holds.
  Until the shared helper exists, raise the local limit to 30 s.
- The lint reports a literal `Duration::from_*` or `Duration::new` under 10 s that is passed to
  a call whose name holds `timeout`, `deadline`, `wait`, `until`, `eventually` or `within`
  (also through `Some(...)`; not a capitalized constructor or enum variant such as
  `Error::Timeout(..)`), added to `Instant::now()`, assigned to a name holding `timeout`,
  `deadline` or `wait` (not `expected_*`), or compared with `elapsed()` outside an assertion
  (a loop condition, an `if`) or in an assertion inside a poll loop (a loop that sleeps or
  yields). In TypeScript, a `timeout` (and `testTimeout`, `actionTimeout`,
  `navigationTimeout`, `hookTimeout`, `asyncUtilTimeout`) under 10,000 ms in an options object
  passed to a call, and `test.setTimeout(...)` under 10,000 ms. Zero is not reported (it means
  "do not wait").
- It cannot see: a limit held in a variable or constant of another name, a computed or
  multiplied limit, a helper's default (Testing Library's `findBy*` and `waitFor` wait 1 s by
  default, which no line shows), an options object built before the call.

### 3. No assertion on a duration or a rate (`duration`)

A test that says "within 100 ms" measures the machine as much as the product.

- Remedy: a latency or throughput claim of the product belongs in `bench/` or in an
  `#[ignore]`d measurement run on the shipped release binary; the functional test keeps the
  behavior and, if it needs one, a wide bound (at least 10 s, usually 30 s).
- The lint reports an assertion macro (Rust) whose first argument puts an upper bound on a
  measured time (`elapsed`, `took`, `Instant::now()`, `duration_since`), and an `expect(...)`
  of `elapsed`, `took` or `performance.now()` with `toBeLessThan`, `toBeLessThanOrEqual` or
  `toBeCloseTo`. Not reported: a lower bound (it holds under load), a literal bound of at least
  10 s, `Instant::now() < deadline` (the limit of a wait), an assertion in a poll loop (the
  `deadline` rule), `#[ignore]`d tests, a paused clock.
- It cannot see: a duration check written as `if took > limit { panic!() }`, a time under
  another name, a rate (`qps`, `per_second`): a rate is also what the product computes from
  fixed input, which a line does not tell apart.

### 4. No count that depends on timing (not checked)

Rounds, retries, restarts or ticks counted in a real-time window change with the machine's
speed. Assert the outcome (the write is committed, the leader is one of the members), or move
the count into a measurement. The lint has no rule for this: nothing on the line tells a count
that timing changes from one it does not.

### 5. No wall clock in an expectation, no literal date beside it (`clock`)

A test that compares with the current time fails at midnight, at the end of a month or on the
day a fixture's date falls out of a retention window.

- Remedy: the product takes the time as a parameter or an injected clock
  (`tenko_auth::clock::MockClock`, the `Clock` of `tenko-jobs`, a
  `tenko_core::timestamp::Timestamp` passed as a value), and fixtures are relative to that
  time. In the UI, `vi.setSystemTime`; end to end, `page.clock`.
- The lint reports `SystemTime::now()`, `Timestamp::now()`, `Utc::now()`, `Local::now()`,
  `OffsetDateTime::now_utc()` inside an assertion, `Date.now()` or `new Date()` inside an
  `expect(...)`, and a test function (or TypeScript test) that reads the wall clock and also
  holds a literal date (`"2026-..."`, `new Date(2026, ...)`, `Date.UTC(2026, ...)`).
  TypeScript files that fake the clock are skipped.
- It cannot see: a fixed date in a test while the product reads the clock on its own (the
  fixture date that fails eight tenko-ipam tests from 2026-11-21 is of this kind: finding it
  means following the calls into the product, which only a reader or a call graph does);
  clock reads in helpers;
  dates written as Unix seconds; the time zone and locale (fixed for the unit tests instead,
  below).

### 6. No port found by binding and dropping; no host order or size (`port`)

A port that was free when the test asked may be taken before the server binds it, by another
test of the same run.

- Remedy: keep the socket until the server takes it, or let the server bind port 0 and report
  the address it got; the pooled helpers `free_port` in `crates/tenko/tests/serve_support` and
  `crates/tenko-dns/tests/support/ports.rs` hand out each port once per process and retry the
  start on a lost race.
- The lint reports a bind to port 0 (`"127.0.0.1:0"`, `(addr, 0)`, `SocketAddrV4::new(.., 0)`)
  whose socket is a temporary chained into `.local_addr()`, or bound to a name that is only
  asked for its address or dropped; in TypeScript, `listen(0)` in a function that also closes
  the server.
- It cannot see: an address held in a variable; the order of a hash map or a directory
  listing, and the number of cores, which the rule also forbids depending on.

### 7. No retries, no `.only` (`retries`, `only`)

A retry turns a flaky test into a passing one and hides its cause; a focused test silently
skips the rest of its file.

- The lint reports a non-zero `retries` in `ui/playwright.config.ts` or in an end-to-end
  `configure(...)`, a non-zero `retry` in `ui/vite.config.ts` or in a test's options, a
  non-zero `retries` in `.config/nextest.toml` (also as `{ count = N }`), a non-zero
  `--retries` or `--retry` on a nextest, Playwright, vitest or `cargo test` command line, and a
  non-zero `NEXTEST_RETRIES`, in a workflow or in `ui/package.json`; and `it.only`,
  `test.only`, `describe.only` and their chained forms.
- It cannot see: retries set on a command line outside the repository (the gate's script), or
  passed through a script name (`npm run e2e -- --retries 1`).

### 8. A skipped test names its runner; an early return names its job (`ignore`, `early-return`)

A test that nothing runs, or that returns before it asserts, is green whether the property
holds or not.

- Remedy: every `#[ignore]` (and every `skip`, `fixme` or `todo` test) names who runs it and
  when, and every `return` before the first assertion names the job that meets its condition.
  The form is a runner reference, `runner: ci.yml#cluster-lab` (a job of a workflow under
  `.github/workflows/`) or `runner: docs/connectors.md` (a file in the repository that says
  who runs it and when), in the `#[ignore = "..."]` reason, in the skip's arguments, or in a
  comment on the line or the line above. A generator or a tool is a command, not a test.
- The lint reports an `#[ignore]` or `cfg_attr(.., ignore)` and a skipped TypeScript test
  (`skip`, `skipIf`, `runIf`, `fixme`, `todo`) without a runner reference, or with one whose
  workflow, job or file does not exist (a file is a regular file, its path written with the
  exact case, which Windows would forgive and Linux CI does not); and a
  `return` in the body of a test (not in a closure or nested function, not in a property
  test's case) before its first assertion (an assertion macro, `panic!`, `unreachable!`,
  `unwrap_err`, `expect_err`, an `assert_*` helper; `expect(` or `assert*(` in TypeScript),
  unless a runner reference that exists is on the line or the line above.
- It cannot see: whether the named job really runs the test; a skip decided at run time inside
  a test (`ctx.skip()`); an exit through `?`; an assertion in a helper of another name (the
  return before it is reported). An assertion inside the returned expression (`return
  expect(p).resolves...`) counts as coming first.

### 9. A refusal is asserted by its code (`is-err`)

`is_err()` passes for any error, so a test of a refusal also passes when the operation fails
for an unrelated reason.

- Remedy: match the error variant or its code (`assert!(matches!(r, Err(Error::Refused)))`,
  `assert_eq!(r.unwrap_err().code(), "...")`); in TypeScript, `toThrow("...")` or
  `toThrow(ErrorClass)`.
- The lint reports `assert!(x.is_err())`, `assert!(!x.is_ok())`, `assert!(matches!(x,
  Err(_)))` and `toThrow()` or `toThrowError()` without an argument.
- It cannot see: `.unwrap_err();` with nothing checked afterwards, `assert_eq!(x.is_err(),
  true)`.

## Time zone and locale of the unit tests

The UI unit tests run in UTC and in the `en-US` locale on every host: `ui/vite.config.ts` sets
`TZ` before vitest starts its workers, and `ui/src/app/testing/host.ts` (the first setup file)
checks the zone and makes `en-US` the default locale of `Intl` and of the `toLocale*` and
`localeCompare` methods. The end-to-end tests set the same in `ui/playwright.config.ts`
(`locale`, `timezoneId`). A test that needs another zone or locale names it in the call. No test
has a different time budget when `CI` is set.

## nextest

`.config/nextest.toml` sets no retries, ends a test that runs longer than ten minutes with its
name (`slow-timeout`), fails a test that leaves a process holding its output for a second
after it ended (`leak-timeout`), and writes a JUnit report of every run to
`target/nextest/default/junit.xml` under the workspace root.

## Exceptions

A finding that is right for its test (the limit is what the test checks, a sleep paces a load
generator) carries a comment on its line or the line above:

```rust
// test-lint: allow deadline the 300 ms handshake limit is what this test checks
let config = Config { handshake_timeout: Duration::from_millis(300), ..Config::default() };
```

The reason is required. An exception that names no known rule, has no reason or suppresses
nothing fails the check, so exceptions do not outlive their code.

## The baseline

`scripts/test-lint.baseline.json` lists the findings of the day the lint was introduced, by
rule, file, scope (the test or function) and the matched text, with a count when the same text
occurs more than once in a scope; it holds no line numbers, so moving code does not matter. The
check fails on a finding that is not in the baseline and on an entry that nothing matches any
more. Whoever fixes a test removes its entry in the same commit:

```sh
node scripts/test-lint.mjs                          # the check
node scripts/test-lint.mjs --list                   # every finding, baseline included, with its place
node scripts/test-lint.mjs --prune                  # remove the entries nothing matches; never adds one
node scripts/test-lint.mjs --grown-since origin/main  # fail when a rule has more entries than there
```

A hand-written entry would pass the check, so a second check compares the baseline with the
one at the base of the change: `--grown-since <ref>` fails when any rule has more entries than
at the ref (CI passes the pull request's base or the push's previous commit). Renaming a test
or a file moves its entries without changing a rule's total, which passes; edit the entry's
`file` or `scope` in the same commit. `--write-baseline` writes the file from the current
findings only where none exists: it was for the first run, and it refuses to overwrite one.

The baseline of 2026-11-11 against the review's counts (section 1.1): the review counts rows by
primary class, a row grouping the lines of one test or helper, and covers only host
dependence; the lint counts each occurrence. So it reports more sleeps (338 against 133: the
sleeps inside poll loops, which the review files under deadlines, are sleeps here too) and more
deadlines (327 against 177: every short limit, also those the review grouped by helper), fewer
duration assertions (37 against 54: no rates, no lower bounds), and 21 ports against 38
host-environment rows (the rest are interfaces, tools and orders it cannot see); 39 `clock`
findings against 41 calendar rows (most of those are zone and locale, which the lint does not
read). The 53 `ignore` findings are every `#[ignore]`, the 30 no job runs and those the weekly
cluster lab runs (none names its runner yet); the 28 `early-return` findings include the 10
vacuous tests of section 2.2 and the child-process entry points written as tests. The 739
`is-err` findings cover every suite; the review sampled only the security suites (section 3).
In all, 1,583 findings in 1,480 entries.
