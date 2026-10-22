<!--
Thank you for the pull request. The checklist below is what a maintainer looks for
before merging; CONTRIBUTING.md explains each item. Keep the headings, fill in the
text, and tick the boxes that hold.
-->

## What this change does

<!-- The behaviour before and after, in a few sentences, written for a user of the
product. Link the issue it closes, if any. -->

## How it was tested

<!-- The commands you ran and what they showed: unit tests, an acceptance test, the
lab, a manual check in the UI. A performance claim links to a result file under bench/. -->

## Checklist

- [ ] **First contribution:** the description of this pull request contains the
      acceptance sentence of `CLA.md`, Part D.1 (individuals) or D.2 (contributors of
      an entity that has sent in Schedule 1), with my real name.
- [ ] **Every commit is signed off** (`git commit -s`): a `Signed-off-by: Full Name
      <email>` trailer with the name and email of the commit's author field.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes (the workspace
      lints include `clippy::pedantic`).
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo nextest run --workspace` passes (or `cargo test --workspace`).
- [ ] A change under `crates/**` or `ui/src/**` has a line under `## [Unreleased]` in
      `CHANGELOG.md`, written for a user of the product.
- [ ] A change that names a requirement, a test or a document of a phase keeps the
      generated traces current: `node scripts/requirement-trace.mjs --check`, and with
      `--phase 2` and `--phase 3`.
- [ ] A new parser of network input ships with a fuzz target under `fuzz/`.
- [ ] Code, comments, commit messages and documentation are in English.
- [ ] No attribution trailers (`Co-authored-by`, "Generated with" or the like) in the
      commits and no tooling banners in the code; `Signed-off-by` is the only trailer.
- [ ] Fixtures and examples use placeholders only: addresses from RFC 5737
      (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 3849
      (`2001:db8::/32`), MAC addresses from RFC 7042, names under `example.test`. No
      real hosts, domains, accounts or secrets.
- [ ] Third-party code is declared above with its source and licence, and is
      permissively licensed (see `CONTRIBUTING.md`, "Licensing and the Contributor
      License Agreement").
