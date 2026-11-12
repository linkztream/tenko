//! Network rules that a published standard defines, over `std::net` and `ipnet` types.
//!
//! This crate is a home of shared code (`CONTRIBUTING.md`, "Where shared code lives"). Before
//! writing an address rule anywhere else, look here; if the rule belongs here and is missing,
//! add it here.
//!
//! # What goes in
//!
//! Functions whose rule an RFC or an IEEE standard defines, and that take and return
//! `std::net`, `ipnet` or plain byte and string types: address classes (link-local,
//! special-purpose, IPv4-mapped, the reserved addresses of a subnet), the reverse name of an
//! address and the address of a reverse name, the client address from a PROXY protocol header
//! or a forwarded-for chain with a list of trusted hops. Each function's doc comment names the
//! rule and its source; its unit tests live beside it. A parser of network input gets a fuzz
//! target, as every parser does.
//!
//! # What never goes in
//!
//! - A dependency on a workspace crate (a test below reads the manifest), `serde` or
//!   `utoipa` derives.
//! - A setting or a default that Tenko chooses: the caller passes those in.
//! - Input or output, `async`, logging.
//! - A domain type (zone, scope, prefix, host). The stored types of network identifiers
//!   (MAC address, DUID, host and domain names) and their parsing live in `tenko_core::net`:
//!   a type a stored record holds lives there, a rule over addresses that no stored type
//!   needs lives here.
//!
//! # Who may depend on it
//!
//! Any crate except `tenko-core`, which never depends on it (a test below reads its
//! manifest), so that a change here never rebuilds every crate of the workspace.
//!
//! # Modules
//!
//! None yet. Each module is one line below; parallel changes each append their own line and
//! never edit or reorder another's.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    /// The names of the dependencies a manifest declares, in every dependency table
    /// (`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, and their
    /// `[target.'...'.*]` forms), from both the `name = ...` and the `[dependencies.name]`
    /// spellings.
    fn dependencies(manifest: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut in_table = false;
        for line in manifest.lines().map(str::trim) {
            if let Some(header) = line.strip_prefix('[') {
                let header = header.trim_end_matches(']');
                let table = header.rsplit('.').next().unwrap_or(header);
                let is_dependency_table = |t: &str| t.ends_with("dependencies");
                if is_dependency_table(table) {
                    in_table = true;
                } else if let Some((parent, name)) = header.rsplit_once('.')
                    && is_dependency_table(parent.rsplit('.').next().unwrap_or(parent))
                {
                    names.push(name.trim_matches('"').to_owned());
                    in_table = false;
                } else {
                    in_table = false;
                }
            } else if in_table
                && let Some((name, _)) = line.split_once('=')
                && !line.starts_with('#')
            {
                names.push(name.trim().trim_matches('"').to_owned());
            }
        }
        names
    }

    /// Workspace crates are the `tenko` crate and the `tenko-*` crates.
    fn is_workspace_crate(name: &str) -> bool {
        name == "tenko" || name.starts_with("tenko-") || name.starts_with("tenko_")
    }

    #[test]
    fn tenko_net_depends_on_no_workspace_crate() {
        let ours = dependencies(include_str!("../Cargo.toml"));
        let workspace: Vec<_> = ours.iter().filter(|n| is_workspace_crate(n)).collect();
        assert!(
            workspace.is_empty(),
            "tenko-net is a leaf crate; it depends on {workspace:?}"
        );
        let derives: Vec<_> = ours
            .iter()
            .filter(|n| *n == "serde" || *n == "utoipa")
            .collect();
        assert!(
            derives.is_empty(),
            "tenko-net carries no derives; it depends on {derives:?}"
        );
    }

    #[test]
    fn tenko_core_does_not_depend_on_tenko_net() {
        let core = dependencies(include_str!("../../tenko-core/Cargo.toml"));
        assert!(
            !core.is_empty(),
            "the reader found no dependency of tenko-core at all"
        );
        assert!(
            !core.iter().any(|n| n == "tenko-net"),
            "tenko-core must not depend on tenko-net"
        );
    }

    #[test]
    fn the_reader_sees_every_spelling_of_a_dependency() {
        let manifest = "[package]\nname = \"x\"\n\n[dependencies]\n# tenko-commented = 1\nipnet = \"2\"\n\
                        tenko-core = { workspace = true }\n\n[dev-dependencies.tenko-store]\nworkspace = true\n\n\
                        [target.'cfg(unix)'.build-dependencies]\n\"tenko\" = { path = \"..\" }\n\n[lints]\nworkspace = true\n";
        assert_eq!(
            dependencies(manifest),
            ["ipnet", "tenko-core", "tenko-store", "tenko"]
        );
        assert_eq!(
            dependencies(manifest)
                .iter()
                .filter(|n| is_workspace_crate(n))
                .count(),
            3
        );
    }
}
