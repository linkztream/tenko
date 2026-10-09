//! Black-box tests of the configuration of `tenko`: `tenko config check` on the shipped
//! example file and on invalid files, the precedence of file, environment and flags, and
//! the refusals of `tenko serve` before it starts anything (status 3 for a bad
//! configuration, status 2 for roles that Phase 1 does not implement).

mod serve_support;

use std::path::{Path, PathBuf};

use serve_support::{Outcome, run_tenko, step_marker};

/// The configuration file shipped in `deploy/`.
fn example_file() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("deploy")
        .join("tenko.example.toml")
}

fn text(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

/// `tenko config check` with these arguments and environment.
fn check(args: &[&str], env: &[(&str, &str)]) -> Outcome {
    let mut all = vec!["config", "check"];
    all.extend_from_slice(args);
    run_tenko(&all, env)
}

/// Writes `contents` to a configuration file in `dir`. A literal `{data}` becomes the
/// data directory `dir/data`, as a path that needs no escaping inside TOML literal strings.
fn write_config(dir: &Path, contents: &str) -> PathBuf {
    let data = dir.join("data");
    let path = dir.join("tenko.toml");
    std::fs::write(&path, contents.replace("{data}", text(&data)))
        .expect("write the configuration");
    path
}

#[test]
fn config_check_accepts_the_example_file() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let data = dir.path().join("data");
    let outcome = check(
        &["--config", text(&example_file()), "--data-dir", text(&data)],
        &[],
    );
    outcome.assert_code(0);
    assert!(
        outcome
            .stdout
            .starts_with("# tenko config check: the configuration is valid\n"),
        "{}",
        outcome.diagnostics()
    );
    outcome.assert_stdout_contains("# environment overrides: (none)");
    outcome.assert_stdout_contains("# roles: controller");

    // The effective configuration is TOML again, with the flag winning over the file.
    let effective: toml::Table = toml::from_str(&outcome.stdout).expect("the output is TOML");
    assert_eq!(effective["data_dir"].as_str(), Some(text(&data)));
    assert_eq!(effective["roles"].as_str(), Some("controller"));
    assert_eq!(effective["tls"]["mode"].as_str(), Some("internal_ca"));
    assert_eq!(effective["profile"]["name"].as_str(), Some("home"));
    assert!(!data.exists(), "a check must not create the data directory");
}

#[test]
fn config_check_prints_no_secrets() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let key = dir.path().join("kek.key");
    // A key file that exists: its contents must never appear in the output.
    let secret = "d7".repeat(32);
    std::fs::write(&key, &secret).expect("write the key");
    let config = write_config(
        dir.path(),
        &format!(
            "data_dir = '{{data}}'\n[kek]\nprovider = \"file\"\npath = '{}'\n",
            text(&key)
        ),
    );
    let outcome = check(&["--config", text(&config)], &[]);
    outcome.assert_code(0);
    outcome.assert_stdout_contains("no OS protection");
    assert!(!outcome.stdout.contains(&secret) && !outcome.stderr.contains(&secret));
}

/// Asserts that `tenko config check` and `tenko serve` both refuse the file with status 3,
/// name the stable `code` and the offending `word`, and that `serve` starts nothing: no log
/// of the start steps, nothing on standard output, no data directory.
#[track_caller]
fn assert_refused(what: &str, contents: &str, code: &str, word: &str) {
    let dir = tempfile::tempdir().expect("temporary directory");
    let config = write_config(dir.path(), contents);

    let checked = check(&["--config", text(&config)], &[]);
    checked.assert_code(3);
    assert!(
        checked
            .stderr
            .contains(&format!("tenko config check: {code}"))
            && checked.stderr.contains(word),
        "{what}: expected `{code}` naming `{word}`\n{}",
        checked.diagnostics()
    );
    assert!(
        checked.stdout.is_empty(),
        "{what}: check printed a configuration\n{}",
        checked.diagnostics()
    );

    let served = run_tenko(&["serve", "--config", text(&config)], &[]);
    served.assert_code(3);
    assert!(
        served.stderr.contains(&format!("tenko serve: {code}")) && served.stderr.contains(word),
        "{what}: expected `{code}` naming `{word}`\n{}",
        served.diagnostics()
    );
    assert!(
        served.stdout.is_empty() && !served.stderr.contains(&step_marker("kek", "")),
        "{what}: serve started something\n{}",
        served.diagnostics()
    );
    assert!(
        !dir.path().join("data").exists(),
        "{what}: serve created the data directory"
    );
}

#[test]
fn files_that_do_not_parse_are_refused_as_config_parse() {
    // (what is wrong, the file, a word the message must contain)
    let cases = [
        (
            "unknown key",
            "data_dir = '{data}'\nbogus_key = 1\n",
            "bogus_key",
        ),
        (
            "unknown key in a section",
            "data_dir = '{data}'\n[server]\nlistenn = []\n",
            "listenn",
        ),
        ("syntax error", "data_dir = '{data}\n", "tenko.toml"),
        (
            "unknown TLS mode",
            "data_dir = '{data}'\n[tls]\nmode = \"carrier_pigeon\"\n",
            "carrier_pigeon",
        ),
    ];
    for (what, contents, word) in cases {
        assert_refused(what, contents, "config.parse", word);
    }
}

#[test]
fn settings_that_do_not_fit_together_are_refused_as_config_invalid() {
    // (what is wrong, the file, a word the message must contain)
    let cases = [
        (
            "reverse proxy without a public host",
            "data_dir = '{data}'\n[tls]\nmode = \"reverse_proxy\"\ntrusted_proxies = [\"127.0.0.1\"]\n",
            "public_host",
        ),
        (
            "reverse proxy without trusted proxies",
            "data_dir = '{data}'\n[tls]\nmode = \"reverse_proxy\"\npublic_host = \"ddi.example.org\"\n",
            "trusted_proxies",
        ),
        (
            "plain HTTP outside the Lab profile",
            "data_dir = '{data}'\n[tls]\nmode = \"plain\"\n",
            "Lab profile",
        ),
        (
            "imported certificate without files",
            "data_dir = '{data}'\n[tls]\nmode = \"imported\"\n",
            "cert_path",
        ),
        (
            "key file provider without a path",
            "data_dir = '{data}'\n[kek]\nprovider = \"file\"\n",
            "kek.path",
        ),
        (
            "no workers",
            "data_dir = '{data}'\n[server]\nworkers = 0\n",
            "server.workers",
        ),
        (
            "listen address without a port",
            "data_dir = '{data}'\n[server]\nlisten = [\"127.0.0.1\"]\n",
            "server.listen",
        ),
        ("no data directory", "roles = \"controller\"\n", "data_dir"),
    ];
    for (what, contents, word) in cases {
        assert_refused(what, contents, "config.invalid", word);
    }
}
#[test]
fn plain_http_is_valid_under_the_lab_profile() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let config = write_config(
        dir.path(),
        "data_dir = '{data}'\n[profile]\nname = \"lab\"\n[tls]\nmode = \"plain\"\n",
    );
    let outcome = check(&["--config", text(&config)], &[]);
    outcome.assert_code(0);
    outcome.assert_stdout_contains("# TLS: plain HTTP (Lab)");
}

#[test]
fn a_missing_configuration_file_is_reported_as_unreadable() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let missing = dir.path().join("no").join("tenko.toml");
    let data = dir.path().join("data");

    let checked = check(&["--config", text(&missing)], &[]);
    checked.assert_code(3).assert_stderr_contains("config.read");

    let served = run_tenko(
        &[
            "serve",
            "--config",
            text(&missing),
            "--data-dir",
            text(&data),
        ],
        &[],
    );
    served
        .assert_code(3)
        .assert_stderr_contains("tenko serve: config.read");
    assert!(
        served.stdout.is_empty() && !data.exists(),
        "{}",
        served.diagnostics()
    );
}

#[test]
fn a_bad_environment_value_is_refused() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let data = dir.path().join("data");

    let checked = check(
        &["--data-dir", text(&data)],
        &[("TENKO_SERVER__WORKERS", "many")],
    );
    checked.assert_code(3);
    checked.assert_stderr_contains("tenko config check: config.env");

    let served = run_tenko(
        &["serve", "--data-dir", text(&data)],
        &[("TENKO_SERVER__WORKERS", "many")],
    );
    served
        .assert_code(3)
        .assert_stderr_contains("tenko serve: config.env");
    assert!(
        served.stdout.is_empty() && !data.exists(),
        "{}",
        served.diagnostics()
    );
}

#[test]
fn environment_overrides_the_file_and_the_flags_override_both() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let from_file = dir.path().join("from-file");
    let from_env = dir.path().join("from-env");
    let from_flag = dir.path().join("from-flag");
    let config = write_config(
        dir.path(),
        &format!(
            "data_dir = '{}'\n[server]\nworkers = 2\n[log]\nlevel = \"info\"\n",
            text(&from_file)
        ),
    );
    let env = [
        ("TENKO_DATA_DIR", text(&from_env)),
        ("TENKO_SERVER__WORKERS", "3"),
        ("TENKO_LOG__LEVEL", "debug"),
        ("TENKO_SERVER__LISTEN", "127.0.0.1:18080,127.0.0.1:18081"),
    ];

    let by_env = check(&["--config", text(&config)], &env);
    by_env.assert_code(0);
    let effective: toml::Table = toml::from_str(&by_env.stdout).expect("TOML");
    assert_eq!(effective["data_dir"].as_str(), Some(text(&from_env)));
    assert_eq!(effective["server"]["workers"].as_integer(), Some(3));
    assert_eq!(effective["log"]["level"].as_str(), Some("debug"));
    let listen: Vec<&str> = effective["server"]["listen"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    assert_eq!(listen, ["127.0.0.1:18080", "127.0.0.1:18081"]);
    by_env.assert_stdout_contains("# environment overrides: ");
    for name in [
        "TENKO_DATA_DIR",
        "TENKO_SERVER__WORKERS",
        "TENKO_LOG__LEVEL",
        "TENKO_SERVER__LISTEN",
    ] {
        by_env.assert_stdout_contains(name);
    }

    let by_flag = check(
        &["--config", text(&config), "--data-dir", text(&from_flag)],
        &env,
    );
    by_flag.assert_code(0);
    let effective: toml::Table = toml::from_str(&by_flag.stdout).expect("TOML");
    assert_eq!(effective["data_dir"].as_str(), Some(text(&from_flag)));

    // Names that are not configuration keys are not overrides.
    let unrelated = check(
        &["--config", text(&config)],
        &[
            ("TENKO_URL", "https://example.org"),
            ("TENKO_TOKEN", "not-a-real-token"),
        ],
    );
    unrelated
        .assert_code(0)
        .assert_stdout_contains("# environment overrides: (none)");
}

#[test]
fn roles_that_phase_1_does_not_implement_exit_with_status_2() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let data = dir.path().join("data");
    for roles in ["dns", "dhcp", "probe", "dns,dhcp"] {
        let served = run_tenko(&["serve", "--roles", roles, "--data-dir", text(&data)], &[]);
        served.assert_code(2);
        served.assert_stderr_contains("not implemented in Phase 1");
        served.assert_stderr_contains("tenko serve: role(s) ");
        assert!(
            served.stdout.is_empty() && !served.stderr.contains(&step_marker("kek", "")),
            "{}",
            served.diagnostics()
        );
        assert!(
            !data.exists(),
            "`--roles {roles}` created the data directory"
        );
    }

    // A name that is no role at all is a configuration error, not a missing feature.
    let unknown = run_tenko(
        &["serve", "--roles", "wizard", "--data-dir", text(&data)],
        &[],
    );
    unknown
        .assert_code(3)
        .assert_stderr_contains("config.invalid");

    // `config check` only notes the missing roles: the configuration itself is valid.
    let checked = check(&["--roles", "dns", "--data-dir", text(&data)], &[]);
    checked
        .assert_code(0)
        .assert_stderr_contains("not implemented in Phase 1");
}
