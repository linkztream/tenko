//! Black-box tests of the first-run setup token: while setup is open every start writes a
//! new token to `<data_dir>/setup-token` (mode 0600 on Unix) and prints it nowhere else,
//! `tenko setup token` prints it from there, a restart writes a different one, failed
//! attempts do not use the token up, and once `tenko setup` has succeeded the file is gone
//! and a restart writes none.
//!
//! The harness starts the server with piped standard output, which is not a terminal: the
//! framed block on standard output names the file instead of showing the token. The
//! interactive case (a terminal shows the token) is a unit test of `serve::setup_token`.

mod serve_support;

use std::time::Duration;

use serve_support::{
    Node, is_setup_token, log_setup_tokens, run_tenko, stdout_setup_tokens, step_marker,
    wait_for_setup_token,
};

/// The rule that frames the first-run block on standard output.
const RULE: &str = "========================================================================";

/// How long the server may take to remove the token file once setup completed.
const REMOVAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Starts a server on the node, reads the token, stops the server and returns the token
/// together with the complete output.
fn start_read_and_stop(node: &mut Node) -> (String, serve_support::Outcome) {
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    server
        .wait_stdout_line(Duration::from_secs(30), |line| {
            line.starts_with("The token changes at every start")
        })
        .expect("the block ends with its closing note");
    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    (token, outcome)
}

/// Asserts that neither stream of the server carries the token, in any form.
#[track_caller]
fn assert_token_absent(outcome: &serve_support::Outcome, token: &str) {
    assert!(
        !outcome.stdout.contains(token) && !outcome.stderr.contains(token),
        "the token is in the output of the server\n{}",
        outcome.diagnostics().replace(token, "<token>")
    );
    // Also without the dashes: no field of any log line may carry the token.
    let bare = token.replace('-', "");
    assert!(
        !outcome.stdout.contains(&bare) && !outcome.stderr.contains(&bare),
        "the token is in the output of the server without its dashes"
    );
    assert!(
        stdout_setup_tokens(&outcome.stdout).is_empty(),
        "{}",
        outcome.stdout
    );
    assert!(
        log_setup_tokens(&outcome.stderr).is_empty(),
        "{}",
        outcome.stderr
    );
}

#[cfg(unix)]
#[track_caller]
fn assert_owner_only(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = std::fs::metadata(path)
        .expect("the token file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "{} has mode {mode:o}", path.display());
}

#[test]
fn each_start_writes_a_token_file_and_a_restart_writes_another() {
    let mut node = Node::new();
    let file = node.setup_token_path();
    let dir = node.data_dir();
    let command = format!("tenko setup token --data-dir {}", dir.display());

    let (first, outcome) = start_read_and_stop(&mut node);
    assert!(is_setup_token(&first), "`{first}`");
    assert_eq!(
        std::fs::read_to_string(&file).expect("the token file"),
        format!("{first}\n")
    );
    #[cfg(unix)]
    assert_owner_only(&file);
    assert!(
        !file.with_file_name("setup-token.part").exists(),
        "a part file is left behind"
    );
    assert_token_absent(&outcome, &first);

    // The log names the command and the data directory; the console block names the file.
    outcome.assert_stderr_contains("first-run setup is open");
    outcome.assert_stderr_contains(&format!("`{command}`"));
    let lines: Vec<&str> = outcome.stdout.lines().collect();
    let rules: Vec<usize> = (0..lines.len()).filter(|at| lines[*at] == RULE).collect();
    assert_eq!(rules.len(), 2, "{}", outcome.stdout);
    let at = lines
        .iter()
        .position(|line| line.starts_with("Setup token: "))
        .expect("the token line");
    assert_eq!(
        lines[at],
        format!(
            "Setup token: in {}; print it with {command}",
            file.display()
        )
    );
    assert!(
        rules[0] < at && at < rules[1],
        "the token line is outside its frame\n{}",
        outcome.stdout
    );
    assert!(
        lines[rules[0]..rules[1]]
            .iter()
            .any(|line| line.contains("tenko setup --url")),
        "the block does not name the command\n{}",
        outcome.stdout
    );

    // `tenko setup token` prints the token alone, however it finds the data directory.
    let printed = node.print_setup_token();
    printed.assert_code(0);
    assert_eq!(printed.stdout, format!("{first}\n"));
    assert_eq!(printed.stderr, "");
    let config = node.config_path();
    let by_config = run_tenko(
        &[
            "setup",
            "token",
            "--config",
            config.to_str().expect("UTF-8"),
        ],
        &[],
    );
    by_config.assert_code(0);
    assert_eq!(by_config.stdout, format!("{first}\n"));
    let by_env = run_tenko(
        &["setup", "token"],
        &[("TENKO_DATA_DIR", dir.to_str().expect("UTF-8"))],
    );
    by_env.assert_code(0);
    assert_eq!(by_env.stdout, format!("{first}\n"));
    // Without a data directory there is nothing to look in: a configuration error.
    run_tenko(&["setup", "token"], &[])
        .assert_code(3)
        .assert_stderr_contains("data_dir is not set");

    let (second, outcome) = start_read_and_stop(&mut node);
    assert!(is_setup_token(&second), "`{second}`");
    assert_ne!(first, second, "a restart must write a new token");
    assert_eq!(node.read_setup_token().as_deref(), Some(second.as_str()));
    #[cfg(unix)]
    assert_owner_only(&file);
    assert_token_absent(&outcome, &second);
    assert_token_absent(&outcome, &first);
    let printed = node.print_setup_token();
    printed.assert_code(0);
    assert_eq!(printed.stdout, format!("{second}\n"));
}

#[test]
fn the_token_is_in_the_file_when_the_server_is_ready() {
    let mut node = Node::new();
    // `start` returns when the readiness line is out and the probe answers 200; the file is
    // written by the auth step, long before that, and is read here without waiting.
    let mut server = node.start();
    let token = node.read_setup_token().expect("the token file");
    assert!(is_setup_token(&token), "`{token}`");
    server.stop().assert_graceful_shutdown();
}

#[test]
fn the_token_of_an_earlier_start_does_not_open_setup() {
    let mut node = Node::new();
    let (stale, _) = start_read_and_stop(&mut node);

    let mut server = node.start();
    let current = wait_for_setup_token(&server);
    assert_ne!(stale, current);

    let refused = node.setup(&stale);
    refused.assert_code(6);
    refused.assert_stderr_contains("error[auth.setup.token_invalid]");

    // The refusal did not use up the current token, nor remove its file.
    assert_eq!(node.read_setup_token().as_deref(), Some(current.as_str()));
    node.setup(&current)
        .assert_code(0)
        .assert_stdout_contains("setup complete");
    server.stop().assert_graceful_shutdown();
}

#[test]
fn a_refused_password_does_not_use_up_the_token() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);

    let weak = node.client_stdin(
        &[
            "setup",
            "--setup-token",
            &token,
            "--admin",
            "admin",
            "--host-name",
            "localhost",
            "--password-stdin",
        ],
        "1234\n",
    );
    weak.assert_code(5);
    weak.assert_stderr_contains("tenko setup: error[");
    assert!(
        !weak.stderr.contains(&token) && !weak.stdout.contains(&token),
        "the client must not echo the token"
    );

    // Setup is still open: the file is there and its token still works.
    assert_eq!(node.read_setup_token().as_deref(), Some(token.as_str()));
    node.setup(&token)
        .assert_code(0)
        .assert_stdout_contains("setup complete");
    server.stop().assert_graceful_shutdown();
}

#[test]
fn the_token_printed_by_the_command_completes_setup() {
    let mut node = Node::new();
    let mut server = node.start();
    let printed = node.print_setup_token();
    printed.assert_code(0);
    let token = printed.stdout.trim().to_owned();
    assert!(is_setup_token(&token), "`{token}`");

    node.setup(&token)
        .assert_code(0)
        .assert_stdout_contains("setup complete");
    server.stop().assert_graceful_shutdown();
}

#[test]
fn the_file_goes_when_setup_completes_and_a_restart_writes_none() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    assert!(node.setup_token_path().exists());

    node.setup(&token).assert_code(0).assert_stdout_contains(
        "setup complete: profile home, administrator admin, host name localhost",
    );
    assert!(
        node.wait_for_setup_token_removal(REMOVAL_TIMEOUT),
        "the token file is still there after setup completed"
    );
    // With the file gone the command says why there is no token.
    let gone = node.print_setup_token();
    gone.assert_code(1);
    assert_eq!(gone.stdout, "");
    gone.assert_stderr_contains("first-run setup is complete");

    // Setup is closed for good, also for the token that just worked.
    let again = node.setup(&token);
    again.assert_code(5);
    again.assert_stderr_contains("error[auth.setup.closed]");
    let stopped = server.stop();
    stopped.assert_graceful_shutdown();
    assert_token_absent(&stopped, &token);

    let mut restarted = node.start();
    let outcome = restarted.stop();
    outcome.assert_graceful_shutdown();
    assert!(
        !node.setup_token_path().exists(),
        "a restart after setup wrote a token file"
    );
    assert!(
        !outcome.stdout.contains("First-run setup is open")
            && !outcome.stdout.contains("Setup token:"),
        "{}",
        outcome.stdout
    );
    assert!(
        !outcome.stderr.contains("first-run setup"),
        "the log announces setup after it completed\n{}",
        outcome.stderr
    );
    assert_token_absent(&outcome, &token);
    outcome.assert_stderr_contains(&step_marker("auth", "ready in "));
    outcome.assert_stderr_contains("installation localhost (profile home)");
    node.print_setup_token().assert_code(1);
}

#[test]
fn a_start_with_setup_closed_removes_a_leftover_file() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);
    node.setup(&token).assert_code(0);
    assert!(node.wait_for_setup_token_removal(REMOVAL_TIMEOUT));
    server.stop().assert_graceful_shutdown();

    // A file from before setup completed (a crash between the two) must not survive.
    std::fs::write(node.setup_token_path(), format!("{token}\n")).expect("plant the file");
    std::fs::write(
        node.setup_token_path().with_file_name("setup-token.part"),
        format!("{token}\n"),
    )
    .expect("plant the part file");
    let mut restarted = node.start();
    assert!(
        !node.setup_token_path().exists(),
        "the leftover token file is still there"
    );
    assert!(
        !node
            .setup_token_path()
            .with_file_name("setup-token.part")
            .exists(),
        "the leftover part file is still there"
    );
    restarted.stop().assert_graceful_shutdown();
}
