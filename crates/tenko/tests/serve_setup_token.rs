//! Black-box tests of the first-run setup token: while setup is open every start prints
//! exactly one token on standard output (framed) and once in the log, a restart prints a
//! different one, failed attempts do not use the token up, and once `tenko setup` has
//! succeeded no token is printed any more.

mod serve_support;

use std::time::Duration;

use serve_support::{
    Node, is_setup_token, log_setup_tokens, stdout_setup_tokens, wait_for_setup_token,
};

/// The rule that frames the first-run block on standard output.
const RULE: &str = "========================================================================";

/// Starts a server on the node, waits for the whole token block, stops the server and
/// returns the token together with the complete output.
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

#[test]
fn each_start_prints_one_setup_token_and_a_restart_prints_another() {
    let mut node = Node::new();

    let (first, outcome) = start_read_and_stop(&mut node);
    assert!(is_setup_token(&first), "`{first}`");
    assert_eq!(
        stdout_setup_tokens(&outcome.stdout),
        std::slice::from_ref(&first),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        log_setup_tokens(&outcome.stderr),
        std::slice::from_ref(&first),
        "{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stdout.matches(&first).count(),
        1,
        "{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stderr.matches(&first).count(),
        1,
        "{}",
        outcome.stderr
    );

    // The token sits in a framed block that says what to do with it.
    let lines: Vec<&str> = outcome.stdout.lines().collect();
    let rules: Vec<usize> = (0..lines.len()).filter(|at| lines[*at] == RULE).collect();
    assert_eq!(rules.len(), 2, "{}", outcome.stdout);
    let at = lines
        .iter()
        .position(|line| line.starts_with("Setup token: "))
        .expect("the token line");
    assert!(
        rules[0] < at && at < rules[1],
        "the token is outside its frame\n{}",
        outcome.stdout
    );
    assert!(
        lines[rules[0]..rules[1]]
            .iter()
            .any(|line| line.contains("tenko setup --url")),
        "the block does not name the command\n{}",
        outcome.stdout
    );
    outcome.assert_stderr_contains("first-run setup is open");

    let (second, outcome) = start_read_and_stop(&mut node);
    assert!(is_setup_token(&second), "`{second}`");
    assert_ne!(first, second, "a restart must print a new token");
    assert_eq!(
        stdout_setup_tokens(&outcome.stdout),
        std::slice::from_ref(&second)
    );
    assert_eq!(
        log_setup_tokens(&outcome.stderr),
        std::slice::from_ref(&second)
    );
    assert!(
        !outcome.stdout.contains(&first) && !outcome.stderr.contains(&first),
        "the token of the earlier start is still printed\n{}",
        outcome.diagnostics()
    );
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

    // The refusal did not use up the current token.
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

    node.setup(&token)
        .assert_code(0)
        .assert_stdout_contains("setup complete");
    server.stop().assert_graceful_shutdown();
}

#[test]
fn no_token_is_printed_once_setup_is_complete() {
    let mut node = Node::new();
    let mut server = node.start();
    let token = wait_for_setup_token(&server);

    node.setup(&token).assert_code(0).assert_stdout_contains(
        "setup complete: profile home, administrator admin, host name localhost",
    );

    // Setup is closed for good, also for the token that just worked.
    let again = node.setup(&token);
    again.assert_code(5);
    again.assert_stderr_contains("error[auth.setup.closed]");
    server.stop().assert_graceful_shutdown();

    let mut restarted = node.start();
    let outcome = restarted.stop();
    outcome.assert_graceful_shutdown();
    assert!(
        stdout_setup_tokens(&outcome.stdout).is_empty(),
        "a token was printed after setup\n{}",
        outcome.stdout
    );
    assert!(
        !outcome.stdout.contains("First-run setup is open"),
        "{}",
        outcome.stdout
    );
    assert!(
        log_setup_tokens(&outcome.stderr).is_empty() && !outcome.stderr.contains("first-run setup"),
        "the log announces setup after it completed\n{}",
        outcome.stderr
    );
    assert!(
        !outcome.stdout.contains(&token) && !outcome.stderr.contains(&token),
        "the old token is printed again"
    );
    outcome.assert_stderr_contains("step 5/8 auth ready in ");
    outcome.assert_stderr_contains("installation localhost (profile home)");
}
