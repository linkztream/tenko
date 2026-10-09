//! Validation of a manifest before the plugin starts.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::path::Path;

use serde_json::Value;

use super::settings::{is_hostname, is_identifier, quote, validate_settings_schema};
use super::{
    Capability, Entry, MANIFEST_VERSION, Manifest, ManifestError, ManifestProblem, NetworkTarget,
};

/// Longest plugin name.
const MAX_NAME_CHARS: usize = 63;
/// Longest version string.
const MAX_VERSION_CHARS: usize = 64;
/// Longest description of a manifest, a secret or a network target.
const MAX_DESCRIPTION_CHARS: usize = 500;
/// Longest homepage.
const MAX_HOMEPAGE_CHARS: usize = 2_048;
/// Longest licence expression.
const MAX_LICENSE_CHARS: usize = 100;
/// Most secrets a plugin declares.
const MAX_SECRETS: usize = 16;
/// Most network targets a plugin declares.
const MAX_NETWORK_TARGETS: usize = 32;
/// Longest relative path or interpreter of an entry.
const MAX_PATH_CHARS: usize = 1_024;
/// Most arguments of an entry.
const MAX_ARGS: usize = 64;
/// Longest argument of an entry.
const MAX_ARG_CHARS: usize = 4_096;
/// Allowed `defaults.poll_interval_secs`.
const POLL_INTERVAL_SECS: RangeInclusive<u32> = 60..=86_400;
/// Allowed `defaults.call_timeout_secs`.
const CALL_TIMEOUT_SECS: RangeInclusive<u32> = 1..=600;

/// Every rule that does not depend on the plugin directory.
pub(super) fn validate(manifest: &Manifest) -> Result<(), ManifestError> {
    finish(collect(manifest, None))
}

/// [`validate`] plus the rules of a plugin installed in `dir`.
pub(super) fn validate_installed(manifest: &Manifest, dir: &Path) -> Result<(), ManifestError> {
    finish(collect(manifest, Some(dir)))
}

fn finish(problems: Vec<ManifestProblem>) -> Result<(), ManifestError> {
    if problems.is_empty() {
        Ok(())
    } else {
        Err(ManifestError { problems })
    }
}

/// Every problem, in document order; the rules of an installed plugin when `dir` is given.
fn collect(manifest: &Manifest, dir: Option<&Path>) -> Vec<ManifestProblem> {
    let mut problems = Vec::new();
    check_identity(manifest, &mut problems);
    check_protocol(&manifest.protocol, &mut problems);
    check_capabilities(&manifest.capabilities, &mut problems);
    problems.extend(validate_settings_schema(&manifest.settings));
    check_secrets(manifest, &mut problems);
    check_network(manifest, &mut problems);
    check_platforms(&manifest.platforms, &mut problems);
    check_entry(manifest.entry.as_ref(), dir, &mut problems);
    check_defaults(manifest, &mut problems);
    problems
}

fn push(problems: &mut Vec<ManifestProblem>, path: impl Into<String>, message: impl Into<String>) {
    problems.push(ManifestProblem::new(path, message));
}

// ---------------------------------------------------------------------------------------
// Identity: format version, name, version, description, homepage, licence
// ---------------------------------------------------------------------------------------

fn check_identity(manifest: &Manifest, problems: &mut Vec<ManifestProblem>) {
    if manifest.manifest_version != MANIFEST_VERSION {
        push(
            problems,
            "/manifest_version",
            format!(
                "this host reads manifest version {MANIFEST_VERSION}, found {}",
                manifest.manifest_version
            ),
        );
    }
    if !is_plugin_name(&manifest.name) {
        push(
            problems,
            "/name",
            format!(
                "{} is not a plugin name: lowercase letters, digits and `-`, starting with a \
                 letter, at most {MAX_NAME_CHARS} characters",
                quote(&manifest.name)
            ),
        );
    }
    if !is_semver(&manifest.version) {
        push(
            problems,
            "/version",
            format!(
                "{} is not a semantic version: MAJOR.MINOR.PATCH with an optional `-prerelease` \
                 and `+build`, at most {MAX_VERSION_CHARS} characters",
                quote(&manifest.version)
            ),
        );
    }
    check_description(&manifest.description, "/description", problems);
    if manifest.description.chars().any(char::is_control) {
        push(
            problems,
            "/description",
            "the description must not contain control characters",
        );
    }
    if let Some(homepage) = &manifest.homepage {
        check_homepage(homepage, problems);
    }
    if let Some(license) = &manifest.license {
        check_license(license, problems);
    }
}

/// `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, at most 63 characters.
fn is_plugin_name(name: &str) -> bool {
    name.len() <= MAX_NAME_CHARS
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// Semantic versioning 2.0.0: `MAJOR.MINOR.PATCH`, an optional `-prerelease` and an optional
/// `+build`, at most 64 characters.
fn is_semver(text: &str) -> bool {
    if text.len() > MAX_VERSION_CHARS {
        return false;
    }
    let (without_build, build) = match text.split_once('+') {
        Some((head, build)) => (head, Some(build)),
        None => (text, None),
    };
    if build.is_some_and(|build| !build.split('.').all(is_build_identifier)) {
        return false;
    }
    let (core, prerelease) = match without_build.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (without_build, None),
    };
    if prerelease.is_some_and(|pre| !pre.split('.').all(is_prerelease_identifier)) {
        return false;
    }
    let mut parts = core.split('.');
    (0..3).all(|_| parts.next().is_some_and(is_numeric_identifier)) && parts.next().is_none()
}

/// Digits without a leading zero (except `0` itself).
fn is_numeric_identifier(part: &str) -> bool {
    !part.is_empty()
        && part.bytes().all(|b| b.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'))
}

/// A build identifier: ASCII letters, digits and `-`.
fn is_build_identifier(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A pre-release identifier: like a build identifier, but all-digit identifiers have no
/// leading zero.
fn is_prerelease_identifier(part: &str) -> bool {
    is_build_identifier(part)
        && (!part.bytes().all(|b| b.is_ascii_digit()) || is_numeric_identifier(part))
}

/// A non-empty text of at most 500 characters (the description of a manifest, a secret or a
/// network target).
fn check_description(text: &str, path: &str, problems: &mut Vec<ManifestProblem>) {
    if text.trim().is_empty() {
        push(problems, path, "the description must not be empty");
    }
    if text.chars().count() > MAX_DESCRIPTION_CHARS {
        push(
            problems,
            path,
            format!("the description is longer than {MAX_DESCRIPTION_CHARS} characters"),
        );
    }
}

fn check_homepage(homepage: &str, problems: &mut Vec<ManifestProblem>) {
    let path = "/homepage";
    if homepage.chars().count() > MAX_HOMEPAGE_CHARS {
        push(
            problems,
            path,
            format!("the homepage is longer than {MAX_HOMEPAGE_CHARS} characters"),
        );
    }
    if homepage
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        push(
            problems,
            path,
            "the homepage must not contain whitespace or control characters",
        );
    }
    match homepage
        .strip_prefix("https://")
        .or_else(|| homepage.strip_prefix("http://"))
    {
        None => push(
            problems,
            path,
            "the homepage must start with `https://` or `http://`",
        ),
        Some(rest) if !has_host(rest) => {
            push(problems, path, "the homepage needs a host after the scheme");
        }
        Some(_) => {}
    }
}

/// Whether the part of a URL after the scheme starts with a non-empty host (user information
/// and port aside).
fn has_host(rest: &str) -> bool {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_and_port = authority.rsplit('@').next().unwrap_or_default();
    let host = match host_and_port.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => host_and_port.split(':').next().unwrap_or_default(),
    };
    !host.is_empty()
}

fn check_license(license: &str, problems: &mut Vec<ManifestProblem>) {
    let path = "/license";
    if license.trim().is_empty() {
        push(problems, path, "the license must not be empty");
    }
    if license.chars().count() > MAX_LICENSE_CHARS {
        push(
            problems,
            path,
            format!("the license is longer than {MAX_LICENSE_CHARS} characters"),
        );
    }
    if !license
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '+' | '(' | ')' | '-'))
    {
        push(
            problems,
            path,
            "the license may only contain letters, digits, spaces and `.+()-`",
        );
    }
}

// ---------------------------------------------------------------------------------------
// Protocol and capabilities
// ---------------------------------------------------------------------------------------

fn check_protocol(protocol: &[u32], problems: &mut Vec<ManifestProblem>) {
    if protocol.is_empty() {
        push(
            problems,
            "/protocol",
            "the plugin must name at least one protocol version",
        );
    }
    let mut seen = HashSet::new();
    for (index, &version) in protocol.iter().enumerate() {
        let path = format!("/protocol/{index}");
        if version == 0 {
            push(problems, &path, "protocol versions start at 1");
        }
        if !seen.insert(version) {
            push(
                problems,
                &path,
                format!("protocol version {version} is listed twice"),
            );
        }
    }
}

fn check_capabilities(capabilities: &[Capability], problems: &mut Vec<ManifestProblem>) {
    if capabilities.is_empty() {
        push(
            problems,
            "/capabilities",
            "the plugin must implement at least one capability",
        );
    }
    let mut seen = HashSet::new();
    for (index, capability) in capabilities.iter().enumerate() {
        if !seen.insert(*capability) {
            push(
                problems,
                format!("/capabilities/{index}"),
                format!("`{}` is listed twice", capability.as_str()),
            );
        }
    }
    if let Some(index) = capabilities
        .iter()
        .position(|capability| *capability == Capability::Webhook)
        && !capabilities.contains(&Capability::Inventory)
    {
        push(
            problems,
            format!("/capabilities/{index}"),
            "`webhook` needs the `inventory` capability",
        );
    }
}

// ---------------------------------------------------------------------------------------
// Secrets and network targets
// ---------------------------------------------------------------------------------------

fn check_secrets(manifest: &Manifest, problems: &mut Vec<ManifestProblem>) {
    if manifest.secrets.len() > MAX_SECRETS {
        push(
            problems,
            "/secrets",
            format!(
                "a plugin declares at most {MAX_SECRETS} secrets, found {}",
                manifest.secrets.len()
            ),
        );
    }
    let mut seen = HashSet::new();
    for (index, secret) in manifest.secrets.iter().enumerate() {
        let path = format!("/secrets/{index}");
        if !is_identifier(&secret.purpose) {
            push(
                problems,
                format!("{path}/purpose"),
                format!(
                    "{} is not a secret purpose: lowercase letters, digits and `_`, starting \
                     with a letter, at most 64 characters",
                    quote(&secret.purpose)
                ),
            );
        }
        if !seen.insert(secret.purpose.as_str()) {
            push(
                problems,
                format!("{path}/purpose"),
                format!("{} is declared twice", quote(&secret.purpose)),
            );
        }
        check_description(
            &secret.description,
            &format!("{path}/description"),
            problems,
        );
    }
}

fn check_network(manifest: &Manifest, problems: &mut Vec<ManifestProblem>) {
    if manifest.network.len() > MAX_NETWORK_TARGETS {
        push(
            problems,
            "/network",
            format!(
                "a plugin declares at most {MAX_NETWORK_TARGETS} network targets, found {}",
                manifest.network.len()
            ),
        );
    }
    for (index, target) in manifest.network.iter().enumerate() {
        check_target(
            target,
            &manifest.settings,
            &format!("/network/{index}"),
            problems,
        );
    }
}

fn check_target(
    target: &NetworkTarget,
    settings: &Value,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    match (&target.setting, &target.host) {
        (Some(setting), None) => {
            check_target_setting(setting, settings, &format!("{path}/setting"), problems);
        }
        (None, Some(host)) => check_target_host(host, &format!("{path}/host"), problems),
        _ => push(
            problems,
            path,
            "a network target needs exactly one of `setting` and `host`",
        ),
    }
    for (index, &port) in target.ports.iter().enumerate() {
        if port == 0 {
            push(
                problems,
                format!("{path}/ports/{index}"),
                "ports start at 1",
            );
        }
    }
    check_description(
        &target.description,
        &format!("{path}/description"),
        problems,
    );
}

/// A JSON pointer `/<name>` to a string setting of the settings schema.
fn check_target_setting(
    setting: &str,
    settings: &Value,
    path: &str,
    problems: &mut Vec<ManifestProblem>,
) {
    let Some(name) = setting
        .strip_prefix('/')
        .filter(|name| !name.is_empty() && !name.contains('/'))
    else {
        push(
            problems,
            path,
            format!("{} is not a pointer of the form `/name`", quote(setting)),
        );
        return;
    };
    match settings.get("properties").and_then(|props| props.get(name)) {
        None => push(
            problems,
            path,
            format!(
                "{} names no property of the settings schema",
                quote(setting)
            ),
        ),
        Some(property) if property.get("type").and_then(Value::as_str) != Some("string") => {
            push(
                problems,
                path,
                format!(
                    "{} is not a string setting: a network target takes its address from a \
                     setting of type `string`",
                    quote(setting)
                ),
            );
        }
        Some(_) => {}
    }
}

/// A host name or an IP address.
fn check_target_host(host: &str, path: &str, problems: &mut Vec<ManifestProblem>) {
    if !is_hostname(host) && host.parse::<IpAddr>().is_err() {
        push(
            problems,
            path,
            format!("{} is not a host name or an IP address", quote(host)),
        );
    }
}

// ---------------------------------------------------------------------------------------
// Platforms
// ---------------------------------------------------------------------------------------

fn check_platforms(platforms: &[String], problems: &mut Vec<ManifestProblem>) {
    if platforms.is_empty() {
        push(
            problems,
            "/platforms",
            "the plugin must name at least one platform: `any` or `<os>-<arch>`",
        );
    }
    let mut seen = HashSet::new();
    for (index, platform) in platforms.iter().enumerate() {
        let path = format!("/platforms/{index}");
        if !is_platform(platform) {
            push(
                problems,
                &path,
                format!(
                    "{} is not a platform: `any` or `<os>-<arch>` such as `linux-x86_64`",
                    quote(platform)
                ),
            );
        }
        if !seen.insert(platform.as_str()) {
            push(
                problems,
                path,
                format!("{} is listed twice", quote(platform)),
            );
        } else if platform == "any" && platforms.len() > 1 {
            push(problems, path, "`any` must be the only platform");
        }
    }
}

/// `any`, or `^[a-z0-9]+-[a-z0-9_]+$`.
fn is_platform(text: &str) -> bool {
    if text == "any" {
        return true;
    }
    let Some((os, arch)) = text.split_once('-') else {
        return false;
    };
    !os.is_empty()
        && os
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !arch.is_empty()
        && arch
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

// ---------------------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------------------

fn check_entry(entry: Option<&Entry>, dir: Option<&Path>, problems: &mut Vec<ManifestProblem>) {
    let Some(entry) = entry else {
        if dir.is_some() {
            push(problems, "/entry", "an installed plugin needs an entry");
        }
        return;
    };
    check_entry_shape(entry, problems);
    let executable = entry
        .executable
        .as_deref()
        .filter(|path| check_relative(path, "/entry/executable", problems));
    if let Some(interpreter) = entry.interpreter.as_deref()
        && let Some(message) = interpreter_problem(interpreter)
    {
        push(problems, "/entry/interpreter", message);
    }
    let script = entry
        .script
        .as_deref()
        .filter(|path| check_relative(path, "/entry/script", problems));
    check_args(&entry.args, problems);
    if let Some(dir) = dir {
        check_installed_files(dir, executable, script, problems);
    }
}

/// Exactly one of `executable` or the pair `interpreter` + `script`.
fn check_entry_shape(entry: &Entry, problems: &mut Vec<ManifestProblem>) {
    let executable = entry.executable.is_some();
    let interpreter = entry.interpreter.is_some();
    let script = entry.script.is_some();
    if executable && (interpreter || script) {
        push(
            problems,
            "/entry",
            "`executable` cannot be combined with `interpreter` or `script`",
        );
    } else if !executable && !interpreter && !script {
        push(
            problems,
            "/entry",
            "an entry needs an `executable`, or an `interpreter` with a `script`",
        );
    } else if interpreter && !script && !executable {
        push(
            problems,
            "/entry/script",
            "an `interpreter` needs a `script` to run",
        );
    } else if script && !interpreter && !executable {
        push(
            problems,
            "/entry/interpreter",
            "a `script` needs an `interpreter` to run it",
        );
    }
}

/// Reports a problem with a relative path; true when the path is fine.
fn check_relative(path: &str, pointer: &str, problems: &mut Vec<ManifestProblem>) -> bool {
    match relative_path_problem(path) {
        Some(message) => {
            push(problems, pointer, message);
            false
        }
        None => true,
    }
}

/// What is wrong with a relative path, if anything: non-empty, at most 1,024 characters, `/`
/// separators only, no leading `/`, no drive letter, no `.` or `..` and no empty component, no
/// NUL.
fn relative_path_problem(path: &str) -> Option<&'static str> {
    if path.is_empty() {
        return Some("the path must not be empty");
    }
    if path.chars().count() > MAX_PATH_CHARS {
        return Some("the path is longer than 1024 characters");
    }
    if path.contains('\0') {
        return Some("the path must not contain a NUL character");
    }
    if path.contains('\\') {
        return Some("the path must use `/` as separator, not `\\`");
    }
    if path.starts_with('/') {
        return Some("the path must be relative, without a leading `/`");
    }
    let mut chars = path.chars();
    if chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.next() == Some(':') {
        return Some("the path must be relative, without a drive letter");
    }
    for component in path.split('/') {
        if component.is_empty() {
            return Some("the path must not have an empty component (`//` or a trailing `/`)");
        }
        if component == "." || component == ".." {
            return Some("the path must not contain `.` or `..` components");
        }
    }
    None
}

/// What is wrong with an interpreter, if anything: a bare command name of
/// `[A-Za-z0-9._+-]` or an absolute path, no NUL.
fn interpreter_problem(interpreter: &str) -> Option<&'static str> {
    if interpreter.contains('\0') {
        return Some("the interpreter must not contain a NUL character");
    }
    if interpreter.chars().count() > MAX_PATH_CHARS {
        return Some("the interpreter is longer than 1024 characters");
    }
    if is_command_name(interpreter) || is_absolute_path(interpreter) {
        None
    } else {
        Some("the interpreter must be a command name such as `python3` or an absolute path")
    }
}

fn is_command_name(text: &str) -> bool {
    !matches!(text, "" | "." | "..")
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// `/usr/bin/python3` or `C:\Python312\python.exe` (also `C:/...`).
fn is_absolute_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    text.starts_with('/')
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

fn check_args(args: &[String], problems: &mut Vec<ManifestProblem>) {
    if args.len() > MAX_ARGS {
        push(
            problems,
            "/entry/args",
            format!(
                "an entry has at most {MAX_ARGS} arguments, found {}",
                args.len()
            ),
        );
    }
    for (index, arg) in args.iter().enumerate() {
        let path = format!("/entry/args/{index}");
        if arg.contains('\0') {
            push(
                problems,
                &path,
                "an argument must not contain a NUL character",
            );
        }
        if arg.chars().count() > MAX_ARG_CHARS {
            push(
                problems,
                &path,
                format!("an argument is longer than {MAX_ARG_CHARS} characters"),
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// Installed plugins
// ---------------------------------------------------------------------------------------

/// The executable or script exists in `dir` as a regular file and stays inside it. Only
/// paths that passed the relative-path rules reach this function.
fn check_installed_files(
    dir: &Path,
    executable: Option<&str>,
    script: Option<&str>,
    problems: &mut Vec<ManifestProblem>,
) {
    if executable.is_none() && script.is_none() {
        return;
    }
    let root = match dir.canonicalize() {
        Ok(root) => root,
        Err(error) => {
            push(
                problems,
                "/entry",
                format!("the plugin directory cannot be read: {error}"),
            );
            return;
        }
    };
    if let Some(executable) = executable {
        check_file(&root, executable, "/entry/executable", true, problems);
    }
    if let Some(script) = script {
        check_file(&root, script, "/entry/script", false, problems);
    }
}

/// One file of the plugin: it exists, resolves (through symbolic links) to a place inside
/// the canonical plugin directory `root`, is a regular file and, for an executable on Unix,
/// has an execute bit.
fn check_file(
    root: &Path,
    relative: &str,
    pointer: &str,
    executable: bool,
    problems: &mut Vec<ManifestProblem>,
) {
    let resolved = match root.join(relative).canonicalize() {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            push(
                problems,
                pointer,
                format!("{} does not exist in the plugin directory", quote(relative)),
            );
            return;
        }
        Err(error) => {
            push(
                problems,
                pointer,
                format!("{} cannot be resolved: {error}", quote(relative)),
            );
            return;
        }
    };
    if !resolved.starts_with(root) {
        push(
            problems,
            pointer,
            format!(
                "{} resolves to a place outside the plugin directory",
                quote(relative)
            ),
        );
        return;
    }
    let metadata = match resolved.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            push(
                problems,
                pointer,
                format!("{} cannot be read: {error}", quote(relative)),
            );
            return;
        }
    };
    if !metadata.is_file() {
        push(
            problems,
            pointer,
            format!("{} is not a regular file", quote(relative)),
        );
    } else if executable && !is_executable(&metadata) {
        push(
            problems,
            pointer,
            format!(
                "{} is not executable: it has no execute bit",
                quote(relative)
            ),
        );
    }
}

/// Whether any execute bit is set.
#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

/// Windows has no execute bit: any file may be started.
#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    true
}

// ---------------------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------------------

fn check_defaults(manifest: &Manifest, problems: &mut Vec<ManifestProblem>) {
    if let Some(secs) = manifest.defaults.poll_interval_secs
        && !POLL_INTERVAL_SECS.contains(&secs)
    {
        push(
            problems,
            "/defaults/poll_interval_secs",
            format!("the poll interval must be between 60 and 86,400 seconds, found {secs}"),
        );
    }
    if let Some(secs) = manifest.defaults.call_timeout_secs
        && !CALL_TIMEOUT_SECS.contains(&secs)
    {
        push(
            problems,
            "/defaults/call_timeout_secs",
            format!("the call timeout must be between 1 and 600 seconds, found {secs}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // -----------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------

    /// A valid manifest document.
    fn base() -> Value {
        json!({
            "manifest_version": 1,
            "name": "sample",
            "version": "0.1.0",
            "description": "Sample inventory source with documentation data",
            "protocol": [1],
            "capabilities": ["inventory"],
            "settings": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "format": "uri", "title": "Address" },
                    "site": { "type": "string", "default": "lab" }
                },
                "required": ["url"]
            },
            "secrets": [{ "purpose": "api_key", "description": "API key", "required": true }],
            "network": [{ "setting": "/url", "description": "The source system" }],
            "platforms": ["any"],
            "entry": { "executable": "bin/sample-plugin" }
        })
    }

    /// The base manifest with the top-level members of `patch` replaced (`null` removes one).
    fn manifest(patch: &Value) -> Manifest {
        let mut document = base();
        let members = document.as_object_mut().expect("the base is an object");
        for (key, value) in patch.as_object().expect("the patch is an object") {
            if value.is_null() {
                members.remove(key);
            } else {
                members.insert(key.clone(), value.clone());
            }
        }
        serde_json::from_value(document).expect("a manifest that deserializes")
    }

    fn problems(patch: &Value) -> Vec<ManifestProblem> {
        validate(&manifest(patch))
            .err()
            .map(|error| error.problems)
            .unwrap_or_default()
    }

    fn paths(patch: &Value) -> Vec<String> {
        problems(patch)
            .into_iter()
            .map(|problem| problem.path)
            .collect()
    }

    #[track_caller]
    fn assert_valid(patch: &Value) {
        let found = problems(patch);
        assert!(found.is_empty(), "unexpected problems: {found:#?}");
    }

    /// Some problem is at `pointer` and its message contains `fragment`.
    #[track_caller]
    fn assert_problem(patch: &Value, pointer: &str, fragment: &str) {
        let found = problems(patch);
        assert!(
            found
                .iter()
                .any(|problem| problem.path == pointer && problem.message.contains(fragment)),
            "no problem at {pointer} containing {fragment:?} in {found:#?}"
        );
    }

    /// The only problem is at `pointer` and its message contains `fragment`.
    #[track_caller]
    fn assert_only_problem(patch: &Value, pointer: &str, fragment: &str) {
        assert_problem(patch, pointer, fragment);
        let found = problems(patch);
        assert_eq!(found.len(), 1, "more than one problem: {found:#?}");
    }

    // -----------------------------------------------------------------------------------
    // The whole manifest
    // -----------------------------------------------------------------------------------

    #[test]
    fn the_base_manifest_is_valid() {
        assert_valid(&json!({}));
    }

    #[test]
    fn the_documented_example_is_valid() {
        let example = br#"{
            "manifest_version": 1,
            "name": "sample",
            "version": "0.1.0",
            "description": "Sample inventory source with documentation data",
            "protocol": [1],
            "capabilities": ["inventory"],
            "settings": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "format": "uri", "title": "Address" },
                    "site": { "type": "string", "default": "lab" }
                },
                "required": ["url"]
            },
            "secrets": [{ "purpose": "api_key", "description": "API key", "required": true }],
            "network": [{ "setting": "/url", "description": "The source system" }],
            "platforms": ["any"],
            "entry": { "executable": "bin/sample-plugin" }
        }"#;
        Manifest::parse(example).expect("the documented example is valid");
    }

    #[test]
    fn a_fully_populated_manifest_is_valid() {
        assert_valid(&json!({
            "homepage": "https://example.org/tenko/sample",
            "license": "MIT OR Apache-2.0",
            "protocol": [1, 2],
            "capabilities": ["inventory", "webhook", "network_controller", "actuator", "migration"],
            "secrets": [
                { "purpose": "api_key", "description": "API key" },
                { "purpose": "password", "description": "Password", "required": false }
            ],
            "network": [
                { "setting": "/url", "ports": [8443], "description": "The controller" },
                { "host": "api.example.com", "ports": [443], "description": "A cloud service" },
                { "host": "192.0.2.10", "description": "A fixed address" },
                { "host": "2001:db8::10", "description": "A fixed IPv6 address" }
            ],
            "platforms": ["linux-x86_64", "linux-aarch64", "windows-x86_64"],
            "entry": {
                "interpreter": "python3",
                "script": "main.py",
                "args": ["--quiet", "--config=plugin.toml"]
            },
            "defaults": { "poll_interval_secs": 600, "call_timeout_secs": 60 }
        }));
    }

    #[test]
    fn a_manifest_without_an_entry_is_valid_for_a_bundled_plugin() {
        assert_valid(&json!({ "entry": null }));
    }

    #[test]
    fn several_problems_are_collected_in_document_order() {
        let patch = json!({
            "manifest_version": 3,
            "name": "Bad",
            "version": "x",
            "description": " ",
            "protocol": [],
            "capabilities": [],
            "settings": { "type": "string" },
            "secrets": [{ "purpose": "Api", "description": "" }],
            "network": [{ "description": "nothing" }],
            "platforms": [],
            "entry": {},
            "defaults": { "poll_interval_secs": 1 }
        });
        assert_eq!(
            paths(&patch),
            [
                "/manifest_version",
                "/name",
                "/version",
                "/description",
                "/protocol",
                "/capabilities",
                "/settings/type",
                "/secrets/0/purpose",
                "/secrets/0/description",
                "/network/0",
                "/platforms",
                "/entry",
                "/defaults/poll_interval_secs",
            ]
        );
    }

    #[test]
    fn the_error_lists_every_problem() {
        let error =
            validate(&manifest(&json!({ "name": "Bad", "version": "x" }))).expect_err("invalid");
        assert_eq!(error.problems.len(), 2);
        let text = error.to_string();
        assert!(text.contains("/name: "), "{text}");
        assert!(text.contains("/version: "), "{text}");
    }

    // -----------------------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------------------

    #[test]
    fn only_manifest_version_1_is_read() {
        assert_only_problem(
            &json!({ "manifest_version": 2 }),
            "/manifest_version",
            "reads manifest version 1, found 2",
        );
        assert_only_problem(
            &json!({ "manifest_version": 0 }),
            "/manifest_version",
            "found 0",
        );
    }

    #[test]
    fn plugin_names_are_lowercase_words_joined_by_single_hyphens() {
        let longest = "a".repeat(63);
        for name in [
            "a",
            "unifi",
            "network-controller",
            "a1-b2-c3",
            "x9",
            longest.as_str(),
        ] {
            assert_valid(&json!({ "name": name }));
        }
        let too_long = "a".repeat(64);
        for name in [
            "",
            "Unifi",
            "1abc",
            "-a",
            "a-",
            "a--b",
            "a_b",
            "a b",
            "a.b",
            "ä",
            too_long.as_str(),
        ] {
            assert_only_problem(&json!({ "name": name }), "/name", "is not a plugin name");
        }
    }

    #[test]
    fn the_name_message_names_the_rule() {
        let found = problems(&json!({ "name": "Unifi" }));
        assert_eq!(
            found[0].message,
            "`Unifi` is not a plugin name: lowercase letters, digits and `-`, starting with a \
             letter, at most 63 characters"
        );
    }

    #[test]
    fn versions_follow_semantic_versioning() {
        let longest = format!("1.0.0-{}", "a".repeat(58));
        for version in [
            "0.0.0",
            "1.2.3",
            "10.20.30",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-0.3.7",
            "1.0.0-x.7.z.92",
            "1.0.0-x-y-z.-",
            "1.0.0-0a",
            "1.0.0+20130313144700",
            "1.0.0-beta+exp.sha.5114f85",
            "1.0.0+21AF26D3----117B344092BD",
            "1.0.0+001",
            longest.as_str(),
        ] {
            assert_valid(&json!({ "version": version }));
        }
        let too_long = format!("1.0.0-{}", "a".repeat(59));
        for version in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-",
            "1.2.3-01",
            "1.2.3-alpha..1",
            "1.2.3-.alpha",
            "1.2.3+",
            "1.2.3+build..1",
            "1.2.3+a+b",
            "v1.2.3",
            "-1.2.3",
            "1.2.a",
            "1.2.3 ",
            "1.2.3-alpha_1",
            "1.2.3-ä",
            ">=1.0.0",
            too_long.as_str(),
        ] {
            assert_only_problem(
                &json!({ "version": version }),
                "/version",
                "semantic version",
            );
        }
    }

    #[test]
    fn descriptions_are_short_non_empty_text_without_control_characters() {
        assert_valid(&json!({ "description": "d".repeat(500) }));
        assert_valid(&json!({ "description": "Zwei Sätze. Und ein Ünicode-Zeichen." }));
        assert_only_problem(
            &json!({ "description": "" }),
            "/description",
            "must not be empty",
        );
        assert_only_problem(
            &json!({ "description": "    " }),
            "/description",
            "must not be empty",
        );
        assert_only_problem(
            &json!({ "description": "d".repeat(501) }),
            "/description",
            "longer than 500 characters",
        );
        assert_only_problem(
            &json!({ "description": "line one\nline two" }),
            "/description",
            "control characters",
        );
    }

    #[test]
    fn description_limits_count_characters() {
        assert_valid(&json!({ "description": "ä".repeat(500) }));
    }

    #[test]
    fn homepages_are_http_urls_with_a_host() {
        for homepage in [
            "https://example.com",
            "http://example.org/path?x=1#y",
            "https://example.net:8443/docs",
            "https://user@example.com/x",
            "https://[2001:db8::1]/x",
        ] {
            assert_valid(&json!({ "homepage": homepage }));
        }
        let longest = format!("https://example.com/{}", "a".repeat(2048 - 20));
        assert_eq!(longest.len(), 2048);
        assert_valid(&json!({ "homepage": longest }));
        assert_only_problem(
            &json!({ "homepage": format!("{longest}a") }),
            "/homepage",
            "longer than 2048",
        );
        for homepage in [
            "ftp://example.com",
            "example.com",
            "HTTPS://example.com",
            "mailto:a@b",
        ] {
            assert_only_problem(
                &json!({ "homepage": homepage }),
                "/homepage",
                "must start with",
            );
        }
        for homepage in [
            "https://",
            "http:///path",
            "https://@/x",
            "https://:8443/",
            "https://?q",
        ] {
            assert_only_problem(
                &json!({ "homepage": homepage }),
                "/homepage",
                "needs a host",
            );
        }
        for homepage in [
            "https://example.com/a b",
            "https://example.com/\n",
            "https://exa\tmple.com",
        ] {
            assert_only_problem(&json!({ "homepage": homepage }), "/homepage", "whitespace");
        }
    }

    #[test]
    fn licenses_are_short_expressions() {
        for license in [
            "MIT",
            "Apache-2.0",
            "MIT OR Apache-2.0",
            "(MIT OR Apache-2.0) AND BSD-3-Clause",
            "GPL-2.0+",
        ] {
            assert_valid(&json!({ "license": license }));
        }
        assert_valid(&json!({ "license": "L".repeat(100) }));
        assert_only_problem(&json!({ "license": "" }), "/license", "must not be empty");
        assert_only_problem(
            &json!({ "license": "   " }),
            "/license",
            "must not be empty",
        );
        assert_only_problem(
            &json!({ "license": "L".repeat(101) }),
            "/license",
            "longer than 100",
        );
        for license in ["MIT/X11", "MIT;", "Ünlicense", "MIT\n"] {
            assert_only_problem(
                &json!({ "license": license }),
                "/license",
                "may only contain",
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // Protocol and capabilities
    // -----------------------------------------------------------------------------------

    #[test]
    fn protocol_versions_are_a_unique_non_empty_list_from_1() {
        assert_valid(&json!({ "protocol": [1, 2, 7] }));
        assert_only_problem(&json!({ "protocol": [] }), "/protocol", "at least one");
        assert_only_problem(&json!({ "protocol": [0] }), "/protocol/0", "start at 1");
        assert_only_problem(
            &json!({ "protocol": [1, 2, 1] }),
            "/protocol/2",
            "listed twice",
        );
        assert_problem(
            &json!({ "protocol": [0, 0] }),
            "/protocol/1",
            "listed twice",
        );
    }

    #[test]
    fn capabilities_are_a_unique_non_empty_list() {
        assert_valid(&json!({ "capabilities": ["actuator"] }));
        assert_valid(&json!({ "capabilities": ["migration", "network_controller"] }));
        assert_only_problem(
            &json!({ "capabilities": [] }),
            "/capabilities",
            "at least one",
        );
        assert_only_problem(
            &json!({ "capabilities": ["inventory", "actuator", "inventory"] }),
            "/capabilities/2",
            "`inventory` is listed twice",
        );
    }

    #[test]
    fn webhook_requires_inventory() {
        assert_valid(&json!({ "capabilities": ["inventory", "webhook"] }));
        assert_valid(&json!({ "capabilities": ["webhook", "inventory"] }));
        assert_only_problem(
            &json!({ "capabilities": ["webhook"] }),
            "/capabilities/0",
            "`webhook` needs the `inventory` capability",
        );
        assert_only_problem(
            &json!({ "capabilities": ["actuator", "webhook"] }),
            "/capabilities/1",
            "needs the `inventory`",
        );
    }

    // -----------------------------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------------------------

    #[test]
    fn settings_problems_are_reported_under_settings() {
        assert_only_problem(
            &json!({ "settings": { "type": "string" }, "network": [] }),
            "/settings/type",
            "object",
        );
        assert_only_problem(
            &json!({
                "settings": { "type": "object", "properties": { "password": { "type": "string" } } },
                "network": []
            }),
            "/settings/properties/password",
            "secrets are declared in `secrets` and injected per call, never stored in settings",
        );
    }

    #[test]
    fn the_settings_schema_may_be_absent() {
        let document = json!({
            "manifest_version": 1,
            "name": "plain",
            "version": "1.0.0",
            "description": "A plugin without settings",
            "protocol": [1],
            "capabilities": ["actuator"],
            "platforms": ["any"]
        });
        let manifest: Manifest = serde_json::from_value(document).expect("a manifest");
        validate(&manifest).expect("the default settings schema is valid");
    }

    // -----------------------------------------------------------------------------------
    // Secrets
    // -----------------------------------------------------------------------------------

    fn secret(purpose: &str) -> Value {
        json!({ "purpose": purpose, "description": "A secret" })
    }

    #[test]
    fn secret_purposes_are_identifiers() {
        let longest = "a".repeat(64);
        for purpose in ["api_key", "password", "a", "token2", longest.as_str()] {
            assert_valid(&json!({ "secrets": [secret(purpose)] }));
        }
        let too_long = "a".repeat(65);
        for purpose in [
            "",
            "Api",
            "1a",
            "_a",
            "api-key",
            "api key",
            "ä",
            too_long.as_str(),
        ] {
            assert_only_problem(
                &json!({ "secrets": [secret(purpose)] }),
                "/secrets/0/purpose",
                "is not a secret purpose",
            );
        }
    }

    #[test]
    fn secret_purposes_are_unique() {
        assert_only_problem(
            &json!({ "secrets": [secret("a"), secret("b"), secret("a")] }),
            "/secrets/2/purpose",
            "`a` is declared twice",
        );
    }

    #[test]
    fn secret_descriptions_are_short_non_empty_text() {
        let described =
            |text: &str| json!({ "secrets": [{ "purpose": "a", "description": text }] });
        assert_valid(&described(&"d".repeat(500)));
        assert_only_problem(
            &described(""),
            "/secrets/0/description",
            "must not be empty",
        );
        assert_only_problem(
            &described("  "),
            "/secrets/0/description",
            "must not be empty",
        );
        assert_only_problem(
            &described(&"d".repeat(501)),
            "/secrets/0/description",
            "longer than 500",
        );
    }

    #[test]
    fn at_most_16_secrets() {
        let sixteen: Vec<Value> = (0..16).map(|index| secret(&format!("s{index}"))).collect();
        assert_valid(&json!({ "secrets": sixteen }));
        let seventeen: Vec<Value> = (0..17).map(|index| secret(&format!("s{index}"))).collect();
        assert_only_problem(&json!({ "secrets": seventeen }), "/secrets", "at most 16");
    }

    // -----------------------------------------------------------------------------------
    // Network targets
    // -----------------------------------------------------------------------------------

    fn target(extra: &Value) -> Value {
        let mut target = json!({ "description": "A target" });
        for (key, value) in extra.as_object().expect("object") {
            target[key] = value.clone();
        }
        target
    }

    #[test]
    fn a_target_has_exactly_one_of_setting_and_host() {
        assert_valid(&json!({ "network": [target(&json!({ "setting": "/url" }))] }));
        assert_valid(&json!({ "network": [target(&json!({ "host": "example.com" }))] }));
        assert_only_problem(
            &json!({ "network": [target(&json!({}))] }),
            "/network/0",
            "exactly one of `setting` and `host`",
        );
        assert_only_problem(
            &json!({ "network": [target(&json!({ "setting": "/url", "host": "example.com" }))] }),
            "/network/0",
            "exactly one of `setting` and `host`",
        );
    }

    #[test]
    fn a_setting_target_names_a_string_setting() {
        let settings = json!({
            "type": "object",
            "properties": {
                "url": { "type": "string" },
                "port": { "type": "integer" },
                "hosts": { "type": "array", "items": { "type": "string" } }
            }
        });
        let with = |setting: &str| json!({ "settings": settings, "network": [target(&json!({ "setting": setting }))] });
        assert_valid(&with("/url"));
        assert_only_problem(&with("/nope"), "/network/0/setting", "names no property");
        assert_only_problem(&with("/port"), "/network/0/setting", "not a string setting");
        assert_only_problem(
            &with("/hosts"),
            "/network/0/setting",
            "not a string setting",
        );
        for pointer in ["url", "", "/", "/a/b", "/url/", "#/url"] {
            assert_only_problem(
                &with(pointer),
                "/network/0/setting",
                "pointer of the form `/name`",
            );
        }
    }

    #[test]
    fn a_host_target_is_a_host_name_or_an_ip_address() {
        let longest = format!("{}a", "a.".repeat(126));
        for host in [
            "example.com",
            "api.example.org.",
            "a",
            "192.0.2.10",
            "2001:db8::10",
            "::1",
            "my-host.test",
            longest.as_str(),
        ] {
            assert_valid(&json!({ "network": [target(&json!({ "host": host }))] }));
        }
        let long_label = "a".repeat(64);
        let too_long = format!("{longest}.a");
        for host in [
            "",
            "-a.example.com",
            "a-.example.com",
            "a..example.com",
            "a_b.example.com",
            "a b",
            "https://example.com",
            "example.com:443",
            "[2001:db8::1]",
            "192.0.2.256.5:80",
            long_label.as_str(),
            too_long.as_str(),
        ] {
            assert_only_problem(
                &json!({ "network": [target(&json!({ "host": host }))] }),
                "/network/0/host",
                "is not a host name or an IP address",
            );
        }
    }

    #[test]
    fn target_ports_start_at_1() {
        assert_valid(
            &json!({ "network": [target(&json!({ "setting": "/url", "ports": [1, 65535] }))] }),
        );
        assert_only_problem(
            &json!({ "network": [target(&json!({ "setting": "/url", "ports": [443, 0] }))] }),
            "/network/0/ports/1",
            "start at 1",
        );
    }

    #[test]
    fn target_descriptions_are_short_non_empty_text() {
        let described =
            |text: &str| json!({ "network": [{ "setting": "/url", "description": text }] });
        assert_valid(&described(&"d".repeat(500)));
        assert_only_problem(
            &described(""),
            "/network/0/description",
            "must not be empty",
        );
        assert_only_problem(
            &described(&"d".repeat(501)),
            "/network/0/description",
            "longer than 500",
        );
    }

    #[test]
    fn at_most_32_targets() {
        let one_target = target(&json!({ "setting": "/url" }));
        assert_valid(&json!({ "network": vec![one_target.clone(); 32] }));
        assert_only_problem(
            &json!({ "network": vec![one_target; 33] }),
            "/network",
            "at most 32",
        );
    }

    #[test]
    fn target_problems_carry_the_index_of_the_target() {
        let patch = json!({
            "network": [
                target(&json!({ "setting": "/url" })),
                target(&json!({ "host": "bad host" })),
                target(&json!({ "setting": "/nope" })),
            ]
        });
        assert_eq!(paths(&patch), ["/network/1/host", "/network/2/setting"]);
    }

    // -----------------------------------------------------------------------------------
    // Platforms
    // -----------------------------------------------------------------------------------

    #[test]
    fn platforms_are_any_or_os_and_arch() {
        assert_valid(&json!({ "platforms": ["any"] }));
        assert_valid(&json!({ "platforms": ["linux-x86_64", "windows-x86_64", "macos-aarch64"] }));
        assert_valid(&json!({ "platforms": ["freebsd-x86_64", "linux-riscv64"] }));
        for platform in [
            "",
            "linux",
            "Linux-x86_64",
            "linux_x86_64",
            "linux-",
            "-x86_64",
            "linux-x86-64",
            "linux-X86",
            "anything",
            "linux x86",
        ] {
            assert_only_problem(
                &json!({ "platforms": [platform] }),
                "/platforms/0",
                "is not a platform",
            );
        }
    }

    #[test]
    fn platforms_are_a_unique_non_empty_list() {
        assert_only_problem(&json!({ "platforms": [] }), "/platforms", "at least one");
        assert_only_problem(
            &json!({ "platforms": ["linux-x86_64", "linux-x86_64"] }),
            "/platforms/1",
            "listed twice",
        );
    }

    #[test]
    fn any_must_be_the_only_platform() {
        assert_only_problem(
            &json!({ "platforms": ["any", "linux-x86_64"] }),
            "/platforms/0",
            "`any` must be the only platform",
        );
        assert_only_problem(
            &json!({ "platforms": ["linux-x86_64", "any"] }),
            "/platforms/1",
            "`any` must be the only platform",
        );
    }

    // -----------------------------------------------------------------------------------
    // Entry
    // -----------------------------------------------------------------------------------

    #[test]
    fn an_entry_is_an_executable_or_an_interpreter_with_a_script() {
        assert_valid(&json!({ "entry": { "executable": "plugin" } }));
        assert_valid(&json!({ "entry": { "executable": "bin/plugin", "args": ["--x"] } }));
        assert_valid(&json!({ "entry": { "interpreter": "python3", "script": "main.py" } }));
        assert_only_problem(
            &json!({ "entry": {} }),
            "/entry",
            "needs an `executable`, or an `interpreter` with a `script`",
        );
        assert_only_problem(
            &json!({ "entry": { "args": ["--x"] } }),
            "/entry",
            "needs an `executable`",
        );
        assert_only_problem(
            &json!({ "entry": { "interpreter": "python3" } }),
            "/entry/script",
            "needs a `script`",
        );
        assert_only_problem(
            &json!({ "entry": { "script": "main.py" } }),
            "/entry/interpreter",
            "needs an `interpreter`",
        );
        assert_only_problem(
            &json!({ "entry": { "executable": "plugin", "script": "main.py" } }),
            "/entry",
            "cannot be combined",
        );
        assert_only_problem(
            &json!({ "entry": { "executable": "plugin", "interpreter": "python3" } }),
            "/entry",
            "cannot be combined",
        );
    }

    #[test]
    fn entry_paths_are_clean_relative_paths() {
        let longest = "a".repeat(1024);
        for path in [
            "plugin",
            "bin/plugin",
            "a/b/c.py",
            ".hidden/x",
            "a.b/c..d",
            "dir.d/x",
            longest.as_str(),
        ] {
            assert_valid(&json!({ "entry": { "executable": path } }));
            assert_valid(&json!({ "entry": { "interpreter": "node", "script": path } }));
        }
        let too_long = "a".repeat(1025);
        let cases = [
            ("", "must not be empty"),
            ("a/../b", "`.` or `..`"),
            ("..", "`.` or `..`"),
            ("../x", "`.` or `..`"),
            ("./x", "`.` or `..`"),
            ("a/./b", "`.` or `..`"),
            ("/etc/passwd", "leading `/`"),
            ("C:/x", "drive letter"),
            ("c:x", "drive letter"),
            ("a\\b", "not `\\`"),
            ("C:\\x", "not `\\`"),
            ("a//b", "empty component"),
            ("a/", "empty component"),
            ("a\0b", "NUL"),
            (too_long.as_str(), "longer than 1024"),
        ];
        for (path, fragment) in cases {
            assert_only_problem(
                &json!({ "entry": { "executable": path } }),
                "/entry/executable",
                fragment,
            );
            assert_only_problem(
                &json!({ "entry": { "interpreter": "node", "script": path } }),
                "/entry/script",
                fragment,
            );
        }
    }

    #[test]
    fn interpreters_are_command_names_or_absolute_paths() {
        let longest = format!("/{}", "a".repeat(1023));
        for interpreter in [
            "python3",
            "node",
            "python3.12",
            "g++",
            "my-tool_2",
            "/usr/bin/python3",
            "C:\\Python312\\python.exe",
            "C:/Python312/python.exe",
            longest.as_str(),
        ] {
            assert_valid(&json!({ "entry": { "interpreter": interpreter, "script": "main.py" } }));
        }
        let too_long = format!("/{}", "a".repeat(1024));
        for interpreter in [
            "",
            ".",
            "..",
            "py thon",
            "bin/python3",
            "./python3",
            "C:python",
            "\\\\server\\share\\python.exe",
            "python3\0",
            too_long.as_str(),
        ] {
            assert_only_problem(
                &json!({ "entry": { "interpreter": interpreter, "script": "main.py" } }),
                "/entry/interpreter",
                "interpreter",
            );
        }
    }

    #[test]
    fn entry_arguments_are_bounded() {
        let sixty_four: Vec<String> = (0..64).map(|index| format!("--a{index}")).collect();
        assert_valid(&json!({ "entry": { "executable": "p", "args": sixty_four } }));
        let sixty_five: Vec<String> = (0..65).map(|index| format!("--a{index}")).collect();
        assert_only_problem(
            &json!({ "entry": { "executable": "p", "args": sixty_five } }),
            "/entry/args",
            "at most 64",
        );
        assert_valid(&json!({ "entry": { "executable": "p", "args": ["a".repeat(4096)] } }));
        assert_only_problem(
            &json!({ "entry": { "executable": "p", "args": ["ok", "a".repeat(4097)] } }),
            "/entry/args/1",
            "longer than 4096",
        );
        assert_only_problem(
            &json!({ "entry": { "executable": "p", "args": ["a\0b"] } }),
            "/entry/args/0",
            "NUL",
        );
    }

    // -----------------------------------------------------------------------------------
    // Defaults
    // -----------------------------------------------------------------------------------

    #[test]
    fn the_poll_interval_is_between_one_minute_and_one_day() {
        for secs in [60, 300, 86_400] {
            assert_valid(&json!({ "defaults": { "poll_interval_secs": secs } }));
        }
        for secs in [0, 59, 86_401] {
            assert_only_problem(
                &json!({ "defaults": { "poll_interval_secs": secs } }),
                "/defaults/poll_interval_secs",
                "between 60 and 86,400",
            );
        }
    }

    #[test]
    fn the_call_timeout_is_between_one_second_and_ten_minutes() {
        for secs in [1, 30, 600] {
            assert_valid(&json!({ "defaults": { "call_timeout_secs": secs } }));
        }
        for secs in [0, 601] {
            assert_only_problem(
                &json!({ "defaults": { "call_timeout_secs": secs } }),
                "/defaults/call_timeout_secs",
                "between 1 and 600",
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // Installed plugins
    // -----------------------------------------------------------------------------------

    /// Writes a file below `dir`, executable on Unix when asked.
    fn write_file(dir: &Path, relative: &str, executable: bool) {
        let path = dir.join(relative);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("create directories");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write the file");
        set_mode(&path, executable);
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, executable: bool) {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[cfg(not(unix))]
    fn set_mode(_path: &Path, _executable: bool) {}

    fn installed(patch: &Value, dir: &Path) -> Vec<ManifestProblem> {
        validate_installed(&manifest(patch), dir)
            .err()
            .map(|error| error.problems)
            .unwrap_or_default()
    }

    #[test]
    fn an_installed_plugin_needs_an_entry() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let patch = json!({ "entry": null });
        validate(&manifest(&patch)).expect("valid as a bundled plugin");
        let found = installed(&patch, dir.path());
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/entry");
        assert_eq!(found[0].message, "an installed plugin needs an entry");
    }

    #[test]
    fn a_missing_executable_is_reported() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let found = installed(&json!({}), dir.path());
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/entry/executable");
        assert!(
            found[0].message.contains("does not exist"),
            "{}",
            found[0].message
        );
        assert!(
            found[0].message.contains("bin/sample-plugin"),
            "{}",
            found[0].message
        );
    }

    #[test]
    fn an_existing_executable_passes() {
        let dir = tempfile::tempdir().expect("temporary directory");
        write_file(dir.path(), "bin/sample-plugin", true);
        let found = installed(&json!({}), dir.path());
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn a_script_must_exist_but_needs_no_execute_bit() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let patch = json!({ "entry": { "interpreter": "python3", "script": "lib/main.py" } });
        let found = installed(&patch, dir.path());
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/entry/script");
        assert!(found[0].message.contains("does not exist"));
        write_file(dir.path(), "lib/main.py", false);
        let found = installed(&patch, dir.path());
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let dir = tempfile::tempdir().expect("temporary directory");
        std::fs::create_dir_all(dir.path().join("bin/sample-plugin")).expect("create directories");
        let found = installed(&json!({}), dir.path());
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/entry/executable");
        assert!(
            found[0].message.contains("not a regular file"),
            "{}",
            found[0].message
        );
    }

    #[test]
    fn dot_dot_is_refused_without_looking_at_the_disk() {
        let parent = tempfile::tempdir().expect("temporary directory");
        let plugin = parent.path().join("plugin");
        std::fs::create_dir_all(&plugin).expect("create the plugin directory");
        write_file(parent.path(), "outside/tool", true);
        let patch = json!({ "entry": { "executable": "../outside/tool" } });
        let found = installed(&patch, &plugin);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/entry/executable");
        assert!(found[0].message.contains("`..`"), "{}", found[0].message);
    }

    #[test]
    fn an_absolute_path_is_refused_even_if_it_exists() {
        let dir = tempfile::tempdir().expect("temporary directory");
        write_file(dir.path(), "tool", true);
        let absolute = dir.path().join("tool").to_string_lossy().replace('\\', "/");
        let found = installed(&json!({ "entry": { "executable": absolute } }), dir.path());
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/entry/executable");
    }

    #[test]
    fn the_plugin_directory_must_be_readable() {
        let parent = tempfile::tempdir().expect("temporary directory");
        let missing = parent.path().join("missing");
        let found = installed(&json!({}), &missing);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/entry");
        assert!(
            found[0].message.contains("plugin directory"),
            "{}",
            found[0].message
        );
    }

    #[test]
    fn installed_problems_join_the_general_ones_in_document_order() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let patch = json!({ "name": "Bad", "defaults": { "call_timeout_secs": 0 } });
        let found = installed(&patch, dir.path());
        let found_paths: Vec<&str> = found.iter().map(|problem| problem.path.as_str()).collect();
        assert_eq!(
            found_paths,
            ["/name", "/entry/executable", "/defaults/call_timeout_secs"]
        );
    }

    #[test]
    fn a_manifest_that_is_invalid_for_any_plugin_is_invalid_when_installed() {
        let dir = tempfile::tempdir().expect("temporary directory");
        write_file(dir.path(), "bin/sample-plugin", true);
        let found = installed(&json!({ "version": "one" }), dir.path());
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/version");
    }

    #[cfg(unix)]
    #[test]
    fn an_executable_needs_an_execute_bit() {
        let dir = tempfile::tempdir().expect("temporary directory");
        write_file(dir.path(), "bin/sample-plugin", false);
        let found = installed(&json!({}), dir.path());
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/entry/executable");
        assert!(
            found[0].message.contains("not executable"),
            "{}",
            found[0].message
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_directory_is_refused() {
        let parent = tempfile::tempdir().expect("temporary directory");
        let plugin = parent.path().join("plugin");
        std::fs::create_dir_all(&plugin).expect("create the plugin directory");
        write_file(parent.path(), "outside/tool", true);
        std::os::unix::fs::symlink(parent.path().join("outside/tool"), plugin.join("tool"))
            .expect("create a symbolic link");
        let patch = json!({ "entry": { "executable": "tool" } });
        let found = installed(&patch, &plugin);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path, "/entry/executable");
        assert!(
            found[0].message.contains("outside the plugin directory"),
            "{}",
            found[0].message
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_the_directory_is_fine() {
        let dir = tempfile::tempdir().expect("temporary directory");
        write_file(dir.path(), "real/tool", true);
        std::os::unix::fs::symlink(dir.path().join("real/tool"), dir.path().join("tool"))
            .expect("create a symbolic link");
        let patch = json!({ "entry": { "executable": "tool" } });
        let found = installed(&patch, dir.path());
        assert!(found.is_empty(), "{found:#?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_out_of_the_directory_is_refused() {
        let parent = tempfile::tempdir().expect("temporary directory");
        let plugin = parent.path().join("plugin");
        std::fs::create_dir_all(&plugin).expect("create the plugin directory");
        write_file(parent.path(), "outside/tool", true);
        std::os::unix::fs::symlink(parent.path().join("outside"), plugin.join("bin"))
            .expect("create a symbolic link");
        let patch = json!({ "entry": { "executable": "bin/tool" } });
        let found = installed(&patch, &plugin);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            found[0].message.contains("outside the plugin directory"),
            "{}",
            found[0].message
        );
    }
}
