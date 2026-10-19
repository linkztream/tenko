//! `tenko config init`: writes a short `tenko.toml` from flags.
//!
//! Installers call it (the Windows MSI writes `%ProgramData%\Tenko\tenko.toml` with it), and
//! an administrator can use it instead of copying `deploy/tenko.example.toml`. The file holds
//! the keys the flags name and nothing else; every other key keeps its default. The text is
//! validated exactly as `tenko serve` would load it before it replaces anything.
//!
//! An empty flag value counts as not given, so an installer can pass every flag on each run
//! (`--host-name ""`) without building the command line from conditions.

use std::{
    fmt::Write as _,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

use clap::Args;

use crate::{config, exit};

/// The profiles the file accepts, as `[profile] name` spells them.
const PROFILES: [&str; 4] = ["home", "standard", "hardened", "lab"];

/// Arguments of `tenko config init`.
#[derive(Debug, Clone, Args)]
pub struct InitArgs {
    /// The file to write.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

    /// The data directory; made absolute.
    #[arg(long, value_name = "PATH")]
    pub data_dir: PathBuf,

    /// The roles of this node, for example `controller` or `controller,dns`.
    #[arg(long, value_name = "ROLES", default_value = "controller")]
    pub roles: String,

    /// The product modules (`ipam,dns`); empty or not given leaves the choice to first-run
    /// setup.
    #[arg(long, value_name = "LIST")]
    pub modules: Option<String>,

    /// The security profile before first-run setup: home, standard, hardened or lab.
    #[arg(long, value_name = "PROFILE", default_value = "home")]
    pub profile: String,

    /// The host name of the certificate until first-run setup stores one; `localhost` is
    /// added as an extra name.
    #[arg(long, value_name = "HOST")]
    pub host_name: Option<String>,

    /// IP addresses the dns role answers on, comma-separated; empty means every address.
    #[arg(long, value_name = "ADDRESSES")]
    pub dns_address: Option<String>,

    /// The port the dns role answers on.
    #[arg(long, value_name = "PORT")]
    pub dns_port: Option<String>,

    /// Leave an existing file alone and exit with status 0.
    #[arg(long, conflicts_with = "force")]
    pub if_missing: bool,

    /// Replace an existing file.
    #[arg(long)]
    pub force: bool,
}

/// The given, non-empty value of an optional flag.
fn given(value: Option<&String>) -> Option<&str> {
    value.map(|v| v.trim()).filter(|v| !v.is_empty())
}

/// A TOML string: a literal string when it can be one (Windows paths stay readable), a basic
/// string with escapes otherwise.
fn toml_string(text: &str) -> String {
    if !text.contains('\'') && !text.chars().any(char::is_control) {
        return format!("'{text}'");
    }
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A TOML array of strings.
fn toml_list<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let items: Vec<String> = items.into_iter().map(toml_string).collect();
    format!("[{}]", items.join(", "))
}

/// The socket addresses of the dns role: every address of both families by default.
fn dns_listen(addresses: Option<&str>, port: Option<&str>) -> Result<Vec<String>, String> {
    let port: u16 = match port {
        None => 53,
        Some(text) => match text.parse() {
            Ok(0) | Err(_) => {
                return Err(format!("--dns-port `{text}` is not a port (1 to 65535)"));
            }
            Ok(port) => port,
        },
    };
    let Some(addresses) = addresses else {
        return Ok(vec![format!("0.0.0.0:{port}"), format!("[::]:{port}")]);
    };
    let mut listen = Vec::new();
    for item in addresses
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let address: IpAddr = item
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| format!("--dns-address `{item}` is not an IP address"))?;
        listen.push(match address {
            IpAddr::V4(v4) => format!("{v4}:{port}"),
            IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        });
    }
    if listen.is_empty() {
        return dns_listen(None, Some(&port.to_string()));
    }
    Ok(listen)
}

/// The text of the file.
///
/// # Errors
///
/// A flag that cannot become a valid key, as a message.
pub fn render(args: &InitArgs, data_dir: &Path) -> Result<String, String> {
    let profile = args.profile.trim().to_ascii_lowercase();
    if !PROFILES.contains(&profile.as_str()) {
        return Err(format!(
            "--profile `{}` is not one of home, standard, hardened, lab",
            args.profile
        ));
    }
    let roles = args.roles.trim();
    let has_dns = roles
        .split(',')
        .any(|role| matches!(role.trim(), "dns" | "all"));
    let dns_address = given(args.dns_address.as_ref());
    let dns_port = given(args.dns_port.as_ref());

    let mut text = String::new();
    text.push_str("# tenko.toml, written by `tenko config init`.\n");
    text.push_str(
        "# Every key that is not here has its default; deploy/tenko.example.toml in the\n",
    );
    text.push_str("# source and the release documents them all. Check the file with\n");
    text.push_str("# `tenko config check --config <this file>`.\n\n");
    // Writing to a String cannot fail.
    let _ = writeln!(
        text,
        "data_dir = {}",
        toml_string(&data_dir.display().to_string())
    );
    let _ = writeln!(text, "roles = {}", toml_string(roles));
    if let Some(modules) = given(args.modules.as_ref()) {
        let names = modules.split(',').map(str::trim).filter(|s| !s.is_empty());
        let _ = writeln!(text, "modules = {}", toml_list(names));
    }
    let _ = writeln!(text, "\n[profile]\nname = {}", toml_string(&profile));
    if let Some(host) = given(args.host_name.as_ref()) {
        let _ = writeln!(text, "\n[tls]\nhost_name = {}", toml_string(host));
        if !host.eq_ignore_ascii_case("localhost") {
            text.push_str("alt_names = ['localhost']\n");
        }
    }
    if has_dns || dns_address.is_some() || dns_port.is_some() {
        let listen = dns_listen(dns_address, dns_port)?;
        let _ = writeln!(
            text,
            "\n[dns]\nlisten = {}",
            toml_list(listen.iter().map(String::as_str))
        );
    }
    Ok(text)
}

/// Validates the text as `tenko serve` loads a file, without environment overrides.
fn validate(path: &Path) -> Result<(), config::ConfigError> {
    let sources = config::Sources {
        file: Some(path.to_path_buf()),
        data_dir: None,
        roles: None,
    };
    config::load(&sources, std::iter::empty())?
        .config
        .resolve()?;
    Ok(())
}

/// Runs `tenko config init` and returns the exit status.
pub fn command(args: &InitArgs, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let target = args.out.display();
    if args.out.exists() && !args.force {
        if args.if_missing {
            let _ = writeln!(out, "kept {target}: the file exists");
            return exit::OK;
        }
        let _ = writeln!(
            err,
            "tenko config init: {target} exists; pass --force to replace it or --if-missing to keep it"
        );
        return exit::FAILURE;
    }
    if args.data_dir.as_os_str().is_empty() {
        let _ = writeln!(err, "tenko config init: --data-dir must not be empty");
        return exit::USAGE;
    }
    let data_dir = match std::path::absolute(&args.data_dir) {
        Ok(path) => path,
        Err(error) => {
            let _ = writeln!(
                err,
                "tenko config init: cannot make {} absolute: {error}",
                args.data_dir.display()
            );
            return exit::USAGE;
        }
    };
    let text = match render(args, &data_dir) {
        Ok(text) => text,
        Err(message) => {
            let _ = writeln!(err, "tenko config init: {message}");
            return exit::USAGE;
        }
    };
    if let Some(parent) = args.out.parent().filter(|p| !p.as_os_str().is_empty())
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        let _ = writeln!(
            err,
            "tenko config init: cannot create {}: {error}",
            parent.display()
        );
        return exit::FAILURE;
    }
    // Written aside, validated, then renamed over the target: a refused or half-written file
    // never takes the place of a working one.
    let mut staged = args.out.clone().into_os_string();
    staged.push(".new");
    let staged = PathBuf::from(staged);
    if let Err(error) = std::fs::write(&staged, &text) {
        let _ = writeln!(
            err,
            "tenko config init: cannot write {}: {error}",
            staged.display()
        );
        return exit::FAILURE;
    }
    if let Err(error) = validate(&staged) {
        let _ = std::fs::remove_file(&staged);
        let _ = writeln!(err, "tenko config init: the result is not valid: {error}");
        return exit::CONFIG;
    }
    if let Err(error) = std::fs::rename(&staged, &args.out) {
        let _ = std::fs::remove_file(&staged);
        let _ = writeln!(err, "tenko config init: cannot write {target}: {error}");
        return exit::FAILURE;
    }
    let _ = writeln!(out, "wrote {target}");
    exit::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(out: &Path, data_dir: &Path) -> InitArgs {
        InitArgs {
            out: out.to_path_buf(),
            data_dir: data_dir.to_path_buf(),
            roles: "controller".to_owned(),
            modules: None,
            profile: "home".to_owned(),
            host_name: None,
            dns_address: None,
            dns_port: None,
            if_missing: false,
            force: false,
        }
    }

    fn run(args: &InitArgs) -> (u8, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = command(args, &mut out, &mut err);
        (
            status,
            String::from_utf8(out).expect("UTF-8"),
            String::from_utf8(err).expect("UTF-8"),
        )
    }

    fn load(path: &Path) -> config::Resolved {
        let sources = config::Sources {
            file: Some(path.to_path_buf()),
            data_dir: None,
            roles: None,
        };
        config::load(&sources, std::iter::empty())
            .expect("loads")
            .config
            .resolve()
            .expect("resolves")
    }

    #[test]
    fn writes_a_file_that_loads() {
        let dir = tempfile::tempdir().expect("temp dir");
        let out = dir.path().join("conf").join("tenko.toml");
        let data = dir.path().join("data dir");
        let mut a = args(&out, &data);
        a.roles = "controller,dns".to_owned();
        a.modules = Some("ipam, dns".to_owned());
        a.profile = "Standard".to_owned();
        a.host_name = Some("ddi.example.test".to_owned());
        a.dns_address = Some("192.0.2.53, 2001:db8::53".to_owned());
        a.dns_port = Some("5353".to_owned());
        let (status, stdout, stderr) = run(&a);
        assert_eq!(status, exit::OK, "{stderr}");
        assert!(stdout.starts_with("wrote "), "{stdout}");
        let resolved = load(&out);
        assert_eq!(resolved.data_dir, data);
        assert_eq!(resolved.config.roles, "controller,dns");
        assert_eq!(
            resolved.config.dns.listen,
            vec!["192.0.2.53:5353", "[2001:db8::53]:5353"]
        );
        let text = std::fs::read_to_string(&out).expect("read");
        assert!(text.contains("modules = ['ipam', 'dns']"), "{text}");
        assert!(text.contains("name = 'standard'"), "{text}");
        assert!(text.contains("host_name = 'ddi.example.test'"), "{text}");
        assert!(!dir.path().join("conf").join("tenko.toml.new").exists());
    }

    #[test]
    fn empty_values_count_as_not_given() {
        let dir = tempfile::tempdir().expect("temp dir");
        let out = dir.path().join("tenko.toml");
        let mut a = args(&out, &dir.path().join("data"));
        a.modules = Some(String::new());
        a.host_name = Some(" ".to_owned());
        a.dns_address = Some(String::new());
        a.dns_port = Some(String::new());
        let (status, _, stderr) = run(&a);
        assert_eq!(status, exit::OK, "{stderr}");
        let text = std::fs::read_to_string(&out).expect("read");
        assert!(!text.contains("modules"), "{text}");
        assert!(!text.contains("[tls]"), "{text}");
        assert!(!text.contains("[dns]"), "{text}");
        assert!(load(&out).config.modules.is_none());
    }

    #[test]
    fn the_dns_role_listens_on_every_address_by_default() {
        let dir = tempfile::tempdir().expect("temp dir");
        let out = dir.path().join("tenko.toml");
        let mut a = args(&out, &dir.path().join("data"));
        a.roles = "controller,dns".to_owned();
        assert_eq!(run(&a).0, exit::OK);
        let text = std::fs::read_to_string(&out).expect("read");
        assert!(
            text.contains("listen = ['0.0.0.0:53', '[::]:53']"),
            "{text}"
        );
    }

    #[test]
    fn an_existing_file_is_kept_or_replaced_only_when_asked() {
        let dir = tempfile::tempdir().expect("temp dir");
        let out = dir.path().join("tenko.toml");
        std::fs::write(&out, "# mine\n").expect("write");
        let mut a = args(&out, &dir.path().join("data"));
        let (status, _, stderr) = run(&a);
        assert_eq!(status, exit::FAILURE);
        assert!(stderr.contains("--force"), "{stderr}");
        a.if_missing = true;
        let (status, stdout, _) = run(&a);
        assert_eq!(status, exit::OK);
        assert!(stdout.starts_with("kept "), "{stdout}");
        assert_eq!(std::fs::read_to_string(&out).expect("read"), "# mine\n");
        a.if_missing = false;
        a.force = true;
        assert_eq!(run(&a).0, exit::OK);
        assert!(
            std::fs::read_to_string(&out)
                .expect("read")
                .contains("data_dir")
        );
    }

    #[test]
    fn bad_values_are_refused_and_leave_nothing_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let out = dir.path().join("tenko.toml");
        for (change, status) in [
            (
                (|a: &mut InitArgs| a.profile = "open".to_owned()) as fn(&mut InitArgs),
                exit::USAGE,
            ),
            (|a| a.dns_port = Some("0".to_owned()), exit::USAGE),
            (
                |a| a.dns_address = Some("dns.example.test".to_owned()),
                exit::USAGE,
            ),
            (|a| a.roles = "controller,mail".to_owned(), exit::CONFIG),
            (|a| a.modules = Some("ipam,mail".to_owned()), exit::CONFIG),
        ] {
            let mut a = args(&out, &dir.path().join("data"));
            change(&mut a);
            let (got, _, stderr) = run(&a);
            assert_eq!(got, status, "{stderr}");
            assert!(!out.exists());
            assert!(!dir.path().join("tenko.toml.new").exists());
        }
    }

    #[test]
    fn strings_are_quoted_for_toml() {
        assert_eq!(
            toml_string(r"C:\ProgramData\Tenko"),
            r"'C:\ProgramData\Tenko'"
        );
        assert_eq!(toml_string(r"C:\it's"), r#""C:\\it's""#);
        let parsed: toml::Table =
            toml::from_str(&format!("a = {}", toml_string("x'\"\\\ty"))).expect("parses");
        assert_eq!(parsed["a"].as_str(), Some("x'\"\\\ty"));
    }
}
