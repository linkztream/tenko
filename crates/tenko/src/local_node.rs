//! The node a client command runs on, as far as its defaults
//! ([`crate::client::Target::resolve`]) need it: the address of the API and the internal CA
//! root under the data directory.
//!
//! The configuration is read leniently, as a plain TOML table with the `TENKO_*`
//! environment applied ([`config::apply_env`]): the client binary may be older than the
//! configuration, whose newer keys the strict parser of [`config::load`] refuses, and
//! nothing here is worth an error. A file that cannot be read or parsed is no node.

use std::{
    ffi::OsString,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use crate::config;

/// The variable that names the configuration file.
pub const CONFIG_ENV: &str = "TENKO_CONFIG";

/// Where the Linux installer and the systemd unit keep the configuration.
pub const DEFAULT_CONFIG: &str = "/etc/tenko/tenko.toml";

/// The internal CA root under the data directory.
pub const CA_ROOT: &str = "tls/ca-root.pem";

/// The configuration file of the node: `explicit` (`--config`), else the value of
/// `TENKO_CONFIG` as `var` returns it, else [`DEFAULT_CONFIG`] on Unix. Windows has no
/// default: the MSI passes the file to the service.
pub fn config_path(
    explicit: Option<&Path>,
    var: impl Fn(&str) -> Option<OsString>,
) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_owned());
    }
    if let Some(value) = var(CONFIG_ENV).filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(value));
    }
    cfg!(unix).then(|| PathBuf::from(DEFAULT_CONFIG))
}

/// What a command reads from the configuration of the node it runs on.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeConfig {
    /// The file that was read.
    pub file: PathBuf,
    table: toml::Table,
}

impl NodeConfig {
    /// Reads `file` and applies `env`; `None` when the file cannot be read or is not TOML
    /// (a client without access to the node's configuration).
    pub fn read(file: &Path, env: impl IntoIterator<Item = (String, String)>) -> Option<Self> {
        let text = std::fs::read_to_string(file).ok()?;
        Self::parse(file, &text, env)
    }

    /// The configuration `text` of `file` with `env` applied.
    pub fn parse(
        file: &Path,
        text: &str,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Option<Self> {
        let mut table: toml::Table = toml::from_str(text).ok()?;
        config::apply_env(&mut table, env).ok()?;
        Some(Self {
            file: file.to_owned(),
            table,
        })
    }

    /// The configuration of this node: the file of [`config_path`] with the process
    /// environment.
    pub fn discover(explicit: Option<&Path>) -> Option<Self> {
        let file = config_path(explicit, |name| std::env::var_os(name))?;
        Self::read(&file, std::env::vars())
    }

    /// `data_dir`, absolute, with `TENKO_DATA_DIR` applied.
    pub fn data_dir(&self) -> Option<PathBuf> {
        let dir = self.table.get("data_dir")?.as_str()?;
        if dir.is_empty() {
            return None;
        }
        std::path::absolute(dir).ok()
    }

    /// The TLS mode, `internal_ca` when the file names none.
    fn tls_mode(&self) -> &str {
        self.table
            .get("tls")
            .and_then(toml::Value::as_table)
            .and_then(|tls| tls.get("mode"))
            .and_then(toml::Value::as_str)
            .unwrap_or(config::TlsModeName::InternalCa.as_str())
    }

    /// The first address of `[server] listen`, [`config::DEFAULT_LISTEN`] when the file
    /// names none.
    fn listen(&self) -> Option<SocketAddr> {
        let listen = self
            .table
            .get("server")
            .and_then(toml::Value::as_table)
            .and_then(|server| server.get("listen"));
        let first = match listen {
            None => config::DEFAULT_LISTEN.to_owned(),
            Some(toml::Value::String(text)) => text.split(',').next()?.trim().to_owned(),
            Some(toml::Value::Array(list)) => list.first()?.as_str()?.trim().to_owned(),
            Some(_) => return None,
        };
        first.parse().ok()
    }

    /// The base URL of the node's own API: `https://localhost:<port>` for a listener on
    /// every address or on loopback (the name on the internal CA's server certificate
    /// until setup stores another), the address itself for a listener on one address;
    /// `http://` in the `plain` mode of the Lab profile. `None` in the `reverse_proxy`
    /// mode, where clients go through the proxy.
    pub fn api_url(&self) -> Option<String> {
        let scheme = match self.tls_mode() {
            "internal_ca" | "imported" => "https",
            "plain" => "http",
            _ => return None,
        };
        let addr = self.listen()?;
        let ip = addr.ip();
        let host = if ip.is_unspecified() || ip.is_loopback() {
            "localhost".to_owned()
        } else if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        Some(format!("{scheme}://{host}:{}", addr.port()))
    }

    /// The internal CA root, `<data_dir>/tls/ca-root.pem`, in the `internal_ca` mode; an
    /// imported certificate is checked against the system roots.
    pub fn ca_file(&self) -> Option<PathBuf> {
        (self.tls_mode() == config::TlsModeName::InternalCa.as_str())
            .then(|| self.data_dir())
            .flatten()
            .map(|dir| dir.join(CA_ROOT))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(text: &str) -> NodeConfig {
        node_with(text, &[])
    }

    fn node_with(text: &str, env: &[(&str, &str)]) -> NodeConfig {
        NodeConfig::parse(
            Path::new("tenko.toml"),
            text,
            env.iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        )
        .expect("TOML")
    }

    #[test]
    fn the_file_is_the_flag_then_the_variable_then_the_default() {
        let none = |_: &str| None;
        let set = |name: &str| (name == CONFIG_ENV).then(|| OsString::from("/srv/tenko.toml"));
        assert_eq!(
            config_path(Some(Path::new("/x/tenko.toml")), set),
            Some(PathBuf::from("/x/tenko.toml"))
        );
        assert_eq!(
            config_path(None, set),
            Some(PathBuf::from("/srv/tenko.toml"))
        );
        assert_eq!(
            config_path(None, none),
            cfg!(unix).then(|| PathBuf::from(DEFAULT_CONFIG))
        );
    }

    #[test]
    fn the_default_node_is_localhost_8443_with_the_internal_ca_root() {
        let node = node("data_dir = \"/var/lib/tenko\"\n");
        assert_eq!(node.api_url().as_deref(), Some("https://localhost:8443"));
        assert_eq!(
            node.ca_file(),
            Some(std::path::absolute("/var/lib/tenko/tls/ca-root.pem").expect("absolute"))
        );
    }

    #[test]
    fn keys_this_binary_does_not_know_are_ignored() {
        let node = node(
            "data_dir = \"/var/lib/tenko\"\nfuture_key = 1\n[server]\nlisten = \
             [\"[::]:9443\"]\nfuture = true\n",
        );
        assert_eq!(node.api_url().as_deref(), Some("https://localhost:9443"));
    }

    #[test]
    fn a_listener_on_one_address_is_reached_there() {
        let v4 = node("[server]\nlisten = \"192.0.2.10:8443, [::]:8443\"\n");
        assert_eq!(v4.api_url().as_deref(), Some("https://192.0.2.10:8443"));
        let v6 = node("[server]\nlisten = [\"[2001:db8::10]:8443\"]\n");
        assert_eq!(v6.api_url().as_deref(), Some("https://[2001:db8::10]:8443"));
        let loopback = node("[server]\nlisten = [\"127.0.0.1:8443\"]\n");
        assert_eq!(
            loopback.api_url().as_deref(),
            Some("https://localhost:8443")
        );
    }

    #[test]
    fn the_tls_mode_decides_the_scheme_and_the_ca_file() {
        let plain = node("data_dir = \"/d\"\n[tls]\nmode = \"plain\"\n");
        assert_eq!(plain.api_url().as_deref(), Some("http://localhost:8443"));
        assert_eq!(plain.ca_file(), None);
        let imported = node("data_dir = \"/d\"\n[tls]\nmode = \"imported\"\n");
        assert_eq!(
            imported.api_url().as_deref(),
            Some("https://localhost:8443")
        );
        assert_eq!(imported.ca_file(), None);
        let proxied = node("data_dir = \"/d\"\n[tls]\nmode = \"reverse_proxy\"\n");
        assert_eq!(proxied.api_url(), None);
    }

    #[test]
    fn the_environment_overrides_the_file() {
        let node = node_with(
            "data_dir = \"/var/lib/tenko\"\n",
            &[
                ("TENKO_DATA_DIR", "/srv/tenko"),
                ("TENKO_SERVER__LISTEN", "0.0.0.0:9443"),
            ],
        );
        assert_eq!(
            node.data_dir(),
            Some(std::path::absolute("/srv/tenko").expect("absolute"))
        );
        assert_eq!(node.api_url().as_deref(), Some("https://localhost:9443"));
    }

    #[test]
    fn no_data_dir_and_bad_files_give_nothing() {
        assert_eq!(node("").data_dir(), None);
        assert_eq!(node("").ca_file(), None);
        assert!(NodeConfig::parse(Path::new("x"), "not = [toml", Vec::new()).is_none());
        assert!(NodeConfig::read(Path::new("does/not/exist.toml"), Vec::new()).is_none());
    }
}
