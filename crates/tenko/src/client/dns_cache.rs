//! `tenko dns cache ...`: what a node's DNS cache holds (`GET /nodes/{id}/dns/cache`) and
//! its flush (`POST /nodes/{id}/dns/cache/flush`).
//!
//! The listing is one page in the canonical order of the names; a longer cache prints the
//! `--cursor` of the next page. Every page read is audited on the server as
//! `dns.cache.read`, since the entries are the names the clients asked.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use tenko_api::dto::Page;

use super::{ClientOpts, Failure, Output, Target, key, present, table, text};

/// Subcommands of `tenko dns cache`.
#[derive(Debug, Clone, Subcommand)]
pub enum CacheCommand {
    /// List a page of what the node's cache holds.
    List(CacheListArgs),
    /// Empty the node's cache, or the names at or below a suffix.
    Flush(CacheFlushArgs),
}

impl CacheCommand {
    /// The connection options.
    pub fn client(&self) -> &ClientOpts {
        match self {
            Self::List(args) => &args.client,
            Self::Flush(args) => &args.client,
        }
    }

    /// The name as typed.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::List(_) => "dns cache list",
            Self::Flush(_) => "dns cache flush",
        }
    }
}

/// Arguments of `tenko dns cache list`.
#[derive(Debug, Clone, Args)]
pub struct CacheListArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The node's id.
    #[arg(value_name = "NODE")]
    pub node: u64,
    /// Only the names equal to this name or under it.
    #[arg(long, value_name = "NAME")]
    pub suffix: Option<String>,
    /// Only one view: its identifier, or `default` for the entries outside any view.
    #[arg(long, value_name = "VIEW")]
    pub view: Option<String>,
    /// Entries in the page, 1 to 1000.
    #[arg(long, default_value_t = 200, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub limit: u32,
    /// The cursor of the page, as the previous page printed it.
    #[arg(long, value_name = "CURSOR")]
    pub cursor: Option<String>,
}

/// Arguments of `tenko dns cache flush`.
#[derive(Debug, Clone, Args)]
pub struct CacheFlushArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The node's id.
    #[arg(value_name = "NODE")]
    pub node: u64,
    /// Only the names at or below this suffix; everything when absent.
    #[arg(long, value_name = "NAME")]
    pub suffix: Option<String>,
}

/// Runs a `tenko dns cache` subcommand.
pub async fn run(target: &Target, command: &CacheCommand) -> Result<Output, Failure> {
    match command {
        CacheCommand::List(args) => list(target, args).await,
        CacheCommand::Flush(args) => flush(target, args).await,
    }
}

async fn list(target: &Target, args: &CacheListArgs) -> Result<Output, Failure> {
    let mut query: Vec<(&str, String)> = vec![("limit", args.limit.to_string())];
    for (name, value) in [
        ("suffix", &args.suffix),
        ("view", &args.view),
        ("cursor", &args.cursor),
    ] {
        if let Some(value) = value {
            query.push((name, value.clone()));
        }
    }
    let client = target.connect().await?;
    let path = format!("/nodes/{}/dns/cache", args.node);
    let page: Page<Value> = client.get_query(&path, &query).await?;
    if target.json {
        return Ok(Output::json(&page));
    }
    let rows: Vec<Vec<String>> = page.items.iter().map(row).collect();
    let mut output = Output::text(table(
        &["NAME", "TYPE", "TTL", "VIEW", "STALE", "HITS", "DATA"],
        &rows,
    ));
    if let Some(cursor) = &page.next_cursor {
        output = output.note(format!("more entries follow: --cursor {cursor}"));
    }
    Ok(output)
}

/// The row of an entry: the data of a negative answer is its RCODE, a record of another
/// type than the question (a CNAME of a chain) carries its type.
fn row(entry: &Value) -> Vec<String> {
    let rtype = text(entry, &["type"]);
    let records = entry
        .get("records")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let data = if records.is_empty() {
        match entry.get("rcode").and_then(Value::as_u64) {
            Some(3) => "NXDOMAIN".to_owned(),
            Some(0) => "NODATA".to_owned(),
            Some(other) => format!("RCODE {other}"),
            None => String::new(),
        }
    } else {
        let mut out = String::new();
        for (n, record) in records.iter().enumerate() {
            if n > 0 {
                out.push_str(", ");
            }
            let own = text(record, &["type"]);
            if own != rtype {
                let _ = write!(out, "{own} ");
            }
            out.push_str(&present(record));
        }
        out
    };
    let number = |key: &str| {
        entry
            .get(key)
            .and_then(Value::as_u64)
            .map(|value| value.to_string())
            .unwrap_or_default()
    };
    vec![
        text(entry, &["name"]).to_owned(),
        rtype.to_owned(),
        number("ttl"),
        match text(entry, &["view"]) {
            "" => "default".to_owned(),
            view => view.to_owned(),
        },
        if entry.get("stale").and_then(Value::as_bool) == Some(true) {
            "yes".to_owned()
        } else {
            String::new()
        },
        number("hits"),
        data,
    ]
}

async fn flush(target: &Target, args: &CacheFlushArgs) -> Result<Output, Failure> {
    let mut path = format!("/nodes/{}/dns/cache/flush", args.node);
    if let Some(suffix) = &args.suffix {
        let _ = write!(path, "?suffix={}", encode(suffix));
    }
    let client = target.connect().await?;
    let answer: Value = client.post(&path, &json!({}), Some(&key())).await?;
    if target.json {
        return Ok(Output::json(&answer));
    }
    Ok(Output::text(format!(
        "flush recorded as command {} on node {}{}\n",
        text(&answer, &["command_id"]),
        args.node,
        args.suffix
            .as_deref()
            .map(|suffix| format!(", names at or below {suffix}"))
            .unwrap_or_default()
    )))
}

/// `text` percent-encoded for a query parameter.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{encode, row};

    #[test]
    fn rows_show_the_data_the_chain_and_negative_answers() {
        let chain = json!({
            "name": "www.example.test", "type": "A", "ttl": 100, "stale": false, "hits": 2,
            "rcode": 0,
            "records": [
                { "type": "CNAME", "target": "cdn.example.test" },
                { "type": "A", "address": "192.0.2.7" }
            ]
        });
        assert_eq!(
            row(&chain),
            [
                "www.example.test",
                "A",
                "100",
                "default",
                "",
                "2",
                "CNAME cdn.example.test, 192.0.2.7"
            ]
        );
        let missing = json!({
            "name": "missing.example.test", "type": "A", "ttl": 0, "stale": true, "hits": 0,
            "rcode": 3, "records": [], "view": "0190c3a2-0000-7000-8000-000000000001"
        });
        let cells = row(&missing);
        assert_eq!(cells[3], "0190c3a2-0000-7000-8000-000000000001");
        assert_eq!((cells[4].as_str(), cells[6].as_str()), ("yes", "NXDOMAIN"));
    }

    #[test]
    fn a_suffix_is_encoded_for_the_query() {
        assert_eq!(encode("example.test"), "example.test");
        assert_eq!(encode("a b&c"), "a%20b%26c");
    }
}
