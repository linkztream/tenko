//! The Integration API of the fake controller, derived from the classic fixtures: the
//! adopted devices and the connected clients, with UUIDs built from their MAC addresses.

use axum::{http::StatusCode, response::Response};
use serde_json::{Map, Value, json};

use super::{API_KEY, Req, State, VERSION, html, reply};

/// The id of the one site in the Integration API.
pub const SITE: &str = "00000000-0000-0000-0000-0000000000a1";

/// Answers a request under the Integration API prefix (`rest` follows the prefix).
pub(super) fn handle(state: &State, req: &Req, rest: &str) -> Response {
    if req.header("x-api-key") != Some(API_KEY) {
        return reply(
            StatusCode::UNAUTHORIZED,
            &json!({
                "statusCode": 401,
                "statusName": "UNAUTHORIZED",
                "message": "Unauthorized",
            }),
        );
    }
    let parts: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
    match (req.is_get(), parts.as_slice()) {
        (true, ["info"]) => reply(StatusCode::OK, &json!({ "applicationVersion": VERSION })),
        (true, ["sites"]) => page(
            req,
            vec![json!({
                "id": SITE,
                "internalReference": "default",
                "name": "Default",
            })],
        ),
        (true, ["sites", SITE, "devices"]) => page(req, devices(state, false)),
        (true, ["sites", SITE, "devices", id]) => devices(state, true)
            .into_iter()
            .find(|device| device["id"] == *id)
            .map_or_else(not_found, |device| reply(StatusCode::OK, &device)),
        (true, ["sites", SITE, "clients"]) => page(req, clients(state)),
        _ => not_found(),
    }
}

fn not_found() -> Response {
    html(StatusCode::NOT_FOUND, "<html><body>Not found</body></html>")
}

/// A page of a list, by the `offset` and `limit` of the query.
fn page(req: &Req, items: Vec<Value>) -> Response {
    let number = |name: &str, default: usize| {
        req.query
            .get(name)
            .and_then(|text| text.parse::<usize>().ok())
            .unwrap_or(default)
    };
    let (offset, limit) = (number("offset", 0), number("limit", 25));
    let total = items.len();
    let data: Vec<Value> = items.into_iter().skip(offset).take(limit).collect();
    reply(
        StatusCode::OK,
        &json!({
            "offset": offset,
            "limit": limit,
            "count": data.len(),
            "totalCount": total,
            "data": data,
        }),
    )
}

/// A MAC address as 12 lower-case hex digits.
fn mac_digits(mac: &str) -> Option<String> {
    let digits: String = mac
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (digits.len() == 12 && digits.chars().all(|c| c.is_ascii_hexdigit())).then_some(digits)
}

/// The Integration API id of a device.
pub fn device_id(mac: &str) -> String {
    format!(
        "00000000-0000-0000-0000-{}",
        mac_digits(mac).unwrap_or_else(|| "000000000000".to_owned())
    )
}

fn client_id(mac: &str) -> String {
    format!(
        "10000000-0000-0000-0000-{}",
        mac_digits(mac).unwrap_or_else(|| "000000000000".to_owned())
    )
}

fn adopted(device: &Value) -> bool {
    device.get("adopted") != Some(&Value::Bool(false))
}

fn features(kind: &str) -> Vec<&'static str> {
    match kind {
        "usw" => vec!["switching"],
        "uap" => vec!["accessPoint"],
        "ugw" | "udm" | "uxg" => vec!["gateway"],
        _ => Vec::new(),
    }
}

/// The adopted devices; the list leaves out the upstream device, the detail carries it.
fn devices(state: &State, detail: bool) -> Vec<Value> {
    let adopted_macs: Vec<&str> = state
        .devices
        .iter()
        .filter(|device| adopted(device))
        .filter_map(|device| device.get("mac").and_then(Value::as_str))
        .collect();
    state
        .devices
        .iter()
        .filter(|device| adopted(device))
        .filter_map(|device| {
            let mac = device.get("mac").and_then(Value::as_str)?;
            let mut entry = Map::new();
            entry.insert("id".to_owned(), json!(device_id(mac)));
            entry.insert(
                "name".to_owned(),
                json!(device.get("name").and_then(Value::as_str).unwrap_or(mac)),
            );
            if let Some(model) = device.get("model") {
                entry.insert("model".to_owned(), model.clone());
            }
            entry.insert("macAddress".to_owned(), json!(mac));
            if let Some(ip) = device.get("ip") {
                entry.insert("ipAddress".to_owned(), ip.clone());
            }
            entry.insert("state".to_owned(), json!("ONLINE"));
            let kind = device
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            entry.insert("features".to_owned(), json!(features(kind)));
            if detail
                && let Some(parent) = device
                    .pointer("/uplink/uplink_mac")
                    .and_then(Value::as_str)
                    .filter(|parent| adopted_macs.contains(parent))
            {
                entry.insert(
                    "uplink".to_owned(),
                    json!({ "deviceId": device_id(parent) }),
                );
            }
            Some(Value::Object(entry))
        })
        .collect()
}

fn clients(state: &State) -> Vec<Value> {
    state
        .clients
        .iter()
        .filter_map(|client| {
            let mac = client.get("mac").and_then(Value::as_str)?;
            let wired = client.get("is_wired") == Some(&Value::Bool(true));
            let mut entry = Map::new();
            entry.insert(
                "type".to_owned(),
                json!(if wired { "WIRED" } else { "WIRELESS" }),
            );
            entry.insert("id".to_owned(), json!(client_id(mac)));
            if let Some(name) = ["name", "hostname"]
                .iter()
                .find_map(|member| client.get(*member).and_then(Value::as_str))
            {
                entry.insert("name".to_owned(), json!(name));
            }
            entry.insert("connectedAt".to_owned(), json!("2026-01-01T00:00:00Z"));
            if let Some(ip) = client.get("ip") {
                entry.insert("ipAddress".to_owned(), ip.clone());
            }
            entry.insert("macAddress".to_owned(), json!(mac));
            let uplink = client
                .get(if wired { "sw_mac" } else { "ap_mac" })
                .and_then(Value::as_str);
            if let Some(uplink) = uplink {
                entry.insert("uplinkDeviceId".to_owned(), json!(device_id(uplink)));
            }
            Some(Value::Object(entry))
        })
        .collect()
}
