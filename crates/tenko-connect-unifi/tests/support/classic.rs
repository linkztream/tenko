//! The classic API of the fake controller: sessions, reads and the writes the plugin sends.

use axum::{http::StatusCode, response::Response};
use serde_json::{Value, json};

use super::{Req, SITE_ID, State, VERSION, Write, error, html, ok, session_token};

/// Answers a request under `{P}/api/` (`rest` is the part after that prefix).
pub(super) fn handle(state: &mut State, req: &Req, rest: &str) -> Response {
    let Some(token) = session_token(state, req) else {
        return error(StatusCode::UNAUTHORIZED, "api.err.LoginRequired");
    };
    let csrf = state.sessions.get(&token).cloned().unwrap_or_default();
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        ["self", "sites"] if req.is_get() => ok(vec![json!({
            "_id": SITE_ID,
            "name": "default",
            "desc": "Default",
        })]),
        ["s", site, route @ ..] => {
            if !req.is_get() && req.header("x-csrf-token") != Some(csrf.as_str()) {
                return error(StatusCode::FORBIDDEN, "api.err.NoPermission");
            }
            if !req.is_get() {
                state.writes.push(Write {
                    method: req.method.to_string(),
                    path: req.path.clone(),
                    body: req.body.clone(),
                });
            }
            if *site != "default" {
                return error(StatusCode::BAD_REQUEST, "api.err.NoSiteContext");
            }
            site_route(state, req, route)
        }
        _ => not_found(),
    }
}

fn not_found() -> Response {
    html(StatusCode::NOT_FOUND, "<html><body>Not found</body></html>")
}

fn site_route(state: &mut State, req: &Req, route: &[&str]) -> Response {
    match (req.method.as_str(), route) {
        ("GET", ["stat", "sysinfo"]) => ok(vec![json!({ "version": VERSION })]),
        ("GET", ["stat", "device"]) => ok(state.devices.clone()),
        ("GET", ["stat", "sta"]) => ok(state.clients.clone()),
        ("GET", ["rest", "networkconf"]) => ok(state.networks.clone()),
        ("GET", ["rest", "wlanconf"]) => ok(state.wlans.clone()),
        ("GET", ["rest", "portconf"]) => ok(state.profiles.clone()),
        ("GET", ["stat", "user", mac]) => user_by_mac(state, &decode(mac)),
        ("POST", ["rest", "networkconf"]) => create_network(state, &req.body),
        ("PUT", ["rest", "networkconf", id]) => update_network(state, id, &req.body),
        ("DELETE", ["rest", "networkconf", id]) => delete_network(state, id),
        ("PUT", ["rest", "device", id]) => update_device(state, id, &req.body),
        ("PUT", ["rest", "user", id]) => update_user(state, id, &req.body),
        _ => not_found(),
    }
}

/// Percent-decodes a path segment (a MAC address may arrive as `00%3A00...`).
fn decode(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escaped = (bytes[at] == b'%')
            .then(|| segment.get(at + 1..at + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        if let Some(byte) = escaped {
            out.push(byte);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A member as text.
fn text_of<'a>(value: &'a Value, member: &str) -> Option<&'a str> {
    value.get(member).and_then(Value::as_str)
}

/// Whether a record is flagged `member: true` (also as the text "true").
fn flagged(value: &Value, member: &str) -> bool {
    match value.get(member) {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::String(text)) => text == "true",
        _ => false,
    }
}

/// The VLAN of a network that has VLAN tagging enabled (a number or numeric text).
fn vlan_of(network: &Value) -> Option<u64> {
    if !flagged(network, "vlan_enabled") {
        return None;
    }
    match network.get("vlan")? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// A port index (a number or numeric text).
fn port_idx(value: &Value) -> Option<u64> {
    match value.get("port_idx")? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Puts the members of `body` into `target`.
fn merge(target: &mut Value, body: &Value) {
    if let (Some(target), Some(body)) = (target.as_object_mut(), body.as_object()) {
        for (member, value) in body {
            target.insert(member.clone(), value.clone());
        }
    }
}

fn bad_payload() -> Response {
    error(StatusCode::BAD_REQUEST, "api.err.InvalidPayload")
}

fn invalid_id() -> Response {
    error(StatusCode::BAD_REQUEST, "api.err.IdInvalid")
}

fn user_by_mac(state: &State, mac: &str) -> Response {
    state
        .users
        .iter()
        .find(|user| text_of(user, "mac").is_some_and(|other| other.eq_ignore_ascii_case(mac)))
        .map_or_else(
            || error(StatusCode::BAD_REQUEST, "api.err.UnknownUser"),
            |user| ok(vec![user.clone()]),
        )
}

fn create_network(state: &mut State, body: &Value) -> Response {
    if !body.is_object() {
        return bad_payload();
    }
    let name = text_of(body, "name").map(str::trim).unwrap_or_default();
    // An empty name and a name another network has (in any letter case) are both refused
    // as `NameExisted`.
    if name.is_empty()
        || state.networks.iter().any(|network| {
            text_of(network, "name").is_some_and(|other| other.eq_ignore_ascii_case(name))
        })
    {
        return error(StatusCode::BAD_REQUEST, "api.err.NameExisted");
    }
    if flagged(body, "vlan_enabled") {
        let Some(vlan) = vlan_of(body) else {
            return bad_payload();
        };
        if state
            .networks
            .iter()
            .any(|network| vlan_of(network) == Some(vlan))
        {
            return error(StatusCode::BAD_REQUEST, "api.err.VlanUsed");
        }
    }
    let mut created = body.clone();
    created["_id"] = json!(state.new_id());
    created["site_id"] = json!(SITE_ID);
    let mut stored = created.clone();
    if state.drift_after_write {
        stored["name"] = json!(format!("{name}-drift"));
    }
    state.networks.push(stored);
    ok(vec![created])
}

fn update_network(state: &mut State, id: &str, body: &Value) -> Response {
    let drift = state.drift_after_write;
    let Some(network) = state
        .networks
        .iter_mut()
        .find(|network| text_of(network, "_id") == Some(id))
    else {
        return invalid_id();
    };
    let mut merged = network.clone();
    merge(&mut merged, body);
    *network = merged.clone();
    if drift {
        let name = text_of(&merged, "name").unwrap_or_default();
        network["name"] = json!(format!("{name}-drift"));
    }
    ok(vec![merged])
}

fn delete_network(state: &mut State, id: &str) -> Response {
    let Some(at) = state
        .networks
        .iter()
        .position(|network| text_of(network, "_id") == Some(id))
    else {
        return invalid_id();
    };
    if flagged(&state.networks[at], "attr_no_delete") {
        return error(StatusCode::BAD_REQUEST, "api.err.NoDelete");
    }
    state.networks.remove(at);
    ok(Vec::new())
}

/// Replaces the overrides of `device`; unless `drift`, the profile of each overridden port
/// follows. With `drift` the overrides keep the profiles they had.
fn replace_overrides(device: &mut Value, overrides: &[Value], drift: bool) {
    let previous: Vec<Value> = device
        .get("port_overrides")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut stored = overrides.to_vec();
    if drift {
        for entry in &mut stored {
            let before = previous
                .iter()
                .find(|old| port_idx(old) == port_idx(entry))
                .and_then(|old| old.get("portconf_id"))
                .cloned();
            if let Some(map) = entry.as_object_mut() {
                match before {
                    Some(profile) => {
                        map.insert("portconf_id".to_owned(), profile);
                    }
                    None => {
                        map.remove("portconf_id");
                    }
                }
            }
        }
    }
    device["port_overrides"] = Value::Array(stored);
    if drift {
        return;
    }
    for entry in overrides {
        let (Some(idx), Some(profile)) = (port_idx(entry), text_of(entry, "portconf_id")) else {
            continue;
        };
        if let Some(port) = device
            .get_mut("port_table")
            .and_then(Value::as_array_mut)
            .and_then(|ports| ports.iter_mut().find(|port| port_idx(port) == Some(idx)))
        {
            port["portconf_id"] = json!(profile);
        }
    }
}

fn update_device(state: &mut State, id: &str, body: &Value) -> Response {
    let drift = state.drift_after_write;
    let Some(device) = state
        .devices
        .iter_mut()
        .find(|device| text_of(device, "_id") == Some(id))
    else {
        return invalid_id();
    };
    let Some(overrides) = body.get("port_overrides").and_then(Value::as_array) else {
        return bad_payload();
    };
    let mut answer = device.clone();
    replace_overrides(&mut answer, overrides, false);
    replace_overrides(device, overrides, drift);
    ok(vec![answer])
}

fn update_user(state: &mut State, id: &str, body: &Value) -> Response {
    let drift = state.drift_after_write;
    let Some(user) = state
        .users
        .iter_mut()
        .find(|user| text_of(user, "_id") == Some(id))
    else {
        return invalid_id();
    };
    let mut merged = user.clone();
    merge(&mut merged, body);
    if !drift {
        *user = merged.clone();
    }
    ok(vec![merged])
}
