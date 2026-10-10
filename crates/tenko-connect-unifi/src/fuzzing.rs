//! The entry point of the fuzz target `connect_unifi_answers` (`fuzz/`): arbitrary bytes as
//! controller answers, through the record readers and the topology and inventory mapping.
//! Everything the controller sends passes these functions; none of them may panic.

use std::net::IpAddr;

use serde_json::Value;
use tenko_core::Timestamp;

use crate::{
    classic::{Client, Device, Network, Profile, User, Wlan},
    integration, model,
};

/// Splits `data` at `0xff` bytes into up to seven answers (devices, clients, networks,
/// wireless networks, profiles, a client record, Integration API devices and clients),
/// reads each as JSON, and maps what parses.
pub fn answers(data: &[u8]) {
    let mut parts = data.split(|byte| *byte == 0xff);
    let mut next = || -> Vec<Value> {
        let Some(part) = parts.next() else {
            return Vec::new();
        };
        match serde_json::from_slice::<Value>(part) {
            Ok(Value::Object(map)) => match map.get("data") {
                Some(Value::Array(items)) => items.clone(),
                Some(other) => vec![other.clone()],
                None => vec![Value::Object(map)],
            },
            Ok(Value::Array(items)) => items,
            Ok(other) => vec![other],
            Err(_) => Vec::new(),
        }
    };
    let read = model::Read {
        devices: next()
            .iter()
            .filter_map(|v| Device::from_value(v).ok())
            .collect(),
        clients: next().iter().filter_map(Client::from_value).collect(),
        networks: next()
            .iter()
            .filter_map(|v| Network::from_value(v).ok())
            .collect(),
        wlans: next().iter().filter_map(Wlan::from_value).collect(),
        profiles: next()
            .iter()
            .filter_map(|v| Profile::from_value(v).ok())
            .collect(),
    };
    let _ = next().iter().filter_map(User::from_value).count();
    let local = model::Local {
        controller: vec![IpAddr::from([192, 0, 2, 10])],
        tenko: vec![IpAddr::from([192, 0, 2, 11])],
    };
    let at = Timestamp::now();
    let topology = model::topology(&read, &local, at);
    let _ = tenko_connect::convert::topology_to_proto(&topology);
    let _ = model::inventory(&read);
    let integration = integration::Read {
        devices: next()
            .iter()
            .enumerate()
            .filter_map(|(i, v)| integration::device_of(&format!("d{i}"), v))
            .collect(),
        clients: next().iter().filter_map(integration::client_of).collect(),
    };
    let _ = integration::topology(&integration, at);
    let _ = integration::inventory(&integration);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_answers_do_not_panic() {
        for input in [
            &b""[..],
            b"\xff\xff\xff",
            b"{\"data\":[{\"_id\":\"a\",\"mac\":\"00:00:5e:00:53:01\",\"port_table\":[{\"port_idx\":65535}],\"uplink\":{\"uplink_mac\":\"00:00:5e:00:53:01\"}}]}",
            b"[1,2,3]\xff{\"data\":{\"mac\":7}}\xffnull",
            b"\xff\xff{\"data\":[{\"_id\":\"n\",\"ip_subnet\":\"300.1.1.1/99\",\"vlan\":\"-4\",\"vlan_enabled\":\"1\",\"purpose\":\"corporate\"}]}",
        ] {
            answers(input);
        }
    }
}
