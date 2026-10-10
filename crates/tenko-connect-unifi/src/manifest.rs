//! The manifest of the UniFi plugin: capabilities, the settings schema from which the UI
//! builds the form, the secret purposes and the network target.

use tenko_connect::{Manifest, sdk::http::settings_schema};

/// The plugin name.
pub const NAME: &str = "unifi";

/// The manifest.
///
/// # Panics
///
/// Never: the manifest is a constant document checked by the tests.
pub fn manifest() -> Manifest {
    let mut document = serde_json::json!({
        "manifest_version": 1,
        "name": NAME,
        "version": crate::version(),
        "description": "Reads devices, ports, LLDP, clients, networks and wireless networks from a UniFi Network application, and performs the VLAN, port-profile and per-client VLAN writes the host has planned and checked.",
        "license": "LicenseRef-Proprietary",
        "protocol": [tenko_connect::PROTOCOL_VERSION],
        "capabilities": ["inventory", "network_controller"],
        "settings": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "title": "UniFi Network",
            "properties": {
                "url": {
                    "type": "string",
                    "format": "uri",
                    "title": "Controller address",
                    "description": "Base URL of the Network application: https://host:8443 for a self-hosted application, https://host for a UniFi OS console.",
                    "examples": ["https://unifi.example.net:8443"],
                    "maxLength": 2048
                },
                "deployment": {
                    "type": "string",
                    "enum": ["auto", "self_hosted", "unifi_os"],
                    "title": "Deployment",
                    "description": "Self-hosted Network Application or UniFi OS console; auto detects it on every call.",
                    "default": "auto"
                },
                "site": {
                    "type": "string",
                    "title": "Site",
                    "description": "The site's short name as the address bar shows it (/manage/site/<name>/...), not its description.",
                    "default": "default",
                    "pattern": "^[A-Za-z0-9_-]{1,64}$"
                },
                "username": {
                    "type": "string",
                    "title": "Local account",
                    "description": "User name of a local account of the Network application for the classic API; its password is the secret `password`. Leave empty to read through a local Integration API key only.",
                    "minLength": 1,
                    "maxLength": 128
                }
            },
            "required": ["url"],
            "additionalProperties": false
        },
        "secrets": [
            {
                "purpose": "password",
                "description": "Password of the local account (`username`). A login stored as {\"login\": ..., \"password\": ...} is accepted too.",
                "required": false
            },
            {
                "purpose": "api_key",
                "description": "Local Integration API key of the Network application (Settings, Control Plane, Integrations); used when no local account is configured, for a reduced read-only topology.",
                "required": false
            }
        ],
        "network": [
            {
                "setting": "/url",
                "ports": [443, 8443],
                "description": "The UniFi Network application: classic API and Integration API."
            },
            {
                "setting": "/connect_address",
                "ports": [443, 8443],
                "description": "The address connected to instead of the host of the URL, when set."
            }
        ],
        "platforms": ["any"],
        "defaults": { "poll_interval_secs": 300, "call_timeout_secs": 60 }
    });
    // The TLS settings are the SDK's, shared with the other web-API plugins.
    if let Some(serde_json::Value::Object(properties)) =
        document.pointer_mut("/settings/properties")
    {
        properties.extend(settings_schema());
    }
    serde_json::from_value(document)
        .unwrap_or_else(|error| unreachable!("the UniFi manifest is a constant: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_is_valid_and_fills_defaults() {
        let manifest = manifest();
        manifest.validate().expect("valid");
        assert_eq!(manifest.name, NAME);
        assert!(manifest.supports_this_platform());
        let filled = manifest
            .validate_settings(&serde_json::json!({ "url": "https://unifi.example.test:8443" }))
            .expect("defaults");
        assert_eq!(filled["site"], "default");
        assert_eq!(filled["tls"], "system");
        assert!(
            manifest
                .validate_settings(
                    &serde_json::json!({ "url": "https://unifi.example.test", "colour": 1 })
                )
                .is_err()
        );
        let settings: crate::settings::Settings =
            serde_json::from_value(filled).expect("the filled settings fit the plugin's type");
        assert_eq!(settings.site, "default");
    }
}
