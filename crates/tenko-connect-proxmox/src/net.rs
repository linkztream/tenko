//! The network part of a guest's configuration: the `netN` entries of QEMU guests and LXC
//! containers, the cloud-init `ipconfigN` entries, and the operating system hints of
//! `ostype`. Everything here reads untrusted text from the API and never fails: what does
//! not parse is left out.

use std::net::IpAddr;

use serde_json::{Map, Value};
use tenko_core::MacAddr;

/// One network interface of a guest's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Nic {
    /// The `N` of `netN`.
    pub index: u32,
    /// The MAC address.
    pub mac: Option<MacAddr>,
    /// The bridge or SDN vnet the interface is attached to.
    pub bridge: Option<String>,
    /// The VLAN tag of the interface (`tag=`), 1 to 4094.
    pub vlan: Option<u16>,
    /// Static addresses of the configuration: `ip=` and `ip6=` of a container, or of the
    /// cloud-init `ipconfigN` of a virtual machine. `dhcp`, `auto` and `manual` are not
    /// addresses and are left out.
    pub static_ips: Vec<IpAddr>,
}

/// Splits a Proxmox property string (`virtio=00:00:5E:00:53:01,bridge=vmbr0,tag=20`) into
/// its keys and values; a part without `=` has no value.
pub fn parse_properties(text: &str) -> Vec<(&str, Option<&str>)> {
    text.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once('=') {
            Some((key, value)) => (key.trim(), Some(value.trim())),
            None => (part, None),
        })
        .collect()
}

/// A MAC address in Proxmox's form (`BC:24:11:00:00:01`).
pub fn parse_mac(text: &str) -> Option<MacAddr> {
    let text = text.trim();
    // Six groups of two hexadecimal digits; tenko-core accepts more forms than Proxmox writes.
    if text.len() != 17 {
        return None;
    }
    text.parse().ok()
}

/// An address with an optional prefix length (`192.0.2.10/24`), without the prefix.
pub fn parse_address(text: &str) -> Option<IpAddr> {
    let address = text.trim().split('/').next()?;
    address.parse().ok()
}

/// Whether an address belongs in an inventory: not loopback, unspecified, multicast,
/// link-local or the IPv4 broadcast address.
pub fn usable(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_broadcast(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

fn vlan(text: Option<&str>) -> Option<u16> {
    text?
        .parse::<u16>()
        .ok()
        .filter(|vid| (1..=4094).contains(vid))
}

fn static_address(text: Option<&str>) -> Option<IpAddr> {
    let text = text?;
    if matches!(text, "dhcp" | "auto" | "manual") {
        return None;
    }
    parse_address(text)
}

/// The indexes and texts of the `netN` entries of a configuration, by index.
fn net_entries(config: &Map<String, Value>) -> Vec<(u32, &str)> {
    let mut entries: Vec<(u32, &str)> = config
        .iter()
        .filter_map(|(key, value)| {
            let index = key.strip_prefix("net")?.parse::<u32>().ok()?;
            Some((index, value.as_str()?))
        })
        .collect();
    entries.sort_by_key(|(index, _)| *index);
    entries
}

/// The interfaces of a QEMU guest's configuration. The MAC address is the value of the
/// model key (`virtio=<mac>`) or of `macaddr`; static addresses come from `ipconfigN`.
pub fn qemu_nics(config: &Map<String, Value>) -> Vec<Nic> {
    net_entries(config)
        .into_iter()
        .map(|(index, text)| {
            let properties = parse_properties(text);
            let value = |name: &str| {
                properties
                    .iter()
                    .find(|(key, _)| *key == name)
                    .and_then(|(_, value)| *value)
            };
            let mac = value("macaddr").and_then(parse_mac).or_else(|| {
                properties
                    .iter()
                    .filter(|(key, _)| {
                        !matches!(
                            *key,
                            "bridge"
                                | "tag"
                                | "trunks"
                                | "mtu"
                                | "rate"
                                | "queues"
                                | "firewall"
                                | "link_down"
                                | "model"
                        )
                    })
                    .find_map(|(_, value)| value.and_then(parse_mac))
            });
            let mut static_ips = Vec::new();
            if let Some(cloud_init) = config
                .get(&format!("ipconfig{index}"))
                .and_then(Value::as_str)
            {
                let cloud_init = parse_properties(cloud_init);
                for name in ["ip", "ip6"] {
                    let found = cloud_init
                        .iter()
                        .find(|(key, _)| *key == name)
                        .and_then(|(_, value)| static_address(*value));
                    static_ips.extend(found);
                }
            }
            Nic {
                index,
                mac,
                bridge: value("bridge").filter(|b| !b.is_empty()).map(str::to_owned),
                vlan: vlan(value("tag")),
                static_ips,
            }
        })
        .collect()
}

/// The interfaces of an LXC container's configuration (`hwaddr`, `bridge`, `tag`, `ip`,
/// `ip6`).
pub fn lxc_nics(config: &Map<String, Value>) -> Vec<Nic> {
    net_entries(config)
        .into_iter()
        .map(|(index, text)| {
            let properties = parse_properties(text);
            let value = |name: &str| {
                properties
                    .iter()
                    .find(|(key, _)| *key == name)
                    .and_then(|(_, value)| *value)
            };
            Nic {
                index,
                mac: value("hwaddr").and_then(parse_mac),
                bridge: value("bridge").filter(|b| !b.is_empty()).map(str::to_owned),
                vlan: vlan(value("tag")),
                static_ips: ["ip", "ip6"]
                    .into_iter()
                    .filter_map(|name| static_address(value(name)))
                    .collect(),
            }
        })
        .collect()
}

/// The operating system of a QEMU guest's `ostype`.
pub fn qemu_os(ostype: &str) -> Option<String> {
    let os = match ostype {
        "l26" => "Linux",
        "l24" => "Linux 2.4",
        "win11" => "Windows 11/2022/2025",
        "win10" => "Windows 10/2016/2019",
        "win8" => "Windows 8/2012/2012 R2",
        "win7" => "Windows 7/2008 R2",
        "w2k8" => "Windows Vista/2008",
        "wvista" => "Windows Vista",
        "w2k3" => "Windows 2003",
        "w2k" => "Windows 2000",
        "wxp" => "Windows XP",
        "solaris" => "Solaris",
        _ => return None,
    };
    Some(os.to_owned())
}

/// The operating system of an LXC container's `ostype`.
pub fn lxc_os(ostype: &str) -> Option<String> {
    let distribution = match ostype {
        "debian" => "Debian",
        "devuan" => "Devuan",
        "ubuntu" => "Ubuntu",
        "centos" => "CentOS",
        "fedora" => "Fedora",
        "opensuse" => "openSUSE",
        "archlinux" => "Arch Linux",
        "alpine" => "Alpine",
        "gentoo" => "Gentoo",
        "nixos" => "NixOS",
        "unmanaged" | "" => return Some("Linux".to_owned()),
        other if other.len() <= 32 && other.bytes().all(|b| b.is_ascii_alphanumeric()) => {
            return Some(format!("Linux ({other})"));
        }
        _ => return Some("Linux".to_owned()),
    };
    Some(format!("Linux ({distribution})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(value: serde_json::Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => panic!("an object"),
        }
    }

    #[test]
    fn qemu_interfaces_read_the_model_mac_bridge_tag_and_cloud_init() {
        let nics = qemu_nics(&config(serde_json::json!({
            "net1": "e1000=00:00:5E:00:53:02,bridge=vnet20",
            "net0": "virtio=00:00:5E:00:53:01,bridge=vmbr0,firewall=1,tag=20",
            "net2": "model=virtio,macaddr=00:00:5e:00:53:03,bridge=vmbr1,tag=5000",
            "net9": 7,
            "ipconfig0": "ip=192.0.2.10/24,gw=192.0.2.1,ip6=2001:db8::10/64",
            "ipconfig1": "ip=dhcp,ip6=auto",
            "name": "ignored"
        })));
        assert_eq!(nics.len(), 3);
        assert_eq!(nics[0].index, 0);
        assert_eq!(
            nics[0].mac.map(|m| m.to_string()).as_deref(),
            Some("00:00:5e:00:53:01")
        );
        assert_eq!(nics[0].bridge.as_deref(), Some("vmbr0"));
        assert_eq!(nics[0].vlan, Some(20));
        assert_eq!(
            nics[0].static_ips,
            vec![
                "192.0.2.10".parse::<IpAddr>().expect("ip"),
                "2001:db8::10".parse::<IpAddr>().expect("ip")
            ]
        );
        assert_eq!(
            nics[1].mac.map(|m| m.to_string()).as_deref(),
            Some("00:00:5e:00:53:02")
        );
        assert_eq!(nics[1].static_ips, Vec::<IpAddr>::new());
        assert_eq!(
            nics[2].mac.map(|m| m.to_string()).as_deref(),
            Some("00:00:5e:00:53:03")
        );
        assert_eq!(nics[2].vlan, None, "5000 is not a VLAN id");
    }

    #[test]
    fn lxc_interfaces_read_hwaddr_and_static_addresses() {
        let nics = lxc_nics(&config(serde_json::json!({
            "net0": "name=eth0,bridge=vmbr0,hwaddr=00:00:5E:00:53:11,ip=198.51.100.11/24,gw=198.51.100.1,ip6=manual,type=veth,tag=30",
            "net1": "name=eth1,bridge=vmbr1,hwaddr=not-a-mac,ip=dhcp,type=veth"
        })));
        assert_eq!(nics.len(), 2);
        assert_eq!(
            nics[0].mac.map(|m| m.to_string()).as_deref(),
            Some("00:00:5e:00:53:11")
        );
        assert_eq!(nics[0].vlan, Some(30));
        assert_eq!(
            nics[0].static_ips,
            vec!["198.51.100.11".parse::<IpAddr>().expect("ip")]
        );
        assert_eq!(nics[1].mac, None);
        assert_eq!(nics[1].static_ips, Vec::<IpAddr>::new());
    }

    #[test]
    fn unusable_addresses_are_left_out() {
        for text in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "169.254.1.1",
            "fe80::1",
            "ff02::1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!usable(text.parse().expect("ip")), "{text}");
        }
        for text in ["192.0.2.10", "2001:db8::10", "10.0.0.1"] {
            assert!(usable(text.parse().expect("ip")), "{text}");
        }
    }

    #[test]
    fn operating_systems_follow_ostype() {
        assert_eq!(qemu_os("l26").as_deref(), Some("Linux"));
        assert_eq!(qemu_os("win11").as_deref(), Some("Windows 11/2022/2025"));
        assert_eq!(qemu_os("other"), None);
        assert_eq!(lxc_os("debian").as_deref(), Some("Linux (Debian)"));
        assert_eq!(lxc_os("newdistro").as_deref(), Some("Linux (newdistro)"));
        assert_eq!(lxc_os("we ird;").as_deref(), Some("Linux"));
    }

    #[test]
    fn properties_split_on_commas() {
        assert_eq!(
            parse_properties("a=1, b ,c=x=y,,"),
            vec![("a", Some("1")), ("b", None), ("c", Some("x=y"))]
        );
        assert_eq!(
            parse_mac("00:00:5e:00:53:01")
                .map(|m| m.to_string())
                .as_deref(),
            Some("00:00:5e:00:53:01")
        );
        assert_eq!(parse_mac("00005e005301"), None);
        assert_eq!(
            parse_address("192.0.2.1/24"),
            Some("192.0.2.1".parse().expect("ip"))
        );
        assert_eq!(parse_address("dhcp"), None);
    }
}
