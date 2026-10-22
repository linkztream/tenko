//! The rule table of P3-Q15: what the project knows about the DHCP requests of common
//! systems, written by hand from captured requests and published descriptions of client
//! behaviour.
//!
//! Each [`Entry`] says what a fingerprint must show (the option 55 list exactly or as a
//! prefix, the option 60 vendor class, and whether options 77, 81 and 93 were sent) and
//! the guess with a confidence. [`super::RuleTable::builtin`] tries the entries with an
//! exact list first, then those with a list prefix, then those without a list, each group
//! in the order written here; the first that matches wins.
//!
//! Where an entry comes from ([`Provenance`]):
//!
//! - `Captured`: the request was captured from the client in the compose lab
//!   (`deploy/compose/lab-dhcp`'s tools image, Debian 12 packages) and is kept as a fixture in
//!   `src/fingerprint/captured/`.
//! - `Modelled`: the request is one of the WP7.3 corpus (`fixtures/requests/`), modelled by
//!   hand on the option order and parameter list the client sends.
//! - `Published`: the parameter list or vendor class comes from published fingerprint
//!   collections or the client's own source (the request lists of lwIP and `NetworkManager`).
//!
//! What the table cannot tell, it does not claim: Windows Server sends the request of the
//! desktop release it is built on, iPadOS that of iOS, a Proxmox or `VMware` guest that of the
//! system inside it (only the boot firmware and a `dhcpcd` host with a `-pve` kernel show
//! more); the MAC address's vendor (OUI), which the probes report, is the better hint
//! there. A confidence below 50 is a family guess, not a version.

/// How an entry matches the option 55 parameter request list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum List {
    /// The list, exactly and in the client's order.
    Exact(&'static [u8]),
    /// The list starts with these codes, in this order.
    Prefix(&'static [u8]),
    /// Any list, also none.
    Any,
}

/// How an entry matches the option 60 vendor class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    /// Any vendor class, also none.
    Any,
    /// The client sent no vendor class.
    Absent,
    /// Exactly this text.
    Exact(&'static str),
    /// Text that starts with this.
    Prefix(&'static str),
    /// Text that contains this.
    Contains(&'static str),
}

/// The version of a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// None known.
    Unknown,
    /// This text.
    Fixed(&'static str),
    /// This text with `{}` replaced by the vendor class after the entry's
    /// [`Vendor::Prefix`] (`android-dhcp-13` gives `13`).
    FromVendor(&'static str),
}

/// Where an entry comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Captured from the client in the compose lab.
    Captured,
    /// One of the WP7.3 corpus's modelled requests.
    Modelled,
    /// From published fingerprint collections or the client's source.
    Published,
}

/// One rule of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// A stable name for tests and the documentation.
    pub id: &'static str,
    /// The parameter request list.
    pub list: List,
    /// The vendor class.
    pub vendor: Vendor,
    /// Whether option 77 must (`Some(true)`) or must not (`Some(false)`) be present.
    pub user_class: Option<bool>,
    /// The same for option 81.
    pub client_fqdn: Option<bool>,
    /// The same for option 93.
    pub architecture: Option<bool>,
    /// The family (`windows`, `macos`, `ios`, `android`, `linux`, `chromeos`, `xbox`,
    /// `playstation`, `printer`, `embedded`, `firmware`, `apple`).
    pub family: &'static str,
    /// The version.
    pub version: Version,
    /// How strong the match is, 0 to 100.
    pub confidence: u8,
    /// Where the entry comes from.
    pub provenance: Provenance,
}

impl Entry {
    /// An entry that only says what the list and the vendor class must be.
    const fn new(
        id: &'static str,
        list: List,
        vendor: Vendor,
        family: &'static str,
        version: Version,
        confidence: u8,
        provenance: Provenance,
    ) -> Self {
        Self {
            id,
            list,
            vendor,
            user_class: None,
            client_fqdn: None,
            architecture: None,
            family,
            version,
            confidence,
            provenance,
        }
    }

    /// The same, with the presence of option 77 required or excluded.
    const fn with_user_class(mut self, present: bool) -> Self {
        self.user_class = Some(present);
        self
    }

    /// The same, with the presence of option 93 required or excluded.
    const fn with_architecture(mut self, present: bool) -> Self {
        self.architecture = Some(present);
        self
    }

    /// The group the matcher tries the entry in: exact lists, prefixes, no list.
    pub(super) const fn group(&self) -> u8 {
        match self.list {
            List::Exact(_) => 0,
            List::Prefix(_) => 1,
            List::Any => 2,
        }
    }
}

use List::{Any, Exact, Prefix};
use Provenance::{Captured, Modelled, Published};
use Version::{Fixed, FromVendor, Unknown};

/// The vendor class every Windows release since 2000 sends.
const MSFT: Vendor = Vendor::Exact("MSFT 5.0");
/// The vendor class prefix of Android's own DHCP client (Android 9 and later).
const ANDROID: Vendor = Vendor::Prefix("android-dhcp-");

/// The table, in the order the documentation lists it.
pub static ENTRIES: &[Entry] = &[
    // Windows. Windows Server sends the list of the desktop release it shares a kernel with.
    Entry::new(
        "windows-10",
        Exact(&[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
        MSFT,
        "windows",
        Fixed("10 or 11 (or Server 2016 and later)"),
        85,
        Modelled,
    ),
    Entry::new(
        "windows-7",
        Exact(&[1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43, 252]),
        MSFT,
        "windows",
        Fixed("7 or 8 (or Server 2008 R2 to 2012 R2)"),
        80,
        Modelled,
    ),
    Entry::new(
        "windows-xp",
        Exact(&[1, 15, 3, 6, 44, 46, 47, 31, 33, 249, 43]),
        MSFT,
        "windows",
        Fixed("XP (or Server 2003)"),
        75,
        Published,
    ),
    // Apple. macOS asks for 95 (LDAP), 44 and 46 (NetBIOS); iOS and iPadOS do not.
    Entry::new(
        "macos-13",
        Exact(&[1, 121, 3, 6, 15, 108, 114, 119, 252, 95, 44, 46]),
        Vendor::Absent,
        "macos",
        Fixed("13 or later"),
        80,
        Modelled,
    ),
    Entry::new(
        "macos-11",
        Exact(&[1, 121, 3, 6, 15, 114, 119, 252, 95, 44, 46]),
        Vendor::Absent,
        "macos",
        Fixed("11 or 12"),
        70,
        Published,
    ),
    Entry::new(
        "macos-10",
        Exact(&[1, 121, 3, 6, 15, 119, 252, 95, 44, 46]),
        Vendor::Absent,
        "macos",
        Fixed("10.x"),
        70,
        Published,
    ),
    Entry::new(
        "ios-15",
        Exact(&[1, 121, 3, 6, 15, 108, 114, 119, 252]),
        Vendor::Absent,
        "ios",
        Fixed("15 or later (iOS or iPadOS)"),
        75,
        Published,
    ),
    Entry::new(
        "ios-14",
        Exact(&[1, 121, 3, 6, 15, 114, 119, 252]),
        Vendor::Absent,
        "ios",
        Fixed("14 (iOS or iPadOS)"),
        70,
        Published,
    ),
    Entry::new(
        "ios-10",
        Exact(&[1, 121, 3, 6, 15, 119, 252]),
        Vendor::Absent,
        "ios",
        Fixed("10 to 13 (iOS or iPadOS)"),
        65,
        Published,
    ),
    // Android's own client (Android 9 and later) names its release in the vendor class.
    Entry::new(
        "android-13",
        Exact(&[1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108]),
        ANDROID,
        "android",
        FromVendor("{}"),
        90,
        Modelled,
    ),
    Entry::new(
        "android-11",
        Exact(&[1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114]),
        ANDROID,
        "android",
        FromVendor("{}"),
        85,
        Published,
    ),
    Entry::new(
        "android-9",
        Exact(&[1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
        ANDROID,
        "android",
        FromVendor("{}"),
        85,
        Published,
    ),
    // Linux clients.
    Entry::new(
        "debian-dhclient",
        Exact(&[1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42]),
        Vendor::Absent,
        "linux",
        Fixed("(Debian or Ubuntu, ISC dhclient)"),
        75,
        Captured,
    ),
    Entry::new(
        "systemd-networkd",
        Exact(&[1, 3, 6, 12, 15, 28, 42, 119, 121]),
        Vendor::Absent,
        "linux",
        Fixed("(systemd-networkd: Ubuntu Server, Debian)"),
        65,
        Modelled,
    ),
    Entry::new(
        "networkmanager",
        Exact(&[
            1, 2, 6, 12, 15, 26, 28, 121, 3, 33, 40, 41, 42, 119, 249, 252, 17,
        ]),
        Vendor::Absent,
        "linux",
        Fixed("(Fedora or RHEL, NetworkManager)"),
        70,
        Published,
    ),
    Entry::new(
        "udhcpc",
        Exact(&[1, 3, 6, 12, 15, 28, 42]),
        Vendor::Prefix("udhcp "),
        "linux",
        FromVendor("(BusyBox udhcpc {})"),
        85,
        Captured,
    ),
    Entry::new(
        "udhcpc-quiet",
        Exact(&[1, 3, 6, 12, 15, 28, 42]),
        Vendor::Absent,
        "linux",
        Fixed("(BusyBox udhcpc)"),
        60,
        Captured,
    ),
    Entry::new(
        "chromeos",
        Exact(&[1, 121, 33, 3, 6, 12, 15, 28, 51, 54, 58, 59, 119, 252]),
        Vendor::Absent,
        "chromeos",
        Unknown,
        50,
        Published,
    ),
    // Consoles. The Xbox sends Windows's vendor class with its own suffix.
    Entry::new(
        "playstation",
        Exact(&[1, 3, 15, 6]),
        Vendor::Absent,
        "playstation",
        Fixed("4 or 5"),
        40,
        Published,
    ),
    // Embedded stacks: lwIP asks for the mask, the router, the broadcast address, then
    // DNS when it keeps DNS servers and NTP when SNTP is on (its `dhcp.c`).
    Entry::new(
        "lwip",
        Exact(&[1, 3, 28, 6]),
        Vendor::Absent,
        "embedded",
        Fixed("(lwIP: ESP8266, ESP-IDF, Tasmota, ESPHome)"),
        60,
        Published,
    ),
    Entry::new(
        "lwip-ntp",
        Exact(&[1, 3, 28, 6, 42]),
        Vendor::Absent,
        "embedded",
        Fixed("(lwIP with SNTP: ESP-IDF, Tasmota, ESPHome)"),
        60,
        Published,
    ),
    Entry::new(
        "lwip-minimal",
        Exact(&[1, 3, 28]),
        Vendor::Absent,
        "embedded",
        Fixed("(lwIP without DNS)"),
        50,
        Published,
    ),
    // List prefixes: a release this table does not know yet.
    Entry::new(
        "windows-family",
        Prefix(&[1, 3, 6, 15, 31, 33, 43, 44, 46, 47]),
        MSFT,
        "windows",
        Fixed("10 or later"),
        60,
        Published,
    ),
    Entry::new(
        "android-family",
        Prefix(&[1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
        ANDROID,
        "android",
        FromVendor("{}"),
        80,
        Published,
    ),
    Entry::new(
        "apple-family",
        Prefix(&[1, 121, 3, 6, 15]),
        Vendor::Absent,
        "apple",
        Fixed("(macOS, iOS or iPadOS)"),
        45,
        Published,
    ),
    Entry::new(
        "dhclient-family",
        Prefix(&[1, 28, 2, 3, 15, 6]),
        Vendor::Absent,
        "linux",
        Fixed("(ISC dhclient)"),
        45,
        Captured,
    ),
    // The vendor class alone.
    Entry::new(
        "xbox",
        Any,
        Vendor::Prefix("MSFT 5.0 XBOX"),
        "xbox",
        Unknown,
        70,
        Published,
    ),
    Entry::new(
        "ipxe",
        Any,
        Vendor::Prefix("PXEClient"),
        "firmware",
        Fixed("(iPXE: QEMU and Proxmox VMs boot through it)"),
        65,
        Published,
    )
    .with_user_class(true),
    Entry::new(
        "uefi-http",
        Any,
        Vendor::Prefix("HTTPClient:Arch:"),
        "firmware",
        Fixed("(UEFI HTTP boot)"),
        70,
        Published,
    )
    .with_architecture(true),
    Entry::new(
        "uefi-pxe-x64",
        Any,
        Vendor::Prefix("PXEClient:Arch:00007"),
        "firmware",
        Fixed("(UEFI PXE, x64)"),
        70,
        Modelled,
    )
    .with_architecture(true),
    Entry::new(
        "uefi-pxe-x64-ebc",
        Any,
        Vendor::Prefix("PXEClient:Arch:00009"),
        "firmware",
        Fixed("(UEFI PXE, x64)"),
        70,
        Published,
    )
    .with_architecture(true),
    Entry::new(
        "bios-pxe",
        Any,
        Vendor::Prefix("PXEClient:Arch:00000"),
        "firmware",
        Fixed("(BIOS PXE)"),
        70,
        Modelled,
    )
    .with_architecture(true),
    Entry::new(
        "hp-jetdirect",
        Any,
        Vendor::Prefix("Hewlett-Packard JetDirect"),
        "printer",
        Fixed("(HP JetDirect)"),
        80,
        Published,
    ),
    Entry::new(
        "proxmox-dhcpcd",
        Any,
        Vendor::Contains("-pve:"),
        "linux",
        Fixed("(Proxmox VE host, dhcpcd)"),
        60,
        Published,
    ),
    Entry::new(
        "dhcpcd",
        Any,
        Vendor::Prefix("dhcpcd-"),
        "linux",
        Fixed("(dhcpcd: Raspberry Pi OS, Arch Linux)"),
        55,
        Published,
    ),
    Entry::new(
        "android-vendor",
        Any,
        ANDROID,
        "android",
        FromVendor("{}"),
        75,
        Published,
    ),
    Entry::new(
        "udhcpc-vendor",
        Any,
        Vendor::Prefix("udhcp "),
        "linux",
        FromVendor("(BusyBox udhcpc {})"),
        60,
        Captured,
    ),
    Entry::new(
        "windows-vendor",
        Any,
        MSFT,
        "windows",
        Unknown,
        50,
        Published,
    ),
];

/// The display name of a family.
pub fn family_name(family: &str) -> &str {
    match family {
        "windows" => "Windows",
        "macos" => "macOS",
        "ios" => "iOS",
        "android" => "Android",
        "linux" => "Linux",
        "chromeos" => "ChromeOS",
        "xbox" => "Xbox",
        "playstation" => "PlayStation",
        "printer" => "Printer",
        "embedded" => "Embedded",
        "firmware" => "Boot firmware",
        "apple" => "Apple",
        other => other,
    }
}
