#![no_main]
//! The DHCPv4 option walk and every typed option parser, fed an options area directly.
//!
//! The input is one control octet and the options: bit 0 of the control octet makes the
//! next 192 octets the `sname` (64) and `file` (128) fields, which option 52 may overload;
//! the rest is the options field after the magic cookie. A fixed BOOTREQUEST header is put
//! in front, so that every input reaches the walk instead of the header checks.
//!
//! It checks the walk against the lookups built on it: `option` and `option_data` agree
//! with the instances the walk yields (one instance, a split, the RFC 3396 concatenation in
//! walk order), and every typed parser that accepts a value keeps its own invariants (the
//! lengths it counts, the sub-options it walks, the routes and names it encodes again).

use libfuzzer_sys::fuzz_target;
use tenko_dhcp::v4::{
    AddrList, Architectures, ClientFqdn, ClientId, DecodeError, DomainSearch, HEADER_LEN,
    LengthPrefixed, MAGIC_COOKIE, MachineId, Message, MessageType, NetworkInterfaceId,
    RelayAgentInfo, Route, Routes, SubOptions, UserClass, VendorClasses, VendorInfos, WireName,
    code, encode_classless_routes, encode_domain_search,
};

/// Where `sname` starts in the fixed header; `file` follows it.
const SNAME_AT: usize = 44;
const SNAME_FILE_LEN: usize = 64 + 128;

fn message_bytes(data: &[u8]) -> Vec<u8> {
    let (control, rest) = data.split_first().map_or((0, data), |(c, r)| (*c, r));
    let mut out = vec![0u8; HEADER_LEN];
    out[0] = 1; // BOOTREQUEST
    out[1] = 1; // Ethernet
    out[2] = 6;
    out[28..34].copy_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
    let options = if control & 1 == 0 {
        rest
    } else {
        let take = rest.len().min(SNAME_FILE_LEN);
        out[SNAME_AT..SNAME_AT + take].copy_from_slice(&rest[..take]);
        &rest[take..]
    };
    out.extend_from_slice(&MAGIC_COOKIE);
    out.extend_from_slice(options);
    out
}

/// Runs the parser of the option's type on a value and checks what it accepts.
fn typed(option: u8, value: &[u8]) {
    match option {
        code::ROUTERS | code::DOMAIN_NAME_SERVERS | code::NTP_SERVERS => {
            if let Ok(list) = AddrList::parse(option, value) {
                assert_eq!(list.len() * 4, value.len());
                assert_eq!(list.iter().count(), list.len());
                assert!(!list.is_empty());
                assert_eq!(Some(list.first()), list.iter().next());
                assert_eq!(list.as_bytes(), value);
            }
        }
        code::CLIENT_IDENTIFIER => {
            if let Ok(id) = ClientId::parse(value) {
                assert_eq!(id.as_bytes(), value);
                assert_eq!(id.kind(), value[0]);
                if let Some((kind, address)) = id.hardware() {
                    assert_eq!(kind, value[0]);
                    assert_eq!(address, &value[1..]);
                }
                if let Some((_, duid)) = id.iaid_duid() {
                    let _ = (duid.kind(), duid.enterprise(), duid.link_layer());
                    assert!(duid.body().len() <= duid.as_bytes().len());
                }
            }
        }
        code::CLIENT_FQDN => {
            if let Ok(fqdn) = ClientFqdn::parse(value) {
                let name = fqdn.name();
                assert!(name.as_wire().len() <= 255);
                assert!(value.ends_with(fqdn.name_bytes()));
                let _ = (fqdn.flags(), fqdn.server_updates(), fqdn.overridden());
                let _ = (
                    fqdn.encoded(),
                    fqdn.no_update(),
                    fqdn.rcode1(),
                    fqdn.rcode2(),
                );
                let _ = name.to_string();
            }
        }
        code::RELAY_AGENT_INFORMATION => {
            if let Ok(info) = RelayAgentInfo::parse(value) {
                assert_eq!(info.as_bytes(), value);
                let walked: usize = info
                    .sub_options()
                    .into_iter()
                    .map(|(_, sub)| 2 + sub.len())
                    .sum();
                assert_eq!(walked, value.len());
            }
        }
        code::VENDOR_SPECIFIC => {
            // Option 43 is opaque unless a vendor space says otherwise; read it as
            // sub-options, as a vendor space does.
            if let Ok(subs) = SubOptions::parse(option, value) {
                let walked: usize = subs.into_iter().map(|(_, sub)| 2 + sub.len()).sum();
                assert_eq!(walked, value.len());
            }
        }
        code::USER_CLASS => {
            if let Ok(class) = UserClass::parse(value) {
                assert_eq!(class.as_bytes(), value);
                if let Some(classes) = class.classes() {
                    let walked: usize = classes.into_iter().map(|one| 1 + one.len()).sum();
                    assert_eq!(walked, value.len());
                }
            }
        }
        code::CLIENT_ARCHITECTURE => {
            if let Ok(architectures) = Architectures::parse(value) {
                assert_eq!(architectures.iter().count() * 2, value.len());
                assert_eq!(Some(architectures.first()), architectures.iter().next());
            }
        }
        code::CLIENT_NETWORK_INTERFACE => {
            let _ = NetworkInterfaceId::parse(value);
        }
        code::CLIENT_MACHINE_IDENTIFIER => {
            if let Ok(id) = MachineId::parse(value) {
                assert_eq!(id.kind(), value[0]);
                assert_eq!(id.id(), &value[1..]);
                if let Some(guid) = id.guid() {
                    assert_eq!(&guid[..], id.id());
                }
            }
        }
        code::VENDOR_CLASS => {
            if let Ok(vendors) = VendorClasses::parse(value) {
                for vendor in vendors.iter() {
                    if let Some(classes) = vendor.classes() {
                        let _ = classes.into_iter().count();
                    }
                }
            }
        }
        code::VENDOR_IDENTIFYING_INFO => {
            if let Ok(vendors) = VendorInfos::parse(value) {
                for vendor in vendors.iter() {
                    let _ = vendor.sub_options.into_iter().count();
                }
            }
        }
        code::CLASSLESS_STATIC_ROUTES | code::MS_CLASSLESS_STATIC_ROUTES => {
            if let Ok(routes) = Routes::parse(option, value) {
                let mut list = Vec::new();
                list.extend(routes.iter());
                let mut out = vec![0u8; list.len() * 9];
                let len = encode_classless_routes(option, &list, &mut out).expect("the routes fit");
                let again = Routes::parse(option, &out[..len]).expect("encoded routes decode");
                assert!(again.iter().eq(list.iter().copied()));
                for Route { prefix_len, .. } in list {
                    assert!(prefix_len <= 32);
                }
            }
        }
        code::DOMAIN_SEARCH => {
            if let Ok(search) = DomainSearch::parse(value) {
                let names: Vec<WireName> = search.iter().take(64).collect();
                let mut out = vec![0u8; 8192];
                if let Ok(len) = encode_domain_search(&names, &mut out) {
                    let again = DomainSearch::parse(&out[..len]).expect("an encoded list decodes");
                    assert!(again.iter().eq(names.iter().copied()));
                }
            }
        }
        _ => {}
    }
    // Every value may also be read as length-prefixed instances (options 77 and 124).
    if let Some(prefixed) = LengthPrefixed::parse(value) {
        let walked: usize = prefixed.into_iter().map(|one| 1 + one.len()).sum();
        assert_eq!(walked, value.len());
    }
    let _ = MessageType::from(value.first().copied().unwrap_or(0)).code();
}

/// Calls every typed accessor of the message; nothing may panic.
fn accessors(message: &Message<'_>) {
    let _ = (message.message_type(), message.server_identifier());
    let _ = (message.requested_address(), message.lease_time());
    let _ = (message.renewal_time(), message.rebinding_time());
    let _ = (message.parameter_request_list(), message.max_message_size());
    assert!(message.max_reply_len() >= 548);
    let _ = (message.vendor_class_identifier(), message.host_name());
    let _ = (message.client_identifier(), message.client_fqdn());
    let _ = (message.relay_agent_info(), message.user_class());
    let _ = (message.client_architectures(), message.network_interface());
    let _ = (
        message.machine_id(),
        message.vendor_classes(),
        message.vendor_infos(),
    );
    let _ = (message.auto_configure(), message.subnet_selection());
    let _ = (message.domain_search(), message.classless_routes());
    let _ = (message.ms_classless_routes(), message.subnet_mask());
    let _ = (message.routers(), message.domain_name_servers());
    let _ = (message.domain_name(), message.interface_mtu());
    let _ = (message.broadcast_address(), message.ntp_servers());
    let _ = (message.vendor_specific(), message.tftp_server_name());
    let _ = (message.bootfile_name(), message.server_name_str());
    let _ = message.boot_file_str();
    if let Ok(overload) = message.overload() {
        assert!(overload <= 3);
    }
}

fuzz_target!(|data: &[u8]| {
    let bytes = message_bytes(data);
    let message = Message::parse(&bytes).expect("a full header and the cookie parse");

    // The instances of each code as the walk yields them, up to the first error.
    let mut instances: Vec<Vec<&[u8]>> = vec![Vec::new(); 256];
    let mut walk_error = None;
    for item in message.options() {
        match item {
            Ok(option) => {
                assert_ne!(option.code, code::PAD);
                assert_ne!(option.code, code::END);
                instances[usize::from(option.code)].push(option.data);
            }
            Err(error) => {
                walk_error = Some(error);
                break;
            }
        }
    }
    assert_eq!(message.validate().err(), walk_error);

    // The instances of one code together are never longer than the message.
    let mut scratch = vec![0u8; bytes.len()];
    for (option, seen) in instances.iter().enumerate() {
        let option = u8::try_from(option).expect("a code");
        match (seen.len(), message.option(option)) {
            (0, Ok(found)) => assert!(found.is_none()),
            (0, Err(error)) => assert_eq!(Some(error), walk_error),
            (1, found) => assert_eq!(found, Ok(Some(seen[0]))),
            (_, found) => assert_eq!(found, Err(DecodeError::Split { code: option })),
        }
        if seen.is_empty() {
            continue;
        }
        let joined = message
            .option_data(option, &mut scratch)
            .expect("the instances fit")
            .expect("the option is there");
        assert_eq!(
            joined.len(),
            seen.iter().map(|one| one.len()).sum::<usize>()
        );
        let mut at = 0;
        for one in seen {
            assert_eq!(&joined[at..at + one.len()], *one);
            at += one.len();
        }
        let joined = joined.to_vec();
        typed(option, &joined);
    }
    accessors(&message);

    // An address read from option 50 is its four octets as given.
    if let Ok(Some(addr)) = message.requested_address() {
        assert_eq!(
            &addr.octets()[..],
            instances[usize::from(code::REQUESTED_ADDRESS)][0]
        );
    }
});
