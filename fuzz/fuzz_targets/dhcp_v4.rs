#![no_main]

use std::net::Ipv4Addr;

use libfuzzer_sys::fuzz_target;
use tenko_dhcp::v4::{
    DomainSearch, Message, MessageBuilder, MessageType, Route, Routes, WireName, code,
    encode_classless_routes, encode_domain_search,
};

/// Reads every field and every typed option; nothing may panic.
fn read_everything(message: &Message<'_>) {
    let _ = (
        message.chaddr(),
        message.mac(),
        message.secs(),
        message.broadcast(),
    );
    let _ = (
        message.server_name_str(),
        message.boot_file_str(),
        message.overload(),
    );
    let _ = message.validate();
    let mut scratch = [0u8; 2048];
    for option in message.options() {
        let Ok(option) = option else { break };
        if let Ok(Some(data)) = message.option_data(option.code, &mut scratch) {
            assert!(data.len() >= option.data.len());
        }
    }
    let _ = (message.message_type(), message.server_identifier());
    let _ = (message.requested_address(), message.lease_time());
    let _ = (message.renewal_time(), message.rebinding_time());
    let _ = (message.parameter_request_list(), message.max_message_size());
    assert!(message.max_reply_len() >= 548);
    let _ = (message.vendor_class_identifier(), message.host_name());
    if let Ok(Some(id)) = message.client_identifier() {
        let _ = id.hardware();
        if let Some((_, duid)) = id.iaid_duid() {
            let _ = (duid.enterprise(), duid.link_layer(), duid.body());
        }
    }
    if let Ok(Some(fqdn)) = message.client_fqdn() {
        let name = fqdn.name();
        let _ = name.to_string();
        assert!(name.as_wire().len() <= 255);
    }
    if let Ok(Some(relay)) = message.relay_agent_info() {
        let _ = (
            relay.circuit_id(),
            relay.remote_id(),
            relay.link_selection(),
        );
        let _ = (
            relay.subscriber_id(),
            relay.server_id_override(),
            relay.relay_id(),
        );
    }
    if let Ok(Some(class)) = message.user_class()
        && let Some(classes) = class.classes()
    {
        assert!(classes.into_iter().all(|class| !class.is_empty()));
    }
    if let Ok(Some(architectures)) = message.client_architectures() {
        let _ = architectures.iter().count();
    }
    let _ = (
        message.network_interface(),
        message.machine_id().map(|id| id.map(|id| id.guid())),
    );
    if let Ok(Some(vendors)) = message.vendor_classes() {
        let _ = vendors.iter().filter_map(|vendor| vendor.classes()).count();
    }
    if let Ok(Some(vendors)) = message.vendor_infos() {
        let _ = vendors
            .iter()
            .map(|vendor| vendor.sub_options.into_iter().count())
            .sum::<usize>();
    }
    let _ = (message.auto_configure(), message.subnet_selection());
    let _ = (
        message.subnet_mask(),
        message.routers(),
        message.domain_name_servers(),
    );
    let _ = (
        message.domain_name(),
        message.interface_mtu(),
        message.broadcast_address(),
    );
    let _ = (message.ntp_servers(), message.vendor_specific());
    let _ = (message.tftp_server_name(), message.bootfile_name());
    let _ = (
        message.ms_classless_routes(),
        message.classless_routes(),
        message.domain_search(),
    );

    // A search list and routes, concatenated, decode to what they encode to.
    if let Ok(Some(data)) = message.option_data(code::DOMAIN_SEARCH, &mut scratch)
        && let Ok(list) = DomainSearch::parse(data)
    {
        let mut names = [WireName::default(); 16];
        let mut count = 0;
        for name in list.iter().take(names.len()) {
            names[count] = name;
            count += 1;
        }
        let mut out = [0u8; 4096];
        let len = encode_domain_search(&names[..count], &mut out).expect("the names fit");
        let again = DomainSearch::parse(&out[..len]).expect("an encoded list decodes");
        assert!(again.iter().eq(names[..count].iter().copied()));
    }
    if let Ok(Some(data)) = message.option_data(code::CLASSLESS_STATIC_ROUTES, &mut scratch)
        && let Ok(routes) = Routes::parse(code::CLASSLESS_STATIC_ROUTES, data)
    {
        let mut list = [Route {
            destination: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
            router: Ipv4Addr::UNSPECIFIED,
        }; 64];
        let mut count = 0;
        for route in routes.iter().take(list.len()) {
            list[count] = route;
            count += 1;
        }
        let mut out = [0u8; 1024];
        let len = encode_classless_routes(121, &list[..count], &mut out).expect("the routes fit");
        let again = Routes::parse(121, &out[..len]).expect("encoded routes decode");
        assert!(again.iter().eq(list[..count].iter().copied()));
    }
}

/// Builds an OFFER for any message that parsed, with the options a server echoes or
/// copies, and checks that the reply reads back.
fn build_reply(message: &Message<'_>) {
    let mut buf = [0u8; 1500];
    let Ok(mut reply) = MessageBuilder::reply(&mut buf, message, MessageType::Offer) else {
        return;
    };
    let limit = reply.limit();
    let _ = reply.allow_overload();
    reply.yiaddr(Ipv4Addr::new(192, 0, 2, 50));
    let _ = reply.server_identifier(Ipv4Addr::new(198, 51, 100, 10));
    if let Ok(Some(fqdn)) = message.client_fqdn() {
        let _ = reply.client_fqdn(fqdn.flags() | 0x01, &fqdn.name());
    }
    // Copy the other options of the request; the ones that do not fit are left out.
    for option in message.options() {
        let Ok(option) = option else { break };
        if !matches!(
            option.code,
            code::MESSAGE_TYPE | code::CLIENT_FQDN | code::RELAY_AGENT_INFORMATION
        ) {
            let _ = reply.option(option.code, option.data);
        }
    }
    if let Ok(Some(relay)) = message.relay_agent_info() {
        let _ = reply.relay_agent_info(relay.as_bytes());
    }
    let _ = reply.pad_to(300);
    let len = reply.finish().expect("finish");
    assert!(len <= limit);
    let built = Message::parse(&buf[..len]).expect("a built reply parses");
    built.validate().expect("a built reply walks");
    assert_eq!(built.xid(), message.xid());
    assert_eq!(built.chaddr_field(), message.chaddr_field());
    assert_eq!(built.message_type(), Ok(Some(MessageType::Offer)));
    let first = built.options().next().expect("an option").expect("ok");
    assert_eq!(first.code, code::MESSAGE_TYPE);
}

fuzz_target!(|data: &[u8]| {
    let Ok(message) = Message::parse(data) else {
        return;
    };
    read_everything(&message);
    build_reply(&message);
});
