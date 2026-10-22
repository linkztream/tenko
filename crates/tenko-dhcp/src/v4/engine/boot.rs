//! Network boot (DHCP-05, plan WP8.4, decision P3-Q16): PXE (RFC 4578 and the PXE 2.1
//! specification), UEFI HTTP boot (the UEFI specification's `HTTPClient`), iPXE and
//! PXELINUX (RFC 5071), and proxy DHCP on port 4011.
//!
//! What the boot settings are: options of the levels a reply merges (server, shared
//! network, scope, policies, reservation), so that a boot file per client architecture is a
//! policy over a class of option 93, and iPXE's chain detection a policy over the user
//! class `iPXE` ordered before the others (`docs/dhcp.md` section 16):
//!
//! - option 67, the boot file (a TFTP path, or a URL for iPXE and UEFI HTTP boot);
//! - option 66, the TFTP server's name, and option 150, its addresses;
//! - option 43, the vendor-specific information of PXE (sub-options of the PXE 2.1
//!   specification);
//! - options 208 to 211 of PXELINUX (RFC 5071: the magic, the configuration file, the path
//!   prefix, the reboot time).
//!
//! A boot client is one whose option 60 starts with `PXEClient` (PXE firmware and iPXE) or
//! `HTTPClient` (UEFI HTTP boot). When the effective option set gives such a client a boot
//! file, the reply also carries:
//!
//! - the boot file in the `file` field (when it is shorter than 128 octets) as well as in
//!   option 67, since PXE firmware reads the field and iPXE and UEFI read either;
//! - `siaddr`, the next server: the first address of option 150, else option 66 when it is
//!   an IPv4 address in dotted form; a relative boot file is fetched from it by TFTP;
//! - option 60 echoed as `PXEClient` or `HTTPClient` (UEFI HTTP boot ignores an offer
//!   without it; PXE uses it to tell a boot server from a plain DHCP server), unless an
//!   option set holds option 60;
//! - for PXE, option 43 with discovery control 8 (boot from the file of this reply, no
//!   boot server discovery) unless an option set holds option 43;
//! - options 66, 67 and 208 to 211 when they are set, asked for or not (PXELINUX and PXE
//!   firmware do not always list them in option 55).
//!
//! A boot client without a boot file is answered as any other client.
//!
//! **proxy DHCP** ([`proxy`]): a listener in proxy mode answers boot clients only and hands
//! out no address. A DISCOVER gets an OFFER with `yiaddr` 0 and the boot information; a
//! REQUEST or INFORM (the boot server discovery of PXE 2.1 on port 4011, sent by a client
//! that has its address from whichever server) gets an ACK with the same, unicast to the
//! port it came from. The scope is selected as for every request (by `giaddr`, `ciaddr`
//! or the listener's address) and must exist in Tenko for the boot options and policies to
//! apply; its pools are not used. Nothing is written.

use std::net::Ipv4Addr;

use super::{
    Action, Answer, Context, Destination, DropReason, IgnoreReason, Received, Scratch, assemble,
    select,
};
use crate::{
    class::Facts,
    image::ConfigImage,
    v4::{BOOTREQUEST, EncodeError, Message, MessageBuilder, MessageType, RelayAgentInfo, code},
};

/// The prefix of option 60 of PXE firmware and iPXE.
pub const PXE_CLIENT: &[u8] = b"PXEClient";
/// The prefix of option 60 of UEFI HTTP boot.
pub const HTTP_CLIENT: &[u8] = b"HTTPClient";

/// Option 43 for a PXE client when no option set holds one: sub-option 6, PXE discovery
/// control, with bit 3 set (download the boot file of this reply; no boot server
/// discovery), then the end sub-option.
pub const PXE_VENDOR_DEFAULT: [u8; 4] = [6, 1, 8, 255];

/// The TFTP server addresses (Cisco's option 150, in the catalog).
pub const TFTP_SERVER_ADDRESS: u8 = 150;

/// The codes a boot reply carries unasked when they are set: the TFTP server's name, the
/// boot file and PXELINUX's options (RFC 5071).
pub const BOOT_UNASKED: [u8; 6] = [
    code::TFTP_SERVER_NAME,
    code::BOOTFILE_NAME,
    208,
    209,
    210,
    211,
];

/// The machine identifier (option 97), echoed in proxy DHCP replies.
const MACHINE_ID: u8 = code::CLIENT_MACHINE_IDENTIFIER;

/// What kind of boot client a request comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootClient {
    /// PXE firmware or iPXE (`PXEClient`).
    Pxe,
    /// UEFI HTTP boot (`HTTPClient`).
    Http,
}

impl BootClient {
    /// The kind of the request's option 60, if it is a boot client.
    pub fn of(facts: &Facts<'_>) -> Option<Self> {
        let class = facts.vendor_class?;
        if class.starts_with(PXE_CLIENT) {
            Some(Self::Pxe)
        } else if class.starts_with(HTTP_CLIENT) {
            Some(Self::Http)
        } else {
            None
        }
    }

    /// The option 60 a reply echoes.
    pub fn vendor_class(self) -> &'static [u8] {
        match self {
            Self::Pxe => PXE_CLIENT,
            Self::Http => HTTP_CLIENT,
        }
    }
}

/// The next server of a boot reply: the first address of option 150, else option 66 when
/// it is an IPv4 address in dotted form.
pub fn next_server(levels: &assemble::Levels<'_>) -> Option<Ipv4Addr> {
    if let Some(first) = levels
        .lookup(TFTP_SERVER_ADDRESS)
        .and_then(|data| data.first_chunk::<4>())
    {
        return Some(Ipv4Addr::from(*first));
    }
    levels
        .lookup(code::TFTP_SERVER_NAME)
        .and_then(|name| std::str::from_utf8(name).ok())
        .and_then(|text| text.trim_end_matches('\0').parse().ok())
}

/// The boot client and its boot file, when the reply is a boot reply.
pub fn boot_reply<'a>(levels: &assemble::Levels<'a>) -> Option<(BootClient, &'a [u8])> {
    let client = BootClient::of(levels.decision?.facts())?;
    let file = levels.lookup(code::BOOTFILE_NAME)?;
    (!file.is_empty()).then_some((client, file))
}

/// Sets `siaddr` (the next server) and `file` of a boot reply.
pub fn header(builder: &mut MessageBuilder<'_>, levels: &assemble::Levels<'_>, file: &[u8]) {
    if let Some(server) = next_server(levels) {
        builder.siaddr(server);
    }
    // A name of 128 octets or more is in option 67 only.
    let name = file.strip_suffix(b"\0").unwrap_or(file);
    let _ = builder.file(name);
}

/// The boot options of a reply after the asked ones: option 60, option 43 for PXE, and
/// [`BOOT_UNASKED`]. `put` writes an option unless it was written already.
pub fn options(
    builder: &mut MessageBuilder<'_>,
    levels: &assemble::Levels<'_>,
    client: BootClient,
    put: &mut dyn FnMut(&mut MessageBuilder<'_>, u8, &[u8]),
) {
    let class = levels
        .lookup(code::VENDOR_CLASS_IDENTIFIER)
        .unwrap_or(client.vendor_class());
    put(builder, code::VENDOR_CLASS_IDENTIFIER, class);
    if client == BootClient::Pxe {
        let vendor = levels
            .lookup(code::VENDOR_SPECIFIC)
            .unwrap_or(&PXE_VENDOR_DEFAULT);
        put(builder, code::VENDOR_SPECIFIC, vendor);
    }
    for code in BOOT_UNASKED {
        if let Some(data) = levels.lookup(code) {
            put(builder, code, data);
        }
    }
}

fn answer(request: Option<MessageType>, action: Action) -> Answer {
    Answer {
        request,
        action,
        selector: None,
    }
}

/// Answers a request that arrived on a proxy DHCP listener (the module comment): an OFFER
/// or ACK with the boot information and no address, or nothing for a client that is not a
/// boot client or has no boot file.
pub fn proxy(ctx: &Context<'_>, received: &Received<'_>, scratch: &mut Scratch) -> Answer {
    let Ok(message) = Message::parse(received.bytes) else {
        return answer(None, Action::Drop(DropReason::Malformed));
    };
    if message.op() != BOOTREQUEST {
        return answer(None, Action::Ignore(IgnoreReason::NotRequest));
    }
    let kind = match message.message_type() {
        Ok(Some(kind)) => kind,
        Ok(None) => return answer(None, Action::Ignore(IgnoreReason::NotRequest)),
        Err(_) => return answer(None, Action::Drop(DropReason::Malformed)),
    };
    let request = Some(kind);
    let reply_kind = match kind {
        MessageType::Discover => MessageType::Offer,
        MessageType::Request | MessageType::Inform => MessageType::Ack,
        _ => return answer(request, Action::Ignore(IgnoreReason::OtherType)),
    };
    let (Ok(chaddr), Ok(client_id), Ok(relay)) = (
        message.chaddr(),
        message.client_identifier(),
        message.relay_agent_info(),
    ) else {
        return answer(request, Action::Drop(DropReason::Malformed));
    };
    let image: &ConfigImage = ctx.image;
    let facts = Facts::of(&message);
    if BootClient::of(&facts).is_none() {
        return answer(request, Action::Ignore(IgnoreReason::NotBootClient));
    }
    if message
        .mac()
        .is_ok_and(|mac| image.verdict(&mac) == tenko_core::dhcp::FilterVerdict::Denied)
    {
        return answer(request, Action::Drop(DropReason::Filtered));
    }
    let Some((scope, selector)) = select::select(image, &message, kind, relay, received) else {
        return answer(request, Action::Drop(DropReason::NoScope));
    };
    let client_id = client_id.map(|id| id.as_bytes());
    let mut identity = [0u8; tenko_core::dhcp::lease::MAX_IDENTITY];
    let len = tenko_core::dhcp::write_identity(message.htype(), chaddr, client_id, &mut identity);
    let mut hardware = [0u8; tenko_core::dhcp::lease::MAX_IDENTITY];
    let hardware_len =
        tenko_core::dhcp::write_identity(message.htype(), chaddr, None, &mut hardware);
    let decision = image.matcher().decide(scope.prefix, facts);
    let host = image
        .client_reservation(scope, &identity[..len], &hardware[..hardware_len])
        .map(|reservation| reservation.options.as_slice());
    let levels = assemble::Levels {
        scope,
        pool: None,
        host,
        decision: Some(&decision),
    };
    let Some((client, file)) = boot_reply(&levels) else {
        return Answer {
            request,
            action: Action::Ignore(IgnoreReason::NotBootClient),
            selector: Some(selector),
        };
    };
    let server_id = relay
        .and_then(|info| info.server_id_override())
        .or(scope.server_id)
        .unwrap_or(received.local);
    let Ok(mut builder) = MessageBuilder::reply(&mut scratch.reply, &message, reply_kind) else {
        return answer(request, Action::Drop(DropReason::Malformed));
    };
    if reply_kind == MessageType::Ack {
        builder.ciaddr(message.ciaddr());
    }
    header(&mut builder, &levels, file);
    let written = proxy_options(
        &mut builder,
        &levels,
        client,
        server_id,
        (&message, client_id, relay),
    );
    let (Ok(()), Ok(len)) = (written, builder.finish()) else {
        return answer(request, Action::Drop(DropReason::Malformed));
    };
    let dest = proxy_destination(ctx, &message, kind, received);
    Answer {
        request,
        action: Action::Reply {
            kind: reply_kind,
            len,
            dest,
        },
        selector: Some(selector),
    }
}

/// The options of a proxy reply: 54, the boot options, 97 and 61 echoed, 82 last.
fn proxy_options(
    builder: &mut MessageBuilder<'_>,
    levels: &assemble::Levels<'_>,
    client: BootClient,
    server_id: Ipv4Addr,
    (message, client_id, relay): (&Message<'_>, Option<&[u8]>, Option<RelayAgentInfo<'_>>),
) -> Result<(), EncodeError> {
    builder.server_identifier(server_id)?;
    let mut done = [false; 256];
    let mut put = |builder: &mut MessageBuilder<'_>, code: u8, data: &[u8]| {
        if done[usize::from(code)] {
            return;
        }
        done[usize::from(code)] = true;
        // An option that does not fit is left out whole.
        let _ = builder.option(code, data);
    };
    options(builder, levels, client, &mut put);
    if let Ok(Some(machine)) = message.option(MACHINE_ID) {
        put(builder, MACHINE_ID, machine);
    }
    if let Some(id) = client_id {
        builder.option(code::CLIENT_IDENTIFIER, id)?;
    }
    if let Some(info) = relay {
        builder.relay_agent_info(info.as_bytes())?;
    }
    Ok(())
}

/// Where a proxy reply goes: the relay; a DISCOVER's OFFER by broadcast; else back to the
/// address and port the request came from (the boot server discovery on port 4011).
fn proxy_destination(
    ctx: &Context<'_>,
    message: &Message<'_>,
    kind: MessageType,
    received: &Received<'_>,
) -> Destination {
    if !message.giaddr().is_unspecified() {
        Destination::Relay(std::net::SocketAddrV4::new(
            message.giaddr(),
            ctx.settings.relay_port,
        ))
    } else if kind == MessageType::Discover || received.source.ip().is_unspecified() {
        Destination::Broadcast(ctx.settings.client_port)
    } else {
        Destination::Client(received.source)
    }
}
