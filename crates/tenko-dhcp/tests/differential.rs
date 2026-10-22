//! The differential test of the DHCPv4 codec against `dhcproto` (ADR 0019 point 7), the
//! first cut that WP7.0 adds with the dev-dependency: every well-formed fixture is decoded
//! by both codecs and the fixed header and the message type are compared. WP7.1a and WP7.3
//! extend it to the options in order, the typed values, the relay sub-options and the
//! replies built by `MessageBuilder`, over the corpus of captured requests
//! (`docs/dhcp-contracts.md` section 12).

mod support;

use dhcproto::{Decodable, v4};
use support::{WELL_FORMED, fixture};
use tenko_dhcp::v4::Message;

#[test]
fn both_codecs_read_the_same_header_and_message_type() {
    for name in WELL_FORMED {
        let bytes = fixture(name);
        let ours = Message::parse(&bytes).expect("our codec parses the fixture");
        let theirs = v4::Message::from_bytes(&bytes).expect("dhcproto parses the fixture");
        assert_eq!(ours.op(), u8::from(theirs.opcode()), "{name}: op");
        assert_eq!(ours.htype(), u8::from(theirs.htype()), "{name}: htype");
        assert_eq!(ours.xid(), theirs.xid(), "{name}: xid");
        assert_eq!(ours.ciaddr(), theirs.ciaddr(), "{name}: ciaddr");
        assert_eq!(ours.giaddr(), theirs.giaddr(), "{name}: giaddr");
        assert_eq!(
            ours.chaddr().expect("chaddr"),
            theirs.chaddr(),
            "{name}: chaddr"
        );
        let our_type = ours
            .message_type()
            .expect("a valid option 53")
            .map(tenko_dhcp::v4::MessageType::code);
        let their_type = theirs.opts().msg_type().map(u8::from);
        assert_eq!(our_type, their_type, "{name}: message type");
    }
}
