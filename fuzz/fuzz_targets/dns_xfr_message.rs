#![no_main]
//! The messages of zone transfers and NOTIFY (`tenko_dns::xfr::message`): a request as any
//! client sends it over TCP or UDP (AXFR, IXFR with the client's SOA, NOTIFY), and an answer
//! as a primary sends it to this node's secondary zones, with its names decompressed.
//!
//! The input is one message, read both ways. It checks that a request that reads writes back
//! (the header-only answer of the transfer path, and the request written again from what was
//! read) to messages that read to the same facts; and that the records of an answer that reads
//! are written by the transfer writer into messages of at most `MAX_TRANSFER_MESSAGE` octets
//! that read back to the same records, the SOA data with its serial.

use libfuzzer_sys::fuzz_target;
use tenko_dns::xfr::{
    self,
    message::{
        self, MAX_TRANSFER_MESSAGE, MessageWriter, OPCODE_NOTIFY, OPCODE_QUERY, Record, TYPE_AXFR,
        TYPE_SOA, read_answer, read_request, short_answer, soa_serial, write_request,
    },
};

/// One message of the writer read back: the records it holds are `pending`, in order.
fn check(message: &[u8], pending: &mut Vec<&Record>) {
    assert!(message.len() <= MAX_TRANSFER_MESSAGE);
    let answer = read_answer(message).expect("a written answer reads");
    assert_eq!(answer.id, 0x5e00);
    assert!(answer.authoritative && !answer.truncated && answer.rcode == 0);
    assert_eq!(answer.answers.len(), pending.len());
    for (back, record) in answer.answers.iter().zip(pending.iter()) {
        assert_eq!(back.name, record.name);
        assert_eq!(back.rtype, record.rtype);
        assert_eq!(back.ttl, record.ttl);
        assert_eq!(back.rdata, record.rdata);
        assert_eq!(back.class, 1);
    }
    pending.clear();
}

/// The records of `records` written by the transfer writer under a question for `zone`, read
/// back message by message; each record lands in a message unless it alone is too large.
fn written_back(zone: &[u8], records: &[Record]) {
    let mut request = Vec::new();
    write_request(&mut request, 0x5e00, OPCODE_QUERY, zone, TYPE_AXFR, None);
    let read = read_request(&request).expect("a written request reads");
    let mut writer = MessageWriter::new(&request, &read, MAX_TRANSFER_MESSAGE);
    let mut pending: Vec<&Record> = Vec::new();
    for record in records {
        let owner = record.name.to_wire();
        let data = record.rdata.as_bytes();
        if writer.push(&owner, record.rtype.0, record.ttl, data) {
            pending.push(record);
            continue;
        }
        if !writer.is_empty() {
            check(&writer.take(), &mut pending);
            if writer.push(&owner, record.rtype.0, record.ttl, data) {
                pending.push(record);
            }
        }
    }
    if !writer.is_empty() {
        check(&writer.take(), &mut pending);
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = xfr::classify(data);
    if let Some(request) = read_request(data) {
        assert!(request.question_end <= data.len());
        // The header-only answer: an error or the empty answer to a NOTIFY.
        for rcode in [0u8, 5, 9] {
            let short = short_answer(data, &request, rcode);
            let answer = read_answer(&short).expect("a short answer reads");
            assert_eq!(answer.id, request.id);
            assert_eq!(answer.opcode, request.opcode);
            assert_eq!(answer.rcode, rcode);
            assert!(answer.answers.is_empty());
        }
        // The request written again from what was read.
        let mut again = Vec::new();
        let opcode = if request.opcode == OPCODE_NOTIFY {
            OPCODE_NOTIFY
        } else {
            OPCODE_QUERY
        };
        let zone = request.question.name.as_wire();
        write_request(
            &mut again,
            request.id,
            opcode,
            zone,
            request.question.qtype,
            None,
        );
        let back = read_request(&again).expect("a written request reads");
        assert_eq!(back.id, request.id);
        assert_eq!(back.opcode, opcode);
        assert_eq!(back.question.name, request.question.name);
        assert_eq!(back.question.qtype, request.question.qtype);
        assert_eq!(back.question.qclass, 1);
        assert_eq!(back.serial, None);
        // A transfer writer for the request starts with its question and nothing else.
        let mut writer = MessageWriter::new(data, &request, MAX_TRANSFER_MESSAGE);
        assert!(writer.is_empty());
        let first = writer.take();
        assert_eq!(first.len(), request.question_end);
    }
    if let Ok(answer) = read_answer(data) {
        for record in &answer.answers {
            if record.rtype.0 == TYPE_SOA {
                let serial = soa_serial(record.rdata.as_bytes()).expect("SOA data has a serial");
                // An IXFR request carries the client's SOA in its authority section.
                let zone = record.name.to_wire();
                let mut ixfr = Vec::new();
                write_request(
                    &mut ixfr,
                    1,
                    OPCODE_QUERY,
                    &zone,
                    message::TYPE_IXFR,
                    Some((record.ttl, record.rdata.as_bytes())),
                );
                let read = read_request(&ixfr).expect("an IXFR request reads");
                assert_eq!(read.serial, Some(serial));
            }
        }
        if let Some(first) = answer.answers.first() {
            written_back(&first.name.to_wire(), &answer.answers);
        }
    }
});
