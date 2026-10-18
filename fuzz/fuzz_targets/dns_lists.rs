#![no_main]

use libfuzzer_sys::fuzz_target;
use tenko_core::dns::ListFormat;
use tenko_dns::{
    NameBuf,
    lists::{
        ListMatcher, compile_text,
        compile::{decode, key_text, name_key},
    },
};

// The input is the text of a block list, as a fetch or an upload hands it in. It is read
// as a hosts file and as a domain list, compiled, and the compiled version is decoded and
// built into the matcher of the query path: every compiled name matches itself and a name
// below it. The same input is also read as a compiled version (the bytes a node receives)
// and as a wire name asked of the matcher.
fuzz_target!(|data: &[u8]| {
    let mut probe = NameBuf::root();
    for format in [ListFormat::Hosts, ListFormat::Domains] {
        let Ok((compiled, _)) = compile_text(data, format) else {
            continue;
        };
        let keys = decode(&compiled.bytes).expect("a compiled version decodes");
        assert_eq!(keys.len() as u64, compiled.entries);
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        let matcher = ListMatcher::build(&compiled.bytes).expect("a compiled version builds");
        for key in keys.iter().take(64) {
            let text = key_text(key);
            assert_eq!(name_key(&text).as_deref(), Some(&key[..]));
            if let Ok(name) = tenko_core::dns::DnsName::new(&text) {
                probe = NameBuf::from_dns_name(&name);
                assert!(matcher.matches(probe.as_wire()));
                if let Ok(below) = tenko_core::dns::DnsName::new(&format!("x.{text}")) {
                    assert!(matcher.matches(NameBuf::from_dns_name(&below).as_wire()));
                }
            }
        }
        if let Ok(name) = NameBuf::from_wire(data) {
            let _ = matcher.matches(name.as_wire());
        }
    }
    let _ = decode(data);
    if let Ok(matcher) = ListMatcher::build(data) {
        let _ = matcher.matches(probe.as_wire());
    }
});
