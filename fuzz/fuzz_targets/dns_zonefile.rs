#![no_main]

use std::{collections::BTreeMap, sync::OnceLock};

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use tenko_core::{
    CounterKey, RequestCtx, Revision, SystemComponent,
    dns::{
        DnsName, Origin, Rdata, RecordData, RrSet, Rtype, ScopeName, SoaDefaults, Zone, ZoneId,
        ZoneKind, ZoneScope, tables::RRSETS,
    },
    ipam::Stamp,
    names::TableName,
};
use tenko_dns::zone::{
    records::{self, Change, Op},
    zonefile::{self, Item, Reader},
};
use tenko_store::{KeyRange, ReadView, StoreError, Versioned};

/// A read view over the apex SOA and NS rows of one zone.
struct Rows(BTreeMap<(TableName, Bytes), Versioned>);

impl ReadView for Rows {
    fn revision(&self) -> Revision {
        Revision(1)
    }

    fn get(&self, table: &TableName, key: &[u8]) -> Result<Option<Versioned>, StoreError> {
        Ok(self
            .0
            .get(&(table.clone(), Bytes::copy_from_slice(key)))
            .cloned())
    }

    fn scan(
        &self,
        table: &TableName,
        range: KeyRange,
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Bytes, Versioned)>, StoreError> {
        let mut rows: Vec<(Bytes, Versioned)> = self
            .0
            .iter()
            .filter(|((name, key), _)| name == table && range.contains(key))
            .map(|((_, key), value)| (key.clone(), value.clone()))
            .collect();
        if reverse {
            rows.reverse();
        }
        rows.truncate(limit);
        Ok(rows)
    }

    fn counter(&self, _counter: &CounterKey) -> Result<u64, StoreError> {
        Ok(0)
    }
}

struct Fixture {
    zone: Zone,
    view: Rows,
    cx: RequestCtx,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let name = |text: &str| DnsName::new(text).expect("name");
        let cx = RequestCtx::system(SystemComponent::Dns);
        let stamp = Stamp::new(cx.now, cx.principal.clone());
        let zone = Zone {
            id: ZoneId::generate(),
            name: name("example.test"),
            kind: ZoneKind::Primary,
            tenant: None,
            scopes: vec![ZoneScope::default_scope()],
            serial: tenko_core::dns::SerialPolicy::Counter,
            soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
            transfer: Default::default(),
            update: Default::default(),
            dnssec: Default::default(),
            source: None,
            reverse_of: None,
            catalog: false,
            description: None,
            created: stamp.clone(),
            updated: stamp.clone(),
        };
        let rrset = |rtype: Rtype, data: RecordData| RrSet {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            name: zone.name.clone(),
            rtype,
            ttl: 3600,
            rdata: vec![Rdata::from_data(&data)],
            origin: Origin::Manual,
            key: None,
            updated: stamp.clone(),
        };
        let soa = rrset(
            Rtype::SOA,
            RecordData::Soa {
                mname: name("ns1.example.test"),
                rname: name("hostmaster.example.test"),
                serial: 1,
                refresh: 3600,
                retry: 900,
                expire: 1_209_600,
                minimum: 300,
            },
        );
        let ns = rrset(
            Rtype::NS,
            RecordData::Ns {
                host: name("ns1.example.test"),
            },
        );
        let mut rows = BTreeMap::new();
        for rrset in [soa, ns] {
            rows.insert(
                (RRSETS.name().clone(), RRSETS.key(&rrset.key())),
                Versioned {
                    value: RRSETS.encode(&rrset).expect("encode"),
                    revision: Revision(1),
                },
            );
        }
        Fixture {
            zone,
            view: Rows(rows),
            cx,
        }
    })
}

// The input is a zone file for `example.test`. It is read record by record (with
// `$GENERATE` expanded and `$INCLUDE` refused); every record becomes an `add` change, the
// changes are validated together as one batch against the apex SOA and NS set, and every
// record read is written back in presentation form and read again.
fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let text = String::from_utf8_lossy(data);
    let Ok(mut reader) = Reader::new(&text, &fixture.zone.name, 256) else {
        return;
    };
    let mut changes = Vec::new();
    while let Ok(Some(item)) = reader.next_item() {
        let Item::Record(record) = item else {
            continue;
        };
        if let Ok(presented) = zonefile::presentation(record.rtype, &record.rdata) {
            let line = format!(
                "{} {} IN {} {presented}\n",
                zonefile::absolute(&record.name),
                record.ttl,
                zonefile::type_name(record.rtype)
            );
            if let Ok(mut again) = Reader::new(&line, &fixture.zone.name, 1) {
                let _ = again.next_item();
            }
        }
        if changes.len() < 512
            && let Ok(data) = record.rdata.decode(record.rtype)
        {
            changes.push(Change {
                op: Op::Add,
                scope: ScopeName::DEFAULT,
                name: record.name,
                rtype: record.rtype,
                ttl: Some(record.ttl),
                records: vec![data],
                take_over: false,
                origin: Origin::Manual,
            });
        }
    }
    let _ = records::validate(&fixture.view, &fixture.zone, &changes, &fixture.cx);
});
