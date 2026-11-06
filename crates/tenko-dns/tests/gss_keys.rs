//! The seam of the account's keys and the acceptor (WP13.2 with the account's lifecycle;
//! DNS-28, identity plan section 3.2): the watcher of the account (`zone::kerberos::follow`)
//! hands the key set the vault holds to the TKEY handler through its `KeyHandle`, at start,
//! when the key set changes (current and previous versions), and clears it when the account
//! is deleted. The keytabs are the recorded ones of `tenko-krb`; no KDC is reached.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tenko_core::{
    RequestCtx, SystemComponent,
    audit::AuditDraft,
    dns::{EncryptionType, QueryTransport, Realm},
};
use tenko_dns::{
    respond::Conn,
    tkey::{
        GssSettings, Tkey,
        testing::Initiator,
        wire::{answer_record, mode, write_query},
    },
    tsig::{GSS_TSIG, Keyring},
    xfr::TransferAudit,
    zone::kerberos::{
        ImportRequest, KerberosConfig, KerberosService, KeySink, RandomPasswords, SilentKdc,
        SystemClock, follow,
    },
};
use tenko_krb::cipher::Key;
use tenko_store::{MemStore, Store};
use tenko_vault::{MemVault, Vault};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const SPN: &str = "DNS/tenko.corp.example.test";
/// The keys of `TENKO-DNS$` in the recorded keytabs (`tests/fixtures/keytabs/*.klist`).
const KVNO_2: &str = "5180f364524e955d59bbc396651d38d25d7aae5515b1cb5f4a7d1751409282a1";
const KVNO_3: &str = "33bf225e01dee5621f2214cca36b25befed000908a0dfbee73a2da37acf9b997";
const KVNO_300: &str = "6914c775fcec2bf9d524ba3372a97d0d294ff54aba4f87a3ad99c6afabcbff1e";

#[derive(Default)]
struct NoAudit(Mutex<Vec<AuditDraft>>);

impl TransferAudit for NoAudit {
    fn record(&self, draft: AuditDraft) {
        self.0.lock().expect("audit").push(draft);
    }
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn keytab(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tenko-krb/tests/fixtures/keytabs")
            .join(name),
    )
    .expect("keytab fixture")
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time")
}

struct Node {
    tkey: Arc<Tkey>,
    service: Arc<KerberosService>,
    hmac: Keyring,
    audit: NoAudit,
    names: Mutex<u32>,
}

impl Node {
    /// One negotiation with a ticket under `key` at `kvno`: the TKEY error, or `None` when
    /// the node answered without a TKEY record (REFUSED: no keys).
    fn negotiate(&self, key: &str, kvno: u32) -> Option<u16> {
        let mut count = self.names.lock().expect("names");
        *count += 1;
        let mut name = vec![4_u8];
        name.extend_from_slice(format!("k{count:03}").as_bytes());
        name.extend_from_slice(b"\x04corp\x07example\x04test\x00");
        let service_key = Key::new(EncryptionType::Aes256CtsHmacSha1, &unhex(key)).expect("key");
        // A second after the acceptor's start, which takes authenticators from after it.
        let mut init = Initiator::new(service_key, kvno, "pc01$", now() + 2);
        init.cusec = *count;
        init.spn = SPN.split('/').map(str::to_owned).collect();
        let mut query = Vec::new();
        write_query(
            &mut query,
            1,
            &name,
            GSS_TSIG,
            mode::GSSAPI,
            &init.raw_token(),
            0,
        );
        let conn = Conn {
            client: SocketAddr::from(([192, 0, 2, 21], 40_000)),
            local: SocketAddr::from(([192, 0, 2, 53], 53)),
            transport: QueryTransport::Tcp,
        };
        let answer = self
            .tkey
            .answer(&query, &conn, &self.hmac, &self.audit)
            .expect("an answer");
        answer_record(&answer)
            .expect("parses")
            .map(|(_, error, _)| error)
    }
}

async fn until(what: &str, check: impl Fn() -> bool) {
    for _ in 0..500 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

/// DNS-28: a key set stored in the vault reaches the acceptor through the watcher: after an
/// import (versions 3 current and 2 previous, both accepted), after a new key set
/// replaces it (version 300 accepted, the old ones refused), and nothing after the account
/// is deleted (TKEY REFUSED).
#[tokio::test]
async fn dns_28_the_accounts_keys_reach_the_acceptor_and_are_cleared() {
    let memory = Arc::new(MemStore::default());
    let vault = Arc::new(MemVault::with_store(Arc::clone(&memory)));
    let service = KerberosService::new(
        Arc::clone(&memory) as Arc<dyn Store>,
        Some(vault as Arc<dyn Vault>),
        Arc::new(SilentKdc),
        Arc::new(SystemClock),
        Arc::new(RandomPasswords),
        KerberosConfig::default(),
    );
    let node = Node {
        tkey: Tkey::new(GssSettings::default()),
        service,
        hmac: Keyring::default(),
        audit: NoAudit::default(),
        names: Mutex::new(0),
    };
    let stop = CancellationToken::new();
    let handle = node.tkey.handle();
    let task = tokio::spawn(follow(
        Arc::clone(&node.service),
        Arc::new(handle.clone()) as Arc<dyn KeySink>,
        stop.clone(),
    ));
    assert_eq!(node.negotiate(KVNO_3, 3), None, "no keys yet: REFUSED");
    let import = |file: &str| ImportRequest {
        realm: Realm::new("CORP.EXAMPLE.TEST").expect("realm"),
        name: None,
        keytab: Zeroizing::new(keytab(file)),
        spns: vec![SPN.to_owned()],
        kdcs: vec!["192.0.2.88".to_owned()],
    };
    // The self-test cannot reach a KDC here; the keys are stored all the same.
    let _ = node
        .service
        .import(&cx(), import("computer-tenko-dns.keytab"))
        .await;
    until("the keys of the import", || handle.installed().is_some()).await;
    assert_eq!(
        handle.installed().map(|(_, spns)| spns),
        Some(vec![SPN.to_owned()])
    );
    assert_eq!(node.negotiate(KVNO_3, 3), Some(0), "the current version");
    assert_eq!(node.negotiate(KVNO_2, 2), Some(0), "the previous version");
    // A new key set for the account replaces the old one.
    node.service.delete(&cx()).await.expect("delete");
    let _ = node.service.import(&cx(), import("kvno-300.keytab")).await;
    until("the new keys", || node.negotiate(KVNO_300, 300) == Some(0)).await;
    assert_eq!(
        node.negotiate(KVNO_3, 3),
        Some(17),
        "the old key set is gone (BADKEY)"
    );
    // The account goes: the acceptor holds no keys.
    node.service.delete(&cx()).await.expect("delete");
    until("the keys to be cleared", || handle.installed().is_none()).await;
    assert_eq!(node.negotiate(KVNO_300, 300), None, "REFUSED");
    stop.cancel();
    task.await.expect("the watcher stops");
}
