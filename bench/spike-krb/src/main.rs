//! `spike-krb serve`: a TCP acceptor for the MIT peer (`peer/gss-peer.c`).
//!
//! Frames are 4-octet big-endian lengths and bytes. The exchange: the initiator's tokens
//! until the context is established, then a message and its MIC from the initiator, the
//! acceptor's message and MIC back, a second message and MIC from the initiator, and the
//! acceptor's verdict `OK` or `FAIL` on the initiator's MICs.
#![forbid(unsafe_code)]

use std::net::{TcpListener, TcpStream};

use spike_krb::acceptor::{Acceptor, Context, Enctype, ServiceKey, Step};
use spike_krb::hex;
use spike_krb::mic::ContextMicKeys;
use spike_krb::wire::{read_frame, write_frame};

const USAGE: &str = "usage: spike-krb serve --acceptor sspi|own --key <enctype>:<kvno>:<hex> [--key ...] \
[--spn DNS/tenko.corp.example.test] [--realm CORP.EXAMPLE.TEST] [--listen 127.0.0.1:5353] [--once] [--no-subkey]";

struct Args {
    acceptor: String,
    keys: Vec<ServiceKey>,
    spn: Vec<String>,
    realm: String,
    listen: String,
    once: bool,
    subkey: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    if it.next().as_deref() != Some("serve") {
        return Err(USAGE.into());
    }
    let mut a = Args {
        acceptor: "own".into(),
        keys: Vec::new(),
        spn: vec!["DNS".into(), "tenko.corp.example.test".into()],
        realm: "CORP.EXAMPLE.TEST".into(),
        listen: "127.0.0.1:5353".into(),
        once: false,
        subkey: true,
    };
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--acceptor" => a.acceptor = val()?,
            "--key" => {
                let v = val()?;
                let mut parts = v.splitn(3, ':');
                let et: i64 = parts.next().unwrap_or("").parse().map_err(|_| "enctype")?;
                let kvno: u32 = parts.next().unwrap_or("").parse().map_err(|_| "kvno")?;
                let key = hex::decode(parts.next().unwrap_or(""))?;
                let enctype = Enctype::from_number(et).ok_or("enctype must be 17 or 18")?;
                if key.len() != enctype.key_len() {
                    return Err("key length does not match the enctype".into());
                }
                a.keys.push(ServiceKey {
                    enctype,
                    kvno: Some(kvno),
                    key,
                });
            }
            "--spn" => a.spn = val()?.split('/').map(str::to_owned).collect(),
            "--realm" => a.realm = val()?,
            "--listen" => a.listen = val()?,
            "--once" => a.once = true,
            "--no-subkey" => a.subkey = false,
            _ => return Err(USAGE.into()),
        }
    }
    if a.keys.is_empty() {
        return Err("at least one --key".into());
    }
    Ok(a)
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let listener = TcpListener::bind(&args.listen).expect("bind");
    eprintln!(
        "spike-krb: {} acceptor listening on {}",
        args.acceptor, args.listen
    );
    #[cfg(feature = "own")]
    let mut own_cfg = {
        let spn: Vec<&str> = args.spn.iter().map(String::as_str).collect();
        let mut c = spike_krb::own::Config::new(&spn, &args.realm, args.keys.clone());
        c.acceptor_subkey = args.subkey;
        c
    };
    #[cfg(feature = "own")]
    let mut replay = spike_krb::own::ReplayCache::new();
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let result = match args.acceptor.as_str() {
            #[cfg(feature = "sspi")]
            "sspi" => {
                let spn: Vec<&str> = args.spn.iter().map(String::as_str).collect();
                // sspi takes one key per service name: the first configured key.
                match spike_krb::sspi_acceptor::SspiAcceptor::new(
                    &spn,
                    &args.keys[0],
                    std::time::Duration::from_secs(300),
                ) {
                    Ok(mut acc) => session(&mut stream, &mut acc),
                    Err(e) => Err(e.0),
                }
            }
            #[cfg(feature = "own")]
            "own" => {
                let _ = &mut own_cfg;
                let mut acc = spike_krb::own::OwnAcceptor::new(&own_cfg, &mut replay);
                session(&mut stream, &mut acc)
            }
            other => {
                let _ = &mut stream;
                Err(format!("acceptor {other} is not compiled in"))
            }
        };
        match result {
            Ok(()) => eprintln!("session: OK"),
            Err(e) => eprintln!("session: FAILED: {e}"),
        }
        if args.once {
            break;
        }
    }
}

#[cfg_attr(not(any(feature = "sspi", feature = "own")), allow(dead_code))]
fn session(stream: &mut TcpStream, acc: &mut dyn Acceptor) -> Result<(), String> {
    let context: Context = loop {
        let token = read_frame(stream).map_err(|e| format!("read token: {e}"))?;
        match acc.step(&token).map_err(|e| e.0)? {
            Step::Continue(out) => write_frame(stream, &out).map_err(|e| e.to_string())?,
            Step::Established { token, context } => {
                write_frame(stream, &token).map_err(|e| e.to_string())?;
                break context;
            }
        }
    };
    eprintln!("context: {context:?}");
    let keys = ContextMicKeys::new(&context.key, context.key_enctype);

    // The initiator's first MIC.
    let msg = read_frame(stream).map_err(|e| e.to_string())?;
    let mic = read_frame(stream).map_err(|e| e.to_string())?;
    let h1 = keys
        .initiator
        .verify(&mic, &msg)
        .map_err(|e| format!("initiator MIC 1: {e:?}"))?;
    eprintln!(
        "initiator MIC 1 verified: flags {:#x} seq {}",
        h1.flags, h1.seq
    );
    let mut ok = true;
    if let Some(expected) = context.initiator_seq
        && h1.seq != u64::from(expected)
    {
        eprintln!(
            "initiator sequence {} differs from the authenticator's {expected}",
            h1.seq
        );
        ok = false;
    }

    // The acceptor's message and MIC.
    let reply = format!(
        "tenko spike acceptor answers {}@{}",
        context.client, context.realm
    );
    let flags = keys.acceptor.sender_flags(context.acceptor_subkey);
    let our = keys
        .acceptor
        .sign(flags, u64::from(context.acceptor_seq), reply.as_bytes());
    write_frame(stream, reply.as_bytes()).map_err(|e| e.to_string())?;
    write_frame(stream, &our).map_err(|e| e.to_string())?;

    // The initiator's second MIC must carry the next sequence number.
    let msg2 = read_frame(stream).map_err(|e| e.to_string())?;
    let mic2 = read_frame(stream).map_err(|e| e.to_string())?;
    let h2 = keys
        .initiator
        .verify(&mic2, &msg2)
        .map_err(|e| format!("initiator MIC 2: {e:?}"))?;
    if h2.seq != h1.seq.wrapping_add(1) {
        eprintln!("initiator MIC 2 sequence {} is not {}", h2.seq, h1.seq + 1);
        ok = false;
    }
    write_frame(stream, if ok { b"OK" } else { b"FAIL" }).map_err(|e| e.to_string())?;
    if ok {
        Ok(())
    } else {
        Err("sequence check failed".into())
    }
}
