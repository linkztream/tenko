//! The fault proxy of the lab: a TCP relay per directed link between two controllers.
//!
//! A [`Relay`] listens on a loopback port of its own and forwards every connection it
//! accepts to one target, copying bytes in both directions on threads of its own. The
//! controller that dials (`A` of the link `A -> B`) reaches the relay instead of `B`'s
//! cluster port through `[cluster] peer_address_map`; the link `B -> A` has a relay of its
//! own, so a partition cuts exactly the links between two sets of controllers.
//!
//! The [`Fault`] of a relay applies at once:
//!
//! - [`Fault::Pass`] forwards.
//! - [`Fault::Cut`] closes the connections it carries and closes every new one right after
//!   the accept, so the dialler sees a reset or an end of stream at once.
//! - [`Fault::Delay`] holds every chunk for that long before it forwards it, in both byte
//!   directions of the link's connections: a call over the link takes twice the delay
//!   longer. The order of the bytes is kept and the throughput is not limited.
//! - [`Fault::Drop`] closes a new connection with that probability right after the accept;
//!   the connections it lets through are forwarded as with `Pass`.

use std::{
    io::{ErrorKind, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// How long the relay waits for the target to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// The seed of the random numbers of [`Fault::Drop`]: fixed, so a drop pattern repeats
/// from run to run.
const SEED: u64 = 0x7E4B_0D5E_ED00_0001;

/// What a relay does with the traffic of its link.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fault {
    /// Forward every byte at once.
    Pass,
    /// Close the open connections and every new one.
    Cut,
    /// Hold every chunk this long before forwarding it.
    Delay(Duration),
    /// Close a new connection with this probability (0.0 to 1.0) right after the accept.
    Drop(f64),
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The state the accept thread and the copy threads share with the control side.
struct Shared {
    fault: Mutex<Fault>,
    /// The open connections: the accepted stream and the stream to the target.
    open: Mutex<Vec<(u64, TcpStream, TcpStream)>>,
    next_id: AtomicU64,
    stopping: AtomicBool,
    /// The `SplitMix64` state for [`Fault::Drop`].
    random: Mutex<u64>,
    accepted: AtomicU64,
    refused: AtomicU64,
}

impl Shared {
    fn fault(&self) -> Fault {
        *lock(&self.fault)
    }

    /// A number in `[0, 1)`.
    fn random(&self) -> f64 {
        let mut state = lock(&self.random);
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        #[allow(
            clippy::cast_precision_loss,
            reason = "53 random bits map exactly onto the mantissa"
        )]
        let unit = (z >> 11) as f64 / (1_u64 << 53) as f64;
        unit
    }

    fn close_all(&self) {
        for (_, accepted, outbound) in lock(&self.open).drain(..) {
            let _ = accepted.shutdown(Shutdown::Both);
            let _ = outbound.shutdown(Shutdown::Both);
        }
    }

    fn forget(&self, id: u64) {
        lock(&self.open).retain(|(open, _, _)| *open != id);
    }
}

/// One directed link: a loopback listener that forwards to `target`.
pub struct Relay {
    addr: SocketAddr,
    target: SocketAddr,
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
}

impl Relay {
    /// Starts a relay to `target` on a free loopback port, in [`Fault::Pass`].
    pub fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind a relay port");
        let addr = listener.local_addr().expect("the relay address");
        let shared = Arc::new(Shared {
            fault: Mutex::new(Fault::Pass),
            open: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            stopping: AtomicBool::new(false),
            random: Mutex::new(SEED),
            accepted: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        });
        let accept = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || accept_loop(&listener, target, &shared))
        };
        Self {
            addr,
            target,
            shared,
            accept: Some(accept),
        }
    }

    /// The address dialled instead of the target.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The address the relay forwards to.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// The current fault.
    pub fn fault(&self) -> Fault {
        self.shared.fault()
    }

    /// Sets the fault; [`Fault::Cut`] also closes the open connections.
    pub fn set(&self, fault: Fault) {
        *lock(&self.shared.fault) = fault;
        if fault == Fault::Cut {
            self.shared.close_all();
        }
    }

    /// Connections accepted and forwarded so far.
    pub fn accepted(&self) -> u64 {
        self.shared.accepted.load(Ordering::Relaxed)
    }

    /// Connections closed right after the accept (cut or dropped) so far.
    pub fn refused(&self) -> u64 {
        self.shared.refused.load(Ordering::Relaxed)
    }

    /// The number of connections open now.
    pub fn open(&self) -> usize {
        lock(&self.shared.open).len()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        // Wake the accept loop with a connection of our own.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(500));
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        self.shared.close_all();
    }
}

fn accept_loop(listener: &TcpListener, target: SocketAddr, shared: &Arc<Shared>) {
    for incoming in listener.incoming() {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let Ok(accepted) = incoming else { continue };
        let refuse = match shared.fault() {
            Fault::Cut => true,
            Fault::Drop(ratio) => shared.random() < ratio,
            Fault::Pass | Fault::Delay(_) => false,
        };
        if refuse {
            shared.refused.fetch_add(1, Ordering::Relaxed);
            let _ = accepted.shutdown(Shutdown::Both);
            continue;
        }
        let Ok(outbound) = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT) else {
            let _ = accepted.shutdown(Shutdown::Both);
            continue;
        };
        let _ = accepted.set_nodelay(true);
        let _ = outbound.set_nodelay(true);
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let (Ok(accepted_copy), Ok(outbound_copy)) = (accepted.try_clone(), outbound.try_clone())
        else {
            continue;
        };
        lock(&shared.open).push((id, accepted_copy, outbound_copy));
        shared.accepted.fetch_add(1, Ordering::Relaxed);
        let (Ok(a_read), Ok(b_read)) = (accepted.try_clone(), outbound.try_clone()) else {
            shared.forget(id);
            continue;
        };
        let done = Arc::new(AtomicU64::new(0));
        for (from, to) in [(a_read, outbound), (b_read, accepted)] {
            let shared = Arc::clone(shared);
            let done = Arc::clone(&done);
            thread::spawn(move || {
                pump(from, &to, &shared);
                // The second direction to finish removes the connection.
                if done.fetch_add(1, Ordering::SeqCst) == 1 {
                    shared.forget(id);
                }
            });
        }
    }
}

/// Copies `from` to `to` until the end of `from` or an error, holding each chunk for the
/// delay of the relay at the time it was read.
fn pump(mut from: TcpStream, to: &TcpStream, shared: &Arc<Shared>) {
    let (sender, receiver) = mpsc::channel::<(Instant, Vec<u8>)>();
    let writer = {
        let mut to = to.try_clone().expect("clone a relayed stream");
        thread::spawn(move || {
            for (due, chunk) in receiver {
                let now = Instant::now();
                if due > now {
                    thread::sleep(due - now);
                }
                if to.write_all(&chunk).is_err() {
                    let _ = to.shutdown(Shutdown::Both);
                    return false;
                }
            }
            true
        })
    };
    let mut buffer = vec![0_u8; 64 * 1024];
    let clean = loop {
        match from.read(&mut buffer) {
            Ok(0) => break true,
            Ok(read) => {
                let delay = match shared.fault() {
                    Fault::Delay(delay) => delay,
                    _ => Duration::ZERO,
                };
                if sender
                    .send((Instant::now() + delay, buffer[..read].to_vec()))
                    .is_err()
                {
                    break false;
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => break false,
        }
    };
    drop(sender);
    let written = writer.join().unwrap_or(false);
    if clean && written {
        // Pass the end of the stream on; the other direction may still be open.
        let _ = to.shutdown(Shutdown::Write);
    } else {
        let _ = from.shutdown(Shutdown::Both);
        let _ = to.shutdown(Shutdown::Both);
    }
}

/// An echo server on a loopback port for the relay's own tests: every connection gets its
/// bytes back.
pub struct Echo {
    addr: SocketAddr,
    stopping: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl Echo {
    /// Starts the server.
    pub fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the echo port");
        let addr = listener.local_addr().expect("the echo address");
        let stopping = Arc::new(AtomicBool::new(false));
        let accept = {
            let stopping = Arc::clone(&stopping);
            thread::spawn(move || {
                for incoming in listener.incoming() {
                    if stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(mut stream) = incoming else { continue };
                    thread::spawn(move || {
                        let mut buffer = [0_u8; 16 * 1024];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) | Err(_) => return,
                                Ok(read) => {
                                    if stream.write_all(&buffer[..read]).is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    });
                }
            })
        };
        Self {
            addr,
            stopping,
            accept: Some(accept),
        }
    }

    /// The address of the server.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(500));
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}
