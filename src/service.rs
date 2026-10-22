//! Foreground service: keep HID I/O responsive while authorization/signing/storage
//! run on one bounded worker. A cancelled generation can never finish a new request.
use crate::authenticator::{Authenticator, CtapResult, Prompt, RequestContext, Status};
use crate::control::{self, Request, RequestId, Response};
use crate::hid::{Engine, Event, Transaction};
use crate::store::Store;
use crate::uhid::Device;
use anyhow::Result;
use rand_core::{OsRng, RngCore};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::{self, Receiver, SyncSender},
    Arc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum TestPresence {
    Approve,
    Deny,
}

#[derive(Clone)]
pub struct Options {
    pub node_helper: Option<PathBuf>,
    pub exit_after: Option<u64>,
    pub test_presence: Option<TestPresence>,
}

struct Work {
    transaction: Transaction,
    request: Zeroizing<Vec<u8>>,
    cancel: Arc<AtomicBool>,
}

enum WorkEvent {
    Prompt {
        transaction: Transaction,
        prompt: Prompt,
        decision: SyncSender<bool>,
        deadline: Instant,
    },
    Processing(Transaction),
    Completed {
        transaction: Transaction,
        response: Zeroizing<Vec<u8>>,
        fatal: bool,
    },
}

struct ContextImpl {
    transaction: Transaction,
    cancel: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    clock: Instant,
    events: SyncSender<WorkEvent>,
}

impl RequestContext for ContextImpl {
    fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire) || self.shutdown.load(Ordering::Acquire)
    }
    fn presence(&mut self, prompt: Prompt) -> CtapResult<()> {
        if self.cancelled() {
            return Err(Status::Cancelled);
        }
        let (send, receive) = mpsc::sync_channel(1);
        let deadline = Instant::now() + Duration::from_secs(30);
        self.events
            .send(WorkEvent::Prompt {
                transaction: self.transaction,
                prompt,
                decision: send,
                deadline,
            })
            .map_err(|_| Status::Cancelled)?;
        let approved = loop {
            if self.cancelled() {
                return Err(Status::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Status::UserActionTimeout);
            }
            match receive.recv_timeout(Duration::from_millis(20)) {
                Ok(decision) => break decision,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => return Err(Status::Cancelled),
            }
        };
        if self.cancelled() {
            return Err(Status::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(Status::UserActionTimeout);
        }
        self.events
            .send(WorkEvent::Processing(self.transaction))
            .map_err(|_| Status::Cancelled)?;
        if approved {
            Ok(())
        } else {
            Err(Status::OperationDenied)
        }
    }
}

struct Worker {
    input: Option<SyncSender<Work>>,
    events: Receiver<WorkEvent>,
    shutdown: Arc<AtomicBool>,
    invalidation: Arc<AtomicU64>,
    join: Option<JoinHandle<()>>,
}

impl Worker {
    fn start<S: Store + 'static>(mut authenticator: Authenticator<S>, clock: Instant) -> Self {
        let (input, receive) = mpsc::sync_channel::<Work>(1);
        let (events, output) = mpsc::sync_channel(8);
        let shutdown = Arc::new(AtomicBool::new(false));
        let invalidation = Arc::new(AtomicU64::new(0));
        let stop = shutdown.clone();
        let epoch = invalidation.clone();
        let join = std::thread::spawn(move || {
            let mut last_epoch = 0;
            while let Ok(work) = receive.recv() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let current_epoch = epoch.load(Ordering::Acquire);
                if current_epoch != last_epoch {
                    authenticator.invalidate();
                    last_epoch = current_epoch;
                }
                let mut context = ContextImpl {
                    transaction: work.transaction,
                    cancel: work.cancel,
                    shutdown: stop.clone(),
                    clock,
                    events: events.clone(),
                };
                let response = Zeroizing::new(authenticator.execute(
                    work.transaction.channel,
                    &work.request,
                    &mut context,
                ));
                if events
                    .send(WorkEvent::Completed {
                        transaction: work.transaction,
                        response,
                        fatal: !authenticator.healthy(),
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            input: Some(input),
            events: output,
            shutdown,
            invalidation,
            join: Some(join),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        drop(self.input.take());
        // Dropping the receiver unblocks a worker sending a final event on errors.
        let (_, empty) = mpsc::channel();
        drop(std::mem::replace(&mut self.events, empty));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Own the attachment lifetime, including every early `?` return. Rust drops
/// fields in declaration order after this Drop body: stop work, detach HID,
/// then join the worker and clear its authenticator state. A transport/control
/// error must not leave a device attached while waiting for worker cleanup.
struct Attachment<D> {
    device: D,
    worker: Worker,
}

impl<D> Drop for Attachment<D> {
    fn drop(&mut self) {
        self.worker.shutdown.store(true, Ordering::Release);
    }
}

enum Input {
    Line(String),
    End,
}

fn input_reader() -> Receiver<Input> {
    let (send, receive) = mpsc::sync_channel(8);
    std::thread::spawn(move || {
        let mut input = BufReader::new(std::io::stdin());
        let mut discard = false;
        loop {
            let mut line = Vec::with_capacity(128);
            let read = Read::by_ref(&mut input)
                .take(1025)
                .read_until(b'\n', &mut line);
            match read {
                Ok(0) | Err(_) => {
                    let _ = send.send(Input::End);
                    break;
                }
                Ok(_) => {
                    let complete = line.ends_with(b"\n");
                    if !complete || line.len() > 1024 {
                        discard = true;
                    }
                    if complete {
                        if !discard {
                            if let Ok(line) = String::from_utf8(line) {
                                if send.send(Input::Line(line)).is_err() {
                                    break;
                                }
                            }
                        }
                        discard = false;
                    }
                }
            }
        }
    });
    receive
}

struct Approval {
    transaction: Transaction,
    token: String,
    decision: SyncSender<bool>,
    prompt: Prompt,
    deadline: Instant,
}

fn snapshot(approval: Option<&Approval>) -> Response {
    Response::ready(approval.filter(|a| Instant::now() < a.deadline).map(|a| {
        control::Pending {
            token: a.token.clone(),
            operation: a.prompt.operation.into(),
            rp_id: a.prompt.rp_id.clone(),
            account: a.prompt.account.clone(),
            remaining_ms: a
                .deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
        }
    }))
}

pub fn run<S: Store + 'static>(
    authenticator: Authenticator<S>,
    options: Options,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    run_inner(authenticator, &options, shutdown, None).map(|_| ())
}

/// Always starts locked. No unlock secret is retained across a lock or restart.
pub fn serve(
    vault: &Path,
    socket: &Path,
    options: Options,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    if options.test_presence.is_some() {
        anyhow::bail!("persistent service cannot use scripted presence");
    }
    crate::vault::Vault::preflight(vault, false)?;
    Device::preflight()?;
    let mut server = control::Server::bind(socket)?;
    eprintln!("Control service listening, locked. Unlock through the local client to attach.");
    while !shutdown.load(Ordering::Acquire) {
        server.publish(Response::locked())?;
        if let Some((id, request)) = server.poll()? {
            server.take_watcher_loss(); // Already locked; no keys/device remain.
            match &request {
                Request::Watch { version } => server.watch(id, *version, Response::locked())?,
                Request::Status {} | Request::Lock {} => server.respond(id, Response::locked())?,
                Request::Unlock { passphrase } => {
                    match crate::vault::Vault::open(vault, passphrase) {
                        Ok(store) => {
                            // Drop the parsed unlock message before entering the
                            // long-lived ready state; only the vault key remains.
                            drop(request);
                            match run_inner(
                                Authenticator::software(store, 0),
                                &options,
                                shutdown.clone(),
                                Some((&mut server, id)),
                            ) {
                                Ok(Some(lock_id)) => server.respond(lock_id, Response::locked())?,
                                Ok(None) => break,
                                Err(error) => {
                                    if shutdown.load(Ordering::Acquire) {
                                        return Err(error);
                                    }
                                    eprintln!("Device service failed and detached: {error:#}");
                                    server.respond(id, Response::locked().error("device attachment or operation failed; service is locked"))?;
                                }
                            }
                        }
                        Err(error) => {
                            eprintln!("Vault unlock failed: {error}");
                            server.respond(id, Response::locked().error("vault unlock failed"))?;
                        }
                    }
                }
                Request::Approve { .. } | Request::Deny { .. } => {
                    server.respond(
                        id,
                        Response::locked().error("vault is locked; no pending request"),
                    )?;
                }
            }
        }
        server.take_watcher_loss();
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn run_inner<S: Store + 'static>(
    authenticator: Authenticator<S>,
    options: &Options,
    shutdown: Arc<AtomicBool>,
    mut control: Option<(&mut control::Server, RequestId)>,
) -> Result<Option<RequestId>> {
    let device = Device::create(options.node_helper.as_deref())?;
    let clock = Instant::now();
    let mut attachment = Attachment {
        device,
        worker: Worker::start(authenticator, clock),
    };
    let device = &mut attachment.device;
    let worker = &attachment.worker;
    let input = (control.is_none() && options.test_presence.is_none()).then(input_reader);
    let mut input_ended = false;
    let mut fatal_storage = false;
    let mut engine = Engine::default();
    let mut active: Option<(Transaction, Arc<AtomicBool>)> = None;
    let mut approval: Option<Approval> = None;
    let mut lock_requested = None;
    println!("READY {} {}", device.path().display(), device.unique());
    if let Some((server, id)) = &mut control {
        server.respond(*id, Response::ready(None))?;
    } else if options.test_presence.is_none() {
        eprintln!("Approval: type 'approve TOKEN' or 'deny TOKEN' for the displayed request. Type 'lock' or 'quit' to detach.");
    }

    while !shutdown.load(Ordering::Acquire) && lock_requested.is_none() {
        if options
            .exit_after
            .is_some_and(|s| clock.elapsed() >= Duration::from_secs(s))
        {
            break;
        }
        let report = device.read_report(Duration::from_millis(20))?;
        let now = clock.elapsed().as_millis() as u64;
        let mut events: VecDeque<_> = if let Some(report) = report {
            engine.receive(report, now)
        } else {
            engine.tick(now)
        }
        .into();
        while let Some(event) = events.pop_front() {
            match event {
                Event::Send(report) => device.send_report(&report)?,
                Event::Request {
                    transaction,
                    payload,
                } => {
                    let cancel = Arc::new(AtomicBool::new(false));
                    if let Some((_, previous)) = active.replace((transaction, cancel.clone())) {
                        previous.store(true, Ordering::Release);
                    }
                    let work = Work {
                        transaction,
                        request: payload,
                        cancel,
                    };
                    if worker.input.as_ref().unwrap().try_send(work).is_err() {
                        active = None;
                        events.extend(engine.complete(transaction, &[0x06]));
                    }
                }
                Event::Abort(transaction) => {
                    if let Some((running, cancel)) = &active {
                        if *running == transaction {
                            cancel.store(true, Ordering::Release);
                        }
                    }
                    if approval
                        .as_ref()
                        .is_some_and(|a| a.transaction == transaction)
                    {
                        approval = None;
                    }
                    worker.invalidation.fetch_add(1, Ordering::AcqRel);
                }
                Event::Resynchronize(_) => {
                    worker.invalidation.fetch_add(1, Ordering::AcqRel);
                }
            }
        }

        while let Ok(event) = worker.events.try_recv() {
            let emitted = match event {
                WorkEvent::Prompt {
                    transaction,
                    prompt,
                    decision,
                    deadline,
                } => {
                    if !active
                        .as_ref()
                        .is_some_and(|(t, c)| *t == transaction && !c.load(Ordering::Acquire))
                    {
                        continue;
                    }
                    match options.test_presence {
                        Some(TestPresence::Approve) => {
                            let _ = decision.send(true);
                        }
                        Some(TestPresence::Deny) => {
                            let _ = decision.send(false);
                        }
                        None if input_ended => {
                            let _ = decision.send(false);
                        }
                        None => {
                            let mut nonce = [0u8; 8];
                            OsRng
                                .try_fill_bytes(&mut nonce)
                                .map_err(|e| anyhow::anyhow!("approval nonce randomness: {e}"))?;
                            let token = format!("{}-{}", transaction.id, u64::from_ne_bytes(nonce));
                            if control.is_none() {
                                println!(
                                    "APPROVAL {token} {} rp={:?} account={:?}",
                                    prompt.operation, prompt.rp_id, prompt.account
                                );
                            }
                            approval = Some(Approval {
                                transaction,
                                token,
                                decision,
                                prompt,
                                deadline,
                            });
                        }
                    }
                    engine.presence_needed(transaction, now)
                }
                WorkEvent::Processing(transaction) => engine.processing_status(transaction, 1, now),
                WorkEvent::Completed {
                    transaction,
                    response,
                    fatal,
                } => {
                    if fatal {
                        fatal_storage = true;
                        eprintln!(
                            "Detaching: vault write failed; reopen the vault before continuing."
                        );
                        shutdown.store(true, Ordering::Release);
                    }
                    if active.as_ref().is_some_and(|(t, _)| *t == transaction) {
                        active = None;
                    }
                    if approval
                        .as_ref()
                        .is_some_and(|a| a.transaction == transaction)
                    {
                        approval = None;
                    }
                    engine.complete(transaction, &response)
                }
            };
            for event in emitted {
                if let Event::Send(report) = event {
                    device.send_report(&report)?;
                }
            }
        }

        if let Some((server, _)) = &mut control {
            server.publish(snapshot(approval.as_ref()))?;
            // Finite control work per HID iteration. A partial/slow client is
            // polled nonblocking and cannot monopolize report I/O/keepalives.
            for _ in 0..8 {
                let request = server.poll()?;
                if let Some(id) = server.take_watcher_loss() {
                    lock_requested = Some(id);
                    break;
                }
                let Some((id, request)) = request else {
                    break;
                };
                let response = match &request {
                    Request::Watch { version } => {
                        server.watch(id, *version, snapshot(approval.as_ref()))?;
                        continue;
                    }
                    Request::Status {} => snapshot(approval.as_ref()),
                    Request::Unlock { .. } => {
                        Response::ready(None).error("vault is already unlocked")
                    }
                    Request::Lock {} => {
                        // Reply only after device detach and worker/key cleanup.
                        lock_requested = Some(id);
                        break;
                    }
                    Request::Approve { token } | Request::Deny { token } => {
                        if approval.as_ref().is_some_and(|pending| {
                            pending.token == *token && Instant::now() < pending.deadline
                        }) {
                            let pending = approval.take().unwrap();
                            if pending
                                .decision
                                .send(matches!(request, Request::Approve { .. }))
                                .is_ok()
                            {
                                Response::ready(None)
                            } else {
                                Response::ready(None).error("request is no longer pending")
                            }
                        } else {
                            Response::ready(None).error("no pending request matches that token")
                        }
                    }
                };
                server.respond(id, response)?;
            }
        }

        if let Some(input) = &input {
            while let Ok(message) = input.try_recv() {
                match message {
                    Input::End => {
                        input_ended = true;
                        if let Some(pending) = approval.take() {
                            let _ = pending.decision.send(false);
                        }
                        // Losing the foreground approval channel also locks and
                        // detaches; don't retain an unlocked unattended vault.
                        shutdown.store(true, Ordering::Release);
                    }
                    Input::Line(line) => {
                        let parts: Vec<_> = line.split_whitespace().collect();
                        match parts.as_slice() {
                            ["quit" | "lock"] => shutdown.store(true, Ordering::Release),
                            [action @ ("approve" | "deny"), token] => {
                                if approval.as_ref().is_some_and(|a| {
                                    a.token == *token && Instant::now() < a.deadline
                                }) {
                                    let pending = approval.take().unwrap();
                                    let _ = pending.decision.send(*action == "approve");
                                } else {
                                    eprintln!("No pending request matches that approval token.");
                                }
                            }
                            _ => eprintln!("Expected approve TOKEN, deny TOKEN, lock, or quit."),
                        }
                    }
                }
            }
        }
    }
    if let Some((_, cancel)) = active {
        cancel.store(true, Ordering::Release);
    }
    drop(approval);
    drop(attachment); // identical detach-before-join ordering on all exit paths
    if fatal_storage {
        anyhow::bail!("vault write failed; authenticator detached");
    }
    Ok(lock_requested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{self, bytes, int, map, text};
    use crate::crypto::{CredentialSigner, OsRandom, RandomSource, SoftwareSigner};
    use crate::hid;
    use crate::store::MemoryStore;
    use ciborium::Value;

    #[test]
    fn desktop_snapshot_never_renews_or_exposes_expired_approval() {
        let (decision, _receive) = mpsc::sync_channel(1);
        let mut approval = Approval {
            transaction: Transaction { channel: 1, id: 1 },
            token: "internal-request-token".into(),
            decision,
            prompt: Prompt {
                operation: "register",
                rp_id: "example.test".into(),
                account: None,
            },
            deadline: Instant::now() + Duration::from_millis(500),
        };
        let first = snapshot(Some(&approval)).pending.unwrap();
        assert!(first.remaining_ms <= 500);
        assert!(snapshot(Some(&approval)).pending.unwrap().remaining_ms <= first.remaining_ms);
        approval.deadline = Instant::now();
        assert!(snapshot(Some(&approval)).pending.is_none());
    }

    #[test]
    fn attachment_detaches_before_joining_worker_on_success_and_error() {
        struct DetachProbe {
            shutdown: Arc<AtomicBool>,
            detached: mpsc::Sender<()>,
        }
        impl Drop for DetachProbe {
            fn drop(&mut self) {
                assert!(self.shutdown.load(Ordering::Acquire));
                // If the worker was joined first, its bounded wait would expire
                // and this send would fail. No real HID or timing race is needed.
                self.detached.send(()).expect("detach must precede join");
            }
        }
        for fail in [false, true] {
            let shutdown = Arc::new(AtomicBool::new(false));
            let (detached, receive) = mpsc::channel();
            let (_, events) = mpsc::channel();
            let join = std::thread::spawn(move || {
                receive
                    .recv_timeout(Duration::from_secs(3))
                    .expect("attachment must detach before worker cleanup");
            });
            let result = (|| -> Result<()> {
                let _attachment = Attachment {
                    device: DetachProbe {
                        shutdown: shutdown.clone(),
                        detached,
                    },
                    worker: Worker {
                        input: None,
                        events,
                        shutdown: shutdown.clone(),
                        invalidation: Arc::new(AtomicU64::new(0)),
                        join: Some(join),
                    },
                };
                if fail {
                    Err(anyhow::anyhow!("injected service I/O failure"))?;
                }
                Ok(())
            })();
            assert_eq!(result.is_err(), fail);
            assert!(shutdown.load(Ordering::Acquire));
        }
    }

    struct Approve;
    impl RequestContext for Approve {
        fn now_ms(&self) -> u64 {
            0
        }
        fn cancelled(&self) -> bool {
            false
        }
        fn presence(&mut self, _: Prompt) -> CtapResult<()> {
            Ok(())
        }
    }

    struct PausedSigner {
        entered: SyncSender<()>,
        resume: Receiver<()>,
    }
    impl CredentialSigner for PausedSigner {
        fn generate(&self, random: &mut dyn RandomSource) -> CtapResult<Zeroizing<[u8; 32]>> {
            SoftwareSigner.generate(random)
        }
        fn public_key(&self, key: &[u8; 32]) -> CtapResult<Value> {
            SoftwareSigner.public_key(key)
        }
        fn sign(&self, key: &[u8; 32], data: &[u8]) -> CtapResult<Vec<u8>> {
            self.entered.send(()).map_err(|_| Status::Other)?;
            self.resume
                .recv_timeout(Duration::from_secs(3))
                .map_err(|_| Status::Other)?;
            SoftwareSigner.sign(key, data)
        }
    }

    fn command(command: u8, value: Value) -> Vec<u8> {
        let mut request = vec![command];
        request.extend(cbor::encode(&value));
        request
    }

    fn submit(
        engine: &mut Engine,
        worker: &Worker,
        channel: u32,
        request: &[u8],
    ) -> (Transaction, Arc<AtomicBool>) {
        let mut result = None;
        for report in hid::frame(channel, hid::CBOR, request).unwrap() {
            for event in engine.receive(report, 0) {
                if let Event::Request {
                    transaction,
                    payload,
                } = event
                {
                    let cancel = Arc::new(AtomicBool::new(false));
                    worker
                        .input
                        .as_ref()
                        .unwrap()
                        .try_send(Work {
                            transaction,
                            request: payload,
                            cancel: cancel.clone(),
                        })
                        .unwrap();
                    result = Some((transaction, cancel));
                }
            }
        }
        result.expect("complete framed request must reach worker")
    }

    #[test]
    fn cancellation_during_signing_discards_late_result_and_allows_next_request() {
        let (entered, started) = mpsc::sync_channel(1);
        let (resume, resume_rx) = mpsc::sync_channel(1);
        let mut auth = Authenticator::new(
            MemoryStore::default(),
            Box::new(PausedSigner {
                entered,
                resume: resume_rx,
            }),
            Box::new(OsRandom),
            0,
        );
        let registration = command(
            1,
            map([
                (int(1), bytes(&[0; 32])),
                (int(2), map([(text("id"), text("example.test"))])),
                (int(3), map([(text("id"), bytes(b"alice"))])),
                (
                    int(4),
                    Value::Array(vec![map([
                        (text("type"), text("public-key")),
                        (text("alg"), int(-7)),
                    ])]),
                ),
                (int(7), map([(text("rk"), Value::Bool(true))])),
            ]),
        );
        assert_eq!(auth.execute(1, &registration, &mut Approve)[0], 0);
        let worker = Worker::start(auth, Instant::now());
        let mut engine = Engine::default();
        engine.receive(
            hid::frame(hid::BROADCAST, hid::INIT, &[0; 8]).unwrap()[0],
            0,
        );
        let assertion = command(
            2,
            map([(int(1), text("example.test")), (int(2), bytes(&[1; 32]))]),
        );
        let (old, cancel) = submit(&mut engine, &worker, 1, &assertion);
        match worker.events.recv_timeout(Duration::from_secs(2)).unwrap() {
            WorkEvent::Prompt {
                transaction,
                decision,
                ..
            } => {
                assert_eq!(transaction, old);
                decision.send(true).unwrap();
            }
            _ => panic!("assertion must require presence"),
        }
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        let cancelled = engine.receive(hid::frame(1, hid::CANCEL, &[]).unwrap()[0], 1);
        assert!(
            matches!(cancelled.as_slice(), [Event::Abort(transaction), Event::Send(report)]
            if *transaction == old && report[7] == Status::Cancelled as u8)
        );
        cancel.store(true, Ordering::Release);
        worker.invalidation.fetch_add(1, Ordering::AcqRel);
        // Queue a new request while the previous signer is still blocked. Its
        // generation must not be completed or cancelled by the old worker result.
        let (fresh, _) = submit(&mut engine, &worker, 1, &[4]);
        assert_ne!(old, fresh);
        resume.send(()).unwrap();
        let mut discarded = false;
        loop {
            match worker.events.recv_timeout(Duration::from_secs(2)).unwrap() {
                WorkEvent::Processing(transaction) => {
                    assert_eq!(transaction, old);
                    assert!(engine.processing_status(transaction, 1, 2).is_empty());
                }
                WorkEvent::Completed {
                    transaction,
                    response,
                    fatal,
                } => {
                    assert!(!fatal);
                    if transaction == old {
                        assert_eq!(response.as_slice(), [Status::Cancelled as u8]);
                        assert!(engine.complete(transaction, &response).is_empty());
                        discarded = true;
                    } else {
                        assert_eq!(transaction, fresh);
                        assert!(discarded);
                        assert_eq!(response[0], 0);
                        assert!(!engine.complete(transaction, &response).is_empty());
                        break;
                    }
                }
                WorkEvent::Prompt { .. } => panic!("GetInfo must not prompt"),
            }
        }
    }
}
