//! Foreground service: keep HID I/O responsive while authorization/signing/storage
//! run on one bounded worker. A cancelled generation can never finish a new request.
mod locked;
use crate::authenticator::{Authenticator, CtapResult, Prompt, RequestContext, Status};
use crate::control::{self, Request, RequestId, Response};
use crate::hid::{Engine, Event, Transaction};
use crate::store::Store;
use crate::uhid::Device;
use anyhow::Result;
use locked::{Action as LockedAction, Locked, Unlocking, Waiting};
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

enum Job {
    Ctap(Work),
    Credentials {
        id: RequestId,
        offset: usize,
        revision: Option<String>,
    },
    Pin {
        id: RequestId,
        current: Zeroizing<Vec<u8>>,
        new: Zeroizing<Vec<u8>>,
    },
}

enum WorkEvent {
    Credentials {
        id: RequestId,
        response: Box<Response>,
    },
    PinConfigured {
        id: RequestId,
        result: CtapResult<()>,
        fatal: bool,
    },
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

struct LocalContext {
    shutdown: Arc<AtomicBool>,
}
impl RequestContext for LocalContext {
    fn now_ms(&self) -> u64 {
        0
    }
    fn cancelled(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
    fn presence(&mut self, _: Prompt) -> CtapResult<()> {
        Err(Status::OperationDenied)
    }
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
    input: Option<SyncSender<Job>>,
    events: Receiver<WorkEvent>,
    shutdown: Arc<AtomicBool>,
    invalidation: Arc<AtomicU64>,
    pin_configured: Arc<AtomicBool>,
    instance: u128,
    revision: Arc<AtomicU64>,
    join: Option<JoinHandle<()>>,
}

impl Worker {
    fn start<S: Store + 'static>(
        mut authenticator: Authenticator<S>,
        clock: Instant,
    ) -> Result<Self> {
        let instance = random_nonce()?;
        let revision = Arc::new(AtomicU64::new(authenticator.revision()));
        let store_revision = revision.clone();
        let (input, receive) = mpsc::sync_channel::<Job>(1);
        let (events, output) = mpsc::sync_channel(8);
        let shutdown = Arc::new(AtomicBool::new(false));
        let invalidation = Arc::new(AtomicU64::new(0));
        let pin_configured = Arc::new(AtomicBool::new(authenticator.state().pin.is_some()));
        let pin_state = pin_configured.clone();
        let stop = shutdown.clone();
        let epoch = invalidation.clone();
        let join = std::thread::spawn(move || {
            let mut last_epoch = 0;
            while let Ok(job) = receive.recv() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let current_epoch = epoch.load(Ordering::Acquire);
                if current_epoch != last_epoch {
                    authenticator.invalidate();
                    last_epoch = current_epoch;
                }
                let work = match job {
                    Job::Ctap(work) => work,
                    Job::Credentials {
                        id,
                        offset,
                        revision,
                    } => {
                        let response = if authenticator.healthy() {
                            crate::credentials::page(
                                authenticator.state(),
                                format!("{instance:032x}-{}", authenticator.revision()),
                                offset,
                                revision.as_deref(),
                            )
                        } else {
                            Response::locked().error("vault is unavailable")
                        };
                        if events
                            .send(WorkEvent::Credentials {
                                id,
                                response: Box::new(response),
                            })
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                    Job::Pin { id, current, new } => {
                        let context = LocalContext {
                            shutdown: stop.clone(),
                        };
                        let result = authenticator.configure_pin(&current, &new, &context);
                        store_revision.store(authenticator.revision(), Ordering::Release);
                        pin_state.store(authenticator.state().pin.is_some(), Ordering::Release);
                        if events
                            .send(WorkEvent::PinConfigured {
                                id,
                                result,
                                fatal: !authenticator.healthy(),
                            })
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
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
                store_revision.store(authenticator.revision(), Ordering::Release);
                pin_state.store(authenticator.state().pin.is_some(), Ordering::Release);
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
        Ok(Self {
            input: Some(input),
            events: output,
            shutdown,
            invalidation,
            pin_configured,
            instance,
            revision,
            join: Some(join),
        })
    }
    fn credentials_revision(&self) -> String {
        format!(
            "{:032x}-{}",
            self.instance,
            self.revision.load(Ordering::Acquire)
        )
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
    worker: Option<Worker>,
}

impl<D> Drop for Attachment<D> {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.shutdown.store(true, Ordering::Release);
        }
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

fn request_token(transaction: Transaction) -> Result<String> {
    Ok(format!("{}-{:032x}", transaction.id, random_nonce()?))
}

fn random_nonce() -> Result<u128> {
    let mut nonce = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| anyhow::anyhow!("request randomness: {e}"))?;
    Ok(u128::from_ne_bytes(nonce))
}

fn service_snapshot(
    worker: Option<&Worker>,
    approval: Option<&Approval>,
    desktop: Option<&Locked>,
) -> Response {
    if let Some(worker) = worker {
        let mut response = snapshot(approval);
        response.pin_configured = Some(worker.pin_configured.load(Ordering::Acquire));
        response.credentials_revision = Some(worker.credentials_revision());
        response.wake_available = desktop.map(|d| d.active);
        response
    } else {
        desktop.expect("locked desktop state").snapshot()
    }
}

pub fn run<S: Store + 'static>(
    authenticator: Authenticator<S>,
    options: Options,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    run_inner(authenticator, &options, shutdown, None, None).map(|_| ())
}

/// Always starts locked. No unlock secret is retained across a lock or restart.
pub fn serve(
    vault: &Path,
    socket: &Path,
    unlock_on_request: bool,
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
    let mut session_active = true;
    let locked_snapshot = || {
        let mut response = Response::locked();
        response.wake_available = unlock_on_request.then_some(false);
        response
    };
    while !shutdown.load(Ordering::Acquire) {
        server.publish(locked_snapshot())?;
        if let Some((id, request)) = server.poll()? {
            server.take_watcher_loss(); // Already locked; no keys/device remain.
            match &request {
                Request::Watch { version } => server.watch(id, *version, locked_snapshot())?,
                Request::Status {} | Request::Lock {} => server.respond(id, locked_snapshot())?,
                Request::Session { active } if unlock_on_request => {
                    session_active = *active;
                    server.respond(id, locked_snapshot())?;
                }
                Request::Unlock { passphrase, token } if session_active && token.is_none() => {
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
                                unlock_on_request.then_some(vault),
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
                Request::Approve { .. }
                | Request::Deny { .. }
                | Request::ConfigurePin { .. }
                | Request::Credentials { .. }
                | Request::Session { .. }
                | Request::Unlock { .. } => {
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
    control: Option<(&mut control::Server, RequestId)>,
    desktop_vault: Option<&Path>,
) -> Result<Option<RequestId>> {
    let device = Device::create(options.node_helper.as_deref())?;
    println!("READY {} {}", device.path().display(), device.unique());
    run_device(
        authenticator,
        options,
        shutdown,
        control,
        desktop_vault,
        device,
    )
}

// The service loop also runs against a bounded in-memory transport in tests.
// Production always constructs a real UHID Device above.
trait HidIo {
    fn read_report(&mut self, timeout: Duration) -> Result<Option<crate::hid::Report>>;
    fn send_report(&mut self, report: &crate::hid::Report) -> Result<()>;
}
impl HidIo for Device {
    fn read_report(&mut self, timeout: Duration) -> Result<Option<crate::hid::Report>> {
        Device::read_report(self, timeout)
    }
    fn send_report(&mut self, report: &crate::hid::Report) -> Result<()> {
        Device::send_report(self, report)
    }
}

fn run_device<S: Store + 'static, D: HidIo>(
    authenticator: Authenticator<S>,
    options: &Options,
    shutdown: Arc<AtomicBool>,
    mut control: Option<(&mut control::Server, RequestId)>,
    desktop_vault: Option<&Path>,
    device: D,
) -> Result<Option<RequestId>> {
    let clock = Instant::now();
    let mut attachment = Attachment {
        device,
        worker: Some(Worker::start(authenticator, clock)?),
    };
    let device = &mut attachment.device;
    let worker = &mut attachment.worker;
    let mut desktop = desktop_vault.map(Locked::new);
    let mut configuring_pin = false;
    let input = (control.is_none() && options.test_presence.is_none()).then(input_reader);
    let mut input_ended = false;
    let mut fatal_storage = false;
    let mut engine = Engine::default();
    let mut active: Option<(Transaction, Arc<AtomicBool>)> = None;
    let mut approval: Option<Approval> = None;
    let mut lock_requested = None;
    if let Some((server, id)) = &mut control {
        server.respond(
            *id,
            service_snapshot(worker.as_ref(), None, desktop.as_ref()),
        )?;
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
        if worker.is_none() && desktop.as_ref().is_some_and(|mode| !mode.unchanged()) {
            lock_requested = Some(0);
            break; // Public discovery metadata is stale. Require manual unlock.
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
                    if configuring_pin {
                        events.extend(engine.complete(transaction, &[0x06]));
                        continue;
                    }
                    let cancel = Arc::new(AtomicBool::new(false));
                    if let Some((_, previous)) = active.replace((transaction, cancel.clone())) {
                        previous.store(true, Ordering::Release);
                    }
                    let work = Work {
                        transaction,
                        request: payload,
                        cancel,
                    };
                    if worker.is_none() {
                        let mode = desktop
                            .as_mut()
                            .expect("only desktop mode remains attached while locked");
                        if !mode.unchanged() {
                            events.extend(engine.complete(transaction, &[Status::Other as u8]));
                            lock_requested = Some(0); // invalid public profile: detach, require manual unlock
                            break;
                        }
                        match locked::classify(&work.request, mode.pin_configured) {
                            LockedAction::Reply(reply) => {
                                active = None;
                                events.extend(engine.complete(transaction, &reply));
                            }
                            LockedAction::Unlock if mode.active && mode.unlocking.is_none() => {
                                mode.waiting = Some(Waiting {
                                    work,
                                    token: request_token(transaction)?,
                                    deadline: Instant::now()
                                        + Duration::from_millis(crate::hid::OPERATION_TIMEOUT_MS),
                                });
                                events.extend(engine.presence_needed(transaction, now));
                            }
                            LockedAction::Unlock => {
                                active = None;
                                events.extend(
                                    engine.complete(transaction, &[Status::OperationDenied as u8]),
                                );
                            }
                        }
                        continue;
                    }
                    if worker
                        .as_ref()
                        .unwrap()
                        .input
                        .as_ref()
                        .unwrap()
                        .try_send(Job::Ctap(work))
                        .is_err()
                    {
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
                    if let Some(worker) = worker.as_ref() {
                        worker.invalidation.fetch_add(1, Ordering::AcqRel);
                    }
                    if let Some(mode) = desktop.as_mut() {
                        mode.cancel();
                    }
                }
                Event::Resynchronize(_) => {
                    if let Some(worker) = worker.as_ref() {
                        worker.invalidation.fetch_add(1, Ordering::AcqRel);
                    }
                    if let Some(mode) = desktop.as_mut() {
                        mode.cancel();
                    }
                }
            }
        }

        while let Some(event) = worker.as_ref().and_then(|w| w.events.try_recv().ok()) {
            let emitted = match event {
                WorkEvent::Credentials { id, response } => {
                    if let Some((server, _)) = &mut control {
                        server.respond(id, *response)?;
                    }
                    continue;
                }
                WorkEvent::PinConfigured { id, result, fatal } => {
                    configuring_pin = false;
                    if let Some((server, _)) = &mut control {
                        let response = match result {
                            Ok(()) => service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref()),
                            Err(Status::PinInvalid) => service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref()).error("The current PIN is incorrect. Try again; attempts are unlimited."),
                            Err(Status::PinPolicyViolation) => service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref()).error("Use at least 4 characters and at most 63 UTF-8 bytes, with no NUL characters."),
                            Err(Status::PinNotSet) => service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref()).error("No PIN is configured. Refresh and choose Set PIN."),
                            Err(_) => service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref()).error("PIN could not be saved. Lock and try again."),
                        };
                        server.respond(id, response)?;
                    }
                    if fatal {
                        fatal_storage = true;
                        break;
                    }
                    continue;
                }
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
                            let token = request_token(transaction)?;
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
            server.publish(service_snapshot(
                worker.as_ref(),
                approval.as_ref(),
                desktop.as_ref(),
            ))?;
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
                        server.watch(
                            id,
                            *version,
                            service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref()),
                        )?;
                        continue;
                    }
                    Request::Status {} => {
                        service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref())
                    }
                    Request::Credentials { offset, revision } => {
                        if worker.is_none() {
                            service_snapshot(None, None, desktop.as_ref()).error("vault is locked")
                        } else if active.is_some() || configuring_pin {
                            service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref())
                                .error(
                                "The key is busy. Finish the browser request and refresh the list.",
                            )
                        } else if worker
                            .as_ref()
                            .unwrap()
                            .input
                            .as_ref()
                            .unwrap()
                            .try_send(Job::Credentials {
                                id,
                                offset: *offset,
                                revision: revision.clone(),
                            })
                            .is_err()
                        {
                            service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref())
                                .error("The key is busy. Refresh the list to try again.")
                        } else {
                            continue;
                        }
                    }
                    Request::ConfigurePin { current, new } => {
                        if worker.is_none() {
                            service_snapshot(worker.as_ref(), None, desktop.as_ref())
                                .error("vault is locked")
                        } else if active.is_some() || configuring_pin {
                            service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref()).error("A browser request or PIN update is in progress. Finish it and try again.")
                        } else if worker
                            .as_ref()
                            .unwrap()
                            .input
                            .as_ref()
                            .unwrap()
                            .try_send(Job::Pin {
                                id,
                                current: Zeroizing::new(current.clone()),
                                new: Zeroizing::new(new.clone()),
                            })
                            .is_err()
                        {
                            service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref())
                                .error("The key is busy. Try again.")
                        } else {
                            configuring_pin = true;
                            continue;
                        }
                    }
                    Request::Unlock { passphrase, token } if worker.is_none() => {
                        let mode = desktop.as_mut().unwrap();
                        if !mode.active
                            || mode.unlocking.is_some()
                            || !mode.unchanged()
                            || token
                                .as_ref()
                                .map_or(mode.waiting.is_some(), |t| !mode.matches(t))
                        {
                            mode.snapshot()
                                .error("unlock request is no longer available")
                        } else {
                            mode.unlocking = Some(Unlocking::start(
                                id,
                                token.clone(),
                                mode.path.clone(),
                                Zeroizing::new(passphrase.clone()),
                            ));
                            continue;
                        }
                    }
                    Request::Unlock { .. } => {
                        Response::ready(None).error("vault is already unlocked")
                    }
                    Request::Lock {} | Request::Session { .. } if desktop.is_some() => {
                        let mode = desktop.as_mut().unwrap();
                        if let Request::Session { active } = &request {
                            mode.active = *active;
                        }
                        if !matches!(request, Request::Session { active: true }) {
                            for event in mode.lock(worker, &mut approval, &mut active, &mut engine)
                            {
                                if let Event::Send(report) = event {
                                    device.send_report(&report)?;
                                }
                            }
                            configuring_pin = false;
                        }
                        service_snapshot(worker.as_ref(), approval.as_ref(), desktop.as_ref())
                    }
                    Request::Session { .. } => {
                        Response::ready(None).error("desktop mode is not enabled")
                    }
                    Request::Lock {} => {
                        // Legacy/headless lock always detaches before replying.
                        lock_requested = Some(id);
                        break;
                    }
                    Request::Deny { token } if worker.is_none() => {
                        let mode = desktop.as_mut().unwrap();
                        if mode.matches(token) {
                            for event in mode.lock(worker, &mut approval, &mut active, &mut engine)
                            {
                                if let Event::Send(report) = event {
                                    device.send_report(&report)?;
                                }
                            }
                            mode.snapshot()
                        } else {
                            mode.snapshot()
                                .error("no pending unlock matches that token")
                        }
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

        if let Some(mode) = desktop.as_mut() {
            if let Some(task) = &mode.unlocking {
                if task.started.elapsed() >= Duration::from_secs(20)
                    || !control
                        .as_mut()
                        .is_some_and(|(server, _)| server.keep_unlock_client(task.id))
                {
                    task.cancelled.store(true, Ordering::Release);
                }
            }
            let completion =
                mode.unlocking
                    .as_ref()
                    .and_then(|task| match task.result.try_recv() {
                        Ok(result) => Some(result),
                        Err(mpsc::TryRecvError::Disconnected) => {
                            Some(Err(anyhow::anyhow!("unlock worker stopped")))
                        }
                        Err(mpsc::TryRecvError::Empty) => None,
                    });
            if let Some(result) = completion {
                let task = mode.unlocking.take().unwrap();
                let live = !task.cancelled.load(Ordering::Acquire)
                    && mode.active
                    && lock_requested.is_none()
                    && task.token.as_ref().is_none_or(|token| mode.matches(token));
                let response = match result {
                    Ok(store) if live => {
                        *worker = Some(Worker::start(Authenticator::software(store, 0), clock)?);
                        if let Some(waiting) = mode.waiting.take() {
                            worker
                                .as_ref()
                                .unwrap()
                                .input
                                .as_ref()
                                .unwrap()
                                .try_send(Job::Ctap(waiting.work))
                                .map_err(|_| anyhow::anyhow!("unlock worker unavailable"))?;
                        }
                        service_snapshot(worker.as_ref(), approval.as_ref(), Some(mode))
                    }
                    result => {
                        drop(result);
                        mode.snapshot().error(if live {
                            "vault unlock failed"
                        } else {
                            "unlock request expired or cancelled"
                        })
                    }
                };
                if let Some((server, _)) = &mut control {
                    server.respond(task.id, response)?;
                }
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
mod wake_tests;

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
                    worker: Some(Worker {
                        input: None,
                        events,
                        shutdown: shutdown.clone(),
                        invalidation: Arc::new(AtomicU64::new(0)),
                        pin_configured: Arc::new(AtomicBool::new(false)),
                        instance: 0,
                        revision: Arc::new(AtomicU64::new(0)),
                        join: Some(join),
                    }),
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
                        .try_send(Job::Ctap(Work {
                            transaction,
                            request: payload,
                            cancel: cancel.clone(),
                        }))
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
        let worker = Worker::start(auth, Instant::now()).unwrap();
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
                WorkEvent::PinConfigured { .. } => panic!("no PIN update submitted"),
                WorkEvent::Credentials { .. } => panic!("no metadata listing submitted"),
            }
        }
    }
}
