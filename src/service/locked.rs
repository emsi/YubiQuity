//! Browser-facing locked state. No vault keys, credential records or PIN tokens.
use super::*;
use crate::cbor::{self, get, int};
use crate::vault::Vault;
use ciborium::Value;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[derive(PartialEq, Eq)]
struct Stamp(u64, u64, u64, i64, i64, i64, i64);
impl Stamp {
    fn read(path: &Path) -> Option<Self> {
        let m = std::fs::symlink_metadata(path).ok()?;
        m.is_file().then(|| {
            Self(
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        })
    }
}

pub(super) struct Waiting {
    pub work: Work,
    pub token: String,
    pub deadline: Instant,
}

/// At most one KDF job. Browser cancellation leaves I/O responsive; explicit
/// locking/shutdown joins it before acknowledging that secrets have been cleared.
pub(super) struct Unlocking {
    pub id: RequestId,
    pub token: Option<String>,
    pub cancelled: Arc<AtomicBool>,
    pub result: Receiver<Result<Vault>>,
    pub started: Instant,
    thread: Option<JoinHandle<()>>,
}
impl Drop for Unlocking {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let (_, empty) = mpsc::channel();
        drop(std::mem::replace(&mut self.result, empty));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Unlocking {
    pub fn start(
        id: RequestId,
        token: Option<String>,
        path: PathBuf,
        secret: Zeroizing<Vec<u8>>,
    ) -> Self {
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let (send, result) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let opened = Vault::open(&path, &secret).map_err(anyhow::Error::from);
            drop(secret);
            let opened = if flag.load(Ordering::Acquire) {
                drop(opened);
                Err(anyhow::anyhow!("unlock cancelled"))
            } else {
                opened
            };
            let _ = send.send(opened);
        });
        Self {
            id,
            token,
            cancelled,
            result,
            started: Instant::now(),
            thread: Some(thread),
        }
    }
}

pub(super) struct Locked {
    pub path: PathBuf,
    pub active: bool,
    pub pin_configured: bool,
    stamp: Option<Stamp>,
    pub waiting: Option<Waiting>,
    pub unlocking: Option<Unlocking>,
}
impl Locked {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.into(),
            active: true,
            pin_configured: false,
            stamp: None,
            waiting: None,
            unlocking: None,
        }
    }
    pub fn remember(&mut self, pin_configured: bool) {
        self.pin_configured = pin_configured;
        self.stamp = Stamp::read(&self.path);
    }
    pub fn unchanged(&self) -> bool {
        self.stamp.is_some() && self.stamp == Stamp::read(&self.path)
    }
    pub fn cancel(&mut self) {
        if let Some(pending) = self.waiting.take() {
            pending.work.cancel.store(true, Ordering::Release);
        }
        if let Some(task) = &self.unlocking {
            task.cancelled.store(true, Ordering::Release);
        }
    }
    pub fn lock(
        &mut self,
        worker: &mut Option<Worker>,
        approval: &mut Option<Approval>,
        active: &mut Option<(Transaction, Arc<AtomicBool>)>,
        engine: &mut Engine,
    ) -> Vec<Event> {
        self.cancel();
        drop(self.unlocking.take());
        *approval = None;
        let events = if let Some((transaction, cancel)) = active.take() {
            cancel.store(true, Ordering::Release);
            engine.complete(transaction, &[Status::OperationDenied as u8])
        } else {
            vec![]
        };
        if let Some(worker) = worker.take() {
            let pin = worker.pin_configured.clone();
            drop(worker); // cancels, joins, and destroys the decrypted store
            self.remember(pin.load(Ordering::Acquire));
        }
        events
    }
    pub fn matches(&self, token: &str) -> bool {
        self.active
            && self.waiting.as_ref().is_some_and(|w| {
                w.token == token
                    && Instant::now() < w.deadline
                    && !w.work.cancel.load(Ordering::Acquire)
            })
    }
    pub fn snapshot(&self) -> Response {
        let mut response = Response::locked();
        response.wake_available = Some(self.active && self.stamp.is_some());
        response.unlock_request = self
            .waiting
            .as_ref()
            .filter(|w| self.matches(&w.token))
            .map(|w| control::Pending {
                token: w.token.clone(),
                operation: "unlock".into(),
                rp_id: String::new(),
                account: None,
                remaining_ms: w
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64,
            });
        response
    }
}
impl Drop for Locked {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(super) enum Action {
    Reply(Vec<u8>),
    Unlock,
}

/// Classify before asking for secrets. Discovery and explicitly silent requests
/// never prompt. PIN key agreement is an interactive PIN workflow; no agreement
/// private key or authorization token from the previous unlock is retained.
pub(super) fn classify(request: &[u8], pin_configured: bool) -> Action {
    let reply = |code: Status| Action::Reply(vec![code as u8]);
    let Some((&command, data)) = request.split_first() else {
        return reply(Status::InvalidLength);
    };
    if command == 4 {
        if !data.is_empty() {
            return reply(Status::InvalidLength);
        }
        let mut response = vec![0];
        response.extend(cbor::encode(&crate::ctap::authenticator_info(
            pin_configured,
        )));
        return Action::Reply(response);
    }
    if !matches!(command, 1 | 2 | 6) {
        return reply(Status::NotAllowed);
    }
    let Ok(parameters @ Value::Map(_)) = cbor::decode(data) else {
        return reply(Status::InvalidCbor);
    };
    if command == 6 {
        if get(&parameters, &int(1)) != Some(&int(1)) {
            return reply(Status::InvalidParameter);
        }
        return match get(&parameters, &int(2)) {
            Some(v) if v == &int(1) => {
                let mut response = vec![0];
                response.extend(cbor::encode(&cbor::map([(
                    int(3),
                    int(crate::pin::REPORTED_RETRIES as i64),
                )])));
                Action::Reply(response)
            }
            Some(v) if v == &int(2) => Action::Unlock,
            // No pre-lock agreement remains valid. Clients must negotiate again.
            Some(v) if [int(3), int(4), int(5)].contains(v) => reply(Status::PinAuthInvalid),
            _ => reply(Status::InvalidParameter),
        };
    }
    let hash_key = if command == 1 { 1 } else { 2 };
    if !matches!(get(&parameters, &int(hash_key)), Some(Value::Bytes(hash)) if hash.len() == 32) {
        return reply(Status::InvalidParameter);
    }
    let rp = if command == 1 {
        get(&parameters, &int(2)).and_then(|v| get(v, &cbor::text("id")))
    } else {
        get(&parameters, &int(1))
    };
    if !matches!(rp, Some(Value::Text(s)) if !s.is_empty() && s.len() <= 253 && !s.chars().any(char::is_control))
    {
        return reply(Status::InvalidParameter);
    }
    let options = get(&parameters, &int(if command == 1 { 7 } else { 5 }));
    if let Some(options) = options {
        let Value::Map(_) = options else {
            return reply(Status::InvalidParameter);
        };
        if let Some(up) = get(options, &cbor::text("up")) {
            match up {
                Value::Bool(false) => {
                    return reply(if pin_configured {
                        Status::PinRequired
                    } else {
                        Status::OperationDenied
                    })
                }
                Value::Bool(true) if command == 2 => (),
                _ => return reply(Status::InvalidOption),
            }
        }
    }
    if command == 1
        && (!matches!(get(&parameters, &int(3)), Some(Value::Map(_)))
            || !matches!(get(&parameters, &int(4)), Some(Value::Array(a)) if !a.is_empty()))
    {
        return reply(Status::MissingParameter);
    }
    Action::Unlock
}
