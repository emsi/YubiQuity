//! Full service loop, real encrypted vault and control socket, bounded transport.
//! These complement (and do not replace) the real HID/browser integration tests.
use super::*;
use crate::cbor::{self, bytes, int, map, text};
use crate::hid::{frame, Report, BROADCAST, CBOR, INIT, KEEPALIVE};
use crate::vault::Vault;
use ciborium::Value;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const SECRET: &[u8] = b"disposable wake test passphrase";
struct TestDevice {
    input: Receiver<Report>,
    output: SyncSender<Report>,
}
impl HidIo for TestDevice {
    fn read_report(&mut self, timeout: Duration) -> Result<Option<Report>> {
        Ok(self.input.recv_timeout(timeout).ok())
    }
    fn send_report(&mut self, report: &Report) -> Result<()> {
        self.output.try_send(*report).map_err(anyhow::Error::from)
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    vault: PathBuf,
    socket: PathBuf,
    input: SyncSender<Report>,
    output: Receiver<Report>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<Option<RequestId>>>>,
    channel: u32,
}
impl Fixture {
    fn new(desktop: bool) -> Self {
        let directory = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let vault = directory.path().join("test.yq");
        let store = Vault::create(&vault, SECRET).unwrap();
        let socket = directory.path().join("control.sock");
        let mut server = control::Server::bind(&socket).unwrap();
        let (input, rx) = mpsc::sync_channel(64);
        let (tx, output) = mpsc::sync_channel(256);
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let path = vault.clone();
        let thread = std::thread::spawn(move || {
            run_device(
                Authenticator::software(store, 0),
                &Options {
                    node_helper: None,
                    exit_after: Some(20),
                    test_presence: None,
                },
                flag,
                Some((&mut server, 0)),
                desktop.then_some(path.as_path()),
                TestDevice {
                    input: rx,
                    output: tx,
                },
            )
        });
        let mut f = Self {
            _directory: directory,
            vault,
            socket,
            input,
            output,
            shutdown,
            thread: Some(thread),
            channel: 0,
        };
        f.input
            .send(frame(BROADCAST, INIT, &[1; 8]).unwrap()[0])
            .unwrap();
        let report = f.output.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(report[4], INIT | 0x80);
        f.channel = u32::from_be_bytes(report[15..19].try_into().unwrap());
        f
    }
    fn ctl(&self, request: Request) -> Response {
        control::call(&self.socket, &request).unwrap()
    }
    fn wait(&self, predicate: impl Fn(&Response) -> bool) -> Response {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = self.ctl(Request::Status {});
            if predicate(&status) {
                return status;
            }
            assert!(Instant::now() < deadline, "service state did not converge");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn send(&self, payload: &[u8]) {
        for report in frame(self.channel, CBOR, payload).unwrap() {
            self.input.send(report).unwrap();
        }
    }
    fn response(&self) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline);
            let first = self.output.recv_timeout(Duration::from_secs(3)).unwrap();
            if first[4] == KEEPALIVE | 0x80 {
                continue;
            }
            assert_eq!(first[4], CBOR | 0x80);
            let size = u16::from_be_bytes([first[5], first[6]]) as usize;
            let mut bytes = first[7..7 + size.min(57)].to_vec();
            while bytes.len() < size {
                let next = self.output.recv_timeout(Duration::from_secs(3)).unwrap();
                bytes.extend_from_slice(&next[5..5 + (size - bytes.len()).min(59)]);
            }
            return bytes;
        }
    }
    fn pending(&self) -> control::Pending {
        self.wait(|s| s.unlock_request.is_some())
            .unlock_request
            .unwrap()
    }
    fn unlock(&self, token: &str) -> Response {
        self.ctl(Request::Unlock {
            passphrase: SECRET.to_vec(),
            token: Some(token.into()),
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap().unwrap();
        }
    }
}
fn request(command: u8, body: Value) -> Vec<u8> {
    let mut out = vec![command];
    out.extend(cbor::encode(&body));
    out
}
fn register() -> Vec<u8> {
    request(
        1,
        map([
            (int(1), bytes(&[1; 32])),
            (int(2), map([(text("id"), text("example.test"))])),
            (
                int(3),
                map([(text("id"), bytes(&[1])), (text("name"), text("alice"))]),
            ),
            (
                int(4),
                Value::Array(vec![map([
                    (text("type"), text("public-key")),
                    (text("alg"), int(-7)),
                ])]),
            ),
        ]),
    )
}

#[test]
fn discovery_is_silent_and_unlock_does_not_approve_registration() {
    let f = Fixture::new(true);
    assert_eq!(f.ctl(Request::Lock {}).wake_available, Some(true));
    // Lock released the encrypted vault and destroyed the worker holding keys.
    drop(Vault::open(&f.vault, SECRET).unwrap());
    f.send(&[4]);
    assert_eq!(f.response()[0], 0);
    assert!(f.ctl(Request::Status {}).unlock_request.is_none());
    f.send(&request(6, map([(int(1), int(1)), (int(2), int(1))])));
    assert_eq!(f.response()[0], 0);
    f.send(&register());
    let pending = f.pending();
    assert!(!f.unlock("stale-token").ok);
    assert!(
        !f.ctl(Request::Unlock {
            passphrase: b"wrong password".to_vec(),
            token: Some(pending.token.clone())
        })
        .ok
    );
    assert_eq!(f.pending().token, pending.token);
    assert!(f.unlock(&pending.token).ok);
    let approval = f.wait(|s| s.pending.is_some()).pending.unwrap();
    assert_eq!(approval.operation, "register");
    assert!(
        !f.ctl(Request::Approve {
            token: pending.token
        })
        .ok
    );
    assert!(
        f.ctl(Request::Deny {
            token: approval.token
        })
        .ok
    );
    assert_eq!(f.response(), vec![Status::OperationDenied as u8]);
}

#[test]
fn cancellation_and_session_lock_revoke_unlock_requests() {
    let f = Fixture::new(true);
    f.ctl(Request::Lock {});
    f.send(&register());
    let old = f.pending();
    f.input
        .send(frame(f.channel, crate::hid::CANCEL, &[]).unwrap()[0])
        .unwrap();
    assert_eq!(f.response(), vec![Status::Cancelled as u8]);
    assert!(!f.unlock(&old.token).ok);
    f.send(&register());
    let old = f.pending();
    assert_eq!(f.ctl(Request::Session { active: false }).state, "locked");
    assert_eq!(f.response(), vec![Status::OperationDenied as u8]);
    assert!(!f.unlock(&old.token).ok);
    f.send(&register());
    assert_eq!(f.response(), vec![Status::OperationDenied as u8]);
    assert!(f.ctl(Request::Status {}).unlock_request.is_none());
    f.ctl(Request::Session { active: true });
    f.send(&register());
    let fresh = f.pending();
    assert_ne!(fresh.token, old.token);
    assert!(f.ctl(Request::Deny { token: fresh.token }).ok);
    assert_eq!(f.response(), vec![Status::OperationDenied as u8]);
}

#[test]
fn pin_negotiation_can_unlock_and_silent_assertions_do_not_prompt() {
    let f = Fixture::new(true);
    assert!(
        f.ctl(Request::ConfigurePin {
            current: vec![],
            new: b"1234".to_vec()
        })
        .ok
    );
    f.ctl(Request::Lock {});
    f.send(&[4]);
    let info = f.response();
    let info = cbor::decode(&info[1..]).unwrap();
    let options = cbor::get(&info, &int(4)).unwrap();
    assert_eq!(
        cbor::get(options, &text("clientPin")),
        Some(&Value::Bool(true))
    );
    f.send(&request(
        2,
        map([
            (int(1), text("example.test")),
            (int(2), bytes(&[1; 32])),
            (int(5), map([(text("up"), Value::Bool(false))])),
        ]),
    ));
    assert_eq!(f.response(), vec![Status::PinRequired as u8]);
    assert!(f.ctl(Request::Status {}).unlock_request.is_none());
    f.send(&request(6, map([(int(1), int(1)), (int(2), int(2))])));
    let pending = f.pending();
    assert!(f.unlock(&pending.token).ok);
    assert_eq!(f.response()[0], 0);
    assert!(f.ctl(Request::Status {}).pending.is_none());
}

#[test]
fn legacy_lock_detaches_and_changed_vault_invalidates_cached_capabilities() {
    let mut legacy = Fixture::new(false);
    // run_device returns before the outer legacy service sends its lock reply.
    let path = legacy.socket.clone();
    let caller = std::thread::spawn(move || control::call(&path, &Request::Lock {}));
    assert!(legacy
        .thread
        .take()
        .unwrap()
        .join()
        .unwrap()
        .unwrap()
        .is_some());
    assert!(caller.join().unwrap().is_err());
    let mut f = Fixture::new(true);
    f.ctl(Request::Lock {});
    std::fs::rename(&f.vault, f.vault.with_extension("moved")).unwrap();
    assert_eq!(f.thread.take().unwrap().join().unwrap().unwrap(), Some(0));
}

#[test]
fn expired_tokens_and_late_password_checks_cannot_unlock() {
    let f = Fixture::new(true);
    f.ctl(Request::Lock {});
    let mut mode = Locked::new(&f.vault);
    mode.remember(false);
    mode.waiting = Some(Waiting {
        work: Work {
            transaction: Transaction { id: 1, channel: 1 },
            request: Zeroizing::new(register()),
            cancel: Arc::new(AtomicBool::new(false)),
        },
        token: "expired".into(),
        deadline: Instant::now(),
    });
    assert!(!mode.matches("expired"));
    let task = Unlocking::start(
        1,
        Some("expired".into()),
        f.vault.clone(),
        Zeroizing::new(SECRET.to_vec()),
    );
    mode.unlocking = Some(task);
    mode.cancel();
    let task = mode.unlocking.take().unwrap();
    let result = task.result.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(task.cancelled.load(Ordering::Acquire));
    assert!(!mode.matches("expired"));
    drop(result);
    drop(Vault::open(&f.vault, SECRET).unwrap());

    mode.unlocking = Some(Unlocking::start(
        2,
        None,
        f.vault.clone(),
        Zeroizing::new(SECRET.to_vec()),
    ));
    mode.lock(&mut None, &mut None, &mut None, &mut Engine::default());
    assert!(mode.unlocking.is_none());
    // An acknowledged lock must not leave a KDF result holding the vault open.
    drop(Vault::open(&f.vault, SECRET).unwrap());
}

#[test]
fn malformed_and_noninteractive_commands_do_not_request_secrets() {
    for payload in [
        vec![],
        vec![4, 0],
        vec![1, 0xff],
        vec![7],
        vec![8],
        request(1, map([])),
        request(6, map([(int(1), int(99)), (int(2), int(2))])),
        request(6, map([(int(1), int(1)), (int(2), int(5))])),
    ] {
        assert!(matches!(
            locked::classify(&payload, true),
            LockedAction::Reply(_)
        ));
    }
}
