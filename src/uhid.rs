//! Linux UHID adapter. All wire-layout handling lives here, not in CTAPHID.
use crate::hid::Report;
use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const NAME: &str = "YubiQuity Software FIDO2";
pub const DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];
// Packed Linux UAPI struct uhid_event, with a 4096-byte maximum descriptor.
const EVENT_SIZE: usize = 4376;
type WireEvent = [u8; EVENT_SIZE];
const DESTROY: u32 = 1;
const START: u32 = 2;
const STOP: u32 = 3;
const OUTPUT: u32 = 6;
const GET_REPORT: u32 = 9;
const GET_REPORT_REPLY: u32 = 10;
const CREATE2: u32 = 11;
const INPUT2: u32 = 12;
const SET_REPORT: u32 = 13;
const SET_REPORT_REPLY: u32 = 14;

pub struct Device {
    file: File,
    helper: Option<NodeGuard>,
    node: PathBuf,
    unique: String,
}

impl Device {
    /// Read-only access check; opening UHID does not attach a device.
    pub fn preflight() -> Result<()> {
        // SAFETY: geteuid has no arguments or memory preconditions.
        if unsafe { libc::geteuid() } == 0 {
            bail!("Run the authenticator as a normal user, not root");
        }
        drop(crate::device_access::open_uhid()?);
        Ok(())
    }

    pub fn create(node_helper: Option<&Path>) -> Result<Self> {
        // SAFETY: geteuid has no arguments, memory accesses or preconditions.
        if unsafe { libc::geteuid() } == 0 {
            bail!("Run the authenticator as a normal user, not root");
        }
        let file = crate::device_access::open_uhid()?;
        let mut random = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|e| anyhow::anyhow!("OS randomness: {e}"))?;
        let unique = format!(
            "yubiquity-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let mut device = Self {
            file,
            helper: None,
            node: PathBuf::new(),
            unique,
        };
        let mut event = wire_event(CREATE2);
        event[4..4 + NAME.len()].copy_from_slice(NAME.as_bytes());
        event[196..196 + device.unique.len()].copy_from_slice(device.unique.as_bytes());
        event[260..262].copy_from_slice(&(DESCRIPTOR.len() as u16).to_ne_bytes());
        event[262..264].copy_from_slice(&3u16.to_ne_bytes()); // BUS_USB metadata
                                                              // Development identity; not borrowed from Yubico or another manufacturer.
        event[264..268].copy_from_slice(&0xffffu32.to_ne_bytes());
        event[268..272].copy_from_slice(&1u32.to_ne_bytes());
        event[272..276].copy_from_slice(&1u32.to_ne_bytes());
        event[280..280 + DESCRIPTOR.len()].copy_from_slice(DESCRIPTOR);
        device.write_event(&event)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if Instant::now() >= deadline {
                bail!("UHID_START timed out");
            }
            if let Some(event) = device.read_event(Duration::from_millis(50))? {
                match kind(&event) {
                    START => {
                        if u64::from_ne_bytes(event[4..12].try_into().unwrap()) != 0 {
                            bail!("Kernel reported numbered reports for an unnumbered descriptor");
                        }
                        break;
                    }
                    GET_REPORT | SET_REPORT => device.reject_control(&event)?,
                    STOP => bail!("UHID stopped before initialization"),
                    _ => {}
                }
            }
        }
        let sysfs = loop {
            if let Some(path) = find_hidraw(&device.unique)? {
                break path;
            }
            if Instant::now() >= deadline {
                bail!("No hidraw interface appeared for the UHID device");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        device.node = Path::new("/dev").join(sysfs.file_name().context("hidraw basename")?);
        if let Some(helper) = node_helper {
            device.helper = Some(NodeGuard::start(helper, &device.unique, &device.node)?);
        }
        crate::device_access::wait_hidraw(
            &device.node,
            &sysfs,
            &device.unique,
            node_helper.is_some(),
        )?;
        Ok(device)
    }

    pub fn path(&self) -> &Path {
        &self.node
    }
    pub fn unique(&self) -> &str {
        &self.unique
    }

    pub fn read_report(&mut self, timeout: Duration) -> Result<Option<Report>> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Some(event) = self.read_event(remaining)? else {
                return Ok(None);
            };
            match kind(&event) {
                OUTPUT => {
                    let length = usize::from(u16::from_ne_bytes([event[4100], event[4101]]));
                    if event[4102] != 1 || length > 4096 {
                        continue;
                    }
                    // Linux hidraw writes include report ID zero; UHID_OUTPUT on
                    // the tested kernel preserves it. Normalize in this adapter.
                    if let Some(report) = normalize_output(&event[4..4 + length]) {
                        return Ok(Some(report));
                    }
                    // A malformed short/long HID report cannot take down the loop.
                }
                GET_REPORT | SET_REPORT => self.reject_control(&event)?,
                STOP => bail!("UHID device stopped"),
                _ => {} // START/OPEN/CLOSE lifecycle notifications need no response
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    pub fn send_report(&mut self, report: &Report) -> Result<()> {
        let mut event = wire_event(INPUT2);
        event[4..6].copy_from_slice(&64u16.to_ne_bytes());
        event[6..70].copy_from_slice(report);
        self.write_event(&event)
    }

    fn reject_control(&mut self, request: &WireEvent) -> Result<()> {
        let mut reply = wire_event(if kind(request) == GET_REPORT {
            GET_REPORT_REPLY
        } else {
            SET_REPORT_REPLY
        });
        reply[4..8].copy_from_slice(&request[4..8]); // request identifier
        reply[8..10].copy_from_slice(&(libc::EIO as u16).to_ne_bytes());
        self.write_event(&reply)
    }

    fn write_event(&mut self, event: &WireEvent) -> Result<()> {
        loop {
            match self.file.write(event) {
                Ok(EVENT_SIZE) => return Ok(()),
                Ok(n) => bail!("Short UHID event write: {n}/{EVENT_SIZE}"),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("writing UHID event"),
            }
        }
    }

    fn read_event(&mut self, timeout: Duration) -> Result<Option<WireEvent>> {
        let mut poll = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: poll points to one initialized pollfd, alive for this syscall.
        let result = unsafe { libc::poll(&mut poll, 1, millis) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(error).context("polling UHID");
        }
        if result == 0 {
            return Ok(None);
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            bail!("UHID descriptor closed or failed");
        }
        let mut event = [0u8; EVENT_SIZE];
        match self.file.read(&mut event) {
            Ok(0) => bail!("Unexpected EOF on UHID"),
            Ok(1..=3) => bail!("Truncated UHID event header"),
            Ok(_) => Ok(Some(event)), // short events are zero-extended per UAPI
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error).context("reading UHID event"),
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // Cleanup our node while the device still owns its minor. Closing file
        // also destroys the kernel device on errors and SIGKILL.
        drop(self.helper.take());
        let _ = self.write_event(&wire_event(DESTROY));
    }
}

fn wire_event(kind: u32) -> WireEvent {
    let mut event = [0u8; EVENT_SIZE];
    event[..4].copy_from_slice(&kind.to_ne_bytes());
    event
}
fn kind(event: &WireEvent) -> u32 {
    u32::from_ne_bytes(event[..4].try_into().unwrap())
}

fn normalize_output(data: &[u8]) -> Option<Report> {
    match data {
        data if data.len() == 64 => data.try_into().ok(),
        [0, data @ ..] if data.len() == 64 => data.try_into().ok(),
        _ => None,
    }
}

fn find_hidraw(unique: &str) -> Result<Option<PathBuf>> {
    for entry in std::fs::read_dir("/sys/class/hidraw").context("enumerating hidraw sysfs")? {
        let path = entry?.path();
        match std::fs::read_to_string(path.join("device/uevent")) {
            Ok(properties)
                if properties
                    .lines()
                    .any(|line| line.strip_prefix("HID_UNIQ=") == Some(unique)) =>
            {
                return Ok(Some(path))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("reading hidraw identity"),
        }
    }
    Ok(None)
}

const HELPER_TIMEOUT: Duration = Duration::from_secs(3);
const HELPER_STOP_TIMEOUT: Duration = Duration::from_millis(500);

struct NodeGuard(Option<Child>);
impl NodeGuard {
    fn start(script: &Path, unique: &str, expected_path: &Path) -> Result<Self> {
        let script = script
            .canonicalize()
            .context("locating explicitly requested node helper")?;
        // SAFETY: these process identity getters have no memory preconditions.
        let uid = unsafe { libc::getuid() };
        // SAFETY: getgid has no arguments or memory preconditions.
        let gid = unsafe { libc::getgid() };
        let child = Command::new("sudo")
            .args(["-n", "/usr/bin/python3", "-I"])
            .arg(script)
            .arg("--unique")
            .arg(unique)
            .arg("--uid")
            .arg(uid.to_string())
            .arg("--gid")
            .arg(gid.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("starting container device-node helper")?;
        let mut guard = Self(Some(child));
        guard.ready(expected_path, HELPER_TIMEOUT)?;
        Ok(guard)
    }

    fn ready(&mut self, expected: &Path, timeout: Duration) -> Result<()> {
        let mut stdout = self
            .0
            .as_mut()
            .context("helper process")?
            .stdout
            .take()
            .context("helper stdout")?;
        let fd = stdout.as_raw_fd();
        // SAFETY: fcntl operates on the owned pipe FD and takes scalar flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: fd is live and F_SETFL receives scalar status flags.
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error())
                .context("make helper readiness nonblocking");
        }
        let start = Instant::now();
        let mut ready = Vec::new();
        loop {
            if start.elapsed() >= timeout {
                bail!(
                    "explicit node helper did not report readiness within {} ms",
                    timeout.as_millis()
                );
            }
            let mut buffer = [0; 256];
            match stdout.read(&mut buffer) {
                Ok(0) => bail!(
                    "explicit node helper exited before reporting readiness; check its stderr"
                ),
                Ok(count) => {
                    ready.extend_from_slice(&buffer[..count]);
                    if ready.len() > 4096 {
                        bail!("node helper readiness exceeds 4096 bytes");
                    }
                    if ready.contains(&b'\n') {
                        if ready != format!("{}\n", expected.display()).as_bytes() {
                            bail!("node helper reported an unexpected device path");
                        }
                        return Ok(());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(
                        Duration::from_millis(10).min(timeout.saturating_sub(start.elapsed())),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error).context("read helper readiness"),
            }
        }
    }
}

fn child_exited(child: &mut Child, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Err(_) => return false,
            Ok(None) if start.elapsed() >= timeout => return false,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        // EOF tells the helper to clean up, including when the daemon is killed.
        drop(child.stdin.take());
        if child_exited(&mut child, HELPER_STOP_TIMEOUT) {
            return;
        }
        // Never let a malfunctioning external helper prevent UHID detach.
        // Killing a privileged helper may be denied; report that honestly.
        let result = child.kill();
        if !child_exited(&mut child, HELPER_STOP_TIMEOUT) {
            eprintln!("Node helper did not exit after EOF/termination ({result:?}); detaching UHID without waiting further. Check the explicitly selected helper.");
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_report_id_normalization() {
        let report = [9; 64];
        assert_eq!(normalize_output(&report), Some(report));
        let mut numbered = vec![0];
        numbered.extend(report);
        assert_eq!(normalize_output(&numbered), Some(report));
        numbered[0] = 1;
        assert_eq!(normalize_output(&numbered), None);
        for length in [0, 1, 63, 66, 4096] {
            assert_eq!(normalize_output(&vec![0; length]), None);
        }
    }

    fn helper(script: &str) -> NodeGuard {
        NodeGuard(Some(
            Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }

    #[test]
    fn helper_readiness_accepts_only_the_expected_complete_line() {
        let mut correct = helper("printf '/dev/hidraw123\n'; read -r ignored");
        correct
            .ready(Path::new("/dev/hidraw123"), Duration::from_secs(1))
            .unwrap();
        for script in [
            "printf '/dev/hidraw456\n'",
            "printf '/dev/hidraw123'",
            "exit 1",
        ] {
            let mut wrong = helper(script);
            assert!(wrong
                .ready(Path::new("/dev/hidraw123"), Duration::from_secs(1))
                .is_err());
        }
    }

    #[test]
    fn helper_startup_and_shutdown_cannot_block_forever() {
        let mut stuck = helper("exec sleep 30");
        let start = Instant::now();
        let error = stuck
            .ready(Path::new("/dev/hidraw123"), Duration::from_millis(30))
            .unwrap_err();
        assert!(error.to_string().contains("within 30 ms"));
        drop(stuck);
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
