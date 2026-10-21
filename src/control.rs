//! Private, same-UID local control channel. No TCP, key export, or automatic
//! approval. One bounded length-prefixed JSON request per connection.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, Metadata, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_WIRE: usize = 8192;
const MAX_CLIENTS: usize = 8;
const CLIENT_LIFETIME: Duration = Duration::from_secs(5);
pub type RequestId = u64;

// Intentionally no Debug: unlock requests contain passphrase bytes.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status {},
    Unlock { passphrase: Vec<u8> },
    Approve { token: String },
    Deny { token: String },
    Lock {},
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub token: String,
    pub operation: String,
    pub rp_id: String,
    pub account: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub ok: bool,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
}

impl Response {
    pub fn locked() -> Self {
        Self {
            ok: true,
            state: "locked".into(),
            error: None,
            pending: None,
        }
    }
    pub fn ready(pending: Option<Pending>) -> Self {
        Self {
            ok: true,
            state: "ready".into(),
            error: None,
            pending,
        }
    }
    pub fn error(mut self, message: &'static str) -> Self {
        self.ok = false;
        self.error = Some(message.into());
        self
    }
}

fn uid() -> u32 {
    // SAFETY: geteuid takes no pointers and has no preconditions.
    unsafe { libc::geteuid() }
}

fn same_user(stream: &UnixStream) -> io::Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY: getsockopt receives a live socket and correctly sized writable
    // credential/length buffers. Linux fills SO_PEERCRED for Unix streams.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&credentials) || credentials.uid != uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control peer must have the same UID",
        ));
    }
    Ok(())
}

// AF_UNIX connect can otherwise block indefinitely when a listener's backlog is
// full. Nonblocking local connects either complete immediately or fail busy.
fn connect(path: &Path) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: socket takes only scalar values; its successful result is a new
    // owned descriptor transferred exactly once below.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just created and has no other owner.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as libc::c_char;
    }
    // SAFETY: address is a complete initialized sockaddr_un with a terminated
    // path, passed with its exact length, to the live owned Unix socket.
    let result = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn socket_metadata(path: &Path) -> Result<Metadata> {
    let meta = std::fs::symlink_metadata(path).context("control socket metadata")?;
    if !meta.file_type().is_socket()
        || meta.uid() != uid()
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
    {
        bail!("control endpoint must be a single-link socket owned by this user, mode 0600");
    }
    Ok(meta)
}

struct SocketPath {
    // Keep the directory FD alive: /proc/self/fd resolution prevents ancestor
    // rename/symlink races after the shared no-follow private-path validation.
    _directory: File,
    alias: PathBuf,
    owned_inode: Option<(u64, u64)>,
}
impl Drop for SocketPath {
    fn drop(&mut self) {
        if let (Some(identity), Ok(meta)) =
            (self.owned_inode, std::fs::symlink_metadata(&self.alias))
        {
            if meta.file_type().is_socket() && identity == (meta.dev(), meta.ino()) {
                let _ = std::fs::remove_file(&self.alias);
            }
        }
    }
}

fn private_path(path: &Path) -> Result<(SocketPath, std::ffi::CString)> {
    let (directory, name) = crate::vault::directory(path, false)
        .context("control endpoint requires a private 0700 parent with no symlink ancestors")?;
    let alias = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .join(std::ffi::OsStr::from_bytes(name.as_bytes()));
    if alias.as_os_str().as_bytes().len() >= 108 {
        bail!("control socket filename exceeds Linux Unix-socket path limit");
    }
    Ok((
        SocketPath {
            _directory: directory,
            alias,
            owned_inode: None,
        },
        name,
    ))
}

struct Client {
    id: RequestId,
    stream: UnixStream,
    incoming: Zeroizing<Vec<u8>>,
    expected: usize,
    handled: bool,
    outgoing: Option<Vec<u8>>,
    sent: usize,
    accepted: Instant,
}

impl Client {
    fn read_request(&mut self) -> io::Result<Option<Request>> {
        if self.handled {
            return Ok(None);
        }
        let mut buffer = Zeroizing::new([0u8; 1024]);
        // Finite work per poll, even for a client continuously writing.
        for _ in 0..16 {
            let count = (self.expected - self.incoming.len()).min(buffer.len());
            match self.stream.read(&mut buffer[..count]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(count) => self.incoming.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
            if self.incoming.len() == 4 && self.expected == 4 {
                let length = u32::from_be_bytes(self.incoming[..4].try_into().unwrap()) as usize;
                if length == 0 || length > MAX_WIRE {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.expected = 4 + length;
            }
            if self.incoming.len() == self.expected {
                let request = serde_json::from_slice(&self.incoming[4..])
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                self.handled = true;
                self.incoming.zeroize();
                return Ok(Some(request));
            }
        }
        Ok(None)
    }

    // Keep the client only while its nonblocking reply is incomplete.
    fn flush(&mut self) -> bool {
        let Some(output) = &self.outgoing else {
            return true;
        };
        match self.stream.write(&output[self.sent..]) {
            Ok(0) => false,
            Ok(count) => {
                self.sent += count;
                self.sent < output.len()
            }
            Err(error) => matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ),
        }
    }
}

pub struct Server {
    listener: UnixListener,
    _path: SocketPath,
    _lock: File,
    clients: Vec<Client>,
    next_id: RequestId,
}

impl Server {
    pub fn bind(path: &Path) -> Result<Self> {
        let (mut path, name) = private_path(path)?;
        let lock = crate::vault::lock(&path._directory, &name)
            .context("control endpoint already owned or lock unsafe")?;
        if path.alias.try_exists()? || std::fs::symlink_metadata(&path.alias).is_ok() {
            let old = socket_metadata(&path.alias)?;
            // Holding the separate lifetime lock makes stale cleanup safe for
            // cooperating daemons. Never unlink a live endpoint or other file.
            match connect(&path.alias) {
                Ok(_) => bail!("control endpoint is already listening"),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    let current = socket_metadata(&path.alias)?;
                    if (old.dev(), old.ino()) != (current.dev(), current.ino()) {
                        bail!("control endpoint changed during stale cleanup");
                    }
                    std::fs::remove_file(&path.alias)
                        .context("remove stale owned control socket")?;
                }
                Err(error) => return Err(error).context("check existing control endpoint"),
            }
        }
        let listener = UnixListener::bind(&path.alias).context("bind local control socket")?;
        let meta = std::fs::symlink_metadata(&path.alias)?;
        path.owned_inode = Some((meta.dev(), meta.ino()));
        std::fs::set_permissions(&path.alias, Permissions::from_mode(0o600))?;
        socket_metadata(&path.alias)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            _path: path,
            _lock: lock,
            clients: Vec::new(),
            next_id: 0,
        })
    }

    pub fn poll(&mut self) -> Result<Option<(RequestId, Request)>> {
        self.clients
            .retain_mut(|client| client.accepted.elapsed() < CLIENT_LIFETIME && client.flush());
        for _ in 0..MAX_CLIENTS {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if self.clients.len() >= MAX_CLIENTS || same_user(&stream).is_err() {
                        continue;
                    }
                    stream.set_nonblocking(true)?;
                    self.next_id = self
                        .next_id
                        .checked_add(1)
                        .context("control request ID space exhausted")?;
                    self.clients.push(Client {
                        id: self.next_id,
                        stream,
                        incoming: Zeroizing::new(Vec::with_capacity(MAX_WIRE + 4)),
                        expected: 4,
                        handled: false,
                        outgoing: None,
                        sent: 0,
                        accepted: Instant::now(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("accept control request"),
            }
        }
        let mut index = 0;
        while index < self.clients.len() {
            match self.clients[index].read_request() {
                Ok(Some(request)) => return Ok(Some((self.clients[index].id, request))),
                Ok(None) => index += 1,
                Err(_) => {
                    self.clients.swap_remove(index);
                }
            }
        }
        Ok(None)
    }

    pub fn respond(&mut self, id: RequestId, response: Response) -> Result<()> {
        if let Some(client) = self.clients.iter_mut().find(|client| client.id == id) {
            let bytes = serde_json::to_vec(&response)?;
            if bytes.len() > MAX_WIRE {
                bail!("internal control response exceeds bound");
            }
            let mut framed = Vec::with_capacity(4 + bytes.len());
            framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            framed.extend(bytes);
            client.outgoing = Some(framed);
        }
        Ok(())
    }
}

/// Blocking one-shot CLI client. No passphrase in argv/env or request logging.
pub fn call(path: &Path, request: &Request) -> Result<Response> {
    let (path, _) = private_path(path)?;
    socket_metadata(&path.alias)?;
    let mut stream = connect(&path.alias).context("connect local control service")?;
    same_user(&stream)?;
    stream.set_read_timeout(Some(CLIENT_LIFETIME))?;
    stream.set_write_timeout(Some(CLIENT_LIFETIME))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_WIRE));
    serde_json::to_writer(&mut *bytes, request)?;
    if bytes.len() > MAX_WIRE {
        bail!("control request exceeds bound");
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    drop(bytes);
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .context("read control reply (check status if an operation timed out)")?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_WIRE {
        bail!("invalid control reply size");
    }
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response)?;
    serde_json::from_slice(&response).context("invalid control response")
}

#[cfg(test)]
mod tests;
