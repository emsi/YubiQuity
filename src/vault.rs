//! Linux encrypted whole-vault store. All filesystem operations are relative to
//! verified directory FDs, and an independent lock inode survives replacement.
use crate::store::{State, Store, StoreError, MAX_CREDENTIALS};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Component, Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"YQVAULT\0";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 68;
const TAG_LEN: usize = 16;
const MAX_PLAIN: usize = 1024 * 1024;
pub const MAX_PASSPHRASE: usize = 1024;
type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug)]
pub enum VaultError {
    Io(&'static str, io::Error),
    UnsafePath(String),
    IoAt(&'static str, PathBuf, io::Error),
    Busy,
    AlreadyExists,
    InvalidHeader,
    UnsupportedVersion,
    Authentication,
    InvalidState,
    Passphrase,
    Failed,
}
impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(operation, error) => write!(f, "vault {operation}: {error}"),
            Self::IoAt(operation, path, error) => {
                write!(f, "vault {operation} at {}: {error}", path.display())
            }
            Self::UnsafePath(reason) => write!(f, "unsafe vault path: {reason}"),
            Self::Busy => f.write_str("vault is locked by another process"),
            Self::AlreadyExists => {
                f.write_str("vault already exists; initialization will not overwrite it")
            }
            Self::InvalidHeader => {
                f.write_str("invalid or oversized vault envelope/KDF parameters")
            }
            Self::UnsupportedVersion => f.write_str("unsupported vault format version"),
            Self::Authentication => {
                f.write_str("wrong vault passphrase or corrupt/tampered encrypted data")
            }
            Self::InvalidState => f.write_str("invalid or unsupported decrypted vault state"),
            Self::Passphrase => {
                f.write_str("vault passphrase must be 12–1024 bytes, without NUL or line breaks")
            }
            Self::Failed => f.write_str("vault stopped after a failed write; close and reopen it"),
        }
    }
}
impl std::error::Error for VaultError {}
impl VaultError {
    fn at(self, path: &Path) -> Self {
        match self {
            Self::Io(operation, error) => Self::IoAt(operation, path.to_path_buf(), error),
            Self::UnsafePath(reason) => Self::UnsafePath(format!("{}: {reason}", path.display())),
            other => other,
        }
    }
}
fn io_error(operation: &'static str) -> impl FnOnce(io::Error) -> VaultError {
    move |error| VaultError::Io(operation, error)
}

#[derive(Clone, Copy)]
struct Kdf {
    memory: u32,
    passes: u32,
    lanes: u32,
}
impl Default for Kdf {
    fn default() -> Self {
        Self {
            memory: 65_536,
            passes: 3,
            lanes: 1,
        }
    }
}
impl Kdf {
    fn params(self) -> Result<Params> {
        if !(16_384..=131_072).contains(&self.memory)
            || !(2..=6).contains(&self.passes)
            || !(1..=4).contains(&self.lanes)
        {
            return Err(VaultError::InvalidHeader);
        }
        Params::new(self.memory, self.passes, self.lanes, Some(32))
            .map_err(|_| VaultError::InvalidHeader)
    }
    fn derive(self, passphrase: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
        let params = self.params()?;
        let mut memory = Zeroizing::new(Vec::new());
        memory
            .try_reserve_exact(params.block_count())
            .map_err(|_| VaultError::InvalidHeader)?;
        memory.resize(params.block_count(), Block::default());
        let mut key = Zeroizing::new([0; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(passphrase, salt, key.as_mut(), memory.as_mut_slice())
            .map_err(|_| VaultError::InvalidHeader)?;
        Ok(key)
    }
}

pub fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
    if !(12..=MAX_PASSPHRASE).contains(&passphrase.len())
        || passphrase.iter().any(|b| matches!(b, 0 | b'\r' | b'\n'))
    {
        return Err(VaultError::Passphrase);
    }
    Ok(())
}

#[derive(Serialize)]
struct PayloadRef<'a> {
    version: u32,
    state: &'a State,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    version: u32,
    state: State,
}

fn validate_state(state: &State) -> Result<()> {
    if state.credentials.len() > MAX_CREDENTIALS
        || state.pin.as_ref().is_some_and(|p| p.retries > 8)
    {
        return Err(VaultError::InvalidState);
    }
    let mut ids = HashSet::new();
    let mut residents = HashSet::new();
    for c in &state.credentials {
        if c.id.len() != 32
            || !ids.insert(&c.id)
            || c.algorithm != -7
            || c.rp_id.is_empty()
            || c.rp_id.len() > 253
            || c.rp_id.chars().any(char::is_control)
            || !(1..=64).contains(&c.user.id.len())
            || c.user.name.as_ref().is_some_and(|s| s.len() > 64)
            || c.user.display_name.as_ref().is_some_and(|s| s.len() > 64)
            || p256::SecretKey::from_slice(&c.private_key).is_err()
            || (c.discoverable && !residents.insert((&c.rp_id, &c.user.id)))
        {
            return Err(VaultError::InvalidState);
        }
    }
    Ok(())
}

/// Bound serialization without reallocating plaintext-bearing buffers.
struct BoundedBuffer(Zeroizing<Vec<u8>>);
impl Write for BoundedBuffer {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > MAX_PLAIN.saturating_sub(self.0.len()) {
            return Err(io::Error::other("vault plaintext limit"));
        }
        self.0.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}
impl From<&Metadata> for Identity {
    fn from(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
        }
    }
}

pub struct Vault {
    directory: File,
    name: CString,
    _lock: File,
    identity: Option<Identity>,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    kdf: Kdf,
    state: State,
    failed: bool,
    #[cfg(test)]
    fault: Option<Stage>,
}

impl Vault {
    /// Validate public path/envelope information before requesting a secret.
    /// Creates no directories, lock files or vaults, and does not decrypt data.
    /// The actual operation repeats all FD-relative checks to avoid TOCTOU trust.
    pub fn preflight(path: &Path, create: bool) -> Result<()> {
        let (directory, name, missing_leaf) =
            directory_walk(path, create, true, DirectoryPolicy::Vault)?;
        if missing_leaf {
            return writable_directory(&directory).map_err(|e| e.at(path.parent().unwrap_or(path)));
        }
        if create {
            match open_at(&directory, &name, libc::O_PATH, 0) {
                Ok(_) => return Err(VaultError::AlreadyExists),
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(io_error("inspect existing file")(error).at(path)),
            }
            writable_directory(&directory).map_err(|e| e.at(path.parent().unwrap_or(path)))?;
        } else {
            let mut file = open_at(&directory, &name, libc::O_RDONLY, 0)
                .map_err(|error| io_error("open (initialize a new vault explicitly with init; do not reinitialize an existing vault)")(error).at(path))?;
            let meta = private_file(&file).map_err(|e| e.at(path))?;
            if !(HEADER_LEN as u64 + TAG_LEN as u64..=(HEADER_LEN + MAX_PLAIN + TAG_LEN) as u64)
                .contains(&meta.len())
            {
                return Err(VaultError::InvalidHeader);
            }
            let mut header = [0; HEADER_LEN];
            file.read_exact(&mut header)
                .map_err(|error| io_error("read header")(error).at(path))?;
            let (_, _, _, length) = parse_header(&header)?;
            if meta.len() != (HEADER_LEN + length) as u64 {
                return Err(VaultError::InvalidHeader);
            }
        }
        // Check an existing lock without creating one. Release immediately;
        // create/open still obtain the lifetime lock after the secret is read.
        let lock_name = lock_name(&name)?;
        match open_at(&directory, &lock_name, libc::O_RDONLY, 0) {
            Ok(file) => {
                private_file(&file).map_err(|e| {
                    e.at(&path.with_file_name(OsStr::from_bytes(lock_name.to_bytes())))
                })?;
                exclusive_lock(&file)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(io_error("inspect writer lock")(error).at(path)),
        }
        Ok(())
    }

    pub fn create(path: &Path, passphrase: &[u8]) -> Result<Self> {
        Self::create_with_kdf(path, passphrase, Kdf::default())
    }
    fn create_with_kdf(path: &Path, passphrase: &[u8], kdf: Kdf) -> Result<Self> {
        validate_passphrase(passphrase)?;
        let (directory, name) = directory(path, true, DirectoryPolicy::Vault)?;
        let lock = lock(&directory, &name)?;
        match open_at(&directory, &name, libc::O_RDONLY, 0) {
            Ok(_) => return Err(VaultError::AlreadyExists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(io_error("check existing file")(error)),
        }
        let mut salt = [0; 16];
        random(&mut salt)?;
        let key = kdf.derive(passphrase, &salt)?;
        let mut vault = Self {
            directory,
            name,
            _lock: lock,
            identity: None,
            key,
            salt,
            kdf,
            state: State::default(),
            failed: false,
            #[cfg(test)]
            fault: None,
        };
        vault.replace(State::default())?;
        Ok(vault)
    }

    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        validate_passphrase(passphrase)?;
        let (directory, name) = directory(path, false, DirectoryPolicy::Vault)?;
        let lock = lock(&directory, &name)?;
        let mut file = open_at(&directory, &name, libc::O_RDONLY, 0).map_err(io_error("open"))?;
        let meta = private_file(&file)?;
        if !(HEADER_LEN as u64 + TAG_LEN as u64..=(HEADER_LEN + MAX_PLAIN + TAG_LEN) as u64)
            .contains(&meta.len())
        {
            return Err(VaultError::InvalidHeader);
        }
        let mut header = [0; HEADER_LEN];
        file.read_exact(&mut header)
            .map_err(io_error("read header"))?;
        let (kdf, salt, nonce, length) = parse_header(&header)?;
        if meta.len() != (HEADER_LEN + length) as u64 {
            return Err(VaultError::InvalidHeader);
        }
        // Check the entire public envelope and bounded KDF before expensive work.
        let key = kdf.derive(passphrase, &salt)?;
        let mut plain = Zeroizing::new(vec![0; length]);
        file.read_exact(&mut plain)
            .map_err(io_error("read ciphertext"))?;
        let mut extra = [0; 1];
        if file
            .read(&mut extra)
            .map_err(io_error("check file length"))?
            != 0
        {
            return Err(VaultError::InvalidHeader);
        }
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        cipher
            .decrypt_in_place((&nonce).into(), &header, &mut *plain)
            .map_err(|_| VaultError::Authentication)?;
        let payload: Payload =
            serde_json::from_slice(&plain).map_err(|_| VaultError::InvalidState)?;
        if payload.version != VERSION {
            return Err(VaultError::UnsupportedVersion);
        }
        validate_state(&payload.state)?;
        Ok(Self {
            directory,
            name,
            _lock: lock,
            identity: Some(Identity::from(&meta)),
            key,
            salt,
            kdf,
            state: payload.state,
            failed: false,
            #[cfg(test)]
            fault: None,
        })
    }

    /// Metadata management uses the exact same atomic commit path as CTAP writes.
    pub fn remove_credential(&mut self, id: &[u8]) -> Result<()> {
        if !self.state.credentials.iter().any(|c| c.id == id) {
            return Err(VaultError::InvalidState);
        }
        let mut next = self.state.clone();
        next.credentials.retain(|c| c.id != id);
        self.replace(next)
    }

    fn replace(&mut self, next: State) -> Result<()> {
        if self.failed {
            return Err(VaultError::Failed);
        }
        let result = self.write_state(&next);
        match result {
            Ok(identity) => {
                self.identity = Some(identity);
                self.state = next;
                Ok(())
            }
            Err(error) => {
                self.failed = true;
                self.key.zeroize();
                Err(error)
            }
        }
    }

    fn write_state(&self, next: &State) -> Result<Identity> {
        validate_state(next)?;
        private_directory(&self.directory)?;
        if let Some(identity) = self.identity {
            let current = open_at(&self.directory, &self.name, libc::O_RDONLY, 0)
                .map_err(io_error("check current file"))?;
            if Identity::from(&private_file(&current)?) != identity {
                return Err(VaultError::UnsafePath(
                    "vault file replaced outside the writer lock".into(),
                ));
            }
        }
        let mut buffer = BoundedBuffer(Zeroizing::new(Vec::with_capacity(MAX_PLAIN + TAG_LEN)));
        serde_json::to_writer(
            &mut buffer,
            &PayloadRef {
                version: VERSION,
                state: next,
            },
        )
        .map_err(|_| VaultError::InvalidState)?;
        let mut nonce = [0; 24];
        random(&mut nonce)?;
        let header = header(self.kdf, &self.salt, &nonce, buffer.0.len() + TAG_LEN);
        XChaCha20Poly1305::new(self.key.as_ref().into())
            .encrypt_in_place((&nonce).into(), &header, &mut *buffer.0)
            .map_err(|_| VaultError::InvalidState)?;
        let mut temporary = Temporary::new(&self.directory)?;
        self.stage(Stage::Write)?;
        temporary
            .file
            .write_all(&header)
            .map_err(io_error("write temporary header"))?;
        self.stage(Stage::PartialWrite)?;
        temporary
            .file
            .write_all(&buffer.0)
            .map_err(io_error("write temporary ciphertext"))?;
        self.stage(Stage::FileSync)?;
        temporary
            .file
            .sync_all()
            .map_err(io_error("sync temporary file"))?;
        let identity = Identity::from(&private_file(&temporary.file)?);
        self.stage(Stage::Rename)?;
        let flags = if self.identity.is_none() {
            libc::RENAME_NOREPLACE
        } else {
            0
        };
        // SAFETY: both live directory FDs and NUL-terminated names remain valid;
        // this only renames the exclusively created temporary file in that directory.
        let result = unsafe {
            libc::renameat2(
                self.directory.as_raw_fd(),
                temporary.name.as_ptr(),
                self.directory.as_raw_fd(),
                self.name.as_ptr(),
                flags,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                VaultError::AlreadyExists
            } else {
                io_error("atomic rename")(error)
            });
        }
        temporary.armed = false;
        self.stage(Stage::DirectorySync)?;
        self.directory
            .sync_all()
            .map_err(io_error("sync vault directory"))?;
        Ok(identity)
    }

    fn stage(&self, _stage: Stage) -> Result<()> {
        #[cfg(test)]
        if self.fault == Some(_stage) {
            return Err(io_error("injected write failure")(
                io::Error::from_raw_os_error(libc::EIO),
            ));
        }
        Ok(())
    }
}

impl Store for Vault {
    fn state(&self) -> &State {
        &self.state
    }
    fn commit(&mut self, next: State) -> std::result::Result<(), StoreError> {
        self.replace(next).map_err(|error| {
            // Error variants contain no plaintext, passphrase, PIN, token or key.
            eprintln!("Vault commit failed; stopping credential operations: {error}");
            StoreError
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Write,
    PartialWrite,
    FileSync,
    Rename,
    DirectorySync,
}

fn header(kdf: Kdf, salt: &[u8; 16], nonce: &[u8; 24], length: usize) -> [u8; HEADER_LEN] {
    let mut result = [0; HEADER_LEN];
    result[..8].copy_from_slice(MAGIC);
    for (offset, value) in [
        (8, VERSION),
        (12, kdf.memory),
        (16, kdf.passes),
        (20, kdf.lanes),
        (64, length as u32),
    ] {
        result[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    result[24..40].copy_from_slice(salt);
    result[40..64].copy_from_slice(nonce);
    result
}

fn parse_header(header: &[u8; HEADER_LEN]) -> Result<(Kdf, [u8; 16], [u8; 24], usize)> {
    if &header[..8] != MAGIC {
        return Err(VaultError::InvalidHeader);
    }
    let number = |offset| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap());
    if number(8) != VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    let kdf = Kdf {
        memory: number(12),
        passes: number(16),
        lanes: number(20),
    };
    kdf.params()?;
    let length = number(64) as usize;
    if !(TAG_LEN..=MAX_PLAIN + TAG_LEN).contains(&length) {
        return Err(VaultError::InvalidHeader);
    }
    Ok((
        kdf,
        header[24..40].try_into().unwrap(),
        header[40..64].try_into().unwrap(),
        length,
    ))
}

fn random(output: &mut [u8]) -> Result<()> {
    OsRng
        .try_fill_bytes(output)
        .map_err(|_| io_error("OS randomness")(io::Error::other("entropy unavailable")))
}
fn cstring(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| VaultError::UnsafePath("NUL in path".into()))
}
fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: openat receives a valid directory FD and a terminated name. The
    // returned FD is owned exactly once by File; failed calls do not construct one.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful openat returned a fresh owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn uid() -> u32 {
    // SAFETY: geteuid has no preconditions or pointers.
    unsafe { libc::geteuid() }
}
fn private_directory(file: &File) -> Result<()> {
    let meta = file.metadata().map_err(io_error("directory metadata"))?;
    if !meta.is_dir() || meta.uid() != uid() || meta.mode() & 0o7777 != 0o700 {
        return Err(VaultError::UnsafePath(format!(
            "directory must be owned by uid {} with mode 0700; found uid {}, gid {}, mode {:04o}",
            uid(),
            meta.uid(),
            meta.gid(),
            meta.mode() & 0o7777
        )));
    }
    Ok(())
}
fn private_file(file: &File) -> Result<Metadata> {
    let meta = file.metadata().map_err(io_error("file metadata"))?;
    if !meta.is_file() || meta.uid() != uid() || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1
    {
        return Err(VaultError::UnsafePath(
            format!("vault/lock file must be regular, single-link, owned by uid {}, mode 0600; found uid {}, gid {}, mode {:04o}, links {}", uid(), meta.uid(), meta.gid(), meta.mode() & 0o7777, meta.nlink()),
        ));
    }
    Ok(meta)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DirectoryPolicy {
    Vault,
    ControlSocket,
}
impl DirectoryPolicy {
    fn allows_ancestor(self, owner: u32, mode: u32, user: u32) -> bool {
        if owner != 0 && owner != user {
            return false;
        }
        // Preserve the existing exception for root-owned sticky directories,
        // e.g. /tmp. A user's sticky bit does not make a public path trusted.
        if owner == 0 && mode & 0o1000 != 0 {
            return true;
        }
        // Common user-owned .local/share directories are 0775. Accept their
        // group-write bit for vaults without loosening the private leaf/files
        // or the separate control endpoint's ancestor policy. This trusts the
        // owner's choice of group; it does not inspect group membership.
        let forbidden_write_bits = match self {
            Self::Vault if owner == user => 0o002,
            _ => 0o022,
        };
        mode & forbidden_write_bits == 0
    }
}

pub(crate) fn directory(
    path: &Path,
    create: bool,
    policy: DirectoryPolicy,
) -> Result<(File, CString)> {
    directory_walk(path, create, false, policy).map(|(directory, name, _)| (directory, name))
}

fn directory_walk(
    path: &Path,
    create: bool,
    inspect: bool,
    policy: DirectoryPolicy,
) -> Result<(File, CString, bool)> {
    if uid() == 0 {
        return Err(VaultError::UnsafePath(
            "run the vault as an unprivileged user".into(),
        ));
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(io_error("working directory"))?
            .join(path)
    };
    let mut names = vec![];
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => names.push(cstring(name)?),
            _ => {
                return Err(VaultError::UnsafePath(
                    "parent/relative path components are not allowed".into(),
                ))
            }
        }
    }
    let name = names
        .pop()
        .ok_or(VaultError::UnsafePath("missing filename".into()))?;
    if name.as_bytes().len() > 180 || name.as_bytes().starts_with(b".") {
        return Err(VaultError::UnsafePath(
            "filename must be non-hidden and at most 180 bytes".into(),
        ));
    }
    let mut current = File::open("/").map_err(io_error("open filesystem root"))?;
    let mut current_path = PathBuf::from("/");
    for (index, part) in names.iter().enumerate() {
        let parent = current.metadata().map_err(io_error("ancestor metadata"))?;
        if !parent.is_dir() || !policy.allows_ancestor(parent.uid(), parent.mode(), uid()) {
            return Err(VaultError::UnsafePath(format!(
                "{}: untrusted or writable ancestor directory (uid {}, gid {}, mode {:04o})",
                current_path.display(),
                parent.uid(),
                parent.gid(),
                parent.mode() & 0o7777
            )));
        }
        current_path.push(OsStr::from_bytes(part.to_bytes()));
        let next = match open_at(&current, part, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(file) => file,
            Err(error)
                if create
                    && index + 1 == names.len()
                    && error.kind() == io::ErrorKind::NotFound =>
            {
                if inspect {
                    return Ok((current, name, true));
                }
                // SAFETY: the verified directory FD and terminated single path
                // component identify only the requested new private directory.
                let result = unsafe { libc::mkdirat(current.as_raw_fd(), part.as_ptr(), 0o700) };
                if result != 0 {
                    return Err(
                        io_error("create private directory")(io::Error::last_os_error())
                            .at(&current_path),
                    );
                }
                current
                    .sync_all()
                    .map_err(io_error("sync new directory entry"))?;
                open_at(&current, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                    .map_err(|error| io_error("open new directory")(error).at(&current_path))?
            }
            Err(error) => {
                return Err(io_error("open directory without symlinks")(error).at(&current_path))
            }
        };
        current = next;
    }
    private_directory(&current).map_err(|e| e.at(&current_path))?;
    Ok((current, name, false))
}

fn writable_directory(directory: &File) -> Result<()> {
    // SAFETY: the directory FD is live; the fixed dot name is terminated. Check
    // effective credentials without creating a probe file or changing modes.
    if unsafe {
        libc::faccessat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::W_OK | libc::X_OK,
            libc::AT_EACCESS,
        )
    } != 0
    {
        return Err(io_error("directory is not writable/searchable")(
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn lock_name(name: &CStr) -> Result<CString> {
    let mut lock_name = b".".to_vec();
    lock_name.extend(name.to_bytes());
    lock_name.extend(b".lock");
    CString::new(lock_name).map_err(|_| VaultError::UnsafePath("invalid lock name".into()))
}

pub(crate) fn lock(directory: &File, name: &CStr) -> Result<File> {
    let lock_name = lock_name(name)?;
    let file = open_at(directory, &lock_name, libc::O_RDWR | libc::O_CREAT, 0o600)
        .map_err(io_error("open writer lock"))?;
    private_file(&file)?;
    exclusive_lock(&file)?;
    Ok(file)
}

fn exclusive_lock(file: &File) -> Result<()> {
    // SAFETY: flock only operates on this owned live descriptor. Nonblocking
    // exclusive locking avoids hanging on another daemon's lifetime lock.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::WouldBlock {
            VaultError::Busy
        } else {
            io_error("exclusive lock")(error)
        });
    }
    Ok(())
}

struct Temporary {
    directory: File,
    name: CString,
    file: File,
    armed: bool,
}
impl Temporary {
    fn new(directory: &File) -> Result<Self> {
        let directory = directory
            .try_clone()
            .map_err(io_error("clone directory handle"))?;
        for _ in 0..8 {
            let mut random_id = [0; 16];
            random(&mut random_id)?;
            let name = format!(".yubiquity-write-{:032x}", u128::from_le_bytes(random_id));
            let name = CString::new(name).unwrap();
            match open_at(
                &directory,
                &name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            ) {
                Ok(file) => {
                    return Ok(Self {
                        directory,
                        name,
                        file,
                        armed: true,
                    })
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(io_error("create private temporary file")(error)),
            }
        }
        Err(io_error("create temporary file")(io::Error::other(
            "name collisions",
        )))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Remove only the exact temporary inode we created, never a replacement.
        let matching = open_at(&self.directory, &self.name, libc::O_RDONLY, 0)
            .ok()
            .and_then(|file| file.metadata().ok())
            .zip(self.file.metadata().ok())
            .is_some_and(|(current, own)| Identity::from(&current) == Identity::from(&own));
        if matching {
            // SAFETY: verified temporary identity; live directory FD and name.
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

#[cfg(test)]
mod tests;
