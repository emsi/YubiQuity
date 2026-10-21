//! Local-only vault unlock input, never a command-line password or environment
//! variable. An inherited descriptor is available for explicit automation.
use crate::vault::{validate_passphrase, MAX_PASSPHRASE};
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;
use zeroize::Zeroizing;

pub fn read(passphrase_fd: Option<i32>, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(fd) = passphrase_fd {
        if fd < 3 {
            bail!("passphrase descriptor must be >= 3; stdin is reserved for approval commands");
        }
        // Do not leak the inherited input handle to the optional node helper.
        // SAFETY: fcntl validates the descriptor; these commands take scalar flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        // SAFETY: F_SETFD receives the descriptor just checked and scalar flags.
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error()).context("protect passphrase descriptor");
        }
        // SAFETY: fcntl validates the supplied number and returns a new owned FD;
        // the original belongs to the caller and is never closed by this function.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error()).context("duplicate passphrase descriptor");
        }
        // SAFETY: duplicate is a fresh owned descriptor, transferred exactly once.
        let file = unsafe { File::from_raw_fd(duplicate) };
        let mut secret = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE + 2));
        file.take((MAX_PASSPHRASE + 2) as u64)
            .read_to_end(&mut secret)
            .context("read passphrase descriptor")?;
        if secret.ends_with(b"\n") {
            secret.pop();
        }
        validate_passphrase(&secret)?;
        return Ok(secret);
    }
    let password = Zeroizing::new(
        rpassword::prompt_password("Vault passphrase (not the authenticator PIN): ")
            .context("read vault passphrase from terminal")?,
    );
    validate_passphrase(password.as_bytes())?;
    if confirm {
        let repeated = Zeroizing::new(
            rpassword::prompt_password("Confirm vault passphrase: ")
                .context("confirm vault passphrase")?,
        );
        if *password != *repeated {
            bail!("vault passphrases do not match");
        }
    }
    Ok(Zeroizing::new(password.as_bytes().to_vec()))
}

pub fn harden_process() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid structure and changes only this process's
    // core-dump limit; prctl's scalar arguments disable ordinary process dumps.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(std::io::Error::last_os_error()).context("disable core dumps");
    }
    // SAFETY: PR_SET_DUMPABLE accepts a scalar boolean, with no pointer arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("disable process dumping");
    }
    Ok(())
}
