//! Device readiness is separate from device existence: udev changes permissions
//! after devtmpfs has published a node. Never repair permissions in the daemon.
use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_millis(20);
pub(crate) const READY_TIMEOUT: Duration = Duration::from_secs(2);

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options
}

pub(crate) fn open_uhid() -> Result<File> {
    // Opening UHID alone does not create a device; CREATE2 does that later.
    options().open("/dev/uhid").with_context(|| {
        format!(
            "cannot open /dev/uhid\n{}\nLoad the uhid module and install the scoped host access rule; run as your normal user, not sudo. See docs/host-testing.md.",
            describe(Path::new("/dev/uhid")),
        )
    })
}

pub(crate) fn process_identity() -> String {
    fs::read_to_string("/proc/self/status")
        .map(|status| {
            status
                .lines()
                .filter(|line| {
                    line.starts_with("Uid:")
                        || line.starts_with("Gid:")
                        || line.starts_with("Groups:")
                })
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_else(|error| format!("process credentials unavailable: {error}"))
}

pub(crate) fn describe(path: &Path) -> String {
    let node = match fs::symlink_metadata(path) {
        Ok(meta) => format!(
            "{}: mode {:04o}, uid {}, gid {}, character device {}, device {}:{}",
            path.display(),
            meta.mode() & 0o7777,
            meta.uid(),
            meta.gid(),
            meta.file_type().is_char_device(),
            libc::major(meta.rdev()),
            libc::minor(meta.rdev()),
        ),
        Err(error) => format!("{}: {error}", path.display()),
    };
    format!("{node}\nProcess: {}", process_identity())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn sysfs_device(sysfs: &Path, unique: &str) -> io::Result<u64> {
    let properties = fs::read_to_string(sysfs.join("device/uevent"))?;
    if !properties
        .lines()
        .any(|line| line.strip_prefix("HID_UNIQ=") == Some(unique))
        || !properties
            .lines()
            .any(|line| line.strip_prefix("HID_NAME=") == Some(crate::uhid::NAME))
    {
        return Err(invalid("hidraw identity changed; refusing another device"));
    }
    let numbers = fs::read_to_string(sysfs.join("dev"))?;
    let (major, minor) = numbers
        .trim()
        .split_once(':')
        .ok_or_else(|| invalid("invalid sysfs device numbers"))?;
    let major: u32 = major.parse().map_err(|_| invalid("invalid sysfs major"))?;
    let minor: u32 = minor.parse().map_err(|_| invalid("invalid sysfs minor"))?;
    Ok(libc::makedev(major, minor))
}

fn open_exact(node: &Path, sysfs: &Path, unique: &str) -> io::Result<File> {
    let expected = sysfs_device(sysfs, unique)?;
    let before = fs::symlink_metadata(node)?;
    if !before.file_type().is_char_device() || before.rdev() != expected {
        return Err(invalid(
            "hidraw path is not the expected character device (or is a symlink)",
        ));
    }
    let file = options().open(node)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_char_device()
        || opened.rdev() != expected
        || (opened.dev(), opened.ino()) != (before.dev(), before.ino())
        || sysfs_device(sysfs, unique)? != expected
    {
        return Err(invalid(
            "hidraw device changed while opening; refusing replacement",
        ));
    }
    Ok(file)
}

// Clock and wait are injectable so the permission race and time bounds can be
// tested deterministically without root, a shared kernel device, or real sleeps.
fn retry<T>(
    timeout: Duration,
    mut attempt: impl FnMut() -> io::Result<T>,
    mut elapsed: impl FnMut() -> Duration,
    mut wait: impl FnMut(Duration),
) -> io::Result<T> {
    loop {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(error) => {
                if !matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::PermissionDenied
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                ) {
                    return Err(error);
                }
                let remaining = timeout.saturating_sub(elapsed());
                if remaining.is_zero() {
                    return Err(error);
                }
                wait(INTERVAL.min(remaining));
            }
        }
    }
}

pub(crate) fn wait_hidraw(node: &Path, sysfs: &Path, unique: &str, helper: bool) -> Result<()> {
    let start = Instant::now();
    retry(READY_TIMEOUT, || open_exact(node, sysfs, unique), || start.elapsed(), std::thread::sleep)
        .with_context(|| {
            let advice = if helper {
                "The explicitly selected node helper did not provide an accessible matching device; check its output and device-cgroup access."
            } else {
                "Native device access failed. Check the installed 72-yubiquity.rules and this process's groups. No node helper was selected. Do not chmod all hidraw devices or run the daemon as root."
            };
            format!("hidraw readiness failed after {} ms\n{}\n{advice}\nThe temporary device will now detach; the vault is unchanged.", start.elapsed().as_millis(), describe(node))
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

    #[test]
    fn delayed_creation_and_permissions_are_retried() {
        let elapsed = Cell::new(Duration::ZERO);
        let mut attempts = 0;
        let result = retry(
            Duration::from_secs(1),
            || {
                attempts += 1;
                match attempts {
                    1 => Err(io::Error::from_raw_os_error(libc::ENOENT)),
                    2 | 3 => Err(io::Error::from_raw_os_error(libc::EACCES)),
                    _ => Ok(42),
                }
            },
            || elapsed.get(),
            |duration| elapsed.set(elapsed.get() + duration),
        );
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 4);
        assert_eq!(elapsed.get(), INTERVAL * 3);
    }

    #[test]
    fn permanent_missing_or_denied_nodes_have_a_bounded_wait() {
        for errno in [libc::ENOENT, libc::EACCES, libc::EPERM] {
            let elapsed = Cell::new(Duration::ZERO);
            let result = retry::<()>(
                Duration::from_millis(55),
                || Err(io::Error::from_raw_os_error(errno)),
                || elapsed.get(),
                |duration| elapsed.set(elapsed.get() + duration),
            );
            assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
            assert_eq!(elapsed.get(), Duration::from_millis(55));
        }
    }

    #[test]
    fn unexpected_errors_do_not_wait() {
        for errno in [libc::ELOOP, libc::ENODEV, libc::EINVAL] {
            let result = retry::<()>(
                READY_TIMEOUT,
                || Err(io::Error::from_raw_os_error(errno)),
                || Duration::ZERO,
                |_| panic!("permanent error was retried"),
            );
            assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
        }
    }

    #[test]
    fn exact_device_validation_rejects_symlinks_regular_files_and_wrong_identity() {
        let temp = tempfile::tempdir().unwrap();
        let sysfs = temp.path().join("sysfs");
        fs::create_dir_all(sysfs.join("device")).unwrap();
        fs::write(sysfs.join("dev"), "1:3\n").unwrap();
        fs::write(
            sysfs.join("device/uevent"),
            format!("HID_NAME={}\nHID_UNIQ=test-instance\n", crate::uhid::NAME),
        )
        .unwrap();
        // Existing harmless character device; no mknod/UHID/host access required.
        assert!(open_exact(Path::new("/dev/null"), &sysfs, "test-instance").is_ok());
        let node = temp.path().join("node");
        fs::write(&node, "").unwrap();
        assert!(open_exact(&node, &sysfs, "test-instance").is_err());
        let link = temp.path().join("link");
        symlink("/dev/null", &link).unwrap();
        assert!(open_exact(&link, &sysfs, "test-instance").is_err());
        assert!(open_exact(Path::new("/dev/null"), &sysfs, "another-instance").is_err());
        fs::write(sysfs.join("dev"), "1:5\n").unwrap();
        assert!(open_exact(Path::new("/dev/null"), &sysfs, "test-instance").is_err());
    }
}
