//! Read-only setup report shared by the CLI and desktop. A probe attaches a
//! disposable key with no vault; it does not register credentials anywhere.
use crate::uhid::Device;
use serde::Serialize;
use std::{path::Path, process::Command};

#[derive(Serialize)]
pub struct Check {
    id: &'static str,
    title: &'static str,
    status: &'static str,
    detail: String,
}
#[derive(Serialize)]
pub struct Report {
    version: u32,
    checks: Vec<Check>,
    pub repair_device: bool,
    pub repair_firefox: bool,
    // Retained for version-1 report readers. ACL-based setup never requires it.
    pub restart_session: bool,
}
impl Report {
    fn add(
        &mut self,
        id: &'static str,
        title: &'static str,
        status: &'static str,
        detail: impl Into<String>,
    ) {
        self.checks.push(Check {
            id,
            title,
            status,
            detail: detail.into(),
        });
    }
}

fn command(program: &str, args: &[&str]) -> Result<String, String> {
    // Coreutils timeout bounds unavailable snapd/desktop services. No shell,
    // secrets, sudo, browser launch or configuration changes in diagnostics.
    let out = Command::new("/usr/bin/timeout")
        .args(["--kill-after=1s", "5s", program])
        .args(args)
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if out.stdout.len() + out.stderr.len() > 1024 * 1024 {
        return Err("Unexpectedly large diagnostic response.".into());
    }
    if !out.status.success() {
        return Err(
            if out.status.code() == Some(124) || out.status.code() == Some(137) {
                "The system service did not respond within five seconds. Try Check again.".into()
            } else {
                String::from_utf8_lossy(&out.stderr).trim().to_string()
            },
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn snap_installed(list: &str, name: &str) -> bool {
    list.lines()
        .skip(1)
        .any(|l| l.split_whitespace().next() == Some(name))
}
fn snap_connected(connections: &str) -> bool {
    connections.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.len() >= 3
            && fields[0] == "u2f-devices"
            && fields[1] == "firefox:u2f-devices"
            && fields[2] != "-"
    })
}
fn has_snap_tag(properties: &str) -> bool {
    properties
        .lines()
        .filter_map(|l| l.strip_prefix("CURRENT_TAGS="))
        .any(|tags| tags.split(':').any(|t| t == "snap_firefox_firefox"))
}

pub fn inspect(probe: bool, helper: Option<&Path>) -> Report {
    let mut report = Report {
        version: 1,
        checks: vec![],
        repair_device: false,
        repair_firefox: false,
        restart_session: false,
    };
    let access = Device::preflight();
    // Test real access, including ACLs. Saved or stale group membership must
    // neither imply access nor hide the action that can repair it immediately.
    report.repair_device = access.is_err();
    match access.as_ref() {
        Ok(()) => report.add(
            "uhid",
            "Security-key access",
            "ok",
            "This application can open /dev/uhid.",
        ),
        Err(e) => report.add(
            "uhid",
            "Security-key access",
            "attention",
            format!("Choose Enable access. Administrator authentication grants access in this session; no logout or reboot is needed.\n{e:#}"),
        ),
    }
    for (name, expected) in [
        (
            "72-yubiquity.rules",
            include_str!("../packaging/udev/72-yubiquity.rules"),
        ),
        (
            "69-yubiquity-firefox-snap.rules",
            include_str!("../packaging/udev/69-yubiquity-firefox-snap.rules"),
        ),
    ] {
        let mut found = false;
        for directory in [
            "/etc/udev/rules.d",
            "/run/udev/rules.d",
            "/usr/lib/udev/rules.d",
        ] {
            let path = Path::new(directory).join(name);
            // symlink_metadata also finds overrides pointing to /dev/null.
            if std::fs::symlink_metadata(&path).is_err() {
                continue;
            }
            found = true;
            match std::fs::read_to_string(&path) {
                Ok(text) if text == expected => (),
                _ => report.add("rule-override", "Local device rule", "attention", format!("{} overrides the packaged rule and differs from this build. Setup will not overwrite local rules. An administrator should review it if device or Snap checks fail.", path.display())),
            }
            break;
        }
        if !found && helper.is_none() {
            report.add("rule-missing", "Device rules", "attention", format!("{name} is missing. Install the current YubiQuity package; it includes both device rules. Source builds need the host setup in docs/host-testing.md."));
        }
    }
    let mut device = None;
    if probe && access.is_ok() {
        match Device::create(helper) {
            Ok(key) => {
                report.add("hidraw", "Browser-facing device", "ok", "A temporary key was attached and its matching hidraw device opened successfully. It will be detached when these checks finish.");
                device = Some(key);
            }
            Err(e) => {
                report.repair_device = true;
                report.add("hidraw", "Browser-facing device", "attention", format!("Could not open the new device. Choose Enable access, then check again.\n{e:#}"));
            }
        }
    } else {
        report.add("hidraw", "Browser-facing device", "unchecked", "Dynamic device access has not been tested. Enable device access and run checks with a temporary device.");
    }
    if Path::new("/usr/bin/snap").exists() {
        match command("/usr/bin/snap", &["list"]) {
            Ok(list) if snap_installed(&list, "firefox") => {
                match command("/usr/bin/snap", &["connections", "firefox"]) {
                    Ok(connections) if snap_connected(&connections) => {
                        report.add(
                            "firefox-interface",
                            "Firefox Snap connection",
                            "ok",
                            "Firefox Snap is installed and its u2f-devices interface is connected.",
                        );
                        if let Some(device) = &device {
                            match command("/usr/bin/udevadm", &["info", "--query=property", &format!("--name={}", device.path().display())]) {
                                Ok(properties) if has_snap_tag(&properties) => report.add("firefox-device", "Firefox Snap device permission", "ok", "The temporary key has Firefox's current Snap device tag. Restart Firefox after repairs and verify with a browser test."),
                                Ok(_) => {
                                    report.repair_firefox = true;
                                    report.add("firefox-device", "Firefox Snap device permission", "attention", "Firefox's Snap device tag is missing. Choose Allow Firefox Snap, then check again. If this persists, review any local rule override reported above.");
                                }
                                Err(e) => report.add("firefox-device", "Firefox Snap device permission", "unknown", e),
                            }
                        } else {
                            report.add("firefox-device", "Firefox Snap device permission", "unchecked", "The interface is connected, but device authorization cannot be checked until a temporary key can be attached.");
                        }
                    }
                    Ok(_) => {
                        report.repair_firefox = true;
                        report.add("firefox-interface", "Firefox Snap connection", "attention", "Firefox Snap is installed but its security-key interface is disconnected. Choose Allow Firefox Snap.");
                    }
                    Err(e) => {
                        report.add("firefox-interface", "Firefox Snap connection", "unknown", e)
                    }
                }
            }
            Ok(_) => report.add(
                "firefox-interface",
                "Firefox Snap",
                "info",
                "Firefox Snap is not installed. No Firefox Snap setup is needed.",
            ),
            Err(e) => report.add(
                "firefox-interface",
                "Firefox Snap detection",
                "unknown",
                format!("Could not query snapd; this does not mean Firefox is absent. {e}"),
            ),
        }
    } else {
        report.add(
            "firefox-interface",
            "Firefox Snap",
            "info",
            "Snap is not installed. No Firefox Snap setup is needed.",
        );
    }
    if Path::new("/usr/bin/flatpak").exists() {
        match command(
            "/usr/bin/flatpak",
            &["list", "--app", "--columns=application"],
        ) {
            Ok(list) => {
                let browsers: Vec<_> = list
                    .lines()
                    .filter(|l| {
                        matches!(
                            *l,
                            "org.mozilla.firefox"
                                | "org.chromium.Chromium"
                                | "com.google.Chrome"
                                | "com.brave.Browser"
                        )
                    })
                    .collect();
                if !browsers.is_empty() {
                    report.add("flatpak", "Flatpak browsers", "info", format!("Detected: {}. Their sandbox permissions are separate from host device access. Test each browser you use; this setup does not change Flatpak permissions.", browsers.join(", ")));
                }
            }
            Err(e) => report.add("flatpak", "Flatpak browser detection", "unknown", e),
        }
    }
    report.add("browser-test", "End-to-end verification", "unchecked", "Device checks do not prove that a browser can use the key. Create or open a vault, unlock it, set its security-key PIN, then register and sign in on the test site below. Choose Security key in the browser and Approve in YubiQuity.");
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snap_detection_requires_exact_package_plug_and_current_tag() {
        assert!(snap_installed("Name Version\nfirefox 154\n", "firefox"));
        assert!(!snap_installed(
            "Name Version\nfirefox-beta 154\n",
            "firefox"
        ));
        assert!(snap_connected(
            "u2f-devices firefox:u2f-devices :u2f-devices -"
        ));
        assert!(!snap_connected("u2f-devices firefox:u2f-devices - -"));
        assert!(!snap_connected(
            "u2f-devices other:u2f-devices :u2f-devices -"
        ));
        assert!(has_snap_tag("CURRENT_TAGS=:seat:snap_firefox_firefox:"));
        assert!(!has_snap_tag(
            "TAGS=:snap_firefox_firefox:\nCURRENT_TAGS=:seat:"
        ));
        assert!(!has_snap_tag("CURRENT_TAGS=:snap_firefox_firefox_fake:"));
    }
}
