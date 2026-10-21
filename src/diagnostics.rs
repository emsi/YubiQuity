//! Explicit local checks. No permission changes, secret prompts or browser edits.
use crate::{device_access, uhid::Device, vault::Vault};
use anyhow::{bail, Result};
use std::path::Path;

const RULE: &str = include_str!("../packaging/udev/72-yubiquity.rules");

pub fn doctor(vault: Option<&Path>, probe: bool, helper: Option<&Path>) -> Result<()> {
    println!(
        "YubiQuity {} — local readiness checks",
        env!("CARGO_PKG_VERSION")
    );
    println!("Executable: {}", std::env::current_exe()?.display());
    println!("Process: {}", device_access::process_identity());
    println!(
        "Device access mode: {}",
        if helper.is_some() {
            "explicit node helper"
        } else {
            "native (no helper)"
        }
    );
    println!("These checks apply to this process, not an already-running browser or systemd user manager.");
    let mut failures = 0;
    let access = Device::preflight();
    let can_probe = access.is_ok();
    report(
        "/dev/uhid read/write access (no device created)",
        access,
        &mut failures,
    );
    if helper.is_none() {
        let mut found = false;
        for path in [
            "/etc/udev/rules.d/72-yubiquity.rules",
            "/run/udev/rules.d/72-yubiquity.rules",
            "/usr/lib/udev/rules.d/72-yubiquity.rules",
        ] {
            match std::fs::read_to_string(path) {
                Ok(installed) => {
                    found = true;
                    if installed == RULE {
                        println!("OK   {path} matches this build (rule application still requires a probe)");
                    } else {
                        println!("WARN {path} differs from this build; review the rule before replacing it");
                    }
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => {
                    found = true;
                    println!("WARN cannot inspect {path}: {error}");
                    break;
                }
            }
        }
        if !found {
            println!("WARN scoped 72-yubiquity.rules not found; see docs/host-testing.md for one-time setup");
        }
    }
    if let Some(path) = vault {
        println!("Vault: {}", path.display());
        report(
            "existing vault path, public envelope and writer availability (not decrypted)",
            Vault::preflight(path, false).map_err(Into::into),
            &mut failures,
        );
    }
    if probe && can_probe {
        println!("Checking temporary UHID attachment and actual hidraw access; no credentials are loaded.");
        report(
            "temporary device ready and detached",
            Device::create(helper).map(drop),
            &mut failures,
        );
    } else if !probe {
        println!("NOTE dynamic hidraw permissions are not checked without --probe.");
    }
    if failures != 0 {
        bail!("{failures} readiness check(s) failed; no settings or vault contents were changed");
    }
    println!("Checks passed. No browser compatibility or decryption claim is made by doctor.");
    Ok(())
}

fn report(label: &str, result: Result<()>, failures: &mut usize) {
    match result {
        Ok(()) => println!("OK   {label}"),
        Err(error) => {
            *failures += 1;
            println!("FAIL {label}: {error:#}");
        }
    }
}
