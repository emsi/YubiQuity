use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use yubiquity::{
    authenticator::Authenticator,
    control, ctap, diagnostics,
    hid::{Engine, Event},
    secret_input, service,
    store::{MemoryStore, Store},
    uhid::Device,
    vault::Vault,
};

#[derive(Parser)]
#[command(version, about = "Software FIDO2 authenticator (under development)")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check this process's access and vault without asking for secrets or changing settings.
    Doctor {
        #[arg(long)]
        vault: Option<PathBuf>,
        /// Also attach and remove a temporary device to verify dynamic hidraw access.
        #[arg(long)]
        probe: bool,
        /// Explicit container-only device-node helper, used only with --probe.
        #[arg(long, requires = "probe")]
        node_helper: Option<PathBuf>,
    },
    /// Create a new encrypted vault, without overwriting any existing file.
    Init {
        #[arg(long)]
        vault: PathBuf,
        /// Explicit automation input: inherited FD >=3, never a password argument.
        #[arg(long, value_parser = clap::value_parser!(i32).range(3..))]
        passphrase_fd: Option<i32>,
    },
    /// Unlock a persistent vault and attach the security key. Always manual presence.
    Run {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(i32).range(3..))]
        passphrase_fd: Option<i32>,
        #[arg(long)]
        node_helper: Option<PathBuf>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        exit_after: Option<u64>,
    },
    /// Start a local user service, initially locked with no attached HID device.
    Serve {
        #[arg(long)]
        vault: PathBuf,
        /// Socket in an existing private 0700 directory owned by this user.
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        node_helper: Option<PathBuf>,
    },
    /// Same-user local service client: unlock, status, explicit approval and lock.
    Control {
        #[arg(long)]
        socket: PathBuf,
        #[command(subcommand)]
        action: ControlAction,
    },
    /// Unlock and list credential metadata; private keys are never printed.
    List {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(i32).range(3..))]
        passphrase_fd: Option<i32>,
        /// Include account names/display names/user handles in this explicit listing.
        #[arg(long)]
        show_users: bool,
    },
    /// Remove one exact credential from an unlocked vault (daemon must be stopped).
    Delete {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(i32).range(3..))]
        passphrase_fd: Option<i32>,
        /// Full 64-hex-character credential identifier from 'list'.
        #[arg(long)]
        credential_id: String,
        /// Confirm deletion of the selected ID in the explicitly named vault.
        #[arg(long)]
        confirm: bool,
    },
    /// Temporary in-memory credentials and PIN. No persistence.
    DevRun {
        #[arg(long)]
        node_helper: Option<PathBuf>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        exit_after: Option<u64>,
        /// Explicit automated presence for disposable development credentials only.
        #[arg(long, value_enum)]
        test_presence: Option<Presence>,
    },
    /// Attach a development device for INIT, PING and GetInfo. No credentials.
    Probe {
        /// Explicitly enable a sudo helper for this container's dynamic hidraw node.
        #[arg(long)]
        node_helper: Option<PathBuf>,
        /// Detach after this many seconds; otherwise run until Ctrl-C.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        exit_after: Option<u64>,
    },
}

#[derive(Subcommand)]
enum ControlAction {
    /// Show lock state and the current request description/token, if any.
    Status,
    /// Unlock from a no-echo terminal or explicitly inherited secret descriptor.
    Unlock {
        #[arg(long, value_parser = clap::value_parser!(i32).range(3..))]
        passphrase_fd: Option<i32>,
    },
    /// Approve exactly this pending request; this is not a blanket authorization.
    Approve { token: String },
    /// Deny exactly this pending request.
    Deny { token: String },
    /// Cancel work, detach and clear unlocked state. Service stays locked.
    Lock,
}

#[derive(Clone, Copy, ValueEnum)]
enum Presence {
    Approve,
    Deny,
}

fn main() -> Result<()> {
    let args = Args::parse();
    secret_input::harden_process()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = shutdown.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    match args.command {
        Commands::Doctor {
            vault,
            probe,
            node_helper,
        } => {
            diagnostics::doctor(vault.as_deref(), probe, node_helper.as_deref())?;
        }
        Commands::Init {
            vault,
            passphrase_fd,
        } => {
            Vault::preflight(&vault, true)?;
            eprintln!("Initializing vault {:?}; choose a strong passphrase separate from the browser PIN.", vault);
            let passphrase = secret_input::read(passphrase_fd, true)?;
            let store = Vault::create(&vault, &passphrase)?;
            drop(passphrase);
            drop(store);
            println!("Created encrypted vault {:?}", vault);
        }
        Commands::Run {
            vault,
            passphrase_fd,
            node_helper,
            exit_after,
        } => {
            Vault::preflight(&vault, false)?;
            Device::preflight()?;
            eprintln!("Unlocking vault {:?}", vault);
            let passphrase = secret_input::read(passphrase_fd, false)?;
            let store = Vault::open(&vault, &passphrase)?;
            drop(passphrase); // retain derived key only, not the unlock passphrase
            service::run(
                Authenticator::software(store, 0),
                service::Options {
                    node_helper,
                    exit_after,
                    test_presence: None,
                },
                shutdown,
            )?;
        }
        Commands::List {
            vault,
            passphrase_fd,
            show_users,
        } => {
            Vault::preflight(&vault, false)?;
            eprintln!("Reading metadata from vault {:?}", vault);
            let vault_name = serde_json::to_value(&vault)?;
            let passphrase = secret_input::read(passphrase_fd, false)?;
            let store = Vault::open(&vault, &passphrase)?;
            drop(passphrase);
            let credentials: Vec<_> = store.state().credentials.iter().map(|c| {
                let mut item = serde_json::json!({"credential_id": hex(&c.id), "rp_id": c.rp_id, "discoverable": c.discoverable, "algorithm": c.algorithm});
                if show_users {
                    item["user_handle"] = serde_json::json!(hex(&c.user.id));
                    item["name"] = serde_json::json!(c.user.name);
                    item["display_name"] = serde_json::json!(c.user.display_name);
                }
                item
            }).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"vault": vault_name, "pin_configured": store.state().pin.is_some(), "credentials": credentials})
                )?
            );
        }
        Commands::Serve {
            vault,
            socket,
            node_helper,
        } => {
            service::serve(
                &vault,
                &socket,
                service::Options {
                    node_helper,
                    exit_after: None,
                    test_presence: None,
                },
                shutdown,
            )?;
        }
        Commands::Control { socket, action } => {
            let request = match action {
                ControlAction::Status => control::Request::Status {},
                ControlAction::Unlock { passphrase_fd } => {
                    let status = control::call(&socket, &control::Request::Status {})?;
                    if !status.ok || status.state != "locked" {
                        bail!(
                            "service is not locked (state: {}); no unlock passphrase needed",
                            status.state
                        );
                    }
                    let passphrase = secret_input::read(passphrase_fd, false)?;
                    control::Request::Unlock {
                        passphrase: passphrase.to_vec(),
                    }
                }
                ControlAction::Approve { token } => control::Request::Approve { token },
                ControlAction::Deny { token } => control::Request::Deny { token },
                ControlAction::Lock => control::Request::Lock {},
            };
            let response = control::call(&socket, &request)?;
            drop(request);
            println!("{}", serde_json::to_string_pretty(&response)?);
            if !response.ok {
                bail!("control request rejected");
            }
        }
        Commands::Delete {
            vault,
            passphrase_fd,
            credential_id,
            confirm,
        } => {
            let id = credential_id_bytes(&credential_id)?;
            if !confirm {
                bail!(
                    "deletion not confirmed: vault {:?}, credential {}; repeat with --confirm",
                    vault,
                    hex(&id)
                );
            }
            Vault::preflight(&vault, false)?;
            eprintln!(
                "Deleting exactly credential {} from vault {:?}",
                hex(&id),
                vault
            );
            let passphrase = secret_input::read(passphrase_fd, false)?;
            let mut store = Vault::open(&vault, &passphrase)?;
            drop(passphrase);
            store.remove_credential(&id)?;
            println!("Deleted credential {} from vault {:?}. No supported recovery/export facility exists.", hex(&id), vault);
        }
        Commands::DevRun {
            node_helper,
            exit_after,
            test_presence,
        } => {
            eprintln!("EPHEMERAL DEVELOPMENT MODE: credentials, PIN and retries are lost on exit. Use 'run --vault PATH' for persistent operation.");
            if test_presence.is_some() {
                eprintln!("WARNING: explicit test presence backend enabled; no real user presence is proved.");
            }
            let test_presence = test_presence.map(|p| match p {
                Presence::Approve => service::TestPresence::Approve,
                Presence::Deny => service::TestPresence::Deny,
            });
            service::run(
                Authenticator::software(MemoryStore::default(), 0),
                service::Options {
                    node_helper,
                    exit_after,
                    test_presence,
                },
                shutdown,
            )?;
        }
        Commands::Probe {
            node_helper,
            exit_after,
        } => {
            let mut device = Device::create(node_helper.as_deref())?;
            eprintln!(
                "Transport probe only: this mode does not provide credentials, PIN or storage."
            );
            println!("READY {} {}", device.path().display(), device.unique());
            let mut engine = Engine::default();
            let clock = Instant::now();
            while !shutdown.load(Ordering::Relaxed) {
                if exit_after.is_some_and(|seconds| clock.elapsed() >= Duration::from_secs(seconds))
                {
                    break;
                }
                let report = device.read_report(Duration::from_millis(25))?;
                let now = clock.elapsed().as_millis() as u64;
                let events = if let Some(report) = report {
                    engine.receive(report, now)
                } else {
                    engine.tick(now)
                };
                let mut events: VecDeque<_> = events.into();
                while let Some(event) = events.pop_front() {
                    match event {
                        Event::Send(report) => device.send_report(&report)?,
                        Event::Request {
                            transaction,
                            payload,
                        } => {
                            let result = ctap::transport_probe(&payload);
                            events.extend(engine.complete(transaction, &result));
                        }
                        Event::Abort(_) | Event::Resynchronize(_) => {} // the probe has no asynchronous operations
                    }
                }
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn credential_id_bytes(value: &str) -> Result<Vec<u8>> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("credential ID must be exactly 64 hexadecimal characters (no prefix matching)");
    }
    (0..64)
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(Into::into))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_cli_cannot_select_scripted_presence_or_stdin_passphrases() {
        assert!(Args::try_parse_from([
            "yubiquity",
            "serve",
            "--vault",
            "test.yq",
            "--socket",
            "control.sock",
            "--test-presence",
            "approve",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "yubiquity",
            "control",
            "--socket",
            "control.sock",
            "unlock",
            "--passphrase",
            "secret",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "yubiquity",
            "control",
            "--socket",
            "control.sock",
            "unlock",
            "--passphrase-fd",
            "0",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "yubiquity",
            "run",
            "--vault",
            "test.yq",
            "--test-presence",
            "approve"
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "yubiquity",
            "run",
            "--vault",
            "test.yq",
            "--passphrase-fd",
            "0"
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "yubiquity",
            "run",
            "--vault",
            "test.yq",
            "--passphrase",
            "secret"
        ])
        .is_err());
    }

    #[test]
    fn deletion_identifier_is_full_hex_without_prefix_matching() {
        assert_eq!(
            credential_id_bytes(&"AB".repeat(32)).unwrap(),
            vec![0xab; 32]
        );
        for value in [
            "ab".repeat(31),
            "ab".repeat(33),
            "xx".repeat(32),
            "é".repeat(32),
        ] {
            assert!(credential_id_bytes(&value).is_err());
        }
    }
}
