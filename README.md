# YubiQuity

A software-backed FIDO2 authenticator for Linux, intended to work through the
normal external security-key path in unmodified Firefox and Chromium browsers.
It is a testing tool, not hardware-backed key protection or a manufacturer-attested
YubiKey. See the [full plan](firefox-virtual-fido2-plan.md) and
[implementation ledger](docs/implementation-status.md).

For a hands-on test with your own browser, follow the
[end-to-end Linux host walkthrough](docs/host-testing.md). It covers host device
permissions, a private test vault, PIN setup, both public demo sites, persistence,
and Firefox/Chrome credential reuse without browser modifications.

**Using Ubuntu's Firefox Snap?** Follow the additional
[Snap device-access requirements](docs/host-testing.md#ubuntu-firefox-installed-as-a-snap):
the connected `u2f-devices` interface alone may not authorize a virtual UHID key.
The guide includes the scoped host rule, verification, and browser restart step.

Already have a vault? Use `yubiquity run --vault PATH`; it checks basic
prerequisites before asking for your passphrase and waits for native hidraw
permissions. `yubiquity doctor --vault PATH` diagnoses without secrets or setting
changes; `doctor --probe` explicitly adds a temporary device-access check.
For a new vault, `yubiquity init --run --vault PATH` creates and attaches in one
flow, with no extra unlock prompt after choosing and confirming the passphrase.

## Current status

The development authenticator creates independent ES256 credentials, supports
allow-list and discoverable login, multiple accounts, terminal approval, and
ClientPIN protocol 1. Firefox 158.0.1 registration and login have passed through
real UHID/hidraw, including a discoverable credential with user verification
required and the browser's normal PIN dialog. Signatures are independently
verified by the local test RP and Python FIDO client.

Persistent operation now uses an encrypted Argon2id/XChaCha20-Poly1305 vault,
exclusive locking and atomic writes. Firefox has reused a saved passkey after a
daemon crash/restart and a fresh browser profile, with PIN verification required.
`init`, `run`, `list`, and exact-ID `delete` commands are implemented.

The optional local service starts locked. Its same-user control client can unlock,
inspect a pending request, explicitly approve/deny it, or lock/detach again.

The planned baseline is implemented and validated for the recorded container
and browser builds. After recreation with the supplied seccomp profile, Chrome for Testing 155.0.8059.84
passes registration/login, required-PIN discoverable credentials, two-account
selection, encrypted-vault crash recovery, the locked-service path and the full
local negative/recovery suite. Firefox/Chrome credential reuse
passes in both directions with and without required UV. Chrome reports active
namespace and seccomp-BPF sandboxes; no added container capabilities or AppArmor
relaxation was needed. See the [test report](docs/test-report.md#chrome-container-validation-2026-10-21).

Approved public-site smoke tests also pass in Firefox and Chrome: webauthn.io
accepts required-PIN resident registration, username login and username-less login;
Yubico's technical demo accepts registration and authentication.

Agent host access remains excluded. The user reported working webauthn.io
registration on Ubuntu 24.04 with Firefox Snap 154.0 after adding the scoped
device authorization; see the [manual host result](docs/test-report.md#snap-firefox-manual-host-smoke-test-2026-10-22).
This is not the full automated browser matrix: other distribution/confined
packages and actual host systemd execution remain unverified. This is still
a software testing tool for disposable accounts, not a universally compatible,
certified or hardware-protected authenticator.

The separate `probe` command deliberately provides only transport and GetInfo,
without advertising credentials or PIN. No mode advertises built-in biometric UV
or trusted manufacturer attestation.

## Build and check

### Desktop interface (new, device validation pending)

The optional Qt 6 desktop application replaces typed approval tokens with a
native **Approve / Cancel** dialog showing the operation, site (RP ID), and
available account. Browser security-key PIN prompts remain unchanged. Vault
passphrases use `pinentry-qt`; they are not stored in settings or passed in
command-line arguments. Settings remember only the selected vault path.

```bash
# Ubuntu 24.04 / compatible Debian systems, inside the environment being built:
sudo apt-get install cmake qt6-base-dev qt6-base-dev-tools qt6-qpa-plugins qt6-wayland pinentry-qt
cargo build --release --locked
cmake -S desktop -B target/desktop -DCMAKE_BUILD_TYPE=Release
cmake --build target/desktop -j2
target/desktop/yubiquity-desktop --backend "$PWD/target/release/yubiquity" \
    --vault "$HOME/.local/share/yubiquity/host-test/credentials.yq"
```

Stop any existing foreground daemon using that vault first. Launch as your normal
desktop user, never with `sudo`. The app owns a locked service, offers Unlock,
and attaches the key only after unlock. Open/create another vault from the main
window. Closing the main window keeps it in the tray when a tray is available;
**Lock and quit** always exits. Without a tray, closing locks and exits. No
autostart or password caching is enabled. Device permissions and Firefox Snap
requirements in the host guide still apply; the GUI does not change them.

The request token remains internal. Cancel/Escape/window close denies that exact
request; expiry, browser cancellation and disconnect remove the dialog. Enter
defaults to Cancel. A lost desktop watch connection locks the service, and owned
child processes die with the app. Screen-lock signals from supported KDE/GNOME
interfaces and login1 sleep notifications trigger locking; unavailable monitoring
is reported. Actual KDE/Wayland focus, tray and suspend behavior still need host
validation. No claim of universal session-lock coverage is made.

For an existing `serve` instance, use `--socket /absolute/private/control.sock`
instead of `--vault`. Only one desktop watcher is allowed. Advanced container
tests may explicitly pass `--node-helper scripts/container-hidraw.py`; native
hosts must not need that option. The Rust `control watch` command provides
bounded version-1 JSON snapshots; this is the desktop bridge, not a key-export API.

Offline GUI tests exercise real Qt widgets, the Rust socket client, exact-token
decisions, cancellation/disconnect, deadlines and encrypted-vault FD input:

```bash
cargo build --locked
YUBIQUITY_TEST_BACKEND="$PWD/target/debug/yubiquity" \
    ctest --test-dir target/desktop --output-on-failure
# Actual secret-prompt windows and app lifecycle, on a private test display:
# requires xvfb, xdotool, python3-pil and dbus-daemon
/usr/bin/python3 tests/desktop_native.py
```

These checks do not yet establish real UHID/browser GUI interoperability. The
container currently needs its normal user's `/dev/uhid` access restored before
that acceptance gate. Same-user/root compromise can bypass or spoof a software
approval UI. Qt input/IPC can make transient secret copies: best-effort clearing
and disabled core dumps are not hardware isolation or a locked-memory guarantee.

### Core command-line build

```bash
bash scripts/install-dev-tools.sh
cargo build --locked
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

Rust 1.99.1 is pinned in `rust-toolchain.toml`; dependencies are in `Cargo.lock`.
Protocol unit tests require no kernel device or elevated privileges.

### CI, dependency audit and parser fuzzing

The [CI workflow](.github/workflows/checks.yml) runs formatting, lint, unit tests,
the independent RP/vault verifiers, both dependency audits, and bounded ASan
fuzz campaigns. It does **not** silently treat missing UHID/browser permissions
as a passed interoperability test. Real-device/browser commands below remain
separate release gates. The workflow is checked in; a hosted CI run is not yet
recorded for this repository.

```bash
cargo install cargo-audit --version 0.22.2 --locked
cargo audit
cargo audit --file fuzz/Cargo.lock
rustup toolchain install nightly-2026-10-19 --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
/usr/bin/python3 scripts/fuzz.py --seconds 120
```

Fuzzing uses a separate pinned nightly compiler; normal builds still use stable
1.99.1. See the [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html).
The four targets cover CBOR parsing/canonicalization, stateful CTAPHID framing
and recovery, CTAP/PIN command parsing with disposable resident credentials,
and bounded local-control JSON request parsing.
The HID target also checks that cancelled/resynchronized/completed transaction
IDs cannot accept late results. Each target uses ASan, overflow/debug assertions,
bounded input length, a five-second per-input timeout and a 1-GiB RSS limit.
No device, root access, browser, network listener, or real secret is used by the
targets. Source seeds are in `scripts/fuzz.py`; generated corpora are retained
under `target/fuzz-corpus/`, and logs/reproducers under `target/fuzz-results/`.
Use `--target cbor|hid|ctap|control` to select one, or a longer `--seconds` for a campaign.
Short clean runs and an advisory-free lockfile are checks, not proof of security.

## Run with an encrypted vault

Use a dedicated private directory. `init` can create its immediate parent with
mode `0700`; it never overwrites an existing vault. All higher parents must already
exist, be root- or user-owned, and not be symlinks. User-owned group-writable
ancestors such as `0775` `~/.local/share` are allowed; world-writable ancestors
are rejected except root-owned sticky directories such as `/tmp`. See the
[vault path policy and group-trust tradeoff](docs/vault.md#filesystem-safety-and-writes).

```bash
cargo build --release --locked
target/release/yubiquity init --vault ./test-vault/credentials.yq
target/release/yubiquity run --vault ./test-vault/credentials.yq --node-helper scripts/container-hidraw.py
```

The vault passphrase is read from the terminal without echo, before device
attachment. It is separate from the browser's security-key PIN. Persistent `run`
always uses explicit terminal approval: type `approve TOKEN` or `deny TOKEN` for
the displayed request. Type `lock` or `quit`, or press Ctrl-C, to detach and release
the vault. Restart with `run` to unlock it again. There is no automatic approval
switch for persistent operation.

Before testing PIN-required passkeys, configure the authenticator PIN once while
the vault is unlocked and attached. In another terminal, substitute the exact
current hidraw path reported for this YubiQuity device (not a physical key):

```bash
fido2-token -S /dev/hidrawN
# Later, to change an existing PIN:
fido2-token -C /dev/hidrawN
```

These commands prompt for the PIN; do not put it in arguments. The PIN is separate
from the vault passphrase and persists in the encrypted vault. See the
[libfido2 command reference](https://developers.yubico.com/libfido2/Manuals/fido2-token.html).

Stop the daemon before listing or deleting credentials; all commands take the
same exclusive vault lock. Metadata is JSON, with account names hidden by default.

```bash
target/release/yubiquity list --vault ./test-vault/credentials.yq
target/release/yubiquity list --vault ./test-vault/credentials.yq --show-users
# Substitute one full 64-character hex ID from the listing; deletion is permanent:
target/release/yubiquity delete --vault ./test-vault/credentials.yq --credential-id FULL_HEX_ID --confirm
```

Explicit automation may supply a passphrase through an inherited descriptor
`--passphrase-fd N` (N >= 3). No password argument, environment variable, or plaintext
passphrase-file option is provided. See [vault format and operation](docs/vault.md)
for filesystem requirements, retry durability, failure behavior and limitations.

## Optional local service and approval client

Foreground `run` remains available unchanged. `serve` instead starts **locked**:
no device is attached until an explicit unlock succeeds. Its control endpoint is
a filesystem Unix socket, not a TCP listener. The parent must already be owned by
you with mode `0700`; the socket is mode `0600`, with same-UID peer checks on both
ends and a separate lifetime lock. Symlinks/unsafe ancestors are rejected. Unlike
vault paths, control socket paths retain the stricter ancestor policy: no
group/world-write access except in root-owned sticky directories such as `/tmp`.

For a direct development run (two terminals), use private temporary runtime state:

```bash
yubiquity_runtime=$(mktemp -d /tmp/yubiquity-runtime.XXXXXXXX)
target/debug/yubiquity serve --vault ./test-vault/credentials.yq \
  --socket "$yubiquity_runtime/control.sock" --node-helper scripts/container-hidraw.py
```

In the other terminal, substitute the exact socket path above:

```bash
yubiquity_socket=/tmp/yubiquity-runtime.REPLACE/control.sock
target/debug/yubiquity control --socket "$yubiquity_socket" unlock
target/debug/yubiquity control --socket "$yubiquity_socket" status
target/debug/yubiquity control --socket "$yubiquity_socket" approve REQUEST_TOKEN
# Or: ... deny REQUEST_TOKEN
target/debug/yubiquity control --socket "$yubiquity_socket" lock
```

`unlock` prompts without echo; explicit automation may supply `--passphrase-fd`
(>=3), never a password argument/environment variable. `status` intentionally
shows the pending RP/account description and one-request token; it never returns
private keys, PINs, PIN tokens or the vault passphrase. JSON escapes untrusted
display text. Approvals acknowledge acceptance of that decision, not successful
completion of a browser ceremony. An unmatched, expired or cancelled token fails.
`lock` acknowledges only after detach and worker cleanup, releases the vault
writer lock, and invalidates PIN tokens; the service stays running but locked.

Service clients are one-shot commands. **Disconnecting a client does not lock the
service**: explicitly lock it or stop the service when finished. No client/no
approval means presence requests time out; there is no persistent auto-approval
mode. A crash/restart always starts locked and requires a new unlock. Stale owned
sockets are recovered under the lifetime lock; unrelated files/live sockets are
not removed. Approval descriptions/tokens are not printed in service logs.

The wire format is internal: one big-endian four-byte length plus a JSON request
or response, up to 8192 bytes, one request per connection. At most eight clients
are retained, with a five-second lifetime. Nonblocking I/O keeps slow/malformed
clients out of the HID loop. A control timeout can leave an operation's result
unknown: query status rather than assuming unlock/lock failed. Any process with
your UID can request approval/unlock operations; this is **not** protection from
a compromised local account or root. Passphrase buffers are cleared where
practical, not a claim that every library/kernel copy can be erased.

### User-unit installation (normal Linux host)

First arrange the scoped host permissions in [device setup](docs/container-uhid.md).
The service uses no sudo helper and `NoNewPrivileges=yes`; the development
container helper is not suitable for this unit. Initialize the intended vault
interactively, and review existing destination files before replacing an older
installation:

```bash
cargo build --release --locked
install -d -m 0700 "$HOME/.local/bin" "$HOME/.config/systemd/user"
install -m 0755 target/release/yubiquity "$HOME/.local/bin/yubiquity"
install -d -m 0700 "$HOME/.local/share/yubiquity/vault"
"$HOME/.local/bin/yubiquity" init --vault "$HOME/.local/share/yubiquity/vault/credentials.yq"
install -m 0644 packaging/systemd/yubiquity.service "$HOME/.config/systemd/user/yubiquity.service"
systemctl --user daemon-reload
systemctl --user enable --now yubiquity.service
"$HOME/.local/bin/yubiquity" control --socket "$XDG_RUNTIME_DIR/yubiquity/control.sock" unlock
```

Use the same socket for `status`, `approve TOKEN`, `deny TOKEN`, and `lock`.
`systemctl --user stop yubiquity` detaches and clears unlocked state;
`systemctl --user disable --now yubiquity` also disables future automatic startup.
Enabling starts only the **locked** service, not an unlocked authenticator.
No passphrase file or systemd credential is installed. Runtime directory creation
and cleanup belong to the user manager. Actual systemd-user execution is still
unverified in this container, where systemd is not running; direct `serve` is
covered by real-device tests. See [test report](docs/test-report.md).

## Run the temporary authenticator

```bash
cargo run --locked -- dev-run --node-helper scripts/container-hidraw.py
```

Omit `--node-helper` on a host with appropriate device-access rules. The daemon
prints `APPROVAL <token> ...` for each request needing presence. Type
`approve <token>` or `deny <token>` for that exact request; old tokens are ignored.
`lock`, `quit`, or Ctrl-C cancels work and detaches. In this temporary mode,
detaching also discards all credentials and the PIN. Do not enroll real accounts.

For automated disposable tests only, `--test-presence approve` explicitly bypasses
manual approval. It does not prove actual user presence and is never an implicit
default. The persistent `run` command does not expose this switch.

## Run the transport probe

On a Linux desktop with device access already configured:

```bash
cargo run --locked -- probe
```

In this development container:

```bash
cargo run --locked -- probe --node-helper scripts/container-hidraw.py
```

The daemon runs as your normal user. The explicit `--node-helper` option invokes
`sudo -n` only for a narrowly scoped development helper. It matches this daemon's
random device identity, creates its hidraw node if absent, assigns it to the
calling user, and removes only its own node when the daemon exits or crashes.
It never changes permissions of pre-existing nodes. This helper assumes a trusted
development user with sudo; it is not a privilege-separation boundary for untrusted
users and must not be installed setuid.

The probe prints `READY /dev/hidrawN ...`. In another terminal:

```bash
fido2-token -L
# Use the exact path printed by the probe:
fido2-token -I /dev/hidrawN
```

Ctrl-C detaches; `--exit-after 10` is available for timed tests. No credential or
vault files are created by the probe. Host/container permissions and the hidraw
cgroup rule are described in [container setup](docs/container-uhid.md).

## Independent real-device tests

```bash
cargo build --locked
/usr/bin/python3 -m unittest discover -s tests -p '*integration.py' -v
/usr/bin/python3 tests/vault_crypto.py
/usr/bin/python3 tests/packaging.py
```

These tests need Ubuntu's `python3-fido2`, `fido2-tools`, `/dev/uhid`, hidraw cgroup
access and passwordless sudo for the development helper. They attach temporary
devices, check independent client discovery and protocol responses, and verify
normal/crash cleanup. They do not use browser virtual-authenticator APIs or modify
browser security settings.

The vault crypto check uses independent Argon2 and libsodium Python bindings.
Each storage test owns a private temporary vault, and failure tests include real
OS write failures. Test daemons are serialized across runners in this workspace
because browser discovery can otherwise select another test's FIDO device.

`tests/packaging.py` is an offline check using systemd/udev 255 on Ubuntu 24.04.
It verifies the exact user-unit contents with strict warning handling and checks
that an intentionally invalid directive fails. If `~/.local/bin/yubiquity` is
absent, it creates a temporary link to the debug build and removes only that
link afterward; existing executables are not replaced. It uses a private runtime
directory, does not start/enable a service, and never installs or applies udev
rules. Actual host permissions and systemd runtime behavior remain separate gates.

## Browser tests

```bash
/usr/bin/python3 tests/browser/test_rp.py
/usr/bin/python3 tests/browser/test_ui.py
/usr/bin/python3 tests/browser/test_public_sites.py
/usr/bin/python3 tests/browser/ceremonies.py --browser firefox
/usr/bin/python3 tests/browser/ceremonies.py --browser firefox --pin-test
/usr/bin/python3 tests/browser/ceremonies.py --browser firefox --pin-test --attach-after-start
/usr/bin/python3 tests/browser/persistence.py --browser firefox
/usr/bin/python3 tests/browser/service.py
/usr/bin/python3 tests/browser/accounts.py
/usr/bin/python3 tests/browser/negative.py --browser firefox
# Verified cross-browser and Chrome scenarios in the recreated container:
/usr/bin/python3 tests/browser/ceremonies.py --browser both
/usr/bin/python3 tests/browser/ceremonies.py --browser both --pin-test
/usr/bin/python3 tests/browser/ceremonies.py --browser chrome --pin-test --attach-after-start
/usr/bin/python3 tests/browser/accounts.py --browser chrome
/usr/bin/python3 tests/browser/persistence.py --browser chrome
/usr/bin/python3 tests/browser/service.py --browser chrome
/usr/bin/python3 tests/browser/negative.py --browser chrome
```

The test fixture binds only to localhost. It checks one-use challenges, exact
origin, RP hash, presence/verification flags, signatures, credential IDs and user
handles. Tests use real WebAuthn and real hidraw, with no browser-internal virtual
authenticator. The ceremony tests explicitly use scripted presence and disposable
in-memory state. The persistence test instead drives the normal terminal approval
path with a disposable encrypted vault, kills the daemon, then verifies login
through new daemon/browser instances against the same RP registration.
`service.py` exercises the locked service with explicit CLI approvals, locks and
re-unlocks it, then verifies saved-credential login in a fresh Firefox or Chrome profile.
`negative.py` checks cancelled/denied registration and login, stale approvals,
excluded and unknown credentials, browser RP rejection, wrong-PIN recovery,
and lock/detach during pending login followed by reattachment/recovery in the
same browser session. It distinguishes a browser error
from an RP rejection so an unrelated failure cannot satisfy an expected result.
Its strict RP requests direct attestation and explicitly rejects the device's
`none` result. This is a negative policy fixture, not a manufacturer trust store.
The full negative suite passes in both Firefox and Chrome. Chrome shows native
retry/error sheets for denial, exclusion and an unknown credential; the harness
recognizes the specific failure before clicking Cancel/Close and checking the
browser's rejection. It never cancels an ordinary presence/PIN sheet just to
manufacture the expected error. The denial/exclusion checks also verify unchanged
vault contents and rejected stale approval tokens.

For another stock installation, set `YUBIQUITY_FIREFOX_BINARY` or
`YUBIQUITY_CHROME_BINARY` to its executable path. Matching driver paths can be
selected with `YUBIQUITY_FIREFOX_DRIVER` or `YUBIQUITY_CHROME_DRIVER`. These options
apply to all browser harnesses and are recorded alongside the browser version;
they select executables, not authenticator modes, browser preferences or flags.
They do not bypass package confinement or make an unsupported launcher work.

The optional ESR setup downloads exactly Mozilla's Linux x86-64 en-US archive,
checks its SHA-256 against the release's `SHA256SUMS`, and leaves stable untouched:

```bash
bash scripts/install-firefox-esr.sh 153.5.1esr
YUBIQUITY_FIREFOX_BINARY="$HOME/.local/share/yubiquity/browsers/firefox-153.5.1esr/firefox" \
  /usr/bin/python3 tests/browser/ceremonies.py --browser firefox --pin-test
```

Use the same environment override for the account, negative, persistence and
service scenarios. The script does not change the default Firefox symlink or
your browser profiles. The selected release is pinned for replay; it is not a
promise that this version remains current indefinitely.

`--pin-test` configures the public test PIN `1234` using an independent FIDO client,
then exercises the browser's real PIN-entry flow. It starts a separate Xvfb display
and types only after detecting the PIN dialog. WebDriver can identify Firefox's
password dialog but cannot fill it; `xdotool` supplies keyboard input on that
test-owned display. No input is sent to your desktop. `--headed` also uses an
isolated display; its `/tmp/.X11-unix` directory needs normal writable/sticky
permissions (conventionally root-owned `1777`).

Chrome's native Views PIN/account dialogs are not WebDriver JavaScript alerts.
The Chrome 155 adapter recognizes their text using Tesseract English OCR on the
isolated display, types the public test PIN and uses ordinary mouse clicks for
account selection/Continue. It recognizes the expected account before clicking;
the RP independently verifies the resulting identity, signature and UV. Unknown
UI versions fail explicitly. This is test automation, not an authenticator mode
or a security boundary. Each Chrome session records `chrome://sandbox` and requires
namespace, PID/network and seccomp-BPF/TSYNC layers to report active.

`accounts.py` registers two residents at one RP, checks each allow list, then
selects each account from Firefox's ordinary popup using native keyboard/mouse UI.
The RP must verify the selected user handle, credential ID and UV flag. This
UI automation does not change authenticator behavior. `--browser chrome` selects
the separately verified native Chrome chooser. The Firefox menu click
coordinates match the inspected en-US Firefox 158 stable and 153 ESR layouts on
the isolated display; unknown versions fail explicitly rather than guessing.
A different layout may need a harness update. Screenshots retain that evidence.

### Opt-in public-site smoke tests

This command **creates public registrations** on the two named demo services.
Run only after authorizing those writes; it is never run by CI:

```bash
/usr/bin/python3 tests/browser/public_sites.py --allow-public-registration --browser both --site both
```

Select `--site webauthn.io` or `--site yubico`, and `--browser firefox` or
`--browser chrome` for individual runs. Each combination owns a temporary encrypted
vault and fresh browser profile. Webauthn.io receives a random test username;
Yubico's technical demo uses its own disposable session identity. The harness
uses the sites' existing forms/buttons/settings, approves only the expected
RP/operation, types the public fixture PIN on its own display, and checks the
sites' actual success pages. It does not replace site JavaScript or WebAuthn APIs.

The local vaults/keys are removed after each run and cannot be recovered. Public
registrations are not deleted by the harness and remain subject to the sites'
retention policies (webauthn.io's profile currently states 24 hours). These are
compatibility smoke tests, not an audit of either site's verifier. Offline
`test_public_sites.py` tests authorization/evidence guards without contacting sites.

Logs, verified ceremony records, and PIN-dialog screenshots are retained under
`target/browser-results/`. The installed browsers are Firefox 158.0.1, Firefox ESR
153.5.1esr, and Chrome for Testing 155.0.8059.84, with geckodriver 0.37.1 and matching ChromeDriver, under
`~/.local/share/yubiquity/browsers`. Existing installations/profiles are untouched.
See the [test report](docs/test-report.md) for verified scope and validation boundaries.
