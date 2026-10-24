# Development test report

Core evidence: 2026-10-20, rerun/extended on 2026-10-21; container/browser/public-site
validation: 2026-10-21. The planned software baseline is implemented and validated
within the recorded scope. This is not a FIDO certification or hardware-security
report. The acceptance gates and explicit exclusions are in the
[implementation plan](../firefox-virtual-fido2-plan.md).

Scope update, 2026-10-21: the user excluded host access and authorized Firefox-only
validation if Chrome cannot run with narrowly scoped container permissions.
The user subsequently recreated the container with the supplied seccomp policy.
Chrome is now runnable and the positive interoperability scenarios below pass.
Host deployment remains outside authorized execution scope and unverified.

## First binary release packaging (2026-10-23)

`scripts/package-deb.py` builds both canonical components and packages Ubuntu
24.04 amd64 binaries, desktop integration, device/Snap rules, module configuration,
an explicit account setup helper, documentation and third-party notices. Shared
library dependencies come from `dpkg-shlibdeps`. A build manifest identifies the
source commit and packaged executable hashes; release assets have SHA-256 sums.

All four package checks pass: archive ownership/modes and executable versions,
checksums and notices, apt dependency resolution without development packages,
desktop/udev/shell validation, and maintainer/setup scripts executed in a
disposable chroot with fake system tools. The latter checks idempotent group
creation, exact-user membership, UHID/rule setup, optional Firefox Snap connection,
invalid-user rejection and preservation of vault/group data on purge. No host
devices or system directories are mounted into the chroot. This establishes the
script behavior and dependency resolution, not installation on every host. The
backend extracted from the actual `.deb` also passes all six real UHID ClientPIN
integration tests, including repeated errors followed by successful use.

## Unlimited PIN and passphrase attempts (2026-10-23)

At the user's request, removed temporary and permanent PIN lockouts, including
blocking after invalid PIN-token MACs. Incorrect input now rejects only the
current request, with no failed-attempt counter, cooldown or automatic erasure.
ClientPIN always reports eight retries as a fixed compatibility response, not an
enforced limit. This intentionally differs from CTAP's retry/blocking policy.
The vault passphrase already had no attempt limits; that behavior now has repeated
failure/recovery coverage through both CLI and the desktop service's control API.

Existing v1 vaults retain their legacy retry field, but it is never used to decide
whether a PIN is accepted. Tests reopen a real encrypted zero-retry fixture and
use its existing credential without reset, migration or rewriting the file.
PIN verification no longer writes the vault; setup/change still require a durable
commit. Historical lockout and retry-write results below describe the old policy
and are superseded by this section.

Passing checks:

- All 79 Rust tests, including 260 consecutive wrong PIN token requests and 260
  wrong change-PIN requests before recovery, repeated across restart; 260 invalid
  token MACs followed by a valid token; every legacy retry value from zero to eight;
  and 16 incorrect passphrases followed by successful access with unchanged data.
- Production and fuzz formatting and strict Clippy.
- `scripts/desktop.sh build`: canonical release backend and desktop app built.
- With `YUBIQUITY_TEST_BINARY="$PWD/target/host/release/yubiquity"`, all 19 real
  UHID/hidraw PIN, vault and control integration cases pass (six PIN, eight vault,
  five control). They check repeated bad PINs/MACs followed by valid signatures,
  SIGKILL/restart, unchanged vault bytes/inode during verification, failed durable
  PIN changes, and repeated bad passphrases followed by successful unlock.
- Independent Argon2/libsodium vault format verification passes.
- Stock Firefox 158.0.1 local negative/recovery suite passes with the rebuilt
  release backend: normal registration/login, native wrong-PIN recovery with UV,
  denial/cancellation and reuse after explicit lock/unlock. Artifacts:
  `target/browser-results/negative-1792768081144734630/`.

These runs use disposable vaults and an isolated browser display inside the
container. They do not establish how every browser chooses to display retries or
cancel its own dialog. No host session or user vault was accessed.

## Vault capacity and unlocked-copy verification (2026-10-23)

Removed the fixed 256-credential limit from registration and vault validation.
The existing 1 MiB serialized-plaintext limit remains; the envelope is still v1.
An oversized update is rejected before any temporary file is created and returns
CTAP `KEY_STORE_FULL` for registration. It no longer poisons the storage guard or
clears the active encryption key. Actual persistence failures still latch closed.
The CTAP fuzz invariant now checks that a command can add at most one credential
instead of depending on the removed global count cap.

Passing checks:

- `cargo test --all-targets --locked`: 77 tests. New cases create 300 credentials
  through CTAP, use credentials on both sides of the former cap and replace a
  resident credential without increasing the count; persist/reopen a 512-record
  fixture; preserve the file/key and allow deletion after an oversized update;
  and retain authentication/reset after a store-capacity rejection.
- A deterministic file-copy test opens an encrypted source while its vault is
  unlocked, commits a change that replaces the source pathname, then finishes
  copying through the original descriptor. The copied file decrypts as the
  complete earlier state while the original vault remains open with the new state.
  Reopening a vault is also checked not to rewrite its file. These are local
  filesystem semantics, not tests of network filesystems or synchronization tools.
- Formatting and strict Clippy pass for the production and fuzz crates.
- `scripts/desktop.sh build` rebuilds the canonical release backend successfully.
- With `YUBIQUITY_TEST_BINARY="$PWD/target/host/release/yubiquity"`, all eight
  `tests/vault_integration.py` cases pass through the real UHID/hidraw path,
  including PIN retries, restart/SIGKILL, deletion and real write failures.
  The independent Argon2/libsodium vault-format test also passes.

Existing vaults need no migration. Old binaries retain their 256-record reader
limit, so all computers need the update before using larger vaults. No user vault
was opened, copied or modified by these tests. No host access occurred.

## Desktop build and launch correction (2026-10-23)

The previous workspace tests exercised `target/desktop/yubiquity-desktop`, while
the host instructions launched `target/host-desktop/yubiquity-desktop`. The latter
binary in the shared checkout still predated the tray changes. The user's rebuild
command invoked only Cargo, which does not build the Qt GUI. Passing tests of the
separate development binary did not establish that their launch path was updated.

`scripts/desktop.sh run` now builds both components and starts the resulting GUI
with the matching backend. `build` performs the same build without opening a
window. The single GUI build directory is `target/host-desktop`, with the backend
in `target/host/release`. Qt tests, native tests, compositor tests, CI and the
user-facing instructions now use those same outputs. The obsolete generated
`target/desktop` directory was removed from this checkout. No vault, host setting
or running host application was changed.

The launcher stops on any build failure. A new GUI option also rejects a launch
if an existing GUI owns the session name, with instructions to use **Lock and
quit**; it cannot silently report success after activating an older process.
Ordinary installed-app activation without that option retains its existing
single-instance behavior.

Passing local verification:

- `scripts/desktop.sh build`: both release components built successfully.
- `tests/desktop_launcher.py`: three cases cover rebuilding both artifacts,
  paths with spaces and invocation from outside the checkout, build-only mode,
  and refusing to launch an old binary after Cargo/configure/compile failure.
- Full Qt suite using the canonical release backend: 14 substantive offline
  cases pass (16 including setup/cleanup), with four native cases run separately.
- `tests/desktop_native.py`: actual build-and-run launcher, graphical pinentry,
  single-instance activation, explicit update refusal and SIGKILL watch cleanup.
  Artifacts: `target/desktop-native-results/1792758899666543308/`.
- `tests/desktop_workspaces.py`: canonical GUI/backend pass the existing
  isolated KWin X11 and native Wayland workspace/tray checks.
  Artifacts: `target/desktop-workspace-results/1792758951585001649/`.

These remain container-local fixture tests, not a new host browser ceremony.

## Tray and workspace follow-up (2026-10-23)

The user reports that the GUI works on their KDE X11 host, but approvals appeared
on the app's launch workspace. This increment hides the main window after unlock,
gives each approval an independent top-level window, and recalls only the pending
request from the tray. X11 requests the current desktop through EWMH. Native
Wayland uses normal top-level placement and remaps an existing recalled window;
the QWidget, request token and monotonic deadline are retained. No focus-policy
bypass, KWin configuration, privileged compositor API or host access is involved.

Passing local checks on Qt 6.4.2 / KWin 5.27.11:

- Strict C++ build and the complete Qt suite: 14 substantive offline cases pass
  (16 with setup/cleanup); four native-display cases run separately. New coverage
  verifies independent window ownership, no-tray accessibility, recall without
  reopening the main window, and no deadline renewal after hiding/re-presenting.
- `tests/desktop_native.py`: graphical pinentry unlock/create/cancel, approval
  rendering, second-launch activation and SIGKILL watch cleanup still pass.
  Artifacts: `target/desktop-native-results/1792738699849770435/`.
- `tests/desktop_workspaces.py`: both X11 and **native Wayland** pass with private
  D-Bus, configuration/runtime directories and isolated KWin sessions. Checks
  include automatic hiding after ready, a parentless approval on desktop 2 after
  launch on desktop 1, tray recall on another desktop without changing the
  current desktop, exact-token denial on close, browser cancellation, and keeping
  an explicitly reopened main window visible across service heartbeats. X11
  minimize-to-tray and Wayland close-to-tray pass. Native Wayland does not report
  compositor-initiated minimized state through xdg-shell; Hide/close are the
  supported explicit tray actions on both platforms.
  Artifacts: `target/desktop-workspace-results/1792738699846786378/`.

The workspace harness runs the real GUI and Rust control bridge against a test
socket service and StatusNotifierItem host. It does not render a full Plasma
panel, run a browser ceremony, or prove focus behavior under every compositor's
policy. The distro Wayland compositor's file capability is omitted from a private
test copy so it runs within existing container capabilities; no capability was
added. Tests and dependencies are wired into CI, but a hosted CI result is not
claimed. Manual X11/Wayland acceptance steps are in the
[host guide](host-testing.md#graphical-interface-and-virtual-desktops).

The earlier UHID permission blocker below is resolved: the container node is now
`root:yubiquity 0660` and accessible to the development user. The user has also
reported working host GUI operation. Neither fact substitutes for the full
automated GUI/browser acceptance matrix or host screen-lock/suspend validation.

## Desktop UX increment (2026-10-22)

This is a new UI acceptance track, not a rerun of the browser matrix below.
Implemented a Qt 6.4-compatible Widgets application with pinentry-qt 1.2.1,
using the Rust `control watch` bridge and existing one-shot control commands.
No browser, CTAP capability advertisement, trusted attestation, host permission,
or host desktop setting was modified.

Passing checks:

- `cargo test --all-targets --locked`: 72 tests. New coverage includes bounded
  versioned snapshots, single-watcher enforcement, heartbeat/coalescing, loss
  latching, bridge version/sequence/size/rejection checks and non-renewable
  daemon approval deadlines. Formatting and strict Clippy pass.
- `cmake --build target/desktop -j2`: Qt 6.4.2, C++17, warnings-as-errors.
- `YUBIQUITY_TEST_BACKEND="$PWD/target/debug/yubiquity" ctest --test-dir target/desktop --output-on-failure`:
  11 substantive offline Qt cases pass (13 including Qt setup/cleanup).
  Four native-display cases intentionally skip here and run in the next command.
  Covers plain-text/control-character display, hidden tokens, default Cancel,
  exact-token single decisions, Escape/window close, expiration/non-renewal,
  destructive reset wording, snapshot validation, Assuan decoding, real bridge
  approval/cancellation/disconnect, session-lock handler, actual vault FD input,
  and child death after parent SIGKILL. Some cases cover multiple checks.
- `/usr/bin/python3 tests/desktop_native.py`: actual graphical pinentry unlock,
  create/confirm and Cancel pass on an independently created Xvfb display.
  The actual GUI executable passes D-Bus second-launch activation and SIGKILL
  cleanup of its real Rust watch child against a test-only Unix socket fixture.
  A normal approval-dialog screenshot was also rendered and inspected.
  Latest artifacts: `target/desktop-native-results/1792675200450806658/`.
- `/usr/bin/python3 tests/startup.py`: all seven existing startup checks pass.
- `desktop-file-validate desktop/org.yubiquity.Desktop.desktop`: passes (only
  a non-failing optional category hint).

The socket fixture is not an authenticator, and these are not WebAuthn success
claims. Native test screenshots were taken before typing disposable test secrets.
No existing credential vault or host graphical session was used. CI now includes
these commands/dependencies; a hosted CI result is not claimed.

Blocked acceptance gate: `/dev/uhid` remains `root:root 0600` in this container.
UID 1000 needs read/write access before a real GUI → UHID → browser ceremony can
be tested. Do not replace this gate with root-run GUI tests or declare old
CLI/browser results to be GUI validation. Also pending: real first-use flow,
PIN-management/installation polish, actual KDE/Wayland activation/tray behavior,
and actual screen-lock/suspend integration. Signal-handler unit tests are not
proof of all-session lock coverage or pre-suspend ordering.

## Chrome container validation (2026-10-21)

User and user/PID/network namespace probes now exit 0. The container capability
bounding set remains `00000000a80425fb` (no `CAP_SYS_ADMIN`); seccomp filtering and
`docker-default (enforce)` AppArmor remain active. Existing browser archives were
reused. Ubuntu runtime/test packages and rustup wrappers were restored; no browser
download, setuid helper installation, authenticator change or browser patch was
needed. Tesseract supplies test-only recognition of Chrome's native UI.

Chrome for Testing 155.0.8059.84 reports namespace layer-1, PID/network namespaces,
seccomp-BPF and TSYNC active. The harness now checks these values for every Chrome
session and records the full status. Yama non-broker ptrace protection reports
`No`; this is not a claim that every diagnostic item is enabled or a sandbox audit.

Successful artifacts under `target/browser-results/`:

| Scenario | Run |
|---|---|
| Chrome sandbox diagnostic (headless; also captured in headed runs) | `sandbox-1792588879871827615` |
| Chrome registration/allow-list login, device attached after browser starts | `1792588878705411339` |
| Firefox/Chrome registration and credential reuse in both directions, UV discouraged | `1792588999467477102` |
| Chrome resident registration and discoverable login, required PIN/UV, attach after browser starts | `1792589538209263290` |
| Chrome encrypted-vault resident/PIN registration, SIGKILL, new daemon/fresh browser, allow-list and discoverable login | `persistent-1792589558216348575` |
| Chrome two distinct residents, both allow lists and each native chooser result, required PIN/UV | `accounts-1792589698429350771` |
| Firefox/Chrome required-PIN resident ceremonies and credential reuse in both directions; final harness | `1792589813451807704` |
| Firefox two-account regression after shared harness changes | `accounts-1792589812258240709` |

Seven RP-verifier tests, seven new offline UI/sandbox-guard tests and three
seccomp-profile integrity tests pass. Compose merge tests were skipped in this
recreated container because the Compose plugin is absent; the earlier recorded
offline Compose result is not a new run. Core Rust/full-device suite results below
are the earlier 2026-10-20 evidence, not rerun claims for this update.

Initial PIN runs timed out in test UI handling, not sandbox startup: Chrome uses
a native Views dialog rather than Firefox's WebDriver-visible PIN alert, and its
account sheet needs a recognized selection/Continue click with settling time.
Those failures and interrupted obsolete-harness runs are not counted as passes.
The final adapter recognizes native text/account word boxes on the test-owned
display, rejects unknown UI versions and verifies all successful results at the RP.
At this initial stage, Chrome's complete negative suite was unfinished: an
exploratory run passed registration abort, then was interrupted while investigating
the native denial UI. Subsequent completed results follow below.

### Completed local negative/recovery coverage (2026-10-21)

The earlier unfinished negative-suite note is superseded by these subsequent runs:

| Scenario | Passing run under `target/browser-results/` |
|---|---|
| Chrome: ten expected rejections and five verified successful ceremonies | `negative-1792591258884417216` |
| Firefox stable: same full negative/recovery suite after shared harness changes | `negative-1792591371819224685` |
| Chrome: locked service, explicit approvals, lock/re-unlock, fresh profile and both login forms | `service-1792591370654616865` |

Chrome's denial, exclusion and unknown-credential flows display native retry
sheets. The harness records their specific failure text, then uses the normal
Cancel/Close button before checking the exact JavaScript error. Denial is not
claimed to reject the promise without that user interaction. Vault comparisons,
actual request tokens, stale-token rejection and recovery assertions remain in
place. Wrong PIN produces the native incorrect-PIN feedback; correct PIN restores
eight retries and succeeds with UV. Lock during actual login approval produces
`NotAllowedError`; re-unlock rejects the old token and preserves both login forms.
The strict RP rejects Chrome's `none` attestation, as it does Firefox's.

The recreated container also passes 52 Rust tests, rustfmt, Clippy with warnings
denied, release build, seven RP tests, nine offline UI guards, independent vault
crypto, two packaging checks and all five seccomp/Compose checks. Only the Compose
plugin was reinstalled for offline configuration validation, not a Docker engine.
The existing 27-case real-device suite passes again (282.228 seconds including
waiting for concurrent browser tests). Two additional real-hidraw tests pass:
oversized/empty/invalid-sequence frames recover on the same channel, and 64
malformed CBOR requests fail without presence prompts while GetInfo/PING continue
working. These are bounded-input/recovery checks, not an exhaustive memory audit.
The expanded full real-device suite subsequently passed all 29 cases in 140.011
seconds. Eleven UI guards and four new offline public-test guards pass. Final
required-UV Firefox/Chrome bidirectional credential reuse passed again in
`1792592168744844927` after the public-site UI adapter changes.

## Public-site smoke tests (2026-10-21)

The user explicitly authorized disposable registrations on
[webauthn.io](https://webauthn.io/) and
[Yubico's technical demo](https://demo.yubico.com/webauthn-technical).
The final combined run passed all ten ceremonies in
`target/browser-results/public-1792592188448034133/`:

| Site | Firefox 158.0.1 | Chrome for Testing 155.0.8059.84 |
|---|---|---|
| webauthn.io | Resident registration, username login, username-less login; all require native PIN | Same three flows pass |
| Yubico technical demo | Registration and authentication with its default non-PIN flow | Same two flows pass |

Webauthn.io settings were ES256, external/cross-platform attachment, resident key
required, registration/authentication UV required and attestation none. Its own
success alert and authenticated profile for the generated username were observed.
The username field was explicitly empty for the discoverable login. Yubico's own
registration-completed and authentication-success pages were observed; this is not
a Yubico manufacturer-attestation acceptance claim.

Every combination used a disposable encrypted vault and fresh profile. Explicit
local control approvals checked the RP ID and operation; actual PIN prompts,
success-page snapshots and native screenshots were recorded. Chrome's namespace
and seccomp status checks passed for both sessions. No page API/function was
replaced, no browser security feature disabled, and no authenticator code changed.
Public-site verification is observed through each site's UI; the stronger
independent cryptographic checks remain the local RP/client tests.

The opt-in public harness is not part of CI; four offline guards cover its required
authorization flag, RP/operation binding, origin checks and evidence requirements.
Initial harness failures (a Firefox navigation/PIN read race, an unsubmitted Chrome
PIN sheet, and overly strict punctuation recognition in the local multi-account
regression) are retained and not counted as passes. The final runs above address
those cases with normal native UI interaction and read-only DOM observation.

Temporary local vaults/keys were removed by test cleanup and are not recoverable.
No existing user accounts were used. Remote demo registrations were not deleted;
their retention belongs to each service (webauthn.io displays a 24-hour policy).
Website labels such as “device-bound” or generic descriptions of secure hardware
do not turn this implementation into hardware-backed or trusted-attested storage.

## Environment and versions

- Ubuntu 24.04.3 container, Linux 6.8.0-147-generic, x86-64, UID 1000 daemon.
- Real `/dev/uhid`, dynamically created `/dev/hidrawN`, major 234 allowed by
  the container's device policy. The scoped helper creates only this daemon's node.
- Rust 1.99.1, dependency versions in `Cargo.lock`.
- `fido2-tools` 1.14.0, distro `python3-fido2` 1.1.2 and cryptography 41.0.7.
- Mozilla Firefox 158.0.1 with geckodriver 0.37.1; Google Chrome for Testing
  155.0.8059.84 with matching ChromeDriver. Disposable automation profiles.
- Mozilla Firefox ESR 153.5.1esr, using the same geckodriver and authenticator.

## Browser/package matrix

| Stock package | Observed result | Boundary |
|---|---|---|
| Mozilla Firefox stable 158.0.1, Linux x86-64 en-US archive | Basic/resident/required-UV, native two-account selection, persistence/service, negative cases and hotplug pass; cross-browser and account regression pass after recreation | Historical runs warned `EPERM`; the current namespace probes pass, but Firefox sandbox layers were not independently audited |
| Mozilla Firefox ESR 153.5.1esr, Linux x86-64 en-US archive | Same scenario set passes with the unchanged authenticator | Same namespace warning; native menu UI test adapter has inspected ESR coordinates |
| Chrome for Testing 155.0.8059.84 | Sandbox startup, basic/resident/required-UV, native two-account selection, persistence/service, full local negative/recovery and bidirectional Firefox reuse pass | Other Chrome packages remain unverified; retry/error-sheet dismissal is part of the observed native UI flow |
| Ordinary stable distribution Chrome/Chromium | Not validated; deferred | Chrome for Testing results do not validate other packages |
| Ubuntu Firefox Snap 154.0, revision 8763; snapd 2.77.1+ubuntu24.04 | User reported working webauthn.io registration after installing the scoped Firefox device-tag rule; see [manual host result](#snap-firefox-manual-host-smoke-test-2026-10-22) | User-run smoke test, not an agent-run or independently verified ceremony; login, persistence, hotplug and negative matrix not established for this package |
| Other Snap/Flatpak browser packages | Not validated; deferred | The single Firefox Snap host result does not establish other confined-package support |

No row implies support for arbitrary browsers or packages not tested here.

## Verified checks

| Check | Evidence and scope |
|---|---|
| Build and static checks | Cargo build/test, rustfmt and Clippy with warnings denied |
| Protocol/unit tests | 52 tests: framing, timeouts, cancellation during signing, detach-before-worker-join on normal/error exits, CBOR bounds, commands, signatures, PIN, vault boundaries, CLI and local-control safety |
| Real hidraw | 29 passed in the final complete suite, using independent FIDO clients and actual vaults; includes malformed frame/CBOR recovery, unsupported GET/SET control-report errors, real 30-second approval deadline, stale tokens, competing channels, foreground EOF lock and service control |
| Dependency audits | Production and fuzz lockfiles: no known advisories or warnings using cargo-audit 0.22.2 and the recorded RustSec database revision |
| Seeded parser fuzzing | Four ASan targets, 120-second budget each; original protocol campaigns total 10,310,701 executions, plus 7,547,998 for the new local-control parser, without a detected failure |
| Independent vault crypto | Python Argon2/libsodium decrypts the Rust envelope, verifies header authentication, and creates a disposable payload accepted by Rust |
| Local test RP | 7 tests of success and rejection: fresh one-use challenge, expiry, exact origin, RP hash, UP/UV, signature, credential/user binding and explicit attestation policy |
| Firefox basic | Registration and allow-list assertion; RP independently accepts signature; UP=1, UV=0 |
| Firefox resident + required UV | PIN configured through independent ClientPIN; browser shows its normal PIN prompt; resident registration and no-allow-list assertion accepted with UP=UV=1 |
| Firefox attachment timing | Both device-before-browser and `--attach-after-start` pass the PIN/resident scenario |
| Firefox persistent crash recovery | Resident/PIN registration, SIGKILL, new daemon and fresh profile, then verified allow-list and discoverable UV-required login |
| Firefox local service | Locked `serve`, explicit control-client unlock and approval, PIN-required resident registration, lock/re-unlock, then both login forms in a fresh browser profile |
| Firefox multiple accounts | Two residents at one RP; both allow lists and each native popup choice independently verify the right user/credential with UP=UV=1 |
| Firefox negative cases | Cancellation and denied approval for both registration/login, excluded and unknown credentials, wrong RP, stale-token rejection and subsequent successful login |
| Firefox PIN recovery and live-session reattach | Wrong PIN causes the native retry prompt; correct PIN succeeds with UV and restores eight retries; lock/detach/reattach preserves allow-list and discoverable login in the same browser session |
| Firefox removal during pending login | Lock detaches while the browser awaits actual approval; the old request fails, old tokens are rejected before/after re-unlock, and fresh requests succeed in the same browser |
| Trusted-attestation rejection | Strict RP rejects the actual Firefox `none` response; independent verifier tests also reject valid packed self-attestation; no manufacturer CA trust store is implemented |
| Storage/management | Init without overwrite, encrypted records, private permissions, symlink/hardlink rejection, exclusive writer, exact-ID deletion, persisted reset/retries |
| Write failures | Injected write/fsync/rename/directory-sync faults; actual OS `EFBIG` during registration and PIN retry writes causes failure, detach and nonzero exit |
| Credential/PIN semantics | Independent-client tests cover multiple accounts, user-data privacy, resident replacement, exclusions, wrong RP, silent probes, denied/cancelled requests, PIN setup/change/blocking/reset |
| Lifecycle | Normal exit and SIGKILL remove the temporary kernel device and helper-owned node |
| Local control service | Same-UID authentication, private socket/path/lock, bounded/partial/malformed clients, explicit token-bound approvals, lock-before-acknowledgement, PIN-token invalidation and restart-locked semantics |
| Packaging artifacts | Two offline checks pass: strict user-unit verification (including rejection of an injected unknown directive) and udev 255 syntax verification; actual host application remains unverified |

Commands are in the [README](../README.md). Browser artifacts are retained under
`target/browser-results/<run>/`: driver logs, `ceremonies.jsonl` for newer runs,
failure details where available, and screenshots of real PIN dialogs. Automated
presence is explicitly selected for these disposable runs; it does not establish
real human presence. Separate tests use the normal terminal approval path.

The fixture talks to `navigator.credentials.create/get`; it never calls a
browser's virtual-authenticator API. No browser extensions, WebAuthn preference
overrides, sandbox-disabling flags, or browser-dependent authenticator modes are
used. Standard WebDriver prompt handling is set to `ignore` so polling does not
dismiss the browser's PIN prompt. Keyboard input is confined to the test's own
Xvfb display, after WebDriver (Firefox) or test-only OCR (Chrome) identifies that prompt. PIN `1234` and incorrect
PIN `0000` are public test data, not user secrets.

`accounts.py` additionally selects each native Firefox account-popup result.
The first entry uses its access key; opening the menu and choosing the second
entry uses clicks at inspected en-US Firefox 158 stable/153 ESR layout coordinates, on the
same isolated display. A browser UI/layout change may require a harness update;
this is not an authenticator mode. The RP independently checks both distinct
credential IDs, user handles and required UV. Successful artifact run:
`target/browser-results/accounts-1792528980658589586/` (six verified ceremonies).

`negative.py --browser firefox` passed nine expected rejections and five verified
successful ceremonies in `target/browser-results/negative-1792531011633864156/`.
Assertions check exact error names and whether rejection happened in the browser
or at the RP; a network error or unrelated verifier failure cannot pass a browser
negative case. Cancelled/denied creation and excluded re-enrollment leave the
encrypted vault unchanged. Late approval tokens are rejected. Successful login
after failures proves recovery. The PIN test observes two actual native prompts,
including the incorrect-PIN message, then checks UV and the reset retry count.

The attestation case explicitly requests `direct` and supplies an enforcing
verification callback: python-fido2 otherwise ignores attestation by default.
The observed result is `fmt=none`, type `NONE`, no certificate chain, and an RP
policy rejection without storing the registration at the RP. The authenticator
has already created a credential; RP rejection does not roll that creation back.
The negative fixture has no
trusted manufacturer roots and fails closed for every chain; it is not a general
attestation acceptance test or a hardware-protection claim. This reflects the
explicit unsupported-policy exception in the plan, following the RP's
[attestation trust decision](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential).

Regression runs after the negative-test harness changes also passed: two-account
selection (`accounts-1792531033657740593`), locked-service/fresh-profile recovery
(`service-1792531081491784340`), and PIN-required registration/discoverable login
with attach-after-browser-start (`1792531105556684702`). All are under the same
`target/browser-results/` directory and use stock Firefox 158.0.1.
After the attachment-lifetime fix, both the locked-service scenario
(`service-1792531541002605418`) and the full negative/recovery scenario
(`negative-1792531599048997640`) passed again with the rebuilt daemon. The complete
27-case real-device suite passed in 147.084 seconds.
The expanded removal-during-pending-login suite also passed:
`negative-1792531727696890689` contains ten expected rejections and five verified
successful ceremonies. The browser received `NotAllowedError` for the interrupted
login, not a late success. Both fresh allow-list and discoverable login worked
after reattachment, with a real wrong-PIN/retry/correct-PIN sequence as before.

### Firefox ESR reproduction

`bash scripts/install-firefox-esr.sh 153.5.1esr` installed the official
[Mozilla Linux x86-64 en-US release](https://archive.mozilla.org/pub/firefox/releases/153.5.1esr/linux-x86_64/en-US/firefox-153.5.1esr.tar.xz)
with SHA-256 `e289bdc532decf2b54dea9b5ac64cf6f84a62eeec4d4a9ec2f69590f61b0ff1c`,
matching that release's `SHA256SUMS`. It did not change the stable binary/symlink.
Each run used `YUBIQUITY_FIREFOX_BINARY` set to the installed ESR executable,
geckodriver 0.37.1, and the same daemon/protocol behavior as stable.

| ESR scenario | Passing artifact directory under `target/browser-results/` |
|---|---|
| Basic registration/allow-list login | `1792532504204864708` |
| Resident key and required PIN-mediated UV | `1792532506376836862` |
| Same PIN/resident flow, attach after browser starts | `1792532510116051388` |
| Both accounts through allow lists and the native chooser | `accounts-1792533151670669123` |
| Ten expected failures and five successful recovery ceremonies | `negative-1792532569175563413` |
| Encrypted-vault SIGKILL/restart and fresh browser profiles | `persistent-1792532584623356552` |
| Locked service, explicit approval, lock/re-unlock and saved login | `service-1792532602191877628` |

Initial ESR chooser attempts exposed a harness issue: the stable coordinates
clicked ESR's Cancel button; a keyboard-only menu attempt then timed out. Those
runs are not counted as passes. Screenshots identified the actual menu positions;
the final harness clicks the inspected stable/ESR positions and verifies both
credential IDs/user handles independently. Stable's full account scenario also
passed again in `accounts-1792533159672807618`. Browser executable/driver overrides
only select the test installation; they never alter the authenticator or disable
browser security features.

## Explicit validation boundaries

| Check (including deferred coverage) | Current state |
|---|---|
| Other browser packages | Cross-browser reuse and two-account selection pass for the named Firefox/Chrome builds only |
| Browser hotplug | Firefox/Chrome before/after startup, crash/restart and pending-login removal/recovery verified for the recorded builds; other deployments remain unverified |
| Storage deployment validation | Local-filesystem/crash tests pass; not a claim of tested power-loss behavior on every filesystem/storage stack |
| Release packaging/matrix | Unit and scoped udev rules implemented; user-reported Ubuntu Firefox Snap registration with host rules is recorded below; host systemd-user execution, ordinary stable distribution Chrome/Chromium and other confined packages remain unverified; Mozilla ESR archive scenarios pass |
| Broader release validation | The named public sites and selected browser matrix pass; other deployments and longer campaigns are additional coverage, and hosted CI execution has not been observed |

In the pre-recreation environment, Firefox launched despite an `EPERM` warning from its user-namespace probe. That
does not establish that every sandbox layer is available inside this container.
Chrome's historical launch failure was an environment limitation, not a passed interoperability
test. We have not used `--no-sandbox` to bypass it. Host/container access and sandbox
constraints are documented in [container setup](container-uhid.md).
The renewed stock Chrome attempt is recorded in
`target/browser-results/1792531728866311477/`; it failed before a WebDriver session
or HID attachment. Direct headless startup with a disposable profile also exits
134 with the same sandbox failure. At that time user namespace creation returned `EPERM`,
seccomp filtering and enforcing `docker-default` AppArmor are active, and there
is no host Docker socket or systemd session available here. The exact responsible
policy layer cannot be established from these container checks alone. Host access
remains explicitly excluded. The user-applied container recreation resolved the
startup blocker and enabled the Chrome results recorded above.
The non-root/seccomp-profile route and repeated namespace checks are documented
in the [2026-10-21 container investigation](container-uhid.md#chrome-sandbox-research-and-current-decision).
The agent did not change host policy or add container capabilities/browser overrides.
See Chromium's
[namespace restriction documentation](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md).

## Fuzzing and automation evidence

`/usr/bin/python3 scripts/fuzz.py --seconds 120` completed with cargo-fuzz 0.13.2,
libfuzzer-sys 0.4.13, and Rust nightly-2026-10-19. All targets use address
sanitization plus debug/overflow checks, a five-second per-input timeout and a
1-GiB RSS limit. Inputs/seeds contain only disposable public fixture data.

| Target | Executions | Measured duration | Scope |
|---|---:|---:|---|
| CBOR | 5,115,469 | 121 s | Bounds, key validation, recursive parsing and canonical re-encoding |
| CTAPHID | 1,471,642 | 121 s | Stateful malformed reports, clocks, channels, cancellation/resync, stale completions and recovery |
| CTAP | 3,723,590 | 121 s | Command/PIN parsers, two seeded residents, response bounds, enumeration and cancellation |
| Local control | 7,547,998 | 121 s | Bounded JSON control commands, strict field/type parsing, canonical round-trip; synthetic unlock bytes only |

Artifacts: `target/fuzz-results/1792528537055226250/` for the three protocol
targets and `target/fuzz-results/1792530006330673539/` for local control, including
commands, per-target logs and exit codes. Sanitizer RSS peaks were
519/479/533/508 MiB respectively; these
include sanitizer/fuzzer overhead and are not measurements of daemon memory.
The campaign is useful regression evidence, not exhaustive coverage, a proof of
bounded resource use for every execution, or an independent security audit.

Both lockfiles audit cleanly against RustSec database commit
`e6f94f3760d5e6c54c1b05f204002263bc025524` (1,348 advisories, fetched 2026-10-20).
This says nothing about undisclosed vulnerabilities or application-level bugs.

The checked-in CI workflow uses pinned checkout/artifact actions, read-only
repository permissions, bounded jobs, no credentials, and no hardware tests that
silently skip when permissions are absent. Its build/lint/test/audit/fuzz commands
have passed locally; the workflow YAML parses, but no hosted CI execution is
claimed. Browser and real-hidraw gates were run separately with the results above;
the portable CI job does not substitute for them.

## Local-service and deployment evidence

The five new real-device control tests run the ordinary unprivileged `serve`
process with closed stdin, a disposable vault and private local socket. They
verify wrong-unlock rejection, explicit matching-token approval/denial, slow and
malformed client isolation, cancellation, lock-before-acknowledgement, preserved
credentials/PIN but invalidated transient PIN tokens, and locked restart after
SIGKILL. A separate root client can bypass directory permissions but is rejected
because its peer UID differs; root could still compromise the process/host, so
this is an access-check test, not a root-resistance claim.

`tests/browser/service.py` passes Firefox 158.0.1 resident/required-UV registration
through explicit control-client approvals, then locks/detaches, re-unlocks and
reuses the same credential in a fresh profile with both allow-list and discoverable
login. Artifacts: `target/browser-results/service-1792530083536457149/`.

The host udev rules pass syntax validation with udev 255. Actual host group/ACL
application is unverified. The optional user unit starts locked, has no stored
passphrase or automatic-presence setting, and disables privilege escalation;
it intentionally does not run the container's sudo node helper.

`tests/packaging.py` now verifies an exact copy of the unit with
`systemd-analyze --user --man=no --generators=no --recursive-errors=yes verify`.
A private temporary runtime directory lets the offline verifier initialize
without a running user manager. A temporary link provides the expected executable
path when absent, without replacing an existing installation; it is removed
after the check. The test also injects an unknown directive and requires nonzero
exit, so ignored warnings cannot create a false pass. Both packaging checks pass
and run in the portable CI job. No unit/rule installation or service startup is
performed; systemd runtime and restart-policy tests remain unverified.

## Native-startup remediation (2026-10-21)

The host's `Permission denied` report exposed a startup race: the daemon waited
for node existence and then opened once, without waiting for udev permissions.
An unconditional container-helper hint obscured the failing stage. The report
alone cannot prove whether that particular host failure was transient permission
readiness or a permanently unmatched/missing installed rule.

The corrected path retries actual access for up to two seconds and verifies the
sysfs instance identity, device major/minor and opened node. It rejects symlinks,
regular files and replacement devices; it never changes permissions. Failure
reports contain the stage, elapsed time, node ownership/mode and running process
groups before detach. Helper advice appears only for an explicitly selected
helper. Helper readiness and cleanup are bounded. Slow service attachment now
has a bounded longer unlock-reply wait and a fresh response-flush deadline.

Vault preflight checks public paths/envelopes and existing writer locks without
creating files or decrypting data. Missing/unsafe components are identified
before the secret prompt; actual operations repeat the FD-relative checks.
`doctor` adds read-only diagnostics, with temporary attachment only if `--probe`
is explicitly supplied. `init --run` reuses the newly created unlocked vault,
while ordinary `run` never initializes or replaces one.

Verification for this remediation:

- 67 Rust tests pass, including deterministic delayed-creation/permission and
  permanent-denial cases, node-identity rejection, helper timeout/cleanup,
  delayed control replies, read-only preflight and exact-path diagnostics.
- Seven offline CLI startup tests pass, including missing/unsafe/existing vaults
  and an absent service failing before passphrase input.
- Three udev behavior tests (multiple positive/negative fixtures) pass with the
  real udev 255 matcher. They exercise add/change/remove, exact project identity
  scope, multiline parent attributes, removal of the current uaccess tag, named
  group resolution, and final group/mode assignments resisting later rules.
  These run under chroot against umockdev fixtures with copied binaries/libraries;
  no host filesystem is bound in and no real udev daemon/rule is installed.
  Synthetic sysfs verification is explicitly disabled **inside this test only**.
  This validates rule matching/assignments, not actual devtmpfs chmod/ACL timing
  or the user's installed host policy. Existing two packaging syntax checks pass.
- All 30 pre-existing real-device integration cases pass; the additional
  `init --run` case verifies one passphrase read, explicit approval, durable
  registration and signature-verified login after reopening the vault.
- Independent vault crypto, seven RP-verifier, eleven UI-guard, four offline
  public-harness guard and five seccomp/Compose checks pass. Formatting and strict
  lint pass for production and fuzz targets. No new public registrations were
  made, and no new fuzz campaign is claimed.
- Actual Firefox registration followed by SIGKILL, a fresh Chrome profile, and
  both allow-list/discoverable required-UV logins pass:
  `target/browser-results/persistent-1792614008828779798/`.
- Actual Chrome locked-service registration, lock/re-unlock and fresh-profile
  allow-list/discoverable required-UV logins pass:
  `target/browser-results/service-1792614023290173558/`.

The real-device/browser runs above still use the development container helper.
The harness now supports `YUBIQUITY_TEST_DEVICE_MODE=native` with no helper and
no fallback; `YUBIQUITY_TEST_BINARY` can select the host-built executable. For a
separately authorized native test environment with Python FIDO dependencies:

```bash
YUBIQUITY_TEST_DEVICE_MODE=native \
YUBIQUITY_TEST_BINARY="$PWD/target/host/release/yubiquity" \
PYTHONPATH=tests /usr/bin/python3 -m unittest -v \
    transport_integration credential_integration pin_integration \
    vault_integration control_integration
```

Run this with no unrelated test daemon; it creates disposable devices/vaults.
These environment variables are test-harness settings, not production daemon
backdoors. Actual native host hotplug, desktop group inheritance and systemd-user
execution remain unverified; host access remains excluded. The desktop UX
follow-up is specified in plan section 6.1 and is not yet implemented.

## Snap Firefox manual host smoke test (2026-10-22)

This is a **user-reported manual host result**, distinct from the automated
container tests above. The agent did not access the host or run this ceremony.

Environment supplied by the user:

- Ubuntu 24.04, amd64, kernel `6.8.0-147-generic`.
- Firefox 154.0, Application Binary
  `/snap/firefox/8763/usr/lib/firefox/firefox` (Snap revision 8763).
- snap/snapd `2.77.1+ubuntu24.04`.
- Native foreground YubiQuity with an existing encrypted vault; no container
  node helper. The host shell had the `yubiquity` group after a reboot.

Observed troubleshooting sequence:

1. Independent `fido2-token -L` found the device and `fido2-token -S` succeeded,
   while browser registration waited for a touch without a daemon approval.
2. `firefox:u2f-devices` was already connected to `:u2f-devices`. Host udev
   reported `ID_FIDO_TOKEN=1` and `ID_SECURITY_TOKEN=1`, but neither `TAGS` nor
   `CURRENT_TAGS` contained `snap_firefox_firefox`.
3. The user installed `69-yubiquity-firefox-snap.rules` with the scoped rule in
   the [host guide](host-testing.md#ubuntu-firefox-installed-as-a-snap), reloaded
   udev and triggered a change for the current device. The supplied output then
   included `CURRENT_TAGS=:snap_firefox_firefox:security-device:seat:`.
4. After instructions to fully quit/reopen Firefox and retry, the daemon printed
   an `APPROVAL ... register rp="webauthn.io"` request. An initial literal
   `approve TOKEN` was rejected; after clarification to use the actual request
   token, the user reported that it worked.

This agrees with [snapd 2.77.1's USB-parent matching rules](https://github.com/canonical/snapd/blob/2.77.1/interfaces/builtin/u2f_devices.go#L246):
UHID does not supply the USB parent needed to obtain the Snap device tag through
those rules. The documented remedy adds narrowly scoped host device authorization,
not a Firefox modification, manufacturer-ID spoof, or disabled sandbox.

Evidence boundary: this records reported registration success and the supplied
device/approval output. There are no agent-captured browser/RP artifacts or
independent signature/UP/UV checks for this host ceremony. Allow-list and
discoverable login, persistence, hotplug, negative/recovery cases, other sites,
other Snap versions, and host systemd-user operation remain unverified on this
deployment. Earlier statements that host runtime was unverified describe the
state before this limited user-run test, not the absence of this later evidence.

## Security interpretation

These tests demonstrate software protocol behavior. They do not establish
hardware key protection, trusted manufacturer attestation, resistance to a
compromised local user/root/kernel, or concealment from host inspection. Persistent
`run` encrypts saved state and keeps retries across restarts; `dev-run` remains
ephemeral. Encrypted files can still be rolled back by a privileged/local attacker.
There is no supported backup/export or recovery workflow. Keep accounts disposable:
the intended product is a software testing authenticator, not a production
hardware-key replacement. Details: [vault design](vault.md).

## Guided onboarding validation — 2026-10-23

Version 0.2.0 adds a setup page to the existing Qt application. Device/group
checks distinguish the current process from saved account membership. Firefox
Snap checks use the interface connection and the temporary device's CURRENT_TAGS;
unknown queries remain unknown. Flatpak browser discovery is informational only.
The installed root-owned helper offers separate device and Firefox actions via
polkit; the GUI never elevates itself or supplies vault paths/secrets to it.

Validation in the development container:

- 82 Rust tests, production and fuzz formatting/clippy checks passed.
- 12 live UHID control/PIN tests passed, including desktop PIN creation/change,
  repeated incorrect PINs, rejection while a browser approval is pending, CTAP
  interoperability, and persistence after lock/reopen.
- Qt controller tests and real pinentry-qt accept/create/cancel tests passed on
  private Xvfb. A new full GUI → secret descriptor → Rust control → same-user
  socket fixture test verifies PIN setup. The setup screen was visually reviewed.
- Private KWin X11 and native Wayland tray/workspace suites passed. Setup remains
  visible while in use; finishing returns to normal hide-to-tray behavior.
- The 0.2.0 `.deb` was built and passed five package tests: binary versions and
  checksums, runtime dependency resolution, desktop/udev syntax, polkit policy
  and installed documentation paths, and setup/maintainer scripts in a disposable
  chroot with simulated system tools. These cover invalid pkexec identities,
  caller-scoped group changes, Firefox-only repair and failed Snap queries.

No host access was used. The native administrator authentication dialog and
actual Firefox Snap repair still need a user test on the host; isolated package
checks do not establish those desktop/system integrations. Browser verification
in the onboarding UI is an explicit user-driven registration and login at
webauthn.io, not an automated compatibility claim or a new public-site test run.

## Cryptographic dependency security update — 2026-10-24

Version 0.2.1 upgrades `p256` 0.13.2 → 0.14.0 and its elliptic-curve/ECDSA
stack. Both production and fuzz lockfiles now resolve `crypto-bigint` 0.7.6,
which addresses
[RUSTSEC-2026-0387](https://github.com/RustSec/advisory-db/blob/main/crates/crypto-bigint/RUSTSEC-2026-0387.md).
The source changes adapt the renamed SEC1 point-encoding API. No advisory ignore,
retry limit, vault-format change or browser modification was introduced.

Local validation before publishing:

- Both `cargo audit` 0.22.2 runs pass against the current RustSec database;
  production and fuzz dependency trees contain the patched version.
- All 82 Rust tests and both formatting/clippy checks pass.
- All 27 independent credential, ClientPIN, persistent-vault, control and
  Argon2/libsodium checks pass with the rebuilt release backend over real UHID
  where applicable. Native GUI/PIN-entry and desktop controller tests pass.
- `tests/release_upgrade.py` passes against the binary extracted from the actual
  v0.2.0 `.deb`: create a vault/passkey/PIN in the previous release, authenticate
  in the new release, change the PIN and add a credential, then reopen and use
  both credentials in both versions. Signatures are checked independently by
  Python FIDO/cryptography. Authentication alone leaves the vault bytes unchanged.

Stock Firefox 158.0.1 and sandboxed Chrome for Testing 155.0.8059.84 pass required-PIN
resident registration/login, credential reuse in both browser directions, and
persistent service lock/reopen with fresh browser profiles. Artifacts are in
`target/browser-results/1792843172086827804/`,
`target/browser-results/service-1792843184481955813/`, and
`target/browser-results/service-1792843191723693466/`. These are local RP tests in
isolated container displays, not additional host or public-service test runs.

The upgrade test uses only disposable vaults and can be repeated with:

```bash
YUBIQUITY_TEST_BINARY="$PWD/target/host/release/yubiquity" \
    /usr/bin/python3 tests/release_upgrade.py /path/to/previous/yubiquity
```

The local browser harness now uses its existing guarded PIN-submit retry in the
local ceremonies as well as public-site tests. A Chrome test timed out with the
PIN typed but still awaiting submission; the retry recognizes that exact native
sheet again and sends Enter without retyping, with at most three submissions per
PIN. It refuses incorrect-PIN, error and account-selection screens.

Full hosted CI, including both dependency audits and ASan fuzzing, must succeed
for the release commit before publishing. Passing the audit addresses this known
dependency finding; it is not an independent constant-time audit of YubiQuity.
