# Software FIDO2 Authenticator for Browsers

Status: implementation in progress; Firefox-first validation per user direction on 2026-10-21. Host access is not authorized.

Progress and test evidence: [implementation ledger](docs/implementation-status.md).

Target: Linux, unmodified WebAuthn browsers, software credentials, UHID transport

This plan supersedes the earlier `firefox-virtual-fido2-kernel-module.md` proposal for implementation. The filename is retained for continuity; Firefox is not the only target.

## 1. Goal and scope

Build a software-backed FIDO2 authenticator that browsers use through their normal external security-key path. Websites should register and authenticate its credentials through ordinary WebAuthn, without extensions, injected JavaScript, browser patches, special WebAuthn preferences, or site-specific integration.

Browser independence remains a design requirement: use one device and protocol implementation without browser-specific operating modes. The current validation milestone covers stock Firefox stable and ESR inside this container. Per user direction on 2026-10-21, Chrome is optional: pursue it only with a working browser sandbox and narrowly scoped container permissions; otherwise defer it without blocking Firefox work. Chromium and other browsers that support standard external FIDO2 HID authenticators remain unverified compatibility targets, not claimed successes. Unsupported browser/OS combinations cannot be made to support security keys by this daemon.

“Behaves like a hardware key” means normal registration, passkey login, PIN entry, user approval, and error handling. Concealing the implementation from host inspection or reproducing device fingerprints is outside scope. Trusted manufacturer attestation is an explicit exception.

The first usable release must support:

- Non-discoverable credentials for allow-list-based authentication.
- Discoverable credentials for passkey authentication without an allow list.
- Multiple accounts at one relying party (RP), with correct user handles.
- Software PIN verification through the standard browser-to-authenticator protocol.
- Explicit local approval when user presence is requested.
- Persistent credentials that survive daemon and browser restarts.
- Cancellation, denied operations, and bounded failures.

Cloud sync, CTAP1/U2F, biometrics, enterprise attestation, additional signature algorithms, and optional extensions are later work driven by actual test requirements. Sites that require a platform authenticator or an unsupported extension are not automatically covered by an external-key implementation.

## 2. Design decisions

| Area | Initial choice |
|---|---|
| Language | Rust; pin a compatible stable toolchain and dependency lockfile during setup |
| Transport | Existing Linux `/dev/uhid`, producing a FIDO `/dev/hidrawN` device |
| Execution | Unprivileged foreground daemon first; user service after end-to-end validation |
| Protocol baseline | CTAP2.0 behavior with ClientPIN protocol 1; advertise only implemented capabilities |
| Signing | Independent software P-256 key per credential, ES256 |
| Attestation | `none` by default; packed self-attestation can be added for tests |
| Presence | Terminal approval first, behind an interface that can later support a desktop dialog |
| Persistence | Small encrypted, versioned vault with atomic replacement and exclusive writer locking |
| Signature counter | Consistently zero for the initial release |
| Backups | No sync or supported credential export in the initial release |
| SSH signing | Optional backend after the software implementation works |

The protocol baseline is a compatibility target, not a certification claim. Do not advertise `FIDO_2_1` or `FIDO_2_2` just because a newer specification was used as a reference. The selected commands and PIN behavior are defined in [CTAP2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html).

## 3. Architecture

```text
Website
   │ WebAuthn
Unmodified browser (Firefox, Chrome/Chromium, ...)
   │ CTAPHID through /dev/hidrawN
Linux HID core
   │ existing UHID driver and /dev/uhid
yubiquity daemon
   ├── UHID event adapter
   ├── CTAPHID transaction engine
   ├── CTAP2 command engine
   ├── PIN and presence policy
   ├── credential vault
   └── software signer
```

UHID already creates kernel HID devices on behalf of userspace transports. No project-specific kernel module, backend character device, DKMS package, or kernel signing workflow is needed. Firefox's Linux backend enumerates hidraw and checks the report descriptor for FIDO usage. [UHID interface](https://docs.kernel.org/hid/uhid.html), [Firefox discovery](https://github.com/mozilla-firefox/firefox/blob/main/dom/webauthn/authenticator/src/transport/linux/monitor.rs), [Firefox descriptor checking](https://github.com/mozilla-firefox/firefox/blob/main/dom/webauthn/authenticator/src/transport/linux/hidraw.rs).

Separate the protocol engine from transport, storage, clock, random-number generation, presence, and signing interfaces. Production uses OS randomness and real time; tests can inject controlled inputs without needing a kernel device.

The daemon owns all credential state. Browsers and a paired approval UI are clients, not storage owners. A future approval UI receives only the pending request description and can approve or deny that specific request.

## 4. Implementation work

### 4.1 UHID adapter

Create an unnumbered HID device with the FIDO usage page `0xF1D0`, CTAPHID application usage `0x01`, 64-byte input/output reports, and `BUS_USB` metadata. Use the HID name `YubiQuity Software FIDO2`, a project identity, and a stable project AAGUID; identifiers are not evidence of protected hardware. These metadata do not create a physical USB device or make UHID appear in `lsusb`.

Implement `UHID_CREATE2`, lifecycle events, `UHID_OUTPUT`, and `UHID_INPUT2`. Handle control-channel report requests with explicit replies, including unsupported-request errors. Process complete UHID events and keep the event loop responsive while approval or signing is pending. Destroy the device on clean shutdown and verify removal after process death. [UHID lifecycle and events](https://docs.kernel.org/hid/uhid.html).

Keep report-ID normalization inside this adapter. A hidraw write includes a leading report-ID byte, zero for this unnumbered descriptor; reads contain the report itself. Confirm the corresponding UHID output representation in a transport test before feeding exactly 64 bytes to CTAPHID. Do not treat every UHID payload as a raw 64-byte frame. [hidraw buffer conventions](https://docs.kernel.org/hid/hidraw.html).

### 4.2 CTAPHID engine

Implement `INIT`, `PING`, `CBOR`, `CANCEL`, `ERROR`, and `KEEPALIVE`. Advertise CBOR and absence of the CTAP1 message command.

Use bounded channel allocation and one active transaction, with the specified busy, timeout, resynchronization, and cancellation behavior. Bound message size, CBOR depth, and collections before allocation. Preserve frame boundaries and reject invalid sequence/length combinations. Drop late approval and signer results after cancellation.

Keep transport errors separate from CTAP status codes. Cancellation completes the interrupted CBOR request; it does not produce an independent response to `CANCEL`. Schedule keepalives independently of prompts and storage work. [CTAP HID transport requirements](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb).

### 4.3 CTAP2 commands

| Command | Required outcome |
|---|---|
| `GetInfo` | Accurately describe protocol, algorithms, limits, resident-key support, and PIN state |
| `MakeCredential` | Validate input, enforce exclusion/policy, generate and persist a credential, return registration data |
| `GetAssertion` | Resolve RP-scoped credentials with or without an allow list and return a valid signature |
| `GetNextAssertion` | Return additional eligible accounts with correctly scoped, expiring enumeration state |
| `ClientPIN` | Implement PIN setup/change, retries, key agreement, token issuance, and request authentication |
| `Reset` | Apply the protocol's reset window and explicit presence requirement; clear the selected authenticator's state |

Return CTAP status bytes and CTAP CBOR response maps. Each browser constructs the WebAuthn objects exposed to JavaScript.

During early milestones, advertise resident keys or PIN support only after they work. In the completed baseline, report resident-key support, ClientPIN protocol 1, and the current configured/unconfigured PIN state. Do not advertise built-in `uv`: browser-mediated PIN verification and built-in biometrics are different capabilities.

### 4.4 Credential behavior

Use cryptographically random opaque credential IDs and a new signing key for every registration. Store RP ID, user handle, account display metadata, algorithm, discoverability, policy, and the key together. Validate byte lengths and types; display names are untrusted text.

Require an exact stored RP-ID match. Persist registration before returning success. Follow the selected CTAP version's rules for exclusion lists and repeated registrations for the same RP and user.

When an allow list is absent, search only eligible discoverable credentials. Support multiple accounts and the protocol's user-information privacy rules. Return enough information for the browser to select the account, without inventing a username from the display name.

For assertions, sign `authenticatorData || clientDataHash`. Return the matching COSE public key at registration and ASN.1 DER ECDSA signatures in responses. Verify signatures with an independent implementation in tests.

### 4.5 Presence and PIN

Firefox performs silent `GetAssertion` probes with `up=false` when filtering credentials. Handle them without a presence prompt or an invented `UP=1` result. Normal operations requesting presence require explicit approval. [Firefox preflight requests](https://github.com/mozilla-firefox/firefox/blob/main/dom/webauthn/authenticator/src/ctap2/preflight.rs).

The approval prompt shows operation, RP ID, account when available, and an operation identifier. Approval applies only to that pending operation. Denial, timeout, cancellation, and daemon shutdown all invalidate the prompt. Treat device-selection requests separately from approval for a real registration or login.

Implement ClientPIN using established crypto libraries, with protocol-specific request validation, persistent retry state, temporary blocking, and PIN-token invalidation. Test PIN changes and restart behavior. Set `UV` only when the request has satisfied the implemented verification protocol. A terminal click, an unlocked vault, and successful signing are not PIN verification.

The vault passphrase and the authenticator PIN serve different purposes. Unlock the vault locally before attaching the virtual device; let the browser handle the normal authenticator PIN interaction. Locking the vault cancels pending work, invalidates transient PIN state, clears in-memory secrets where practical, and detaches the device.

## 5. Storage and security

Use an encrypted whole-vault file for the initial, small credential set. Keep indexes in memory after unlock. This avoids coordinating a database, key files, and a separate agent in the first release.

Proposed implementation:

- Versioned envelope with a salt, bounded KDF parameters, nonce, and authenticated ciphertext.
- Argon2id passphrase derivation and XChaCha20-Poly1305 authenticated encryption using maintained libraries.
- Fresh OS-generated salt when creating a vault and fresh nonce for every write.
- Atomic replacement through a private temporary file, file sync, rename, and parent-directory sync.
- A separate exclusive lock preventing two daemon instances from writing the same vault.
- Directory permissions `0700` and file permissions `0600`; reject unsafe paths or permissions.
- Durable PIN retry updates before returning relevant failure responses; fail closed if persistence fails.
- Clear errors for a wrong passphrase, corrupt file, unsupported format, or failed write.

Select dependency versions and KDF parameters during implementation, based on toolchain support and measured unlock cost. Validate untrusted envelope sizes and KDF limits before allocating memory. Use published library interfaces, not custom cryptographic primitives. [Argon2 library](https://docs.rs/argon2/latest/argon2/), [AEAD library](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/).

Use `signCount=0` consistently rather than promising rollback-resistant counters. The first release has no supported backup/export or sync workflow and uses `BE=0`, `BS=0`. Filesystem snapshots used in isolated tests are not a supported multi-device credential feature. If credential backup/export becomes a product feature, define its flags at credential creation and its restore behavior before enabling it; backup eligibility must not change retroactively. These flags do not prove hardware protection. [WebAuthn counters and backup state](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data).

Security assumes a trusted browser, host, daemon, and local user session. The daemon sees the RP ID and client-data hash, not independent proof of the page's origin. It provides software key isolation through process/file access controls, encrypted storage while locked, correct RP binding, and explicit authorization. It does not protect against a compromised user account, root, or kernel.

Do not log PINs, private keys, vault passphrases, or PIN tokens. Keep protocol tracing opt-in and redact account data by default. The authenticator daemon needs no network listener; the separate local test RP does.

## 6. Local operation and packaging

Start with a foreground CLI that can initialize and unlock a vault, attach the device, approve/deny requests, list credential metadata, remove a selected credential, and shut down cleanly. Destructive commands must identify the exact vault and credential.

Use a separate temporary vault per test run. Scripted presence is available only through an explicitly selected test backend; normal persistent operation never silently enables it. Browser tests must exercise the actual UHID device rather than substituting a browser-internal virtual authenticator.

After browser interoperability works, add a user service, a separate approval client if needed, and installation instructions for device access. Restrict `/dev/uhid` to the intended service/user because it permits creating other HID device types too. Grant the logged-in test browser access to this project's hidraw node without broadly relaxing all HID permissions.

Root is needed only where the target deployment requires module loading or access-policy installation; host administration is not authorized in the current session. Keep the running authenticator unprivileged. Test stock Firefox from the first integration milestones; Chrome/Chromium validation is deferred under the current scope. Snap/Flatpak confinement belongs in an OS/device-access test matrix, not in the authenticator protocol or as a prerequisite choice for the user. Physical security keys also depend on browser device permissions.

Use [the setup script](scripts/install-dev-tools.sh) for the Ubuntu development dependencies and stock test-browser binaries. See [container device access](docs/container-uhid.md) for host setup and the distinction between UHID access, hidraw access, and browser sandbox requirements. No browser profile preferences or installed browser extensions are changed by setup.

## 7. Proposed repository layout

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
crates/
  protocol/       CTAPHID, CTAP2, CBOR validation, PIN state
  authenticator/  credential operations, signer, presence, vault
  linux-uhid/     UHID adapter and device lifecycle
  cli/            foreground application and management commands
tests/
  vectors/        protocol and cryptographic fixtures
  integration/    independent client and storage/lifecycle tests
  browser/        local RP fixture and shared cross-browser scenarios
packaging/
  udev/           narrowly scoped device-access rules
  systemd/        optional user service
```

Finalize crate boundaries during setup; this is a responsibility split, not a requirement to create empty scaffolding. Keep most tests independent of kernel devices and desktop access.

## 8. Milestones and acceptance gates

| Stage | Work | Completion evidence |
|---|---|---|
| 1. Foundation | Pin dependencies, introduce interfaces, framing/CBOR boundaries, temporary test state | Protocol tests run without UHID; build and lint checks pass |
| 2. Transport | Create UHID device; `INIT`, `PING`, `GetInfo`, errors, cancellation | Independent FIDO client and selected Firefox builds reach the device; crash removes device |
| 3. First ceremony | ES256 registration/assertion and explicit presence with disposable keys | Local RP verifies registration and allow-list login in selected Firefox builds |
| 4. Complete passkey behavior | Discoverability, multiple accounts, ClientPIN, reset, silent probes | Selected Firefox builds succeed with resident keys and `userVerification: "required"`; negative cases fail correctly |
| 5. Persistence | Encrypted vault, retries, locking, atomic writes, management CLI | Reopened vault authenticates; corruption, write failure, and competing writers fail safely |
| 6. Release validation | Packaging, browser/package matrix, parser fuzzing, lifecycle checks | Reproducible setup and test report, supported combinations documented |

Stages 3 and 4 may use an in-memory store with the same interface as the persistent vault. Stage 3 is a development milestone, not a finished passkey release. Exercise real browser discovery in stages 2–3 rather than relying on library tests. When Chromium validation becomes available, require registration in either browser to authenticate in the other using the same stored credential before claiming cross-browser interoperability. That check is deferred for the current Firefox milestone.

The optional SSH backend comes after these gates. It must cover per-credential key provisioning, agent lifetime, signature conversion, and silent probes before it can replace the software signer. It is not required to finish the initial release.

## 9. Test plan

Use three levels: protocol/unit tests, an independent FIDO client through real hidraw, and unmodified browsers against a local test RP.

The RP fixture should generate unpredictable challenges, validate origin and RP binding, verify signatures independently, and retain registration state between ceremonies. Serve it on localhost or a configured HTTPS origin accepted by the browsers. Separate RP test traffic from the authenticator process.

| Scenario | Expected result |
|---|---|
| Registration and allow-list assertion | Independently verified public key/signature and correct account |
| Discoverable credential, no allow list | Correct user handle returned and login succeeds |
| Two accounts at one RP | Both accounts remain usable through the appropriate selection flow |
| Resident key and UV required | Both succeed with the completed profile and valid PIN; invalid verification fails |
| PIN setup, change, wrong PIN, blocking | Correct state transitions, retries, and persistence |
| Wrong RP, unknown credential, exclusion list | No unauthorized assertion or unintended duplicate registration |
| Silent preflight | No unwanted presence prompt; correct flags and credential results |
| Cancel during approval/signing | No late success; subsequent operations still work |
| Malformed CBOR/frame or competing channel | Bounded resource use and correct failure/recovery |
| Daemon crash and restart | Device disappears, then reattaches; persistent credentials still work |
| Attach before/after browser startup | Enumeration and hotplug both work in each supported deployment |
| Firefox registration, Chromium login, and reverse (deferred) | Required before a cross-browser compatibility claim, not for the current Firefox milestone |
| Wrong vault passphrase, corruption, disk-write failure | No partial state accepted or successful registration falsely reported |
| Two daemon instances using one vault | Second writer refused |
| Trusted-attestation policy | Expected rejection, recorded as outside supported scope |

Current mandatory browser coverage: stock Firefox stable and ESR on Linux inside this container, using disposable profiles and the real external HID path. Chromium and confined-package coverage remain optional, unverified matrix entries. Keep the existing Chrome harness for a future suitably restricted container; do not request a host execution session, add broad capabilities, or disable browser/container sandboxing to obtain a passing result. A physical security key is optional for comparison and is not a prerequisite.

Keep CI tests repeatable without credentials for public websites. After the local fixture passes, use a small set of agreed public sites with disposable accounts as compatibility smoke tests. Account sign-in and any unrelated second factor remain with the user.

No fingerprint-reproduction benchmark is required.

## 10. Environment and information needed

### Observed development environment

Checks and authorized development-tool installation on 2026-10-20 found the following in the current execution environment. These findings describe the container, not necessarily the user's desktop host.

| Component | Observed state | Consequence |
|---|---|---|
| OS and kernel | Ubuntu 24.04.3 userspace, Linux 6.8.0-147-generic, x86_64 | Suitable Linux development baseline |
| Runtime | PID 1 is `docker-init` | Device visibility and access must be arranged at the host/container boundary |
| Compiler | Rust/Cargo 1.99.1, rustfmt, Clippy, C/C++ build tools, pkg-config, libudev/OpenSSL headers installed | Ready for dependency selection and implementation |
| UHID | Host module loaded; `/dev/uhid` opens read/write as UID 1000 | Real UHID device creation and report I/O verified |
| hidraw | Major 234 permitted; scoped helper creates/removes the dynamic node | Unprivileged access and normal/crash cleanup verified |
| FIDO clients | `fido2-tools` 1.14.0 and `python3-fido2` 1.1.2 reinstalled | Both discover the implementation's probe and read GetInfo |
| Firefox | Stock Mozilla Firefox 158.0.1 with geckodriver 0.37.1; registration/login including discoverable + PIN-mediated required UV pass | Real hidraw path verified; user-namespace sandbox probe still reports `EPERM`; full matrix remains |
| Chromium family | Chrome for Testing and ChromeDriver 155.0.8059.84 installed | Browser launch is currently blocked by “No usable sandbox”; do not disable its sandbox to claim compatibility |
| Display | X11 `:0` responds to `xdpyinfo` | A working display is available |
| Administration | Passwordless root inside container; kmod and udev tools installed | No host Docker socket, host module files, `CAP_SYS_MODULE`, or `CAP_SYS_ADMIN`; host launch changes cannot be made from this session |

### Required for implementation

- A selected stable Rust toolchain and access to dependency downloads. Pin exact versions after validating the dependency set.
- Build dependencies required by the chosen libraries; avoid unnecessary native dependencies.
- The defaults in this plan are enough to begin protocol, storage, and CLI work. No existing passkeys, SSH keys, manufacturer certificates, or physical token are needed.

### Required for end-to-end testing

- A Linux test host with `CONFIG_UHID` and `CONFIG_HIDRAW` available, plus permission to open `/dev/uhid`.
- Permission for the test browser and independent client to open the created hidraw node.
- Stock Firefox stable/ESR, independent FIDO clients, and disposable browser profiles. Chrome/Chromium is optional under the revised validation scope.
- The local test RP and browser automation tooling are now implemented; geckodriver and ChromeDriver are installed. Xvfb/xdotool exercise Firefox's real PIN prompt on an isolated test display.
- A user available for the initial real PIN and presence interactions, or an explicit test backend for automated disposable runs.

The authorized integration setup runs the daemon, Firefox and independent clients inside this container. UHID and dynamic hidraw access are already verified; the scoped helper creates the matching device node because device-cgroup permission alone does not populate `/dev`. Host execution and host-policy modification are outside this session's scope. The optional host deployment artifacts remain documented but their runtime behavior is unverified; do not request host access to validate them or make a privileged container the solution.

Useful user input, but not a blocker for starting implementation:

1. Which two or three sites or application flows matter most after the local RP passes?
2. Any preference for the approval interface? Terminal approval is the first-release default; a desktop dialog can follow.

Container UHID/hidraw access is verified. Continue Firefox validation without waiting for Chromium or host access. A runnable, sandboxed Chromium-family environment would still be needed before claiming Chromium compatibility, but is not a gate for the current milestone. No browser protocol patch or browser modification is part of the design. See the [container sandbox research](docs/container-uhid.md#chrome-sandbox-research-and-current-decision) for the documented low-capability route and its unverified prerequisites.
