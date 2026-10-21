# Implementation and verification ledger

The full objective is [the implementation plan](../firefox-virtual-fido2-plan.md).
Unchecked work remains required; passing a transport probe does not finish the product.

## Foundation and transport

- [x] Pinned Rust toolchain, dependency lockfile, formatting, lint, unit tests.
- [x] Bounded CTAPHID framing, channels, busy errors, timeouts, INIT resynchronization.
- [x] CBOR structural bounds, canonical encoding, malformed/duplicate-key rejection (command-specific types follow with commands).
- [x] Transport cancellation and keepalives; stale completion IDs ignored (approval/signer integration remains below).
- [x] UHID lifecycle, report-ID normalization, control-report error replies implemented and exercised through actual hidraw feature-report ioctls.
- [x] Scoped dynamic hidraw helper; normal detach and daemon-crash cleanup.
- [x] Independent libfido2 and python-fido2 discovery, INIT/PING/GetInfo tests.
- [ ] Real discovery in stock Firefox and Chromium; before/after browser startup.

## Authenticator behavior

- [x] ES256 per-credential software keys; none attestation; matching COSE and DER encoding.
- [x] MakeCredential validation, exclusion, limits, repeated RP/user registration policy.
- [x] RP-bound allow-list assertions; silent up=false probes without fabricated presence.
- [x] Discoverable credentials, multiple accounts, correct user handles and privacy (independent-client tests; full browser selection matrix remains).
- [x] GetNextAssertion scope, sequencing, invalidation and expiry.
- [x] ClientPIN protocol 1 setup/change/token/retry/temporary and permanent blocking, including persisted retries across crashes/restarts.
- [x] PIN-mediated UV, no advertised built-in UV; unsupported features not advertised.
- [x] Explicit local approval bound to request; denied/expired/cancelled approval discarded (real 30-second expiry and stale-token recovery tested).
- [x] Reset window and explicit presence; credential/PIN/transient state invalidation.
- [x] Consistent zero signature counter, BE=BS=0, no export/sync feature.

## Persistence and operation

- [x] Encrypted versioned Argon2id/XChaCha20-Poly1305 vault; bounded KDF/envelope.
- [x] Atomic durable writes and registration committed before success.
- [x] Persistent retry updates before responses; fail closed/detach on write failure.
- [x] Exclusive writer lock, private permissions, safe paths, secret lifetime/logging.
- [x] Init/unlock/attach, approval, list/delete metadata, lock/shutdown management CLI.
- [x] Temporary-state scripted test backend cannot silently activate for normal vaults.
- [x] Wrong passphrase/corruption/version/write-failure/competing-writer tests.
- [x] Credentials survive restart; exact deletion and reset persist in the selected vault.
- [x] Locked local service, same-user control client, explicit unlock/status/approval/deny/lock; unprivileged real-device and Firefox service-path tests.
- [ ] Host deployment of the user unit and scoped udev rules (artifacts/instructions implemented; actual systemd/udev application remains unverified here).

## End-to-end and release evidence

- [x] Local RP checks fresh challenges, origin, RP hash, signature and user binding, with negative tests of the verifier.
- [ ] Firefox and Chromium registration, allow-list and discoverable login, UV required.
- [ ] Cross-browser credential reuse in both directions and two-account selection.
- [ ] Negative RP/credential/exclusion/PIN/approval/cancellation tests in both browser families (Firefox suite now passes; Chromium remains unverified).
- [ ] Crash/reattach, concurrent channels, malformed traffic and resource-bound tests.
- [x] Independent signature verification and seeded ASan parser fuzzing; bounded CI workflow implemented and its commands checked locally (hosted execution not yet recorded).
- [x] Dedicated trusted-attestation rejection in the RP verifier and real Firefox flow; explicitly outside supported scope.
- [ ] Completed browser/package compatibility report.
- [ ] Agreed public-site smoke tests with disposable accounts, if available.
- [ ] Requirement-by-requirement completion audit; no unverified compatibility claims.

## Acceptance audit (not a completion claim)

The following audit maps the original plan to code and observed tests. A local
implementation/test result does not satisfy a requirement naming both browser
families or actual host deployment. No acceptance gate has been removed to fit
the current environment.

| Plan requirement | Authoritative evidence inspected | Remaining gap |
|---|---|---|
| §§1–3: software external key, unchanged browsers, selected CTAP2.0/ES256/none profile and separated responsibilities | Rust modules and injectable store/signer/random/context interfaces; stock Firefox WebDriver logs and independent RP verification through real UHID | Mandatory Chromium interoperability remains unproved; no cross-browser success claim |
| §4.1: UHID descriptor/identity, lifecycle, report normalization, control replies | `src/uhid.rs`; report-normalization unit test; real maximum PING, GET/SET feature-report errors, clean exit/SIGKILL removal | Host-managed node permissions and Chromium discovery/hotplug |
| §4.2: INIT/PING/CBOR/CANCEL/KEEPALIVE/ERROR, bounded parsing/channels, busy/resync/timeouts, late-result rejection | `src/hid.rs`, `src/cbor.rs`, `src/service.rs`; boundary/malformed/state tests, four ASan targets, real competing-channel/expiry/cancellation tests | Not a certification or exhaustive resource/security proof; selected deployment/browser matrix still required |
| §§4.3–4.4: all six commands, keys/COSE/DER, RP binding, exclusion, residents, multiple accounts/privacy, durable registration | `src/authenticator.rs`, `src/crypto.rs`, `src/store.rs`; credential/PIN suites, independent signature verification, Firefox account selection and negative cases | Same scenarios and credential reuse in Chromium, both directions |
| §4.5: request-bound approval, silent probes, PIN setup/change/retries/blocking, UV, cancellation and lock | `src/pin.rs`, `src/service.rs`, `src/control.rs`; unit/real-device suites and native Firefox PIN/retry/approval/removal flows | Chromium PIN/account UI and recovery; automated disposable approvals do not prove real human presence |
| §5: encrypted/versioned/bounded vault, fresh salt/nonces, atomic writes, locking/permissions, persistent retries, errors/secret lifetime | `src/vault.rs`, `src/secret_input.rs`, state Drop implementations; vault fault tests, real EFBIG/crash/restart, independent Argon2/libsodium check | Target-filesystem power-loss behavior is not established; root/same-user compromise and rollback remain explicitly outside the protection offered |
| §§5–6: counter/backup flags, no export, ordinary CLI and explicit test backend | Source flag construction and CLI parsing; independent flags, exact deletion/reset, locked-service and persistent-browser tests | No missing export/sync/SSH feature: these are explicitly deferred, not release substitutes |
| §6: user service and scoped device policy | Unit/rules/instructions exist; two strict offline packaging checks; normal unprivileged serve/control exercised with real HID | Actual systemd start/stop/restart and udev group/ACL application need a suitable host |
| §7: repository responsibility split | One Rust package with protocol/authenticator/crypto/PIN/vault/control/UHID modules and separate test/fuzz/packaging artifacts | No requirement for empty crates; the plan expressly permits finalized boundaries |
| §8: milestone gates | Foundation and persistence have local evidence; transport, ceremony and complete-passkey gates have Firefox/independent-client evidence | Stages 2–4 require both browser families; release validation is not complete |
| §9: local RP, three test levels, browser/package matrix, public-site smoke tests | Seven RP tests, 52 Rust tests, 27 real-device tests, recorded Firefox stable/ESR runs, parser campaigns and CI commands | Ordinary stable Chrome/Chromium, cross-browser reuse, confined-package matrix, and user-agreed disposable public-site flows remain |
| §10: runnable environment and input | UHID/hidraw usable; tools installed; PID 1, namespace denial, sandbox launch error and lack of host control rechecked | Host execution/policy change; agreed site/account choices; Git author identity for requested commits |

The renewed Chrome attempt failed before WebAuthn or device discovery:
`tests/browser/ceremonies.py --browser chrome --headed --attach-after-start`,
artifacts `target/browser-results/1792531728866311477/`. A direct disposable-profile
launch also exited 134 with “No usable sandbox”. `unshare --user --map-root-user
true` returns `EPERM`; seccomp filtering and enforcing `docker-default` AppArmor
are active. These observations do not identify which host policy layer(s) must
change. No sandbox-disabling flags or broad host-policy relaxations were applied.

## Current evidence

Current implementation validation (2026-10-20):

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --all-targets --locked -- -D warnings`: passed.
- `cargo test --all-targets --locked`: 52 tests passed (16 protocol/transport,
  10 credential, 5 PIN/state-transition, 12 vault/fault-injection, 2 CLI tests,
  1 worker/signing-cancellation test, 1 attachment-cleanup ordering test,
  5 local-control safety tests).
- `/usr/bin/python3 -m unittest discover -s tests -p '*integration.py' -v`:
  27 tests passed in the full run. Includes libfido2 discovery, transport boundaries,
  independent signature verification, accounts, approval/cancellation, PIN setup,
  changes, tokens, blocking, malformed crypto inputs, persisted reset/deletion,
  SIGKILL/restart, exclusive writers and real `EFBIG` write failures during
  registration and PIN retry updates. New cases exercise the actual 30-second
  approval expiration, rejection of its stale token, and competing HID channels
  returning busy then recovering after cancellation. Foreground EOF locks/detaches.
  Unsupported GET/SET feature reports return explicit `EIO` through hidraw control
  ioctls, followed by a successful normal CTAPHID PING.
- Five real-device service tests cover initially locked/no-stdin operation,
  wrong unlock, explicit request-bound approval/denial, lock/re-unlock and saved
  credentials, pending cancellation, transient PIN-token invalidation, malformed
  or slow control clients, SIGKILL/stale-socket recovery, and rejecting a root
  peer whose UID differs from the unprivileged server's. This is not protection
  against a compromised same-UID process/root.
- Paused-signer worker test cancels an in-flight assertion, queues a new command,
  and verifies that the old result/status cannot complete the new transaction.
- Attachment ownership now guarantees cancellation/detach before worker join on
  early service errors as well as normal shutdown; a no-kernel ordering test
  covers both success and injected-error exits.
- Production and fuzz lockfiles pass `cargo audit` 0.22.2 with no advisories or
  warnings (RustSec database commit `e6f94f3760d5e6c54c1b05f204002263bc025524`).
- `scripts/fuzz.py --seconds 120`: all three ASan targets passed, 10,310,701
  combined executions. Logs and reproduction commands are retained in
  `target/fuzz-results/1792528537055226250/`. See the report for scope/limits.
- The new `control` parser target also passed a 120-second ASan campaign:
  7,547,998 executions, `target/fuzz-results/1792530006330673539/`.
  The default fuzz runner/CI now includes all four targets.
- `.github/workflows/checks.yml` runs portable checks, independent verifiers,
  dependency audits and bounded fuzzing; no remote CI result is claimed.
- `/usr/bin/python3 tests/vault_crypto.py`: independent Argon2/libsodium envelope
  decrypt/encrypt and authenticated-header check passed against a disposable vault.
- `/usr/bin/python3 tests/browser/test_rp.py`: 7 verifier tests passed, including
  rejection of replay, wrong origin/challenge/RP, invalid signatures, wrong user
  handles, and missing requested UP/UV. A strict negative attestation policy
  rejects both `none` and independently verified packed self-attestation; origin,
  challenge and requested UV checks must still precede policy evaluation.
- `tests/browser/ceremonies.py --browser firefox`: Firefox 158.0.1 registration
  and allow-list login passed through real hidraw.
- `tests/browser/ceremonies.py --browser firefox --pin-test`: Firefox 158.0.1
  resident registration and no-allow-list login with `userVerification: required`
  passed. The browser's actual PIN dialog is used, on a test-owned Xvfb display.
- The same Firefox PIN/resident run also passes with `--attach-after-start`:
  the browser is already running when the real UHID device is attached.
- Mozilla Firefox ESR 153.5.1esr is separately installed from the official
  Linux x86-64 en-US archive, verified against Mozilla's release SHA256SUMS.
  Basic, PIN/resident, attach-after-start, two-account selection, all ten negative
  cases with recovery, SIGKILL persistence and locked-service scenarios pass.
  No authenticator changes or browser security overrides were needed. The test
  UI adapter uses separately inspected ESR/stable menu coordinates, and the
  stable two-account test passed again afterward. Detailed artifact paths are
  in the test report. Both Firefox builds still emit a user-namespace `EPERM`
  probe warning; successful ceremonies do not prove every sandbox layer is active.
- `tests/browser/persistence.py --browser firefox`: resident registration in
  normal persistent mode, daemon SIGKILL, new daemon and fresh browser profile,
  then allow-list and discoverable UV-required login all passed. The harness
  explicitly drives terminal approvals; `run` has no automatic-presence option.
- `tests/browser/service.py`: normal `serve`/control CLI path, PIN-required
  resident registration, explicit lock/detach and re-unlock, fresh Firefox
  profile, allow-list and discoverable login all passed using the same saved
  credential. Artifact run: `target/browser-results/service-1792530083536457149/`.
- `tests/browser/accounts.py`: Firefox registered Alice and Bob at the same RP,
  authenticated each via an allow list, then selected each from the native
  no-allow-list account popup. Both distinct credential IDs/user handles were
  independently verified with UP=UV=1. Artifact run:
  `target/browser-results/accounts-1792528980658589586/`. Chromium selection
  remains unverified; the Firefox UI driver is version/layout-specific.
- `tests/browser/negative.py --browser firefox`: ten expected rejections and
  five verified successful ceremonies passed. Covers AbortController cancellation
  and explicit denial of both registration and assertion, stale approval rejection,
  no unintended vault changes, excluded credentials, wrong RP, unknown credential,
  and a strict RP rejecting `none` attestation. A wrong PIN produces the real
  browser retry prompt; the correct PIN then succeeds with UV and resets retries.
  Explicit lock/detach interrupts a pending browser login; that request fails,
  its token is rejected both before and after re-unlock, and new allow-list and
  discoverable requests reuse the credential in the same Firefox session.
  Artifact run: `target/browser-results/negative-1792531727696890689/`.
  Chromium remains unverified.
- `tests/packaging.py`: two offline checks pass with systemd/udev 255. An exact
  copy of the user unit passes strict `systemd-analyze --user` verification with
  a private temporary runtime directory and temporary debug-build installation
  link; an unknown directive is confirmed to fail. The udev rule passes syntax
  verification. Neither actual host group/ACL application nor systemd runtime
  behavior is proven; no service is installed, started or enabled by the check.
- Chrome for Testing 155.0.8059.84 still fails to launch: “No usable sandbox”.
  No sandbox-disabling switch or browser virtual authenticator is used.
- Ephemeral browser automation explicitly selects scripted presence; persistent
  browser and real-device tests drive the normal terminal approval path.
- No test daemon, hidraw node/device, browser driver, or Xvfb process remains
  after the final test runs.

See [test report](test-report.md) for boundaries and remaining acceptance gates.

Implementation uses one Rust package with separate modules for protocol, CBOR,
CTAP commands, PIN, storage interface, signer, authorization service and Linux
transport, rather than creating empty workspace crates. `dev-run` provides
credentials and PIN but is explicitly ephemeral. `probe` still advertises only
its limited transport-test profile. `run --vault PATH` uses the encrypted store.

PIN unit tests reconstruct an authenticator from cloned stored state; real-device
tests now also verify saved retries and credentials across process crashes.
Injected failures cover write/partial-write/file-sync/rename/directory-sync stages.
An OS file-size limit produces actual write errors: no registration or token is
returned, saved state is unchanged, the daemon detaches and exits nonzero.
Default Argon2id release-build unlocks measured 135.38 ms median (64 MiB, 3 passes);
see [vault documentation](vault.md). Power-cut/filesystem behavior on every target
deployment is not implied by these tests.

Before implementation, a disposable UHID device was successfully registered in this
container, exposed as `/dev/hidraw0` (234:0), and opened by UID 1000. Both report
directions passed (65-byte UHID output including report ID; 64-byte hidraw input).
The node and device were removed afterward. Rust and FIDO CLI dependencies are
installed. Stock browser binaries are present; Chromium's container sandbox
startup failure has been reproduced again and requires a host-side resolution
without disabling the browser sandbox.
