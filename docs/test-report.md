# Development test report

Date: 2026-10-20. This is progress evidence, not a completed release or FIDO
certification report. The full acceptance gates remain in the
[implementation plan](../firefox-virtual-fido2-plan.md).

## Environment and versions

- Ubuntu 24.04.3 container, Linux 6.8.0-147-generic, x86-64, UID 1000 daemon.
- Real `/dev/uhid`, dynamically created `/dev/hidrawN`, major 234 allowed by
  the container's device policy. The scoped helper creates only this daemon's node.
- Rust 1.99.1, dependency versions in `Cargo.lock`.
- `fido2-tools` 1.14.0, distro `python3-fido2` 1.1.2 and cryptography 41.0.7.
- Mozilla Firefox 158.0.1 with geckodriver 0.37.1; Google Chrome for Testing
  155.0.8059.84 with matching ChromeDriver. Disposable automation profiles.

## Verified checks

| Check | Evidence and scope |
|---|---|
| Build and static checks | Cargo build/test, rustfmt and Clippy with warnings denied |
| Protocol/unit tests | 51 tests: framing, timeouts, cancellation during signing, CBOR bounds, commands, signatures, PIN, vault boundaries, CLI and local-control safety |
| Real hidraw | 26 passed in a complete suite, using independent FIDO clients and actual vaults; includes the real 30-second approval deadline, stale tokens, competing channels, foreground EOF lock and service control |
| Dependency audits | Production and fuzz lockfiles: no known advisories or warnings using cargo-audit 0.22.2 and the recorded RustSec database revision |
| Seeded parser fuzzing | Four ASan targets, 120-second budget each; original protocol campaigns total 10,310,701 executions, plus 7,547,998 for the new local-control parser, without a detected failure |
| Independent vault crypto | Python Argon2/libsodium decrypts the Rust envelope, verifies header authentication, and creates a disposable payload accepted by Rust |
| Local test RP | 5 tests of success and rejection: fresh one-use challenge, expiry, exact origin, RP hash, UP/UV, signature, credential and user binding |
| Firefox basic | Registration and allow-list assertion; RP independently accepts signature; UP=1, UV=0 |
| Firefox resident + required UV | PIN configured through independent ClientPIN; browser shows its normal PIN prompt; resident registration and no-allow-list assertion accepted with UP=UV=1 |
| Firefox attachment timing | Both device-before-browser and `--attach-after-start` pass the PIN/resident scenario |
| Firefox persistent crash recovery | Resident/PIN registration, SIGKILL, new daemon and fresh profile, then verified allow-list and discoverable UV-required login |
| Firefox local service | Locked `serve`, explicit control-client unlock and approval, PIN-required resident registration, lock/re-unlock, then both login forms in a fresh browser profile |
| Firefox multiple accounts | Two residents at one RP; both allow lists and each native popup choice independently verify the right user/credential with UP=UV=1 |
| Storage/management | Init without overwrite, encrypted records, private permissions, symlink/hardlink rejection, exclusive writer, exact-ID deletion, persisted reset/retries |
| Write failures | Injected write/fsync/rename/directory-sync faults; actual OS `EFBIG` during registration and PIN retry writes causes failure, detach and nonzero exit |
| Credential/PIN semantics | Independent-client tests cover multiple accounts, user-data privacy, resident replacement, exclusions, wrong RP, silent probes, denied/cancelled requests, PIN setup/change/blocking/reset |
| Lifecycle | Normal exit and SIGKILL remove the temporary kernel device and helper-owned node |
| Local control service | Same-UID authentication, private socket/path/lock, bounded/partial/malformed clients, explicit token-bound approvals, lock-before-acknowledgement, PIN-token invalidation and restart-locked semantics |
| udev artifact | udev 255 syntax verification passes; actual host application remains unverified |

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
Xvfb display, after WebDriver identifies that prompt. PIN `1234` is test data.

`accounts.py` additionally selects each native Firefox account-popup result.
The first entry uses its access key; opening the menu and choosing the second
entry uses clicks at the inspected en-US Firefox 158 layout coordinates, on the
same isolated display. A browser UI/layout change may require a harness update;
this is not an authenticator mode. The RP independently checks both distinct
credential IDs, user handles and required UV. Successful artifact run:
`target/browser-results/accounts-1792528980658589586/` (six verified ceremonies).

## Unverified or incomplete

| Gate | Current state |
|---|---|
| Chromium-family ceremonies | Chrome exits before a session starts with “No usable sandbox”; reproduced directly and via ChromeDriver |
| Cross-browser reuse, both directions | Harness present; not executed successfully because Chrome cannot start |
| Multiple-account browser selection | Firefox and independent-client enumeration pass; Chromium selection remains unverified |
| Browser hotplug | Firefox before/after startup verified; Chromium and detach/reattach during active browser requests remain unverified |
| Storage deployment validation | Local-filesystem/crash tests pass; not a claim of tested power-loss behavior on every filesystem/storage stack |
| Release packaging/matrix | Unit and scoped udev rules implemented; host application, systemd-user execution, ordinary stable distribution Chrome/Chromium, Firefox ESR and confined packages remain unverified |
| Trusted-attestation policy | `none` is returned; policy rejection is expected and deliberately unsupported, but a dedicated negative policy test remains |
| Broader release validation | Longer fuzz campaigns, hosted CI execution, remaining fault/lifecycle matrix and agreed disposable public-site smoke tests remain |

Firefox launches despite an `EPERM` warning from its user-namespace probe. That
does not establish that every sandbox layer is available inside this container.
Chrome's launch failure is an environment limitation, not a passed interoperability
test. We have not used `--no-sandbox` to bypass it. Host/container access and sandbox
constraints are documented in [container setup](container-uhid.md).

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
claimed. Browser and real-hidraw tests remain separately required release gates.

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
it intentionally does not run the container's sudo node helper. User-unit
verification could not initialize a manager because this container has no user
runtime manager. No systemd runtime or restart-policy test is claimed.

## Security interpretation

These tests demonstrate software protocol behavior. They do not establish
hardware key protection, trusted manufacturer attestation, resistance to a
compromised local user/root/kernel, or concealment from host inspection. Persistent
`run` encrypts saved state and keeps retries across restarts; `dev-run` remains
ephemeral. Encrypted files can still be rolled back by a privileged/local attacker.
There is no supported backup/export or recovery workflow. Keep accounts disposable
while the remaining release gates are unfinished. Details: [vault design](vault.md).
