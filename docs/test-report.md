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
- Mozilla Firefox ESR 153.5.1esr, using the same geckodriver and authenticator.

## Browser/package matrix

| Stock package | Observed result | Boundary |
|---|---|---|
| Mozilla Firefox stable 158.0.1, Linux x86-64 en-US archive | Basic/resident/required-UV, native two-account selection, persistence/service, negative cases and hotplug pass | Container user-namespace probe warns `EPERM`; not a claim that all sandbox layers work |
| Mozilla Firefox ESR 153.5.1esr, Linux x86-64 en-US archive | Same scenario set passes with the unchanged authenticator | Same namespace warning; native menu UI test adapter has inspected ESR coordinates |
| Chrome for Testing 155.0.8059.84 | Startup blocked before WebAuthn by “No usable sandbox” | No interoperability or cross-browser reuse claim |
| Ordinary stable distribution Chrome/Chromium | Not validated | Suitable sandbox-capable host required |
| Snap/Flatpak browser packages | Not validated | Need a runnable confined-package host and device-access checks; no confinement bypass is proposed |

No row implies support for arbitrary browsers or packages not tested here.

## Verified checks

| Check | Evidence and scope |
|---|---|
| Build and static checks | Cargo build/test, rustfmt and Clippy with warnings denied |
| Protocol/unit tests | 52 tests: framing, timeouts, cancellation during signing, detach-before-worker-join on normal/error exits, CBOR bounds, commands, signatures, PIN, vault boundaries, CLI and local-control safety |
| Real hidraw | 27 passed in a complete suite, using independent FIDO clients and actual vaults; includes unsupported GET/SET control-report errors followed by recovery, the real 30-second approval deadline, stale tokens, competing channels, foreground EOF lock and service control |
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
Xvfb display, after WebDriver identifies that prompt. PIN `1234` and incorrect
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

## Unverified or incomplete

| Gate | Current state |
|---|---|
| Chromium-family ceremonies | Chrome exits before a session starts with “No usable sandbox”; reproduced directly and via ChromeDriver |
| Cross-browser reuse, both directions | Harness present; not executed successfully because Chrome cannot start |
| Multiple-account browser selection | Firefox and independent-client enumeration pass; Chromium selection remains unverified |
| Browser hotplug | Firefox before/after startup, reattach between ceremonies, and removal during pending login followed by recovery verified; Chromium remains unverified |
| Storage deployment validation | Local-filesystem/crash tests pass; not a claim of tested power-loss behavior on every filesystem/storage stack |
| Release packaging/matrix | Unit and scoped udev rules implemented; host application, systemd-user execution, ordinary stable distribution Chrome/Chromium and confined packages remain unverified; Mozilla ESR archive scenarios pass |
| Broader release validation | Target deployment/browser matrix and agreed disposable public-site smoke tests remain; longer fuzz campaigns are additional assurance, and hosted CI execution has not been observed |

Firefox launches despite an `EPERM` warning from its user-namespace probe. That
does not establish that every sandbox layer is available inside this container.
Chrome's launch failure is an environment limitation, not a passed interoperability
test. We have not used `--no-sandbox` to bypass it. Host/container access and sandbox
constraints are documented in [container setup](container-uhid.md).
The renewed stock Chrome attempt is recorded in
`target/browser-results/1792531728866311477/`; it failed before a WebDriver session
or HID attachment. Direct headless startup with a disposable profile also exits
134 with the same sandbox failure. User namespace creation returns `EPERM`,
seccomp filtering and enforcing `docker-default` AppArmor are active, and there
is no host Docker socket or systemd session available here. A suitable host test
session or host-side policy correction is required; the exact responsible policy
layer cannot be established from these container checks alone. See Chromium's
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

## Security interpretation

These tests demonstrate software protocol behavior. They do not establish
hardware key protection, trusted manufacturer attestation, resistance to a
compromised local user/root/kernel, or concealment from host inspection. Persistent
`run` encrypts saved state and keeps retries across restarts; `dev-run` remains
ephemeral. Encrypted files can still be rolled back by a privileged/local attacker.
There is no supported backup/export or recovery workflow. Keep accounts disposable
while the remaining release gates are unfinished. Details: [vault design](vault.md).
