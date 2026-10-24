# Install and set up YubiQuity

The binary package targets **Ubuntu 24.04, amd64/x86-64**, including KDE X11
and Wayland. It contains the matching GUI and backend; apt installs the runtime
dependencies. No Rust toolchain or browser download is needed to install it.

**Version 0.2.1** fixes the cryptographic dependency flagged by
[RUSTSEC-2026-0387](https://github.com/RustSec/advisory-db/blob/main/crates/crypto-bigint/RUSTSEC-2026-0387.md)
and includes guided onboarding in the existing desktop application. If you
installed 0.1.0 or 0.2.0, choose **Lock and quit**, install the new package, then
reopen YubiQuity. Your existing vault and PIN remain usable; no migration or
re-registration is required.

## First installation

1. Download `yubiquity_0.2.1-1_amd64.deb` from
   [the v0.2.1 release](https://github.com/emsi/YubiQuity/releases/tag/v0.2.1).
   In the download directory, install it with:

   ```bash
   sudo apt install ./yubiquity_0.2.1-1_amd64.deb
   ```

2. Open **YubiQuity** from the application menu, as your normal user.
   **Setup and browser checks** opens on first run. Its device check briefly
   attaches a temporary key without opening a vault. Do not start a browser
   registration while these checks are running.

3. If offered, click **Configure device access** and authenticate in your
   desktop's administrator dialog. This grants your account the `yubiquity`
   group, loads UHID and refreshes the installed rules. Group members can create
   HID devices, so grant this access only to trusted local users.

   The application checks again automatically. If it says your desktop session
   has the old groups, save your work and **reboot once**, then reopen YubiQuity.
   Repeating setup or restarting only the application cannot reliably refresh
   KDE and its persistent user manager. Existing users with current membership
   do not need another reboot.

4. If Firefox Snap needs access, click **Enable Firefox Snap** and authenticate.
   This connects `u2f-devices` and reloads the packaged rules. Fully quit and
   reopen Firefox after the repair. If your vault was already unlocked, lock and
   unlock it to create a fresh device. The checks distinguish the Snap interface
   connection from the actual device tag; both matter. A failed Snap query is
   reported as unknown, not as “Firefox is absent.”

5. Choose **Create vault** or **Open vault**, then unlock it. Vault passphrases
   use the existing `pinentry-qt` prompt. When creating a vault, choose a unique
   passphrase of at least 12 bytes; the new vault opens without a second prompt.

6. Choose **Set security-key PIN**. Enter and confirm a PIN of at least four
   characters, up to 63 UTF-8 bytes. This PIN is what the browser asks for; it is
   separate from the vault passphrase. An existing copied vault keeps its PIN
   and shows **Change security-key PIN**, which requires the current PIN.
   No `fido2-token` command or `/dev/hidrawN` selection is needed. Both PIN and
   passphrase attempts remain unlimited, without cooldowns or lockouts.

7. Click **Open webauthn.io in my default browser**. Use a disposable username,
   register with **Security key**, enter the PIN, and click **Approve** in
   YubiQuity. Then authenticate with the same username. This creates a test
   registration on that public site. Repeat in each browser you use. The
   application deliberately does not label browser compatibility “verified”
   just because device checks passed.

8. Click **Done**. When unlocked and a tray is available, the app hides to the
   tray. Later unlocks do this automatically. Return to **Setup and browser
   checks** any time for diagnostics, repairs or a PIN change. Without a system
   tray the window stays visible.

The package installs the UHID boot configuration, both scoped udev rules and the
polkit action for its root-owned setup helper. The GUI, vault, PIN input and
browser requests run as your normal user. Installation does not enable a daemon
or autostart entry. The helper accepts no vault paths or secrets.

## If setup needs attention

| Message or symptom | Next step |
| --- | --- |
| Desktop session has old groups | Save your work and reboot once. Do not repeat group setup. |
| Automatic repair requires the installed package | Install the current `.deb`. Source builds intentionally do not elevate scripts from the checkout. |
| Administrator prompt does not appear | Your desktop needs a running polkit authentication agent. An administrator can alternatively run `sudo yubiquity-setup YOUR_USERNAME`. |
| Snap query failed or timed out | Check that snapd is working, then choose **Check again**. Absence of a successful query is not absence of Firefox. |
| A local device rule differs | An administrator should review the reported file. `/etc` and `/run` overrides take precedence over `/usr/lib`; automatic setup preserves them. |
| Snap interface connected but device tag missing | Apply **Enable Firefox Snap**, recreate the key by locking/unlocking, and restart Firefox. If it persists, inspect **Show diagnostic details** and the [Snap guide](host-testing.md#ubuntu-firefox-installed-as-a-snap). |
| Firefox waits for touch but no approval opens | Check device/Snap access and restart Firefox. A successful command-line FIDO test alone does not prove browser sandbox access. |
| Flatpak browser detected | Its sandbox access is separate. This increment reports installed common Flatpak browsers but does not change their permissions. Test that browser explicitly. |

For support, copy **Show diagnostic details** or run
`yubiquity doctor --json --probe`. This structured report contains device/setup
information, not vault contents or secrets. The existing text command
`yubiquity doctor --vault PATH --probe` remains available for vault-file checks.

See the [host walkthrough](host-testing.md) for additional browser tests,
workspace behavior and source-install instructions. Packaged users normally
should not install another copy of the rules under `/etc/udev/rules.d`.

## Updates, verification and removal

Choose **Lock and quit** before installing an update, then install its `.deb`
with apt and reopen YubiQuity from the menu. Always update both components
together. Existing vaults remain compatible; upgrades do not replace a running
process or change the vault format. Group setup is only needed when first
granting access.

Release assets include `SHA256SUMS` and `build.json`. From an otherwise empty
download directory, download all three assets for the desired version and run
`sha256sum --check SHA256SUMS`. The manifest records the source commit, build
state, platform, compiler, dependencies and executable hashes. Checksums detect
corruption; assets are not separately signed.

`sudo apt remove yubiquity` removes the application. Removal and purge preserve
personal vaults, settings and the access group. Delete vault files yourself only
when you intend to discard their credentials.

## Build this package or run from source

On Ubuntu 24.04 amd64, install the development dependencies in the
[README](../README.md), plus `dpkg-dev`, `binutils` and Python 3.12. Then run:

```bash
./scripts/package-deb.py
/usr/bin/python3 tests/release_package.py target/release-assets/v0.2.1/yubiquity_0.2.1-1_amd64.deb
sudo apt install ./target/release-assets/v0.2.1/yubiquity_0.2.1-1_amd64.deb
```

The builder compiles both components and creates the `.deb`, checksums and build
manifest. Build from a clean committed checkout before publishing; the manifest
records dirty builds. Installed documentation keeps the same `docs/` hierarchy
so links between the guides work.

For development without installing, use `./scripts/desktop.sh run`. This is the
same GUI and backend, not a separate application. Device permissions still need
host setup. The source GUI offers diagnostics and PIN setup; automatic privileged
repairs require the root-owned helper installed by the package.
