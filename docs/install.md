# Install a release

The first binary release targets **Ubuntu 24.04, amd64/x86-64**, including KDE
X11 and Wayland desktops. The `.deb` contains the matching desktop application
and Rust backend. Apt installs their runtime dependencies; Rust, CMake and browser
downloads are not needed. Other distributions/architectures currently build from
source using the [README](../README.md).

## First installation

1. Download `yubiquity_0.1.0-1_amd64.deb` from
   [the v0.1.0 release](https://github.com/emsi/YubiQuity/releases/tag/v0.1.0).
   In a terminal in the download directory, run:

   ```bash
   sudo apt install ./yubiquity_0.1.0-1_amd64.deb
   sudo yubiquity-setup "$USER"
   ```

2. After the first setup, save your work and **reboot once**. This refreshes group
   membership for KDE, its persistent user manager, the application and browsers.
3. Open **YubiQuity** from your application menu as your normal user. Create a
   vault or select an existing copied vault, then unlock it. The app hides to the
   tray when ready; approval prompts show the site, action and account.
4. For PIN-required passkeys, set the vault's authenticator PIN once. While
   unlocked, run `fido2-token -L`, identify YubiQuity's current `/dev/hidrawN`, and
   run `fido2-token -S /dev/hidrawN` with that actual path. An existing copied vault
   keeps its PIN; do not set it again. The browser PIN differs from the vault
   passphrase. Both allow unlimited attempts without lockouts.

The setup helper adds only the named user to the `yubiquity` group, loads the
kernel's UHID module, refreshes the packaged device rules, and connects Firefox
Snap's `u2f-devices` interface if Firefox Snap is installed. The package includes
the scoped Snap authorization rule and loads UHID on future boots. Group members
can create HID devices, so grant membership only to trusted local users. The app
itself never runs as root and no service/autostart entry is enabled by installation.

If you previously installed rules under `/etc/udev/rules.d`, those local files
take precedence over the packaged files under `/usr/lib/udev/rules.d`. Existing
matching rules from the host walkthrough can stay. Compare locally customized
rules if `yubiquity doctor --probe` reports an access problem.

See the [host walkthrough](host-testing.md) for testing registration/login,
workspace behavior, Snap diagnostics and checking group permissions.

## Download and verify with GitHub CLI

From an empty download directory:

```bash
gh release download v0.1.0 --repo emsi/YubiQuity \
    --pattern '*.deb' --pattern SHA256SUMS --pattern build.json
sha256sum --check SHA256SUMS
sudo apt install ./yubiquity_0.1.0-1_amd64.deb
```

`build.json` records the source commit, platform, compiler, runtime dependencies
and the packaged executable hashes. Checksums detect download corruption; these
release files are not separately signed.

## Updates and removal

Choose **Lock and quit** before installing an update, then install its `.deb`
with `sudo apt install ./FILENAME.deb`. Start YubiQuity again from the menu. Group
setup and reboot are only needed when first granting access. Upgrading does not
replace an already-running process or alter your vault.

`sudo apt remove yubiquity` removes the application. Neither removal nor purge
deletes personal vaults, settings or the access group. Only delete vault files
yourself when you intend to discard their credentials.

## Build release assets

On Ubuntu 24.04 amd64, install the development dependencies from the README plus
`dpkg-dev`, `binutils` and Python 3.12. Then run:

```bash
./scripts/package-deb.py
/usr/bin/python3 tests/release_package.py target/release-assets/v0.1.0/yubiquity_0.1.0-1_amd64.deb
```

The builder always builds both components. It derives shared-library dependencies
with `dpkg-shlibdeps`, bundles third-party notices and writes the `.deb`,
`SHA256SUMS` and `build.json` under `target/release-assets/vVERSION/`. Build from a
clean committed checkout before publishing; the manifest records dirty builds.
GitHub also supplies source archives for the release tag.
