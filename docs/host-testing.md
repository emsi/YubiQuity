# End-to-end testing on your Linux host

Run YubiQuity and your existing Firefox or Chrome **on the host**, with two host
terminals open. This walkthrough uses a separate test vault and foreground
approval, so you can see each request. No browser changes, extensions, browser
downloads, Docker changes, or disabled sandboxes are needed for this route.

The package commands below assume Ubuntu/Debian; use equivalent packages on
other distributions. The browser flows have passed in the development container;
this walkthrough is how to verify your host's device permissions and browser
package. Use disposable demo accounts, not an important account's only passkey.
This is software key storage, not hardware protection or trusted attestation.

## Already set up? Start here

If you already created the test vault in this guide, **do not initialize it again**.
After pulling changes, rebuild and run it:

```bash
cd "$HOME/git/YubiQuity"
CARGO_TARGET_DIR=target/host cargo build --release --locked &&
    target/host/release/yubiquity run --vault "$HOME/.local/share/yubiquity/host-test/credentials.yq"
```

Startup checks the existing vault and UHID access before asking for the
passphrase. It then waits for the exact hidraw node to become accessible while
udev applies permissions. It never changes device permissions, invokes a helper
unless explicitly selected, or creates a missing vault during `run`.

If something fails, this optional check reports the executable, **running
process** groups, vault path/envelope, and installed rule comparison without
asking for a password or changing settings:

```bash
target/host/release/yubiquity doctor --vault "$HOME/.local/share/yubiquity/host-test/credentials.yq"
```

Add `--probe` to also attach and remove a temporary credential-free device and
check dynamic hidraw access. Plain `doctor` does not create a device. A failed
attachment now reports the node's mode/UID/GID and process groups before the
temporary device is removed. It does not mean the vault needs reinitializing.

The remaining setup steps are for a first installation, not every launch.

## 1. Build on the host

Open a **host terminal**, as your normal desktop user:

```bash
cd "$HOME/git/YubiQuity"  # Adjust if your checkout is elsewhere.
sudo apt-get update
sudo apt-get install build-essential pkg-config fido2-tools kmod udev
```

If `rustup` is missing, install it using the [official Rust instructions](https://rust-lang.org/tools/install/)
and reopen your terminal. Build from the checkout:

```bash
CARGO_TARGET_DIR=target/host cargo build --release --locked
```

The repository pins Rust 1.99.1; rustup downloads that toolchain if needed, and
Cargo downloads missing dependencies. The separate `target/host` directory avoids
reusing a container-built executable that might require a different host libc.
Do **not** use `scripts/install-dev-tools.sh` for this walkthrough: it also installs
the container's browser automation tools and downloads separate browsers.

## 2. Set up host device access once

Still in the checkout, create the dedicated access group and add yourself:

```bash
yubiquity_user=$(id -un)
getent group yubiquity || sudo groupadd --system yubiquity
sudo usermod -aG yubiquity "$yubiquity_user"
```

Verify the saved **host account** membership:

```bash
getent group yubiquity
id -nG "$(id -un)"
```

The named-user `id` command must include `yubiquity`. Plain `id` without a
username instead shows the running shell's groups, which may still be old.
Changing group membership inside the container does not update the host account.

Only add trusted users. Access to `/dev/uhid` permits creating other kinds of HID
devices too, including input devices. The supplied rule grants hidraw access only
to this project's matching virtual devices, not every security key on the host.

Install the rule without overwriting an existing installation:

```bash
if sudo test -e /etc/udev/rules.d/72-yubiquity.rules; then
    sudo diff -u /etc/udev/rules.d/72-yubiquity.rules packaging/udev/72-yubiquity.rules
else
    sudo install -m 0644 packaging/udev/72-yubiquity.rules /etc/udev/rules.d/72-yubiquity.rules
fi
```

If the comparison prints differences, stop and review the existing rule before
continuing. Otherwise:

```bash
sudo modprobe uhid
sudo udevadm control --reload-rules
sudo udevadm trigger --action=change /sys/class/misc/uhid
sudo udevadm settle
```

### Activate and verify the new group

Logging out and back in can refresh group membership, but **does not guarantee
it on KDE**: the systemd user manager can survive logout and launch processes
with its old groups. See [systemd's user-manager lifetime](https://www.freedesktop.org/software/systemd/man/255/logind.conf.html#UserStopDelaySec=).
After login, check plain `id -nG` in each terminal. If it still lacks `yubiquity`
despite the account check above succeeding, save your work and reboot the host
to refresh the whole desktop, or use the following no-reboot route.

For the no-reboot route, run this command **on its own** in each of Terminal A
and Terminal B:

```bash
newgrp yubiquity
```

It opens a new shell. **Wait for its prompt, then paste the next block separately.**
Do not paste `newgrp` and the checks together: the remaining commands may wait
in the old shell instead of running in the new one. Keep using these updated
shells for the rest of the walkthrough; other terminals are not updated.

Whether you used a fresh login, reboot, or `newgrp`, run this check in both
terminals before continuing:

```bash
id
stat -c '%A %U:%G (%u:%g) %n' /dev/uhid
if test -r /dev/uhid && test -w /dev/uhid; then
    echo 'UHID access OK'
else
    echo 'UHID access DENIED'
fi
```

Expect `yubiquity` among your groups, and `/dev/uhid` owned by `root:yubiquity`
with mode `0660` (`crw-rw----`). Continue only after `UHID access OK`. If it prints
`DENIED`, keep the complete `id` and `stat` output for diagnosis rather than
assuming the group change worked. If the node is missing after a reboot, run
`sudo modprobe uhid` and repeat the check.

`newgrp` does **not** update an already-running browser or KDE's application
launcher. If you used this route, fully quit the browser, including background
instances, and launch it from updated Terminal B (for example, `firefox &`).
Opening another window of an old browser process does not refresh its groups.
Run both the authenticator and browser **without sudo**.

## 3. Terminal A: create and unlock a test vault

```bash
cd "$HOME/git/YubiQuity"
yubiquity_bin="$PWD/target/host/release/yubiquity"
yubiquity_vault="$HOME/.local/share/yubiquity/host-test/credentials.yq"
umask 077
mkdir -p "$HOME/.local/share/yubiquity" &&
    "$yubiquity_bin" init --vault "$yubiquity_vault" &&
    "$yubiquity_bin" run --vault "$yubiquity_vault"
```

User-owned `.local` and `.local/share` directories with mode `0775` are allowed;
you do not need to change their permissions. The vault's immediate `host-test`
directory must still be private (`0700`). The `&&` chain stops on failure, so
`run` does not prompt for a passphrase if `init` failed.

`init` asks you to choose and confirm a vault passphrase of at least 12 bytes
(12 ASCII characters meets that minimum). `run` asks for it again to unlock.
Neither prompt echoes it. Remember the passphrase: there is no recovery feature.
`init` creates the private `host-test` directory and refuses to overwrite an
existing vault. On subsequent runs, skip `init` and use the same vault.

Leave Terminal A running. Expect a line similar to:

```text
READY /dev/hidraw7 yubiquity-...
```

Use the **actual** path it prints, not necessarily `/dev/hidraw7`. On the host,
udev manages this node automatically; do not use `--node-helper`, `mknod`, or
blanket permissions on `/dev/hidraw*`. The device appears when the unlocked
daemon attaches and disappears when it detaches; it is not a permanent device.
See the [Linux UHID lifecycle](https://docs.kernel.org/hid/uhid.html).

## 4. Terminal B: verify discovery and set the security-key PIN

Copy Terminal A's current device path into this variable:

```bash
yubiquity_device=/dev/hidraw7  # Replace with your READY path.
fido2-token -L
fido2-token -I "$yubiquity_device"
```

The list should include the YubiQuity device. Information should identify a FIDO2
authenticator with resident-key and ClientPIN support. Before changing anything,
make sure the path is YubiQuity's, **not a physical security key**.

Set a PIN once for this vault:

```bash
fido2-token -S "$yubiquity_device"
```

Choose a test PIN you will remember (for example, your own six or more digits).
This PIN is **separate from the vault passphrase**. It is what you enter in the
browser's security-key PIN dialog, and it persists across daemon restarts. Do not
repeat `-S` on an already-configured vault; `-C` changes an existing PIN when
needed. Never use `-R` as a troubleshooting shortcut: that is a reset command.
See the [libfido2 command reference](https://developers.yubico.com/libfido2/Manuals/fido2-token.html).

## 5. Register and sign in at webauthn.io

In your normal browser, open [webauthn.io with the test options selected](https://webauthn.io/?regUserVerification=required&authUserVerification=required&attachment=cross_platform&discoverableCredential=required&attestation=none&regPubKeyAlgs=es256&regHints=security-key&authHints=security-key).
This requests an external security key, a discoverable passkey, required user
verification, ES256, and no attestation. You can check these in Advanced Settings.

1. Enter a unique disposable username, such as `yubiquity-yourname-20261021-a`.
   Remember it for the later tests; do not use a real account or email address.
2. Click **Register**. If the browser offers several methods, choose **Security
   key** or **USB security key**, not your phone or a cloud/platform passkey.
3. Enter the security-key PIN when prompted. When asked to touch the key, look
   at Terminal A. It will print something like:

   ```text
   APPROVAL abc123... register rp="webauthn.io" account=...
   ```

   Type this into **Terminal A**, replacing the token with the one just printed:

   ```text
   approve abc123...
   ```

4. The site should report **Success! Now try to authenticate...**
5. Keep the same username and click **Authenticate**. Complete the normal browser
   prompts and approve the new request in Terminal A. Expect a profile page
   showing that username.
6. Reopen the configured link above, **clear the username completely**, and click
   **Authenticate**. Complete the PIN/approval/account-selection prompts. You
   should reach the same profile without typing a username: this tests discovery
   from the authenticator, not just an explicit credential lookup.

Terminal approval is the software equivalent of touching the key. Some browser
flows first request `select-device`, then request registration or authentication;
approve each fresh request you intended to initiate. Their order can differ by
browser. A request times out after about 30 seconds: retry on the site and use
the **new** token if you were too slow. A cached PIN token can also mean the
browser does not ask for the PIN on every operation.

## 6. Test persistence, another browser, and rejection

Run these while the demo still retains your registration:

- **Persistence:** type `lock` in Terminal A. The foreground daemon exits and
  detaches. Run `"$yubiquity_bin" run --vault "$yubiquity_vault"` again and unlock
  with the same passphrase. Do not initialize another vault or set the PIN again.
  Reopen the configured webauthn.io link and authenticate with your existing
  username, without registering again. The hidraw number may have changed.
- **Cross-browser use:** keep the daemon running and open the configured link in
  your other browser. Authenticate with the same username, then try an empty
  username. A credential registered in Firefox should work in Chrome and vice
  versa; no daemon configuration change is needed.
- **Two accounts:** register a second unique username using the same options.
  Authenticate with an empty username and check that you can choose either
  account and reach its matching profile. Browser chooser wording may differ.
- **Rejection and recovery:** start another authentication, then type
  `deny TOKEN` for its current request in Terminal A. It must not log you in.
  Chrome may leave a retry/error dialog open; cancel it. Start a fresh request
  and approve its new token; that request should succeed.
- **Locked state:** type `lock` again, then try authentication. This authenticator
  must not complete it while detached. Cancel the browser prompt, restart `run`,
  and verify that the existing credential works again.

These checks are not a claim that every browser/package combination works.
They exercise your actual installation. Demo registrations are temporary;
webauthn.io's profile page reports a 24-hour lifetime. A later server-side expiry
does not mean the credential disappeared from your vault.

## 7. Try the Yubico technical demo

With YubiQuity unlocked, open [Yubico's WebAuthn technical demo](https://demo.yubico.com/webauthn-technical).
Click **Next** to start registration, choose the security-key route if prompted,
and approve the registration in Terminal A. Expect **Registration completed!**
Then follow **Authenticate**, click **Next**, and approve authentication. Expect
**Authentication successful!** Enter the PIN if the browser requests it.

The demo's YubiKey wording does not mean you are presenting a manufacturer-attested
YubiKey. Sites that require trusted hardware attestation are outside this tool's
supported design.

## 8. Finish and inspect saved credentials

Type `lock` or `quit` in Terminal A, or press Ctrl-C. Closing its terminal also
ends the foreground run. After it stops, list the saved credentials:

```bash
"$yubiquity_bin" list --vault "$yubiquity_vault" --show-users
```

This prompts for the vault passphrase and displays metadata, not private keys.
Omit `--show-users` to hide account names. You must stop the daemon first because
both commands require the exclusive vault lock. Keep the test vault if you want
to test reuse later; this walkthrough does not delete it or the demo registrations.

Once foreground testing works, the [optional user service](../README.md#user-unit-installation-normal-linux-host)
can replace Terminal A with explicit `control` commands. The supplied unit uses
`~/.local/share/yubiquity/vault/credentials.yq`, **not** this walkthrough's
`host-test/credentials.yq`; select the intended vault before switching. A new
vault will not contain these test credentials.

## If something fails

| Symptom | Check |
| --- | --- |
| `/dev/uhid` is missing | Run `sudo modprobe uhid`; if it fails, check host kernel UHID/HIDRAW support. |
| Account belongs to `yubiquity`, but plain `id` does not show it | The running shell has stale groups. Use the separate `newgrp` step above or save your work and reboot; KDE logout/login may not refresh them. |
| Permission denied opening UHID or hidraw | Compare current numeric groups from `id` with device ownership from `stat`, check the installed rule, and repeat the explicit access check above. Do not run the browser or daemon as root. |
| No YubiQuity device while locked | Expected. It exists only while the unlocked daemon is attached. |
| CLI sees the device, browser does not | Verify the security-key route. If you used `newgrp`, fully quit the browser and launch it from the updated shell, not KDE's menu. A confined browser package may also restrict device access; collect the package/version and error before changing policy. Do not disable its sandbox. |
| Vault path rejected | Its immediate directory must be yours and `0700`; user-owned `0775` ancestors are allowed. Inspect with `namei -l "$yubiquity_vault"` and check the remaining [vault requirements](vault.md). Do not recursively change home-directory permissions. |
| Vault already locked | Another `run`, unlocked `serve`, or vault command is using it. Stop that instance; do not delete the lock file. |
| PIN temporarily blocked | Stop and restart `run` to reattach, then use the correct PIN. Reattachment does not replenish the persistent retry budget; repeated wrong PINs can permanently block it. |
| `GLIBC_... not found` | Build on the host using the separate `target/host` directory in step 1. |

For a useful failure report, include the host distribution, browser version and
installation method, failing step, exact error, and this output while the device
is attached (update the variable after every reattachment):

```bash
id
stat -c '%A %U:%G (%u:%g) %n' /dev/uhid "$yubiquity_device"
fido2-token -L
fido2-token -I "$yubiquity_device"
udevadm info --query=property --name="$yubiquity_device"
```

Do not send PINs, vault passphrases, private keys, or the vault itself.
