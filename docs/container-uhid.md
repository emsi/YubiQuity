# UHID access for the development container

The daemon uses `/dev/uhid` to create a kernel HID device. Browsers and independent FIDO clients open the resulting `/dev/hidrawN`, not `/dev/uhid`. The device exists in the shared host kernel even when the daemon runs in a container. [Linux UHID documentation](https://docs.kernel.org/hid/uhid.html).

No Firefox or Chromium patch, extension, or WebAuthn preference is part of this setup.

## 1. On the Docker host

Run this in a host terminal, not inside this container:

```bash
sudo modprobe uhid
test -c /dev/uhid
```

If `modprobe` fails, check the **host's** kernel configuration and installed modules. The host needs `CONFIG_UHID` and `CONFIG_HIDRAW`; UHID can also be built in. Installing kernel modules inside a container does not install them into the running host kernel.

Add this argument to the existing `docker run` invocation, before its image name:

```bash
--device=/dev/uhid:/dev/uhid:rw
```

The current image's entrypoint refers to a host launcher named `./bin/myCodex`. Its launcher source is not mounted in this workspace. Add the flag where that launcher constructs `docker run`, retaining its existing arguments, home volume, and workspace mount.

Create a replacement container with the updated configuration; restarting the existing container retains its old device configuration. Preserve the existing home volume and workspace. Do not delete volumes. Distribution packages in the container's writable layer may need reinstalling with the setup script below. [Docker run device options](https://docs.docker.com/reference/cli/docker/container/run/#device).

Do not add `--privileged`, mount all of host `/dev`, expose the Docker socket, or grant module-loading capability for this task.

## 2. Inside the replacement container

Grant the development user's group access to the exposed UHID node, then run the daemon as that user:

```bash
sudo chgrp "$(id -g)" /dev/uhid
sudo chmod 0660 /dev/uhid
test -r /dev/uhid && test -w /dev/uhid
bash scripts/install-dev-tools.sh
```

These node permissions may need reapplying after recreation. A later installation package can establish persistent access policy. Membership in this group grants the ability to create HID devices, including input devices; restrict it to trusted development users.

If browsers run on the host, this is all the container needs for the authenticator transport. The host browser still needs access to the generated hidraw node through the host's usual FIDO device-access policy. Use `fido2-token -L` on the host to check discovery once the authenticator is implemented and running.

## 3. If a browser or FIDO client also runs inside the container

This includes the installed `fido2-token` command. Both cgroup access and a device node are necessary.

On the host, after enabling UHID, discover the actual hidraw major:

```bash
yubiquity_hidraw_major=$(awk '$2 == "hidraw" { print $1 }' /proc/devices)
test -n "$yubiquity_hidraw_major"
```

If this prints no value, stop and resolve host HIDRAW support; do not guess a major number. Add this additional argument to the launcher:

```bash
--device-cgroup-rule="c ${yubiquity_hidraw_major}:* rwm"
```

Compute the variable in that same host launcher shell. Unlike a fixed `--device=/dev/hidraw0`, this rule accommodates changing minor numbers. It does **not** create or hotplug device nodes into the container. It permits all hidraw minors at the cgroup layer, so container root could create nodes for other host HID devices; use this only for a trusted development container. A more isolated deployment should use host-side clients or a narrowly managed per-device exposure mechanism. [Docker dynamic devices](https://docs.docker.com/reference/cli/docker/container/run/#device-cgroup-rule).

After the daemon creates its device, inspect sysfs from the container:

```bash
for yubiquity_hid in /sys/class/hidraw/hidraw*; do
    test -d "$yubiquity_hid" || continue
    printf '\n%s\n' "$yubiquity_hid"
    cat "$yubiquity_hid/device/uevent"
    cat "$yubiquity_hid/dev"
done
```

Select **only** the entry with `HID_NAME=YubiQuity Software FIDO2`. Its `dev` file gives decimal `MAJOR:MINOR`; its directory basename gives `hidrawN`. Create that node if absent, substituting the observed values:

```text
sudo mknod -m 0600 /dev/hidrawN c MAJOR MINOR
sudo chown YOUR_CONTAINER_UID:YOUR_CONTAINER_GID /dev/hidrawN
fido2-token -L
fido2-token -I /dev/hidrawN
```

Those are templates, not commands to paste without substitution. If a node already exists, verify its identity and device numbers before changing permissions. Do not replace unrelated devices. Start the client/browser after exposure for the initial enumeration test.

Manual nodes are a development workaround, not a lifecycle manager. Remove only the exact node created for this test when the authenticator detaches; otherwise a stale minor might later refer to another device. Repeat discovery after reattachment. A complete in-container test harness must manage attach/remove, minor reuse, and the udev notifications expected by clients. Test hotplug separately; a static node is not evidence that hotplug works. [Linux hidraw discovery](https://docs.kernel.org/hid/hidraw.html).

### Implemented development helper

The transport probe now automates node creation and normal/crash cleanup:

```bash
cargo run --locked -- probe --node-helper scripts/container-hidraw.py
```

The helper runs under `sudo -n`; the daemon remains unprivileged. The helper checks
both the project HID name and the daemon's random instance identity, creates only
the matching node, and never changes pre-existing node permissions. A lifecycle
pipe closes on daemon termination, triggering removal of its own created node.
SIGKILL of the daemon has been tested. Killing the privileged helper itself with
SIGKILL cannot run cleanup; do not do that as a normal shutdown procedure.

This does not yet establish browser hotplug support. Independent client discovery
after attachment works; browser discovery and udev notification behavior remain
separate acceptance tests.

## 4. Installed tools and browser execution

Run `bash scripts/install-dev-tools.sh` as the development user to install the Ubuntu 24.04 x86_64 dependencies. It uses sudo for packages, official Rust/Mozilla/Google distributions for tools, and project-specific browser commands:

```text
~/.local/bin/yubiquity-firefox
~/.local/bin/yubiquity-chrome
~/.local/bin/yubiquity-chromedriver
```

Browser binaries live under `~/.local/share/yubiquity/browsers`, on the persistent home volume. Setup leaves existing browser commands and profiles untouched. It selects current stable versions; pin the versions used for a release test report.

Verified in this container on 2026-10-20:

- Rust/Cargo 1.99.1, rustfmt, Clippy, C/C++ build tools, libudev/OpenSSL development headers.
- `fido2-tools` 1.14.0 and `python3-fido2` 1.1.2; both discover the temporary UHID device and exercise real FIDO commands.
- Firefox 158.0.1 registration/login, resident/PIN-required UV, persistent restart and two-account selection pass. Its user-namespace sandbox probe reports `EPERM`.
- Separately installed Firefox ESR 153.5.1esr also passes basic/resident/PIN, account selection, persistence/service and negative/recovery scenarios with the same daemon. Its namespace probe reports the same warning. See the [browser/package matrix](test-report.md#browserpackage-matrix).
- Chrome for Testing and matching ChromeDriver 155.0.8059.84 are installed. Chrome refuses to launch under the current container policy with “No usable sandbox.”

Chrome's failure is independent of UHID. It requires a compatible container/host sandbox policy or running the stock browser on the host. Do not use `--no-sandbox` or disable browser security preferences to count a test as passing. Diagnose the host's seccomp/AppArmor/user-namespace policy before choosing a narrowly scoped correction. The simplest immediate topology is the daemon in the container and ordinary browsers on the host.

## 5. What this session can and cannot change

The current account can use passwordless root **inside the container**. It has no host Docker socket, host namespace handle, `CAP_SYS_MODULE`, or `CAP_SYS_ADMIN`; `/lib/modules` is absent. After the host-side restart, `/dev/uhid` is exposed and usable by UID 1000. The host has loaded UHID, and hidraw major 234 is allowed by the supplied cgroup rule.

Development dependencies have been reinstalled after container recreation. Real UHID/hidraw traffic and independent FIDO discovery now pass in this container. The host's kernel/module setup and container launch flags still cannot be changed through the currently exposed interfaces.

Transport, credentials, PIN, encrypted storage and a same-user control service
are implemented. Firefox and independent-client tests pass within their recorded
scope; Chromium and remaining release/deployment gates are not complete. See the
[implementation ledger](implementation-status.md).

## 6. Scoped device access on a normal Linux host

[72-yubiquity.rules](../packaging/udev/72-yubiquity.rules) restricts `/dev/uhid`
and this project's hidraw nodes to an explicitly selected `yubiquity` group.
Only add trusted users: opening UHID permits creating other types of HID devices,
including input devices. The group is not just a passkey-signing permission.
For a single-user test deployment, only that user should be a member. Browser
and daemon processes must inherit the updated group membership.

Review existing group/rule configuration first. Run these on the **host**, not
inside a container without udev:

```bash
yubiquity_user=$(id -un)
getent group yubiquity || sudo groupadd --system yubiquity
sudo usermod -aG yubiquity "$yubiquity_user"
sudo install -m 0644 packaging/udev/72-yubiquity.rules /etc/udev/rules.d/72-yubiquity.rules
sudo modprobe uhid
sudo udevadm control --reload-rules
sudo udevadm trigger --action=change /sys/class/misc/uhid
```

Log out/in so both browser and daemon receive the group. Then attach a fresh
device; do not trigger broad permission changes to unrelated hidraw nodes.
Inspect the printed device path with `stat`/`udevadm info` and verify its group and
`0660` mode before testing. The normal host unit does not use the sudo node helper.
These rules do not replace the container's device-cgroup rule or create dynamic
nodes inside a container whose `/dev` is separate from the host.

The hidraw rule checks the virtual UHID path, HID parent subsystem, project
bus/VID/PID, and name/unique properties from the parent's `uevent` attribute.
Those identifiers are scope filters, **not authentication or hardware claims**.
It removes `uaccess` for matching project nodes after generic 70-uaccess rules
and before 73-seat-late, leaving access with the selected group instead of every
active seat user. Other HID nodes are not matched. Review local/distro access
rules too: custom later rules or ACLs can change effective access. See the
[udev rule semantics](https://www.freedesktop.org/software/systemd/man/latest/udev.html).

The rules pass `udevadm verify` 255 and match the observed 6.8 UHID sysfs layout.
Actual host udev permission/ACL application remains unverified here; there is no
running host udev/systemd manager exposed to this container. Do not treat syntax
validation as a passed host deployment. For optional user-service installation
and explicit unlock/approval/lock commands, see the [README](../README.md#optional-local-service-and-approval-client).
