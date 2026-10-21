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

Update after recreation on 2026-10-21: namespace probes now pass and Chrome for
Testing launches with active namespace/seccomp-BPF sandboxes. Basic/PIN/resident,
two-account, persistence and bidirectional Firefox reuse tests pass. The capability
bounding set is unchanged and `docker-default` AppArmor remains enforcing. See
the [current test evidence](test-report.md#chrome-container-validation-2026-10-21).
The failure list above describes the earlier container.

### Applying the Chrome seccomp profile

The user recreated the container with the supplied policy; the instructions below
remain for reproducibility. This does not authorize agent host access. The file is
[packaging/docker/chrome-seccomp.json](../packaging/docker/chrome-seccomp.json).

#### Docker Compose override

[compose.yubiquity.override.yaml](../compose.yubiquity.override.yaml) supplies the
`codex` service settings: UHID, dynamic hidraw major 234, the seccomp profile,
`docker-default` AppArmor, `privileged: false`, and a private 1-GiB `/dev/shm`.
It adds no Linux capabilities and leaves the base image, startup user, entrypoint,
network and volumes unchanged. Keep Docker's normal capabilities; the existing
root node helper needs `MKNOD` and `CHOWN`.

Use Compose **2.24.4 or newer**. The `security_opt: !override` tag replaces the
base list instead of accidentally retaining a conflicting seccomp or
`no-new-privileges` option. Device mappings and device-cgroup rules also replace
their base lists, avoiding duplicate UHID/hidraw entries rejected by Compose.
If your base uses additional intentional security options or devices,
review/preserve them in these lists rather than dropping them unnoticed.
[Compose merge rules](https://docs.docker.com/reference/compose-file/merge/#replace-value).

`no-new-privileges` is deliberately **false** for this development container:
the scoped dynamic-node helper and development package installation use `sudo`.
Setting it true prevents sudo from becoming root; this was reproduced with
`setpriv --no-new-privs sudo -n true`. Chrome still runs as the non-root user with
its own sandbox. Enabling container-wide no-new-privileges would require a
different privileged device-node provisioning arrangement, not just a YAML edit.
The optional host systemd service is a separate deployment and can retain its
`NoNewPrivileges=yes` because it does not invoke the sudo helper.

From the repository root on the Docker host, replace the base-file placeholder
below with your existing Compose file. Preserve any existing project name (`-p`),
`--project-directory`, `--env-file`, and additional base `-f` arguments; append
this override last so you update the existing project, not create a different one:

```bash
docker compose -f /path/to/your/compose.yaml \
  -f "$PWD/compose.yubiquity.override.yaml" config
docker compose -f /path/to/your/compose.yaml \
  -f "$PWD/compose.yubiquity.override.yaml" up -d --force-recreate --no-deps codex
```

No environment variable or export is needed. The override contains the explicit
host path `/home/emsi/git/YubiQuity/packaging/docker/chrome-seccomp.json`.
If your host checkout is elsewhere, edit the `seccomp=` line in the override.
A relative seccomp path would resolve against the base Compose project directory,
not necessarily this override's directory; using the absolute path avoids that
ambiguity without requiring launcher environment propagation.
Review `config` locally; it may contain resolved secrets from your existing base
configuration, so do not publish its full output. Preserve volumes and needed
writable-layer data before recreation. The post-recreation checks below apply
equally to Compose and `docker run`.

Offline validation with Compose 2.40.3 passes: an existing conflicting security
list and duplicate UHID/hidraw settings are replaced correctly, base identity and
volumes survive, and configuration succeeds without any profile environment
variable (an obsolete exported value is ignored). These two
merge checks run alongside the three profile-integrity checks in
`tests/container_seccomp.py`. No Docker Engine was installed or contacted.

#### Existing docker run launcher

Check the profile exists at its explicit path **on the Docker client/host**:

```bash
test -r /home/emsi/git/YubiQuity/packaging/docker/chrome-seccomp.json
```

Add the following single argument to the existing `docker run` in the launcher,
before its image name. Change the path directly if your host checkout is elsewhere:

```bash
--security-opt seccomp=/home/emsi/git/YubiQuity/packaging/docker/chrome-seccomp.json
```

Keep the existing device arguments; major 234 was observed on this host:

```bash
--device=/dev/uhid:/dev/uhid:rw \
--device-cgroup-rule='c 234:* rwm'
```

This profile does not add Linux capabilities. Keep the existing capability set,
AppArmor profile, user, network/IPC isolation, volumes and workspace mounts.
Do not add `--privileged`, `--cap-add=SYS_ADMIN`, `--ipc=host`, unconfined security
profiles or a Docker socket mount. Do not change the image's startup user just
for this flag: the existing entrypoint may need root, but Chrome itself must run
as the normal development user, not under `sudo`.

Recreate the container using the amended launcher; `docker restart` retains the
old configuration. Preserve home/workspace volumes and any other needed data in
the old writable layer. Do not delete volumes. The JSON path is read by the
Docker client at creation time and does not need a separate container mount.

After recreation, run this **inside the container as the development user**:

```bash
id
unshare --user --map-root-user true
unshare --user --map-root-user --pid --net --fork true
```

Both namespace commands should exit 0. They are prerequisites, not proof that
Chrome or WebAuthn works. Development packages may need reinstalling after
recreation. The existing integration command for the subsequent real-device test
is:

```bash
/usr/bin/python3 tests/browser/ceremonies.py --browser chrome --headed --attach-after-start
```

Those tests and Chrome's sandbox-status check have now passed after recreation;
no `--no-sandbox` flag or browser patch was used. Leave existing browser binaries
and profiles alone. Restoring Ubuntu runtime/test packages was sufficient; the
Chrome native-UI harness additionally uses `tesseract-ocr`/English language data.

If namespace creation still returns `EPERM`, do not add broad privileges. On the
host, inspect recent kernel audit messages immediately after reproducing it:

```bash
sudo journalctl -k --since "10 minutes ago" --no-pager | grep -Ei 'apparmor.*(userns|namespace)'
```

An AppArmor `DENIED` record for `userns_create` and the container's profile would
identify an additional restriction. Report that record and the namespace command
output; the next change would be a profile-specific allowance, not disabling
AppArmor or changing a global sysctl. Absence of an audit message does not prove
AppArmor is uninvolved. No AppArmor change is part of this first attempt.

#### Policy provenance and limits

The file is the official Moby profiles `seccomp/v0.2.4` default at commit
[`245180c51918481c0525424b3ee025d2b435d46c`](https://github.com/moby/profiles/blob/245180c51918481c0525424b3ee025d2b435d46c/seccomp/default.json),
with one extra allow rule for `clone`, `setns` and `unshare`, following
[Playwright's sandboxed-container recipe](https://playwright.dev/docs/docker#crawling-and-scraping).
Default-deny and every upstream rule, including the `clone3` ENOSYS fallback,
remain unchanged. The upstream Apache-2.0 license is included in
[MOBY-LICENSE](../packaging/docker/MOBY-LICENSE). Modified for YubiQuity on
2026-10-21; no other upstream rules were edited.

This permits those namespace syscalls for **all processes in this container**,
not only Chrome; kernel capability and AppArmor checks still apply. It increases
the exposed namespace syscall surface. It is not a proof of the absolute minimum
permissions Chrome uses. The Docker daemon version/default policy is not exposed
here, so the pinned upstream baseline is not claimed identical to that daemon's
built-in profile or an organization-specific policy. Do not replace an existing
custom security policy without comparing it first.

`/usr/bin/python3 tests/container_seccomp.py` checks the exact upstream baseline
hash, the three-call exception, default-deny and retained `clone3` fallback.
These are offline checks only; actual browser startup and sandbox-status results
were subsequently obtained in the user-recreated container, separately from those
checks. Docker's [profile instructions](https://docs.docker.com/engine/security/seccomp/)
describe the `--security-opt` mechanism and host-side path resolution.

### Chrome sandbox research and current decision

On 2026-10-21 the user excluded agent host access and authorized Firefox-only
validation if Chrome cannot run with narrowly scoped container permissions.
The user subsequently applied the supplied profile and recreated the container.
Chrome now runs and the recorded positive tests pass; no agent host session,
extra capability, AppArmor relaxation or setuid helper was needed.

[Playwright's Docker documentation](https://playwright.dev/docs/docker#crawling-and-scraping)
describes sandboxed Chromium as a non-root user with a seccomp profile permitting
`clone`, `setns` and `unshare` for namespace creation. That route does not itself
require adding Linux capabilities. It is a container-launch policy change, not
a browser patch. It still expands the permitted syscall surface: review the
namespace exception against the actual Docker default rather than assuming the
entire example profile is a minimal or equivalent replacement. Do not copy the
separate troubleshooting suggestion to add `SYS_ADMIN`, or share host IPC merely
because an example does so.

[Docker documents applying profiles at container launch](https://docs.docker.com/engine/security/seccomp/).
The running process cannot relax its inherited seccomp filter. AppArmor can
independently restrict user namespaces in other deployments. In this deployment,
the user's recreation resolved the blocker with `docker-default` still enforcing.

Historical read-only diagnostics on 2026-10-21, before recreation, found:

- `unshare --user --map-root-user true` fails with `EPERM` as UID 1000 and as
  container root.
- `sudo -n unshare --pid --net --fork /bin/true` also fails with `EPERM`.
- Seccomp filtering is active; `CAP_SYS_ADMIN` is absent from container root's
  permitted and bounding sets. User namespaces are enabled by sysctl, with a
  nonzero namespace limit, while AppArmor's unprivileged-userns restriction is on.
- The bundled `chrome_sandbox` is not setuid. Installing it setuid would not
  grant capabilities outside the container's bounding set or relax seccomp;
  root's failed namespace probe is not a reason to add broad capabilities.

Those initial checks alone did not identify the denying layer. The later
successful container/browser tests establish that no AppArmor relaxation or
additional Linux capability was needed here. Keep browser sandbox checks enabled.
Do not use `--privileged`, `--cap-add=SYS_ADMIN`, `seccomp=unconfined`,
`apparmor=unconfined`, or `--no-sandbox` as a workaround. No additional browser
download or sandbox-helper installation was needed for this investigation.

## 5. What this session can and cannot change

The current account can use passwordless root **inside the container**. It has no host Docker socket, host namespace handle, `CAP_SYS_MODULE`, or `CAP_SYS_ADMIN`; `/lib/modules` is absent. After the host-side restart, `/dev/uhid` is exposed and usable by UID 1000. The host has loaded UHID, and hidraw major 234 is allowed by the supplied cgroup rule.

Development dependencies have been reinstalled after container recreation. Real UHID/hidraw traffic and independent FIDO discovery now pass in this container. The host's kernel/module setup and container launch flags still cannot be changed through the currently exposed interfaces.

Transport, credentials, PIN, encrypted storage and a same-user control service
are implemented. Firefox, sandboxed Chrome and independent-client tests pass
within their recorded scope, including negative/recovery and approved public-site
flows. Actual host deployment and other browser packages remain unverified. See the
[implementation ledger](implementation-status.md).

## 6. Scoped device access on a normal Linux host

Optional deployment reference only. Host access is not authorized for the current
work; do not execute these steps as part of the container/Firefox validation.

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
