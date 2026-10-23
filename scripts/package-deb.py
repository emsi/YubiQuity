#!/usr/bin/env python3
"""Build the matched GUI/backend and an Ubuntu 24.04 amd64 release package.

No installation, sudo or changes to device permissions. Assets go under target/.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def output(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def install(source, target, mode=0o644):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def notices(destination):
    metadata = json.loads(output("cargo", "metadata", "--locked", "--offline",
                                 "--filter-platform", "x86_64-unknown-linux-gnu",
                                 "--format-version", "1", cwd=ROOT))
    index = []
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        if package["source"] is None:
            continue
        source = Path(package["manifest_path"]).parent
        name = package["name"] + "-" + package["version"]
        files = [p for p in source.iterdir() if p.is_file() and p.name.lower().startswith(
            ("license", "licence", "copying", "notice", "copyright"))]
        if not files:
            raise RuntimeError(f"Missing dependency license texts: {name}")
        for path in files:
            install(path, destination / name / path.name)
        index.append(f"{name}: {package['license'] or 'see included license'}")
    rust = Path(output("rustc", "--print", "sysroot")) / "share/doc/rust"
    for name in ("COPYRIGHT.html", "COPYRIGHT-library.html"):
        install(rust / name, destination / "rust" / name)
    (destination / "INDEX.txt").write_text(
        "Rust dependency notices (includes development/build dependencies).\n\n" + "\n".join(index) + "\n")


def main():
    os.chdir(ROOT)
    os.umask(0o022)
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release.get("ID", "").strip('"') != "ubuntu" or release.get("VERSION_ID", "").strip('"') != "24.04":
        raise SystemExit("Build this package on Ubuntu 24.04; other release targets are not yet defined.")
    if output("dpkg", "--print-architecture") != "amd64":
        raise SystemExit("This release target is amd64.")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    subprocess.run([str(ROOT / "scripts/desktop.sh"), "build"], check=True)
    assets = ROOT / "target/release-assets" / f"v{version}"
    assets.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="package-", dir=ROOT / "target") as temporary:
        work = Path(temporary)
        tree = work / "root"
        control = tree / "DEBIAN"
        control.mkdir(parents=True)
        for source, name in ((ROOT / "target/host/release/yubiquity", "yubiquity"),
                             (ROOT / "target/host-desktop/yubiquity-desktop", "yubiquity-desktop")):
            target = tree / "usr/bin" / name
            install(source, target, 0o755)
            subprocess.run(["strip", "--strip-unneeded", str(target)], check=True)
        install(ROOT / "packaging/yubiquity-setup", tree / "usr/sbin/yubiquity-setup", 0o755)
        install(ROOT / "desktop/org.yubiquity.Desktop.desktop", tree / "usr/share/applications/org.yubiquity.Desktop.desktop")
        for rule in (ROOT / "packaging/udev").glob("*.rules"):
            install(rule, tree / "usr/lib/udev/rules.d" / rule.name)
        install(ROOT / "packaging/yubiquity-modules.conf", tree / "usr/lib/modules-load.d/yubiquity.conf")
        for script in ("postinst", "postrm"):
            install(ROOT / "packaging/debian" / script, control / script, 0o755)
        doc = tree / "usr/share/doc/yubiquity"
        for name in ("README.md", "docs/install.md", "docs/vault.md", "docs/host-testing.md"):
            install(ROOT / name, doc / Path(name).name)
        notices(doc / "third-party")
        (doc / "copyright").write_text(
            "YubiQuity — https://github.com/emsi/YubiQuity\n"
            "Copyright 2026 Mariusz Woloszyn and contributors.\n"
            "No project license has been specified in this source repository.\n"
            "Third-party license notices are included in third-party/.\n")
        # dpkg-shlibdeps needs a source control file even for direct binary packaging.
        (work / "debian").mkdir()
        (work / "debian/control").write_text(
            "Source: yubiquity\nSection: utils\nPriority: optional\n"
            "Maintainer: Mariusz Woloszyn <emsi@users.noreply.github.com>\n\n"
            "Package: yubiquity\nArchitecture: amd64\nDescription: Software FIDO2 authenticator\n")
        dependencies = output("dpkg-shlibdeps", "-O", "-e" + str(tree / "usr/bin/yubiquity"),
                              "-e" + str(tree / "usr/bin/yubiquity-desktop"), cwd=work)
        dependencies = next(line.removeprefix("shlibs:Depends=") for line in dependencies.splitlines()
                            if line.startswith("shlibs:Depends="))
        dependencies += ", pinentry-qt, qt6-qpa-plugins, qt6-wayland, fido2-tools, udev, kmod, passwd"
        size = sum(p.stat().st_size for p in (tree / "usr").rglob("*") if p.is_file())
        (control / "control").write_text(
            f"Package: yubiquity\nVersion: {version}-1\nArchitecture: amd64\n"
            "Section: utils\nPriority: optional\n"
            "Maintainer: Mariusz Woloszyn <emsi@users.noreply.github.com>\n"
            f"Installed-Size: {(size + 1023) // 1024}\nDepends: {dependencies}\n"
            "Homepage: https://github.com/emsi/YubiQuity\n"
            "Description: Software FIDO2 security key with a desktop approval app\n"
            " Uses Linux UHID with unmodified browsers, encrypted local vaults,\n"
            " native approval dialogs and a system tray. Intended for testing;\n"
            " no hardware protection or trusted manufacturer attestation.\n")
        manifest = {
            "version": version, "commit": output("git", "rev-parse", "HEAD"),
            "dirty": bool(output("git", "status", "--porcelain")),
            "target": "ubuntu-24.04-amd64", "rustc": output("rustc", "--version"),
            "dependencies": dependencies,
            "sha256": {name: hashlib.sha256((tree / "usr/bin" / name).read_bytes()).hexdigest()
                       for name in ("yubiquity", "yubiquity-desktop")},
        }
        (doc / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (control / "md5sums").write_text("".join(
            f"{hashlib.md5(p.read_bytes(), usedforsecurity=False).hexdigest()}  {p.relative_to(tree)}\n"
            for p in sorted((tree / "usr").rglob("*")) if p.is_file()))
        artifact = assets / f"yubiquity_{version}-1_amd64.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(tree), str(artifact)], check=True)
        (assets / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
        names = (artifact.name, "build.json")
        (assets / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((assets / name).read_bytes()).hexdigest()}  {name}\n" for name in names))
    print(f"Release assets: {assets}")


if __name__ == "__main__":
    main()
