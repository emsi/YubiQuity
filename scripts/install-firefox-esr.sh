#!/usr/bin/env bash
# Optional, separate browser-matrix binary; never replaces Firefox stable.
set -euo pipefail
if (( EUID == 0 )); then
    echo "Run as the development user, not root." >&2
    exit 1
fi
task_version=${1:-153.5.1esr}
if (( $# > 1 )) || [[ ! "$task_version" =~ ^[0-9]+(\.[0-9]+)+esr$ ]]; then
    echo "Usage: bash scripts/install-firefox-esr.sh [VERSIONesr]" >&2
    exit 1
fi
task_user_dir=$(getent passwd "$(id -u)" | cut -d: -f6)
task_browser_root="$task_user_dir/.local/share/yubiquity/browsers"
task_destination="$task_browser_root/firefox-$task_version"
if [[ -x "$task_destination/firefox" ]]; then
    "$task_destination/firefox" --version
    exit 0
fi
if [[ -e "$task_destination" || -L "$task_destination" ]]; then
    echo "Refusing to replace existing path: $task_destination" >&2
    exit 1
fi
task_download_dir=$(mktemp -d /tmp/yubiquity-firefox-esr.XXXXXXXX)
task_release="https://archive.mozilla.org/pub/firefox/releases/$task_version"
task_relative="linux-x86_64/en-US/firefox-$task_version.tar.xz"
curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 "$task_release/SHA256SUMS" \
    -o "$task_download_dir/SHA256SUMS"
task_expected=$(awk -v path="$task_relative" '$2 == path { print $1 }' "$task_download_dir/SHA256SUMS")
[[ "$task_expected" =~ ^[0-9a-f]{64}$ ]]
curl --proto '=https' --tlsv1.2 -fL --retry 2 --max-time 120 "$task_release/$task_relative" \
    -o "$task_download_dir/firefox.tar.xz"
task_actual=$(sha256sum "$task_download_dir/firefox.tar.xz" | cut -d' ' -f1)
[[ "$task_actual" == "$task_expected" ]]
tar -xJf "$task_download_dir/firefox.tar.xz" -C "$task_download_dir" --no-same-owner
mkdir -p "$task_browser_root"
mv -T --no-clobber "$task_download_dir/firefox" "$task_destination"
"$task_destination/firefox" --version
printf 'Binary: %s\nSHA-256: %s\nDownload artifacts: %s\n' \
    "$task_destination/firefox" "$task_actual" "$task_download_dir"
