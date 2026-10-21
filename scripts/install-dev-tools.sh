#!/usr/bin/env bash
# Run as the development user. sudo is used only for distribution packages.
set -euo pipefail

if (( EUID == 0 )); then
    echo "Run this as the development user, with passwordless sudo available." >&2
    exit 1
fi

sudo -n apt-get update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential pkg-config libudev-dev libssl-dev fido2-tools \
    python3-fido2 python3-venv python3-pil python3-argon2 python3-nacl \
    xvfb xauth xdotool kmod udev usbutils \
    libgtk-3-0t64 libdbus-glib-1-2 libasound2t64 libnss3 libgbm1 \
    libxss1 libxtst6 libx11-xcb1 ca-certificates curl xz-utils unzip jq

task_user_dir=$(getent passwd "$(id -u)" | cut -d: -f6)
task_cargo_dir=${CARGO_HOME:-"$task_user_dir/.cargo"}
task_download_dir=$(mktemp -d /tmp/yubiquity-tools.XXXXXXXX)
task_browser_root="$task_user_dir/.local/share/yubiquity/browsers"
task_bin_dir="$task_user_dir/.local/bin"
mkdir -p "$task_browser_root" "$task_bin_dir"

# This image supplies an empty, root-owned /usr/local/cargo.
# Adjust only those two known directories, never an entire existing toolchain.
if [[ "$task_cargo_dir" == /usr/local/cargo && ! -w "$task_cargo_dir" ]]; then
    sudo -n chown "$(id -u):$(id -g)" /usr/local/cargo /usr/local/cargo/bin
fi

if [[ ! -x "$task_cargo_dir/bin/rustup" ]]; then
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
        -o "$task_download_dir/rustup-init.sh"
    sh "$task_download_dir/rustup-init.sh" -y --profile minimal \
        --default-toolchain stable --component rustfmt,clippy
else
    "$task_cargo_dir/bin/rustup" toolchain install stable \
        --profile minimal --component rustfmt --component clippy
fi

task_firefox_version=$(curl -fsSL \
    https://product-details.mozilla.org/1.0/firefox_versions.json |
    jq -er '.LATEST_FIREFOX_VERSION')
[[ "$task_firefox_version" =~ ^[0-9]+(\.[0-9]+)+$ ]]
task_firefox_dir="$task_browser_root/firefox-$task_firefox_version"
if [[ ! -x "$task_firefox_dir/firefox" ]]; then
    task_firefox_release="https://archive.mozilla.org/pub/firefox/releases/$task_firefox_version"
    task_firefox_relative="linux-x86_64/en-US/firefox-$task_firefox_version.tar.xz"
    curl -fsSL "$task_firefox_release/SHA256SUMS" \
        -o "$task_download_dir/firefox-SHA256SUMS"
    task_expected_hash=$(awk -v path="$task_firefox_relative" \
        '$2 == path { print $1 }' "$task_download_dir/firefox-SHA256SUMS")
    [[ "$task_expected_hash" =~ ^[0-9a-f]{64}$ ]]
    curl -fL --retry 2 "$task_firefox_release/$task_firefox_relative" \
        -o "$task_download_dir/firefox.tar.xz"
    task_actual_hash=$(sha256sum "$task_download_dir/firefox.tar.xz" | cut -d' ' -f1)
    [[ "$task_actual_hash" == "$task_expected_hash" ]]
    tar -xJf "$task_download_dir/firefox.tar.xz" -C "$task_download_dir"
    mv "$task_download_dir/firefox" "$task_firefox_dir"
fi

curl -fsSL \
    https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json \
    -o "$task_download_dir/chrome-versions.json"
task_chrome_version=$(jq -er '.channels.Stable.version' \
    "$task_download_dir/chrome-versions.json")
[[ "$task_chrome_version" =~ ^[0-9]+(\.[0-9]+)+$ ]]
task_chrome_dir="$task_browser_root/chrome-$task_chrome_version"
for task_artifact in chrome chromedriver; do
    task_target_dir="$task_chrome_dir/$task_artifact-linux64"
    if [[ ! -x "$task_target_dir/$task_artifact" ]]; then
        task_url=$(jq -er --arg artifact "$task_artifact" \
            '.channels.Stable.downloads[$artifact][] | select(.platform == "linux64") | .url' \
            "$task_download_dir/chrome-versions.json")
        [[ "$task_url" == https://storage.googleapis.com/chrome-for-testing-public/* ]]
        curl -fL --retry 2 "$task_url" -o "$task_download_dir/$task_artifact.zip"
        unzip -tq "$task_download_dir/$task_artifact.zip"
        unzip -q "$task_download_dir/$task_artifact.zip" -d "$task_download_dir"
        mkdir -p "$task_chrome_dir"
        mv "$task_download_dir/$task_artifact-linux64" "$task_target_dir"
    fi
done

# Official Firefox WebDriver binary; pin the version used by these tests.
task_gecko_version=0.37.1
task_gecko_dir="$task_browser_root/geckodriver-$task_gecko_version"
if [[ ! -x "$task_gecko_dir/geckodriver" ]]; then
    curl -fL --retry 2 \
        "https://github.com/mozilla/geckodriver/releases/download/v$task_gecko_version/geckodriver-v$task_gecko_version-linux64.tar.gz" \
        -o "$task_download_dir/geckodriver.tar.gz"
    mkdir -p "$task_gecko_dir"
    tar -xzf "$task_download_dir/geckodriver.tar.gz" -C "$task_gecko_dir" geckodriver
fi

# Project-specific command names leave existing browser commands untouched.
for task_link in yubiquity-firefox yubiquity-chrome yubiquity-chromedriver yubiquity-geckodriver; do
    case "$task_link" in
        yubiquity-firefox) task_target="$task_firefox_dir/firefox" ;;
        yubiquity-chrome) task_target="$task_chrome_dir/chrome-linux64/chrome" ;;
        yubiquity-chromedriver) task_target="$task_chrome_dir/chromedriver-linux64/chromedriver" ;;
        yubiquity-geckodriver) task_target="$task_gecko_dir/geckodriver" ;;
    esac
    if [[ -e "$task_bin_dir/$task_link" && ! -L "$task_bin_dir/$task_link" ]]; then
        echo "Refusing to replace existing non-symlink: $task_bin_dir/$task_link" >&2
        exit 1
    fi
    ln -sfn "$task_target" "$task_bin_dir/$task_link"
done

"$task_cargo_dir/bin/rustc" +stable --version
"$task_cargo_dir/bin/cargo" +stable --version
"$task_bin_dir/yubiquity-firefox" --version
"$task_bin_dir/yubiquity-chrome" --version
"$task_bin_dir/yubiquity-chromedriver" --version
"$task_bin_dir/yubiquity-geckodriver" --version
printf 'Browser binaries: %s\nDownload artifacts: %s\n' "$task_browser_root" "$task_download_dir"
