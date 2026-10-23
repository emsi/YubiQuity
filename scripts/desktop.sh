#!/usr/bin/env bash
# One build and launch entry point for the Rust backend and Qt desktop app.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/desktop.sh [run [GUI options...] | build]

run    Build both components, then start the desktop app (the default).
build  Build both components without opening a window.

Example:
  scripts/desktop.sh run --vault "$HOME/.local/share/yubiquity/host-test/credentials.yq"

Use Lock and quit to close an existing GUI before running an update.
EOF
}

task_action=${1:-run}
if (( $# )); then
    shift
fi
case "$task_action" in
    -h|--help) usage; exit 0 ;;
    build)
        if (( $# )); then
            usage >&2
            exit 2
        fi
        ;;
    run) ;;
    *) usage >&2; exit 2 ;;
esac

task_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
task_gui_dir="$task_root/target/host-desktop"
task_cargo_dir="$task_root/target/host"
# Resolve rust-toolchain.toml and Cargo configuration from this checkout even
# when invoked from another directory. Ignore a caller's unrelated target dir.
cd -- "$task_root"
CARGO_TARGET_DIR="$task_cargo_dir" cargo build --release --locked
cmake -S "$task_root/desktop" -B "$task_gui_dir" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build "$task_gui_dir" --parallel 2

if [[ "$task_action" == build ]]; then
    printf '%s\n' 'Built the YubiQuity backend and desktop app.'
    exit 0
fi

# Never launch a previous executable after a failed build (set -e above), or
# silently hand this launch to an already-running, potentially older GUI.
exec "$task_gui_dir/yubiquity-desktop" \
    --backend "$task_cargo_dir/release/yubiquity" --require-new-instance "$@"
