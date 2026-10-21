#!/bin/sh
# Linux and macOS launcher. Rust owns preparation, validation and flashing.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
if [ -x "$script_dir/gb-install" ]; then
    exec "$script_dir/gb-install" "$@"
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo 'Install Rust stable or place the matching gb-install binary beside this script.' >&2
    exit 1
fi
exec cargo run --release --locked --manifest-path "$root/Cargo.toml" -p gb-installer -- "$@"
