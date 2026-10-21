#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast
cargo test --locked -p gb-boot-logger --example crosvm_runtime_adapter --example terminal_mount_worker
cargo build --release --locked -p gb-cli -p gb-installer
