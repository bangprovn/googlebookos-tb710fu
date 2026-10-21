# Windows launcher. Rust owns preparation, validation and flashing.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$bundled = Join-Path $PSScriptRoot 'gb-install.exe'
$built = Join-Path $root 'target/release/gb-install.exe'
if (Test-Path -LiteralPath $bundled -PathType Leaf) {
    & $bundled @args
} elseif (Test-Path -LiteralPath $built -PathType Leaf) {
    & $built @args
} else {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'Install Rust stable or place the matching gb-install.exe beside this script.'
    }
    & cargo run --release --locked --manifest-path (Join-Path $root 'Cargo.toml') -p gb-installer -- @args
}
exit $LASTEXITCODE
