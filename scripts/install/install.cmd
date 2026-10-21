@echo off
setlocal
set "GB_INSTALL_ROOT=%~dp0..\.."
if exist "%~dp0gb-install.exe" goto bundled
where cargo >nul 2>nul
if errorlevel 1 goto missing_cargo
cargo run --release --locked --manifest-path "%GB_INSTALL_ROOT%\Cargo.toml" -p gb-installer -- %*
exit /b %ERRORLEVEL%
:bundled
"%~dp0gb-install.exe" %*
exit /b %ERRORLEVEL%
:missing_cargo
echo Install Rust stable or place the matching gb-install.exe beside this script. 1>&2
exit /b 1
