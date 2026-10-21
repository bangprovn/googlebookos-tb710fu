//! Emit one fixed owner diagnostic marker; a separate logcat read must verify receipt.
#[path = "support/android_metadata_log.rs"]
mod android_metadata_log;
fn main() {
    if std::env::args_os().len() != 1 {
        std::process::exit(64);
    }
    android_metadata_log::emit("gb-runtime-adapter: logd_transport_fixture=true");
}
