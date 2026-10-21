//! Best-effort Android logd transport for the static-musl argv bridge.
//! Only bounded project metadata is accepted. No argv, console or credentials.
//! Wire header: system/logging/liblog/include/private/android_logger.h.
use std::{
    os::unix::net::UnixDatagram,
    time::{SystemTime, UNIX_EPOCH},
};

const TAG: &[u8] = b"GB-RUNTIME\0";
const PREFIX: &str = "gb-runtime-adapter: ";

fn packet(message: &str, tid: u16, seconds: u32, nanos: u32) -> Option<Vec<u8>> {
    if !message.starts_with(PREFIX)
        || message.len() > 512
        || message.bytes().any(|b| b < 32 || b == 127)
        || nanos >= 1_000_000_000
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(11 + 1 + TAG.len() + message.len() + 1);
    bytes.push(3); // LOG_ID_SYSTEM
    bytes.extend_from_slice(&tid.to_le_bytes());
    bytes.extend_from_slice(&seconds.to_le_bytes());
    bytes.extend_from_slice(&nanos.to_le_bytes());
    bytes.push(4); // ANDROID_LOG_INFO
    bytes.extend_from_slice(TAG);
    bytes.extend_from_slice(message.as_bytes());
    bytes.push(0);
    Some(bytes)
}

fn send_to(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let socket = UnixDatagram::unbound()?;
    socket.set_nonblocking(true)?;
    socket.send_to(bytes, path)?;
    Ok(())
}

pub fn emit(message: &str) {
    eprintln!("{message}");
    let Ok(time) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return;
    };
    let Ok(seconds) = u32::try_from(time.as_secs()) else {
        return;
    };
    // The bridge is single-threaded; after exec the main TID equals the PID.
    // Android's packed logd header truncates gettid() to uint16_t as liblog does.
    let Some(bytes) = packet(
        message,
        std::process::id() as u16,
        seconds,
        time.subsec_nanos(),
    ) else {
        return;
    };
    // Missing/denied/full logging must never affect VM execution or block it.
    let _ = send_to(std::path::Path::new("/dev/socket/logdw"), &bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packed_logd_header_and_payload_match_platform_wire() {
        let message = "gb-runtime-adapter: fixture=true";
        let bytes = packet(message, 0x1234, 0x55667788, 123).unwrap();
        assert_eq!(
            &bytes[..11],
            &[3, 0x34, 0x12, 0x88, 0x77, 0x66, 0x55, 123, 0, 0, 0]
        );
        assert_eq!(bytes[11], 4);
        assert_eq!(&bytes[12..23], TAG);
        assert_eq!(&bytes[23..], [message.as_bytes(), b"\0"].concat());
    }
    #[test]
    fn rejects_unowned_unbounded_or_multiline_metadata() {
        for message in [
            "",
            "fixture-opaque-private",
            "gb-runtime-adapter: x\0y",
            "gb-runtime-adapter: x\ny",
            "gb-runtime-adapter: x\ry",
        ] {
            assert!(packet(message, 1, 1, 1).is_none());
        }
        assert!(packet(&format!("{PREFIX}{}", "x".repeat(512)), 1, 1, 1).is_none());
        assert!(packet(PREFIX, 1, 1, 1_000_000_000).is_none());
    }
    #[test]
    fn datagram_transport_preserves_one_bounded_record() {
        let path = std::env::temp_dir().join(format!(
            "gb-logd-fixture-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let bytes = packet("gb-runtime-adapter: fixture=true", 2, 3, 4).unwrap();
        send_to(&path, &bytes).unwrap();
        let mut output = [0; 1024];
        let count = receiver.recv(&mut output).unwrap();
        assert_eq!(&output[..count], &bytes);
        std::fs::remove_file(path).unwrap();
    }
}
