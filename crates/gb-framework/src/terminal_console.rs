//! Evidence parser for the owned read-only Debian PID1 diagnostic fixture.
//! Prompt prefixes are permitted, but echoed commands are never execution proof.
use anyhow::{Result, ensure};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NativeConsoleReport {
    pub guest_commands_verified: bool,
    pub normal_shutdown_verified: bool,
    pub guest_memtotal_kib: Option<u64>,
    pub requested_memory_mib: u32,
}

fn output_line(mut s: &str) -> &str {
    s = s.trim_end_matches('\r');
    // An interactive PID1 shell may emit several prompts before buffered output.
    // Bound normalization; never remove command words or arbitrary punctuation.
    for _ in 0..4 {
        match s.strip_prefix("# ") {
            Some(rest) => s = rest,
            None => break,
        }
    }
    s
}

pub fn inspect_native_console(
    console: &str,
    client: &str,
    memory_mib: u32,
) -> Result<NativeConsoleReport> {
    ensure!(
        matches!(memory_mib, 512 | 2048),
        "unsupported diagnostic memory size"
    );
    ensure!(
        console.len() <= 4 * 1024 * 1024 && client.len() <= 4 * 1024 * 1024,
        "diagnostic log exceeds bound"
    );
    let lines: Vec<_> = console.lines().map(output_line).collect();
    let ready = lines.iter().position(|s| *s == "GB_RUNTIME_READY");
    let linux = lines
        .iter()
        .position(|s| s.starts_with("Linux ") && s.ends_with(" aarch64 GNU/Linux"));
    let debian = lines.iter().position(|s| *s == "13.7");
    let mem = lines.iter().enumerate().find_map(|(i, s)| {
        let mut fields = s.strip_prefix("MemTotal:")?.split_whitespace();
        let kib = fields.next()?.parse::<u64>().ok()?;
        (fields.next() == Some("kB") && fields.next().is_none()).then_some((i, kib))
    });
    let done = lines.iter().position(|s| *s == "GB_RUNTIME_COMMANDS_DONE");
    let power = lines
        .iter()
        .position(|s| *s == "GB_RUNTIME_POWEROFF_REQUEST");
    let commands = match (ready, linux, debian, mem, done, power) {
        (Some(a), Some(b), Some(c), Some((d, kib)), Some(e), Some(f)) => {
            a < b
                && b < c
                && c < d
                && d < e
                && e < f
                && u64::from(memory_mib - 128) * 1024 <= kib
                && kib <= u64::from(memory_mib) * 1024
                && console.contains("Run /bin/sh as init process")
        }
        _ => false,
    };
    Ok(NativeConsoleReport {
        guest_commands_verified: commands,
        normal_shutdown_verified: commands
            && lines.contains(&"Powering off.")
            && console.contains("reboot: Power down")
            && client
                .lines()
                .any(|s| s.trim_end_matches('\r') == "VM ended: Shutdown"),
        guest_memtotal_kib: mem.map(|(_, kib)| kib),
        requested_memory_mib: memory_mib,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence(prompt: &str, kib: u64) -> String {
        format!(
            "Run /bin/sh as init process\necho GB_RUNTIME_READY\n{prompt}GB_RUNTIME_READY\n{prompt}Linux probe 6.12 aarch64 GNU/Linux\n{prompt}13.7\n{prompt}MemTotal: {kib} kB\n{prompt}GB_RUNTIME_COMMANDS_DONE\n{prompt}GB_RUNTIME_POWEROFF_REQUEST\n{prompt}Powering off.\nreboot: Power down\n"
        )
    }
    #[test]
    fn verifies_prompted_and_unprompted_execution_and_actual_size() {
        for prompt in ["", "# ", "# # "] {
            let r = inspect_native_console(&evidence(prompt, 466648), "VM ended: Shutdown\n", 512)
                .unwrap();
            assert!(r.guest_commands_verified && r.normal_shutdown_verified);
            assert_eq!(r.guest_memtotal_kib, Some(466648));
        }
        assert!(
            !inspect_native_console(&evidence("# ", 466648), "VM ended: Shutdown", 2048)
                .unwrap()
                .guest_commands_verified
        );
    }
    #[test]
    fn echoed_input_crash_and_missing_or_reordered_output_do_not_pass() {
        let echoed = "Run /bin/sh as init process\n# echo GB_RUNTIME_READY\n# uname -a\n# cat /etc/debian_version\n# grep MemTotal /proc/meminfo\n# echo GB_RUNTIME_COMMANDS_DONE\n# echo GB_RUNTIME_POWEROFF_REQUEST\n# /sbin/poweroff -ff\n";
        assert!(
            !inspect_native_console(echoed, "VM ended: Shutdown", 512)
                .unwrap()
                .guest_commands_verified
        );
        let good = evidence("# ", 466648);
        assert!(
            !inspect_native_console(&good, "VM ended: Crash", 512)
                .unwrap()
                .normal_shutdown_verified
        );
        assert!(
            !inspect_native_console(&good.replace("# 13.7\n", ""), "VM ended: Shutdown", 512)
                .unwrap()
                .guest_commands_verified
        );
        assert!(
            !inspect_native_console(
                &good.replace("GB_RUNTIME_READY", "GB_RUNTIME_COMMANDS_DONE"),
                "VM ended: Shutdown",
                512
            )
            .unwrap()
            .guest_commands_verified
        );
    }
}
