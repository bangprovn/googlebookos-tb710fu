//! Exact-build development adapter for the mica CL3B crosvm IRQ allocator.
//!
//! A source-equivalent `first_irq = 16` leaves the fixed watchdog IRQ 15 out of
//! PCI allocation. Mixed edge/level IRQ producers must still be rejected by the
//! kernel. No firmware, APEX signature, guest authentication or library ABI is
//! changed by this offline operation. Unknown donor builds are refused.
use anyhow::{Context, Result, ensure};
use std::{fs, io::Read, path::Path};

pub const INPUT_SHA256: &str = "cc9f1e31025f2826ae050d025c363c885c0d055bff42c18701a2aa507c28fb52";
const INPUT_BYTES: u64 = 13_417_312;
const FUNCTION: usize = 0x45cfb8;
const FUNCTION_BYTES: usize = 0x1b0;
const FUNCTION_SHA256: &str = "522d266c41c79250a334611c4dc8c875db921b3b785652ae72bf41240f321c51";
const INSTRUCTION: usize = 0x45d0b8;
const BUILD_ID: usize = 0x2e8;
const OLD_BUILD_ID: &str = "3fcd48de8a88e347b6992edb43ae55b3";

fn bytes(b: &[u8], p: usize, n: usize) -> Result<&[u8]> {
    b.get(p..p.checked_add(n).context("ELF offset overflow")?)
        .context("truncated crosvm ELF")
}
fn u64v(b: &[u8], p: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes(b, p, 8)?.try_into()?))
}
fn u16v(b: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes(b, p, 2)?.try_into()?))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|n| format!("{n:02x}")).collect()
}

fn apply(b: &mut [u8]) -> Result<String> {
    ensure!(
        bytes(b, 0, 7)? == b"\x7fELF\x02\x01\x01",
        "ELF64 LE required"
    );
    ensure!(
        u16v(b, 16)? == 3 && u16v(b, 18)? == 183,
        "AArch64 ET_DYN required"
    );
    let phoff = usize::try_from(u64v(b, 32)?)?;
    let entsize = usize::from(u16v(b, 54)?);
    let count = usize::from(u16v(b, 56)?);
    ensure!(entsize == 56 && count <= 64, "unsupported program headers");
    let mut executable_mapping = 0;
    for i in 0..count {
        let p = phoff
            .checked_add(i * entsize)
            .context("program header overflow")?;
        let h = bytes(b, p, 56)?;
        let kind = u32::from_le_bytes(h[0..4].try_into()?);
        let flags = u32::from_le_bytes(h[4..8].try_into()?);
        let file = u64v(h, 8)?;
        let va = u64v(h, 16)?;
        let size = u64v(h, 32)?;
        if kind == 1
            && flags & 1 != 0
            && file == va
            && file <= FUNCTION as u64
            && file
                .checked_add(size)
                .is_some_and(|end| end >= (FUNCTION + FUNCTION_BYTES) as u64)
        {
            executable_mapping += 1;
        }
    }
    ensure!(
        executable_mapping == 1,
        "allocator executable mapping differs"
    );
    ensure!(
        bytes(b, INSTRUCTION, 4)? == [0x88, 0, 0x80, 0x52],
        "first_irq MOVZ differs"
    );
    ensure!(
        bytes(b, INSTRUCTION + 16, 4)? == [0x68, 0x52, 0, 0xb9],
        "first_irq store differs"
    );
    ensure!(
        bytes(b, BUILD_ID - 16, 16)? == [4, 0, 0, 0, 16, 0, 0, 0, 3, 0, 0, 0, 71, 78, 85, 0],
        "GNU build-id note differs"
    );
    ensure!(
        hex(bytes(b, BUILD_ID, 16)?) == OLD_BUILD_ID,
        "original build-id differs"
    );
    b[INSTRUCTION..INSTRUCTION + 4].copy_from_slice(&[0x08, 0x02, 0x80, 0x52]);
    // Retain the note length and all offsets; identify this modified binary with
    // the first 128 bits of SHA256 over its bytes with the descriptor zeroed.
    b[BUILD_ID..BUILD_ID + 16].fill(0);
    let id = gb_core::digest(b);
    let new_id: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&id[2 * i..2 * i + 2], 16))
        .collect::<std::result::Result<_, _>>()?;
    b[BUILD_ID..BUILD_ID + 16].copy_from_slice(&new_id);
    Ok(hex(&new_id))
}

/// Publish a new binary and provenance atomically, preserving the original.
pub fn prepare(input: &Path, output: &Path) -> Result<()> {
    ensure!(!output.exists(), "output already exists");
    gb_core::separate_from_input(input, output)?;
    let meta = fs::symlink_metadata(input)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() == INPUT_BYTES,
        "regular exact-size donor crosvm required"
    );
    let mut b = Vec::new();
    fs::File::open(input)?
        .take(INPUT_BYTES + 1)
        .read_to_end(&mut b)?;
    ensure!(
        gb_core::digest(&b) == INPUT_SHA256,
        "unsupported crosvm SHA256"
    );
    ensure!(
        gb_core::digest(bytes(&b, FUNCTION, FUNCTION_BYTES)?) == FUNCTION_SHA256,
        "allocator function hash differs"
    );
    let original = b.clone();
    let build_id = apply(&mut b)?;
    ensure!(
        original.iter().zip(&b).enumerate().all(|(i, (a, b))| a == b
            || (INSTRUCTION..INSTRUCTION + 4).contains(&i)
            || (BUILD_ID..BUILD_ID + 16).contains(&i)),
        "unexpected byte change"
    );
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let binary = staging.path().join("crosvm");
    fs::write(&binary, &b)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
    }
    fs::File::open(&binary)?.sync_all()?;
    gb_core::write_json(
        &staging.path().join("adapter-report.json"),
        &serde_json::json!({
            "schema_version":1,"id":"mica-cl3b-gunyah-irq-floor-v1",
            "source_sha256":INPUT_SHA256,"output_sha256":gb_core::digest(&b),
            "original_allocator_sha256":FUNCTION_SHA256,"instruction_file_offset":INSTRUCTION,
            "old_instruction":"88008052","new_instruction":"08028052",
            "first_irq_before":4,"first_irq_after":16,"reserved_watchdog_irq":15,
            "old_build_id":OLD_BUILD_ID,"new_build_id":build_id,
            "build_id_scheme":"first 128 bits of SHA256 with build-id descriptor zeroed",
            "source_reference_commit":"c7dd8d6950912fa5e6fde7ec2d1616e0ddc090f8",
            "source_equivalent":"aarch64/src/lib.rs: SystemAllocatorConfig.first_irq = 16",
            "runtime_verified":false,"terminal_verified":false,"firmware_written":false,
            "limitations":["Requires separate CPU emulation and device validation","Does not resolve memory allocation, guest signing or other hardware interfaces","Install only as an explicitly declared development override; original APEX is unchanged"]
        }),
    )?;
    ensure!(
        gb_core::hash_file(input)? == INPUT_SHA256,
        "donor changed during adaptation"
    );
    gb_core::publish_directory(staging.path(), output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut b = vec![0; FUNCTION + FUNCTION_BYTES + 64];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[16..18].copy_from_slice(&3u16.to_le_bytes());
        b[18..20].copy_from_slice(&183u16.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&5u32.to_le_bytes());
        b[96..104].copy_from_slice(&((FUNCTION + FUNCTION_BYTES + 64) as u64).to_le_bytes());
        b[INSTRUCTION..INSTRUCTION + 4].copy_from_slice(&[0x88, 0, 0x80, 0x52]);
        b[INSTRUCTION + 16..INSTRUCTION + 20].copy_from_slice(&[0x68, 0x52, 0, 0xb9]);
        b[BUILD_ID - 16..BUILD_ID]
            .copy_from_slice(&[4, 0, 0, 0, 16, 0, 0, 0, 3, 0, 0, 0, 71, 78, 85, 0]);
        for i in 0..16 {
            b[BUILD_ID + i] = u8::from_str_radix(&OLD_BUILD_ID[2 * i..2 * i + 2], 16).unwrap();
        }
        b
    }
    #[test]
    fn only_changes_allocator_immediate_and_build_identity() {
        let original = fixture();
        let mut b = original.clone();
        let id = apply(&mut b).unwrap();
        assert_ne!(id, OLD_BUILD_ID);
        assert_eq!(&b[INSTRUCTION..INSTRUCTION + 4], &[8, 2, 128, 82]);
        for i in 0..b.len() {
            if !(INSTRUCTION..INSTRUCTION + 4).contains(&i)
                && !(BUILD_ID..BUILD_ID + 16).contains(&i)
            {
                assert_eq!(b[i], original[i]);
            }
        }
        assert!(apply(&mut b).is_err());
    }
    #[test]
    fn refuses_wrong_arch_mapping_opcode_and_truncation() {
        for offset in [18, 68, INSTRUCTION, INSTRUCTION + 16, BUILD_ID] {
            let mut b = fixture();
            b[offset] ^= 1;
            assert!(apply(&mut b).is_err(), "offset {offset}");
        }
        for n in [0, 20, 64, 120, BUILD_ID + 3, INSTRUCTION + 2] {
            assert!(apply(&mut fixture()[..n]).is_err());
        }
    }
    #[test]
    fn refuses_unpinned_firmware_without_publishing() {
        let d = tempfile::tempdir().unwrap();
        let input = d.path().join("input");
        let out = d.path().join("output");
        fs::write(&input, fixture()).unwrap();
        assert!(prepare(&input, &out).is_err());
        assert!(!out.exists());
    }
}
