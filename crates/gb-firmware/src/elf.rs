//! Bounded native dependency inspection using Goblin's ELF record parsers.
//! Reads program headers, PT_DYNAMIC and its string table, never the whole library.
use anyhow::{Context, Result, ensure};
use gb_core::NativeLibrary;
use gb_partition::{ReadSeek, read_at};
use goblin::{
    container::Ctx,
    elf::{
        dynamic::{DT_NEEDED, DT_NULL, DT_SONAME, DT_STRSZ, DT_STRTAB, Dynamic},
        header::Header,
        program_header::{PT_DYNAMIC, PT_LOAD, ProgramHeader},
    },
};
use std::io::SeekFrom;
#[derive(Debug)]
pub struct ExternalSegments;
impl std::fmt::Display for ExternalSegments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ELF program data resides outside this header file")
    }
}
impl std::error::Error for ExternalSegments {}
#[derive(Debug)]
pub struct UnsupportedMachine(pub u16);
impl std::fmt::Display for UnsupportedMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ELF machine {} is outside the supported Android userspace ABIs",
            self.0
        )
    }
}
impl std::error::Error for UnsupportedMachine {}

fn bounds(offset: u64, size: u64, len: u64) -> Result<()> {
    ensure!(
        offset.checked_add(size).is_some_and(|end| end <= len),
        "ELF metadata exceeds file bounds"
    );
    Ok(())
}
fn mapped(phdrs: &[ProgramHeader], address: u64, size: u64, len: u64) -> Result<u64> {
    let mut offsets = std::collections::BTreeSet::new();
    for p in phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        if let Some(relative) = address.checked_sub(p.p_vaddr)
            && relative
                .checked_add(size)
                .is_some_and(|end| end <= p.p_filesz)
        {
            let offset = p
                .p_offset
                .checked_add(relative)
                .context("ELF mapping overflow")?;
            bounds(offset, size, len)?;
            offsets.insert(offset);
        }
    }
    ensure!(
        offsets.len() == 1,
        "ELF dynamic address has no unique file-backed LOAD mapping"
    );
    offsets.first().copied().context("ELF mapping unavailable")
}
fn string(table: &[u8], offset: u64) -> Result<String> {
    let start = usize::try_from(offset).context("ELF string offset overflow")?;
    let tail = table
        .get(start..)
        .context("ELF string offset outside table")?;
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .context("unterminated ELF dynamic string")?;
    ensure!(end <= 4096, "ELF dependency name exceeds limit");
    let name = std::str::from_utf8(&tail[..end]).context("non-UTF8 ELF dependency name")?;
    ensure!(
        !name.is_empty() && !name.chars().any(char::is_control),
        "invalid ELF dependency name"
    );
    Ok(name.into())
}
pub fn inspect_native(r: &mut dyn ReadSeek, path: &str) -> Result<NativeLibrary> {
    let len = r.seek(SeekFrom::End(0))?;
    let prefix = read_at(r, 0, len.min(64) as usize)?;
    let header: goblin::elf::header::Header =
        goblin::elf::Elf::parse_header(&prefix).context("invalid ELF header")?;
    ensure!(
        &header.e_ident[..4] == b"\x7fELF" && header.e_ident[6] == 1 && header.e_version == 1,
        "invalid ELF identification/version"
    );
    if ![183, 40, 62, 3].contains(&header.e_machine) {
        return Err(UnsupportedMachine(header.e_machine).into());
    }
    let ctx = Ctx::new(header.container()?, header.endianness()?);
    ensure!(
        header.e_ehsize as usize == Header::size(ctx),
        "invalid ELF header size"
    );
    ensure!(
        header.e_phnum <= 4096,
        "ELF program-header count exceeds limit or uses unsupported extended numbering"
    );
    let phdrs = if header.e_phnum == 0 {
        vec![]
    } else {
        ensure!(
            header.e_phentsize as usize == ProgramHeader::size(ctx),
            "invalid ELF program-header size"
        );
        let size = header.e_phnum as usize * ProgramHeader::size(ctx);
        bounds(header.e_phoff, size as u64, len)?;
        ProgramHeader::parse(
            &read_at(r, header.e_phoff, size)?,
            0,
            header.e_phnum as usize,
            ctx,
        )?
    };
    for p in &phdrs {
        if p.p_type == PT_LOAD
            && p.p_filesz > 0
            && p.p_offset
                .checked_add(p.p_filesz)
                .is_none_or(|end| end > len)
            && !phdrs.iter().any(|p| p.p_type == PT_DYNAMIC)
        {
            return Err(ExternalSegments.into());
        }
        if p.p_filesz == 0 {
            continue;
        }
        bounds(p.p_offset, p.p_filesz, len)?;
        if p.p_type == PT_LOAD {
            ensure!(
                p.p_filesz <= p.p_memsz,
                "ELF LOAD file size exceeds memory size"
            );
        }
    }
    let mut result = NativeLibrary {
        path: path.into(),
        architecture: match header.e_machine {
            183 => "aarch64",
            40 => "arm",
            62 => "x86_64",
            3 => "x86",
            _ => "unknown",
        }
        .into(),
        soname: None,
        needed: vec![],
    };
    let dynamic = phdrs
        .iter()
        .filter(|p| p.p_type == PT_DYNAMIC)
        .collect::<Vec<_>>();
    ensure!(dynamic.len() <= 1, "multiple ELF dynamic segments");
    let Some(p) = dynamic.first() else {
        return Ok(result);
    };
    let entry = goblin::elf::dynamic::Dyn::size(header.container()?);
    ensure!(
        p.p_filesz > 0 && p.p_filesz <= 1024 * 1024 && p.p_filesz % entry as u64 == 0,
        "invalid or oversized ELF dynamic segment"
    );
    let bytes = read_at(r, p.p_offset, p.p_filesz as usize)?;
    let mut rebased = (*p).clone();
    rebased.p_offset = 0;
    let parsed = Dynamic::parse(&bytes, &[rebased], ctx)?.context("ELF dynamic segment missing")?;
    ensure!(
        parsed.dyns.last().is_some_and(|d| d.d_tag == DT_NULL),
        "ELF dynamic segment lacks DT_NULL terminator"
    );
    let single = |tag| -> Result<Option<u64>> {
        let values = parsed
            .dyns
            .iter()
            .filter(|d| d.d_tag == tag)
            .map(|d| d.d_val)
            .collect::<Vec<_>>();
        ensure!(values.len() <= 1, "duplicate ELF singleton dynamic tag");
        Ok(values.first().copied())
    };
    let strtab = single(DT_STRTAB)?;
    let strsz = single(DT_STRSZ)?;
    let soname = single(DT_SONAME)?;
    let needed = parsed
        .dyns
        .iter()
        .filter(|d| d.d_tag == DT_NEEDED)
        .collect::<Vec<_>>();
    ensure!(needed.len() <= 4096, "ELF dependency count exceeds limit");
    if needed.is_empty() && soname.is_none() {
        return Ok(result);
    }
    let size = strsz.context("ELF dependency table lacks DT_STRSZ")?;
    ensure!(
        size > 0 && size <= 16 * 1024 * 1024,
        "ELF dynamic string table exceeds metadata budget"
    );
    let offset = mapped(
        &phdrs,
        strtab.context("ELF dependency table lacks DT_STRTAB")?,
        size,
        len,
    )?;
    let table = read_at(r, offset, size as usize)?;
    result.soname = soname.map(|off| string(&table, off)).transpose()?;
    for d in needed {
        result.needed.push(string(&table, d.d_val)?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek};
    fn fixture(offset: u64) -> Vec<u8> {
        let mut b = vec![0; 512];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[16..18].copy_from_slice(&3u16.to_le_bytes());
        b[18..20].copy_from_slice(&183u16.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (start, kind, filesz) in [(64, PT_LOAD, 64u64), (120, PT_DYNAMIC, 80)] {
            b[start..start + 4].copy_from_slice(&kind.to_le_bytes());
            b[start + 8..start + 16]
                .copy_from_slice(&(if kind == PT_LOAD { offset } else { 256 }).to_le_bytes());
            b[start + 16..start + 24].copy_from_slice(&0x10000u64.to_le_bytes());
            b[start + 32..start + 40].copy_from_slice(&filesz.to_le_bytes());
            b[start + 40..start + 48].copy_from_slice(&filesz.to_le_bytes());
        }
        for (i, tag, value) in [
            (0, DT_STRTAB, 0x10000),
            (1, DT_STRSZ, 64),
            (2, DT_NEEDED, 1),
            (3, DT_SONAME, 14),
            (4, DT_NULL, 0),
        ] {
            b[256 + i * 16..264 + i * 16].copy_from_slice(&tag.to_le_bytes());
            b[264 + i * 16..272 + i * 16].copy_from_slice(&(value as u64).to_le_bytes());
        }
        b
    }
    #[test]
    fn reads_large_library_metadata_without_reading_the_image() {
        struct Counted {
            file: std::fs::File,
            bytes: usize,
        }
        impl Read for Counted {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                let n = self.file.read(b)?;
                self.bytes += n;
                Ok(n)
            }
        }
        impl Seek for Counted {
            fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
                self.file.seek(p)
            }
        }
        use std::io::Write;
        let mut file = tempfile::tempfile().unwrap();
        file.set_len(2 * 1024 * 1024 * 1024).unwrap();
        file.write_all(&fixture(1024 * 1024 * 1024)).unwrap();
        file.seek(SeekFrom::Start(1024 * 1024 * 1024)).unwrap();
        file.write_all(b"\0libneeded.so\0libself.so\0").unwrap();
        let mut r = Counted { file, bytes: 0 };
        let l = inspect_native(&mut r, "libself.so").unwrap();
        assert_eq!(l.architecture, "aarch64");
        assert_eq!(l.soname.as_deref(), Some("libself.so"));
        assert_eq!(l.needed, vec!["libneeded.so"]);
        assert!(r.bytes < 1024);
    }
    #[test]
    fn refuses_unmapped_strings_and_unterminated_dynamic_tables() {
        let b = fixture(1024);
        assert!(inspect_native(&mut std::io::Cursor::new(b), "bad").is_err());
        let mut b = fixture(400);
        b[320..328].copy_from_slice(&DT_NEEDED.to_le_bytes());
        assert!(inspect_native(&mut std::io::Cursor::new(b), "bad").is_err());
    }
}
