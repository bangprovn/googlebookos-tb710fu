use gb_image::metadata::inode;
use std::io::Cursor;
fn fixture() -> Vec<u8> {
    let mut b = vec![0; 131072];
    let s = &mut b[1024..1152];
    s[..4].copy_from_slice(&0xe0f5e1e2u32.to_le_bytes());
    s[12] = 12;
    s[24..32].copy_from_slice(&1230768000u64.to_le_bytes());
    s[36..40].copy_from_slice(&32u32.to_le_bytes());
    let i = &mut b[4096..4160];
    i[..2].copy_from_slice(&1u16.to_le_bytes());
    i[2..4].copy_from_slice(&11u16.to_le_bytes());
    i[4..6].copy_from_slice(&0o100750u16.to_le_bytes());
    i[8..16].copy_from_slice(&512u64.to_le_bytes());
    i[24..28].copy_from_slice(&123456u32.to_le_bytes());
    i[28..32].copy_from_slice(&4002u32.to_le_bytes());
    i[32..40].copy_from_slice(&1230768001u64.to_le_bytes());
    i[40..44].copy_from_slice(&1234u32.to_le_bytes());
    i[44..48].copy_from_slice(&1u32.to_le_bytes());
    // 12-byte header + shared id + 36-byte capability entry = 52 bytes.
    b[4164] = 1;
    b[4172..4176].copy_from_slice(&16384u32.to_le_bytes());
    b[4176] = 10;
    b[4177] = 6;
    b[4178..4180].copy_from_slice(&20u16.to_le_bytes());
    b[4180..4190].copy_from_slice(b"capability");
    b[4190..4210].copy_from_slice(&[3, 0, 0, 2, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[65536] = 7;
    b[65537] = 6;
    b[65538..65540].copy_from_slice(&26u16.to_le_bytes());
    b[65540..65547].copy_from_slice(b"selinux");
    b[65547..65573].copy_from_slice(b"u:object_r:system_file:s0\0");
    b
}
#[test]
fn extended_owner_timestamp_and_binary_xattrs_are_preserved() {
    let b = fixture();
    let m = inode(&mut Cursor::new(b), 128).unwrap();
    assert_eq!(m.uid, 123456);
    assert_eq!(m.gid, 4002);
    assert_eq!(m.mode, 0o100750);
    assert_eq!(m.mtime_nsec, 1234);
    assert_eq!(m.xattrs["security.capability"].len(), 20);
    assert_eq!(m.xattrs["security.selinux"].len(), 26);
}
#[test]
fn truncated_and_unsupported_metadata_is_rejected() {
    let mut b = fixture();
    b[4177] = 0x80;
    assert!(inode(&mut Cursor::new(b), 128).is_err());
    let mut b = fixture();
    b.truncate(4190);
    assert!(inode(&mut Cursor::new(b), 128).is_err());
    assert!(inode(&mut Cursor::new(fixture()), u64::MAX).is_err());
}
fn directory_fixture() -> Vec<u8> {
    let mut b = fixture();
    b[1038..1040].copy_from_slice(&128u16.to_le_bytes());
    let inode = &mut b[4096..4160];
    inode[..2].copy_from_slice(&5u16.to_le_bytes()); // extended, flat-inline
    inode[2..4].copy_from_slice(&0u16.to_le_bytes());
    inode[4..6].copy_from_slice(&0o040755u16.to_le_bytes());
    inode[8..16].copy_from_slice(&29u64.to_le_bytes());
    let d = &mut b[4160..4189];
    d.fill(0);
    d[..8].copy_from_slice(&128u64.to_le_bytes());
    d[8..10].copy_from_slice(&24u16.to_le_bytes());
    d[10] = 2;
    d[12..20].copy_from_slice(&160u64.to_le_bytes());
    d[20..22].copy_from_slice(&25u16.to_le_bytes());
    d[22] = 1;
    d[24..29].copy_from_slice(b".file");
    let child = &mut b[5120..5184];
    child.fill(0);
    child[..2].copy_from_slice(&1u16.to_le_bytes());
    child[4..6].copy_from_slice(&0o100644u16.to_le_bytes());
    child[44..48].copy_from_slice(&1u32.to_le_bytes());
    b
}
#[test]
fn flat_inline_directory_inventory_preserves_paths_and_inode_identity() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), directory_fixture()).unwrap();
    let entries = gb_image::metadata::inventory(file.path()).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries["/file"].nid, 160);
    assert_eq!(entries["/"].metadata.uid, 123456);
}
#[test]
fn directory_inventory_rejects_invalid_name_bounds_and_cycles() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut b = directory_fixture();
    b[4180..4182].copy_from_slice(&200u16.to_le_bytes());
    std::fs::write(file.path(), b).unwrap();
    assert!(gb_image::metadata::inventory(file.path()).is_err());
    let mut b = directory_fixture();
    b[4172..4180].copy_from_slice(&128u64.to_le_bytes());
    std::fs::write(file.path(), b).unwrap();
    assert!(gb_image::metadata::inventory(file.path()).is_err());
}
