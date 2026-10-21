//! Real AOSP/OpenSSL signing with a simulated USB backend. Never uses real USB.
#![cfg(unix)]
use gb_core::hash_file;
use gb_installer::{
    Fastboot, Prepare,
    avb::{Metadata, Tools},
};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

fn run(program: &str, args: &[String]) {
    let o = Command::new(program).args(args).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}
fn avb(script: &Path, args: &[String]) {
    let mut a = vec![script.display().to_string()];
    a.extend_from_slice(args);
    run("python3", &a);
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    package: PathBuf,
    work: PathBuf,
    fb: Fastboot,
    tools: Tools,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().to_owned();
        let package = root.join("package");
        let device = root.join("device");
        let work = root.join("work");
        fs::create_dir(&package).unwrap();
        fs::create_dir(&device).unwrap();
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../third_party/avb/avbtool.py")
            .canonicalize()
            .unwrap();
        let key = root.join("key.pem");
        let pubkey = root.join("key.pub");
        run(
            "openssl",
            &[
                "genrsa".into(),
                "-out".into(),
                key.display().to_string(),
                "2048".into(),
            ],
        );
        avb(
            &script,
            &[
                "extract_public_key".into(),
                "--key".into(),
                key.display().to_string(),
                "--output".into(),
                pubkey.display().to_string(),
            ],
        );
        for name in gb_installer::PARTITIONS {
            let image = root.join(format!("{name}.img"));
            if ["vbmeta", "vbmeta_system"].contains(name) {
                let mut a = vec![
                    "make_vbmeta_image".into(),
                    "--output".into(),
                    image.display().to_string(),
                    "--algorithm".into(),
                    "SHA256_RSA2048".into(),
                    "--key".into(),
                    key.display().to_string(),
                    "--padding_size".into(),
                    "4096".into(),
                ];
                if *name == "vbmeta" {
                    for (n, l) in [("boot", 1), ("recovery", 2), ("vbmeta_system", 3)] {
                        a.extend([
                            "--chain_partition".into(),
                            format!("{n}:{l}:{}", pubkey.display()),
                        ]);
                    }
                }
                avb(&script, &a);
            } else {
                fs::write(&image, vec![17_u8; 4096]).unwrap();
                avb(
                    &script,
                    &[
                        "add_hash_footer".into(),
                        "--image".into(),
                        image.display().to_string(),
                        "--partition_name".into(),
                        (*name).into(),
                        "--partition_size".into(),
                        "131072".into(),
                        "--algorithm".into(),
                        "SHA256_RSA2048".into(),
                        "--key".into(),
                        key.display().to_string(),
                        "--salt".into(),
                        "11".into(),
                    ],
                );
            }
        }
        let tools = Tools {
            python: "python3".into(),
            avbtool: script,
            openssl: "openssl".into(),
        };
        for (name, index) in [("vbmeta", 42), ("vbmeta_system", 61), ("boot", 7)] {
            tools
                .resign(
                    &root.join(format!("{name}.img")),
                    &device.join(format!("{name}.img")),
                    &key,
                    index,
                )
                .unwrap();
        }
        let mut entries = serde_json::Map::new();
        for name in gb_installer::PARTITIONS {
            let image = root.join(format!("{name}.img"));
            let gz = package.join(format!("{name}.img.gz"));
            let data = fs::read(&image).unwrap();
            let mut enc = flate2::GzBuilder::new()
                .mtime(0)
                .write(fs::File::create(&gz).unwrap(), flate2::Compression::fast());
            enc.write_all(&data).unwrap();
            enc.finish().unwrap();
            entries.insert((*name).into(),json!({"filename":format!("{name}.img.gz"),"bytes":fs::metadata(&gz).unwrap().len(),"sha256":hash_file(&gz).unwrap(),"image_bytes":data.len(),"image_sha256":hash_file(&image).unwrap(),"roundtrip_verified":true}));
        }
        fs::write(package.join("manifest.json"),serde_json::to_vec_pretty(&json!({"schema_version":1,"device":"TB710FU","images":entries,"metadata":{"installation":{"requires_device_personalization":true}}})).unwrap()).unwrap();
        let backend = root.join("backend.py");
        fs::write(&backend,format!(r#"import sys,json,shutil
from pathlib import Path
root=Path({:?})
a=sys.argv[1:]
assert a[:2]==['-s','TESTDEVICE']
a=a[2:]
with (root/'calls.jsonl').open('a') as f:f.write(json.dumps(a)+'\n')
if a==['--version']: print('fastboot fixture 1');sys.exit(0)
if a[0]=='getvar':
 n=a[1]
 values={{'product':'OTHER' if (root/'wrong-product').exists() else 'TB710FU','unlocked':'no' if (root/'locked').exists() else 'yes','current-slot':'a','is-userspace':(root/'mode').read_text() if (root/'mode').exists() else 'yes'}}
 if n.startswith('partition-size:'):
  part=n.split(':',1)[1].removesuffix('_a');p=root/'device'/(part+'.img');size=p.stat().st_size if p.exists() else (root/(part+'.img')).stat().st_size
  if (root/'small-partition').exists() and part=='init_boot':size=1
  value=hex(size)
 else:value=values[n]
 print(n+': '+value,file=sys.stderr)
elif a[0]=='fetch':
 if (root/'no-fetch').exists():sys.exit(1)
 shutil.copyfile(root/'device'/(a[1].removesuffix('_a')+'.img'),a[2])
elif a[0]=='reboot':
 assert a[1] in ['fastboot','bootloader']
 (root/'mode').write_text('yes' if a[1]=='fastboot' else 'no')
elif a[0]=='flash':
 assert a[1].endswith('_a')
 if a[1]=='product_a' and (root/'fail-product').exists():sys.exit(1)
else:raise RuntimeError(a)
"#,root.display().to_string())).unwrap();
        let fbpath = root.join("fastboot");
        fs::write(
            &fbpath,
            format!("#!/bin/sh\nexec python3 '{}' \"$@\"\n", backend.display()),
        )
        .unwrap();
        fs::set_permissions(&fbpath, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _temp: t,
            root,
            package,
            work,
            fb: Fastboot {
                program: fbpath,
                serial: "TESTDEVICE".into(),
            },
            tools,
            key,
        }
    }
    fn prepare(&self) -> anyhow::Result<gb_installer::Plan> {
        gb_installer::prepare(Prepare {
            package: &self.package,
            work: &self.work,
            fastboot: &self.fb,
            tools: &self.tools,
            root_key: &self.key,
            system_key: &self.key,
        })
    }
    fn calls(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(self.root.join("calls.jsonl"))
            .unwrap()
            .lines()
            .map(|x| serde_json::from_str(x).unwrap())
            .collect()
    }
}
#[test]
#[ignore = "requires host Python3 and OpenSSL; simulated USB only"]
fn signed_personalization_dry_run_and_flash_failure_are_device_bound() {
    let f = Fixture::new();
    let plan = f.prepare().unwrap();
    for (name, index) in [("vbmeta", 42), ("vbmeta_system", 61), ("boot", 7)] {
        let p = f.work.join("images").join(format!("{name}.img"));
        assert_eq!(Metadata::read(&p).unwrap().index().unwrap(), index);
        assert_eq!(plan.rollback[name].value, index);
        assert!(gb_installer::avb::payload_equal(&f.root.join(format!("{name}.img")), &p).unwrap());
    }
    assert!(
        f.calls()
            .iter()
            .all(|a| a[0] != "flash" && a[0] != "reboot")
    );
    let before = f.calls().len();
    let o = Command::new(env!("CARGO_BIN_EXE_gb-install"))
        .args([
            "flash",
            "--work",
            f.work.to_str().unwrap(),
            "--serial",
            "TESTDEVICE",
            "--fastboot",
            f.fb.program.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_eq!(before, f.calls().len());
    // Every partition's capacity is checked before the first write.
    fs::write(f.root.join("small-partition"), b"").unwrap();
    assert!(gb_installer::flash(&f.work, &f.fb, |_| Ok(true)).is_err());
    assert!(!f.work.join("flash-journal.json").exists());
    assert!(f.calls().iter().all(|a| a[0] != "flash"));
    fs::remove_file(f.root.join("small-partition")).unwrap();
    // Typed confirmation is not bypassed by --execute; reject before any writes.
    assert!(gb_installer::flash(&f.work, &f.fb, |_| Ok(false)).is_err());
    assert!(f.calls().iter().all(|a| a[0] != "flash"));
    // A partial write never resets Android, formats data, or replays automatically.
    fs::write(f.root.join("fail-product"), b"").unwrap();
    assert!(gb_installer::flash(&f.work, &f.fb, |_| Ok(true)).is_err());
    let count = f.calls().len();
    assert!(gb_installer::flash(&f.work, &f.fb, |_| Ok(true)).is_err());
    assert!(f.calls()[count..].iter().all(|a| a[0] != "flash"));
    assert!(f.calls().iter().all(|a| a[0] != "erase"
        && a[0] != "format"
        && !(a[0] == "reboot" && a.as_array().unwrap().len() == 1)));
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(f.work.join("flash-journal.json")).unwrap()).unwrap();
    assert_eq!(journal["status"], "in_progress");
}
#[test]
#[ignore = "requires host Python3 and OpenSSL; simulated USB only"]
fn unsupported_devices_and_unknown_readback_stop_before_firmware_writes() {
    let f = Fixture::new();
    for marker in ["wrong-product", "locked", "no-fetch"] {
        fs::write(f.root.join(marker), b"").unwrap();
        assert!(f.prepare().is_err());
        assert!(!f.work.exists());
        fs::remove_file(f.root.join(marker)).unwrap();
    }
    // A changed rollback field without a valid signature is never trusted.
    let device = f.root.join("device/vbmeta.img");
    let saved = fs::read(&device).unwrap();
    let mut changed = saved.clone();
    changed[119] ^= 1;
    fs::write(&device, changed).unwrap();
    assert!(f.prepare().is_err());
    assert!(!f.work.exists());
    fs::write(device, saved).unwrap();
    // Tampered archives and traversal in manifests are rejected, too.
    let p = f.package.join("manifest.json");
    let original = fs::read(&p).unwrap();
    let mut m: serde_json::Value = serde_json::from_slice(&original).unwrap();
    m["images"]["system"]["filename"] = json!("../other.img.gz");
    fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
    assert!(f.prepare().is_err());
    assert!(!f.work.exists());
    fs::write(&p, original).unwrap();
    fs::write(f.package.join("system.img.gz"), b"bad archive").unwrap();
    assert!(f.prepare().is_err());
    assert!(!f.work.exists());
    assert!(f.calls().iter().all(|a| a[0] != "flash"));
}
#[test]
#[ignore = "requires host Python3 and OpenSSL; simulated USB only"]
fn complete_mock_flash_preserves_the_selected_partition_allowlist() {
    let f = Fixture::new();
    f.prepare().unwrap();
    gb_installer::flash(&f.work, &f.fb, |_| Ok(true)).unwrap();
    let flashed: Vec<_> = f
        .calls()
        .into_iter()
        .filter(|a| a[0] == "flash")
        .map(|a| a[1].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        flashed,
        gb_installer::PARTITIONS
            .iter()
            .map(|n| format!("{n}_a"))
            .collect::<Vec<_>>()
    );
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(f.work.join("flash-journal.json")).unwrap()).unwrap();
    assert_eq!(
        journal["status"],
        "written_pending_recovery_and_runtime_validation"
    );
    assert_eq!(journal["automatic_reboot"], false);
}
