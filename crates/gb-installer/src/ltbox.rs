//! Device-specific rawprogram handoff. LTBox remains a separate external writer.
use crate::{
    PARTITIONS, Plan, checked_json, edl::Device, load_plan, lock_work, preflight, write_json,
};
use anyhow::{Context, Result, ensure};
use gb_core::{checkpoint, hash_file};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

fn rawprogram(plan: &Plan) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<data>\n");
    for name in PARTITIONS {
        let r = &plan.writes[*name];
        // All attribute strings are fixed allowlisted names or validated integers.
        xml.push_str(&format!("  <program SECTOR_SIZE_IN_BYTES=\"4096\" file_sector_offset=\"0\" filename=\"{name}.img\" label=\"{name}_a\" num_partition_sectors=\"{}\" physical_partition_number=\"{}\" sparse=\"false\" start_sector=\"{}\" />\n",r.sectors,r.lun,r.start_sector));
    }
    xml.push_str("</data>\n");
    xml
}
fn copy_synced(from: &Path, to: &Path) -> Result<u64> {
    let mut input = File::open(from)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?;
    let size = std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(size)
}
/// Copies or hardlinks prepared images into an otherwise empty folder. This
/// never generates a stock rawprogram, patch, erase, GPT or userdata operation.
pub fn export(work: &Path, device: &dyn Device, loader: &Path) -> Result<PathBuf> {
    let _lock = lock_work(work)?;
    let plan = load_plan(work)?;
    let output = work.join("ltbox");
    ensure!(
        !output.exists()
            && !work.join("ltbox-handoff.json").exists()
            && !work.join("flash-journal.json").exists(),
        "existing handoff, output or flash attempt; preserve it and prepare a fresh work directory"
    );
    let loader_hash = hash_file(loader)?;
    ensure!(
        fs::symlink_metadata(loader)?.file_type().is_file()
            && plan.tools["edl"]["loader_sha256"] == loader_hash,
        "loader differs from the programmer recorded during preparation"
    );
    preflight(work, device, &plan, true)?;
    let staging = tempfile::tempdir_in(work)?;
    for name in PARTITIONS {
        checkpoint()?;
        let image = &plan.images[*name];
        let from = work.join("images").join(&image.filename);
        let to = staging.path().join(&image.filename);
        if fs::hard_link(&from, &to).is_err() {
            ensure!(
                fs2::available_space(staging.path())? > image.bytes,
                "insufficient free space for LTBox image copy"
            );
            ensure!(
                copy_synced(&from, &to)? == image.bytes,
                "short LTBox image copy"
            );
            ensure!(
                hash_file(&to)? == image.sha256,
                "LTBox image copy checksum mismatch"
            );
        }
    }
    let loader_out = staging.path().join("xbl_s_devprg_ns.melf");
    copy_synced(loader, &loader_out)?;
    ensure!(
        hash_file(&loader_out)? == loader_hash,
        "copied loader changed"
    );

    let xml = rawprogram(&plan);
    let mut file = File::create(staging.path().join("rawprogram_googlebookos.xml"))?;
    file.write_all(xml.as_bytes())?;
    file.sync_all()?;
    let sums = PARTITIONS
        .iter()
        .map(|n| format!("{}  {}.img\n", plan.images[*n].sha256, n))
        .collect::<String>();
    let mut file = File::create(staging.path().join("IMAGES_SHA256SUMS"))?;
    file.write_all(sums.as_bytes())?;
    file.sync_all()?;
    let handoff = json!({"schema_version":1,"status":"exported_not_flashed","serial":plan.serial,
        "plan_sha256":hash_file(&work.join("install-plan.json"))?,"loader_sha256":loader_hash,
        "rawprogram_sha256":hash_file(&staging.path().join("rawprogram_googlebookos.xml"))?,
        "writes":plan.writes,"images":plan.images,"firmware_written_by_export":false,"runtime_verified":false,
        "ltbox_reference_version":"v3.3.5","ltbox_resets_automatically":true,"ltbox_sets_bootable_ufs_lun":1,
        "ltbox_per_write_digest_checks":false,"native_flash_replay_blocked":true});
    write_json(&staging.path().join("LTBOX_PLAN.json"), &handoff)?;
    // Record the handoff before publication. A crash must never permit blind
    // native replay of a folder that may already have reached an external writer.
    write_json(&work.join("ltbox-handoff.json"), &handoff)?;
    let path = staging.keep();
    fs::rename(&path, &output).inspect_err(|_| {
        let _ = fs::remove_dir_all(&path);
    })?;
    #[cfg(unix)]
    File::open(work)?.sync_all()?;
    Ok(output)
}
/// One read-only device digest per image. No implicit reset and no native flash
/// journal: external writes cannot be certified as having followed our journal.
pub fn verify(work: &Path, device: &dyn Device) -> Result<()> {
    let _lock = lock_work(work)?;
    let plan = load_plan(work)?;
    let handoff: Value = checked_json(&work.join("ltbox-handoff.json"))?;
    ensure!(
        handoff["schema_version"] == 1
            && handoff["serial"] == plan.serial
            && handoff["plan_sha256"] == hash_file(&work.join("install-plan.json"))?,
        "LTBox handoff does not match this plan"
    );
    let report_path = work.join("ltbox-verification.json");
    let mut report = json!({"schema_version":1,"status":"in_progress","serial":plan.serial,"plan_sha256":handoff["plan_sha256"],
        "verified":[],"firmware_written_by_verifier":false,"reset_sent":false,"runtime_verified":false});
    write_json(&report_path, &report)?;
    let result = (|| -> Result<()> {
        preflight(work, device, &plan, false)?;
        for name in PARTITIONS {
            checkpoint()?;
            let actual = device
                .digest(&plan.writes[*name])
                .with_context(|| format!("device digest failed for {name}_a"))?;
            ensure!(
                actual == plan.images[*name].sha256,
                "device digest mismatch: {name}_a"
            );
            report["verified"]
                .as_array_mut()
                .context("verification array")?
                .push(json!({"partition":format!("{name}_a"),"sha256":actual}));
            write_json(&report_path, &report)?;
        }
        Ok(())
    })();
    match &result {
        Ok(()) => report["status"] = json!("all_nine_device_images_match_prepared_plan"),
        Err(error) => {
            report["status"] = json!("failed");
            report["error"] = json!(format!("{error:#}"));
        }
    }
    write_json(&report_path, &report)?;
    result
}
