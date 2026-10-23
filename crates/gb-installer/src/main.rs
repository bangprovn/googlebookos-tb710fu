use anyhow::{Result, ensure};
use clap::{Args, Parser, Subcommand};
use gb_installer::{Prepare, avb::Tools, edl::Edl};
use std::{
    io::{self, Write},
    path::PathBuf,
};
#[derive(Parser)]
#[command(
    name = "gb-install",
    about = "TB710FU EDL readback, per-device AVB preparation and explicit installation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Args)]
struct Transport {
    /// Clean bkerler/edl checkout directory at the documented pinned revision.
    #[arg(long)]
    edl_client: PathBuf,
    /// Qualified stock xbl_s_devprg_ns.melf; never downloaded automatically.
    #[arg(long)]
    loader: PathBuf,
    /// Python environment with the EDL client's dependencies installed.
    #[arg(long, default_value = "python3")]
    python: PathBuf,
    /// Optional full path to a libusb-1.0 DLL/shared library.
    #[arg(long)]
    libusb: Option<PathBuf>,
}
impl Transport {
    fn edl(&self, serial: String) -> Edl {
        Edl {
            python: self.python.clone(),
            client: self.edl_client.clone(),
            loader: self.loader.clone(),
            libusb: self.libusb.clone(),
            serial,
        }
    }
}
#[derive(Args)]
struct Signing {
    #[arg(long)]
    avbtool: PathBuf,
    #[arg(long, default_value = "openssl")]
    openssl: PathBuf,
}
impl Signing {
    fn tools(&self, python: &std::path::Path) -> Tools {
        Tools {
            python: python.into(),
            avbtool: self.avbtool.clone(),
            openssl: self.openssl.clone(),
        }
    }
}
#[derive(Subcommand)]
enum Command {
    /// Read UFS identity over EDL. Connect exactly one 05c6:9008 device.
    Probe {
        #[command(flatten)]
        transport: Transport,
    },
    /// Read GPT/LP and AVB; prepare device-specific images. No persistent writes or reset.
    Prepare {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        work: PathBuf,
        /// UFS storage serial from probe, not the Android ADB serial.
        #[arg(long)]
        serial: String,
        #[command(flatten)]
        transport: Transport,
        #[arg(long)]
        root_key: PathBuf,
        #[arg(long)]
        system_key: PathBuf,
        #[command(flatten)]
        signing: Signing,
    },
    /// Export personalized images and a device-specific rawprogram for LTBox. Reads only.
    ExportLtbox {
        #[arg(long)]
        work: PathBuf,
        #[arg(long)]
        serial: String,
        #[command(flatten)]
        transport: Transport,
    },
    /// Read-only EDL digest verification after an external LTBox flash. No reset.
    VerifyLtbox {
        #[arg(long)]
        work: PathBuf,
        #[arg(long)]
        serial: String,
        #[command(flatten)]
        transport: Transport,
    },
    /// Offline preview. --execute additionally needs EDL options and typed confirmation.
    Flash {
        #[arg(long)]
        work: PathBuf,
        #[arg(long)]
        serial: String,
        #[arg(long)]
        execute: bool,
        // Optional only so a dry run never needs USB or host EDL dependencies.
        #[arg(long)]
        edl_client: Option<PathBuf>,
        #[arg(long)]
        loader: Option<PathBuf>,
        #[arg(long, default_value = "python3")]
        python: PathBuf,
        #[arg(long)]
        libusb: Option<PathBuf>,
    },
    /// Explicit EDL reset after a fully digest-verified flash. No automatic reset on errors.
    Reset {
        #[arg(long)]
        work: PathBuf,
        #[arg(long)]
        serial: String,
        #[command(flatten)]
        transport: Transport,
    },
    /// Maintainer: make a zero-index template copy, never an installable final image.
    Template {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "python3")]
        python: PathBuf,
        #[command(flatten)]
        signing: Signing,
    },
}
fn main() -> Result<()> {
    ctrlc::set_handler(|| gb_core::CANCELLED.store(true, std::sync::atomic::Ordering::Relaxed))?;
    match Cli::parse().command {
        Command::Probe { transport } => println!(
            "{}",
            serde_json::to_string_pretty(&transport.edl(String::new()).probe()?)?
        ),
        Command::Prepare {
            package,
            work,
            serial,
            transport,
            root_key,
            system_key,
            signing,
        } => {
            let plan = gb_installer::prepare(Prepare {
                package: &package,
                work: &work,
                device: &transport.edl(serial),
                tools: &signing.tools(&transport.python),
                root_key: &root_key,
                system_key: &system_key,
            })?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
            println!(
                "Prepared only; no persistent firmware writes or reset. Review install-plan.json and keep a complete stock backup."
            );
        }
        Command::ExportLtbox {
            work,
            serial,
            transport,
        } => {
            let output =
                gb_installer::ltbox::export(&work, &transport.edl(serial), &transport.loader)?;
            println!("LTBox folder: {}", output.display());
            println!(
                "No firmware written. Use Advanced > Simple Firmware Flasher with this folder only. LTBox resets automatically and does not run our per-write digest checks; follow LTBOX.md."
            );
        }
        Command::VerifyLtbox {
            work,
            serial,
            transport,
        } => {
            gb_installer::ltbox::verify(&work, &transport.edl(serial))?;
            println!(
                "All nine device images match the prepared plan; see ltbox-verification.json. No write or reset sent. Runtime validation remains required."
            );
        }
        Command::Flash {
            work,
            serial,
            execute,
            edl_client,
            loader,
            python,
            libusb,
        } => {
            let plan = gb_installer::load_plan(&work)?;
            ensure!(plan.serial == serial, "plan belongs to another UFS serial");
            for step in gb_installer::commands(&plan, &work) {
                println!("{}", serde_json::to_string(&step)?);
            }
            if execute {
                let device = Edl {
                    python,
                    client: edl_client
                        .ok_or_else(|| anyhow::anyhow!("--execute requires --edl-client"))?,
                    loader: loader.ok_or_else(|| anyhow::anyhow!("--execute requires --loader"))?,
                    libusb,
                    serial,
                };
                gb_installer::flash(&work, &device, |p| {
                    println!(
                        "This overwrites nine slot-A images on UFS {}. Have a complete stock backup and recovery method ready. GPT, LP metadata, slot B and userdata are preserved; there is no automatic reboot.",
                        p.serial
                    );
                    print!("Type FLASH {} to proceed: ", p.serial);
                    io::stdout().flush()?;
                    let mut answer = String::new();
                    io::stdin().read_line(&mut answer)?;
                    Ok(answer.trim() == format!("FLASH {}", p.serial))
                })?;
                println!(
                    "Nine images written and device SHA-256 verified. Use the separate reset command when ready; runtime validation remains required."
                );
            } else {
                println!(
                    "Dry run only; no EDL connection. --execute requires transport options and typed confirmation."
                );
            }
        }
        Command::Reset {
            work,
            serial,
            transport,
        } => {
            gb_installer::reset(&work, &transport.edl(serial))?;
            println!("EDL reset sent.");
        }
        Command::Template {
            image,
            output,
            key,
            python,
            signing,
        } => {
            signing.tools(&python).resign(&image, &output, &key, 0)?;
            ensure!(
                gb_installer::avb::payload_equal(&image, &output)?,
                "payload changed"
            );
            println!(
                "Zero-index template prepared; device personalization is required before installation."
            );
        }
    }
    Ok(())
}
