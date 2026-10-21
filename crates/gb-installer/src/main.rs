use anyhow::{Result, ensure};
use clap::{Args, Parser, Subcommand};
use gb_installer::{Fastboot, Prepare, avb::Tools};
use std::{
    io::{self, Write},
    path::PathBuf,
};
#[derive(Parser)]
#[command(
    name = "gb-install",
    about = "TB710FU device-specific AVB preparation and explicit flashing"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Args)]
struct Signing {
    #[arg(long, default_value = "python3")]
    python: PathBuf,
    #[arg(long)]
    avbtool: PathBuf,
    #[arg(long, default_value = "openssl")]
    openssl: PathBuf,
}
impl Signing {
    fn tools(&self) -> Tools {
        Tools {
            python: self.python.clone(),
            avbtool: self.avbtool.clone(),
            openssl: self.openssl.clone(),
        }
    }
}
#[derive(Subcommand)]
enum Command {
    /// Read this device's AVB images and prepare signed copies. No firmware writes.
    Prepare {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        work: PathBuf,
        #[arg(long)]
        serial: String,
        #[arg(long, default_value = "fastboot")]
        fastboot: PathBuf,
        #[arg(long)]
        root_key: PathBuf,
        #[arg(long)]
        system_key: PathBuf,
        #[command(flatten)]
        signing: Signing,
    },
    /// Preview the prepared commands. --execute additionally requires a typed confirmation.
    Flash {
        #[arg(long)]
        work: PathBuf,
        #[arg(long)]
        serial: String,
        #[arg(long, default_value = "fastboot")]
        fastboot: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    /// Release maintainer: create a zero-index template copy, never an installable final image.
    Template {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        signing: Signing,
    },
}
fn main() -> Result<()> {
    ctrlc::set_handler(|| gb_core::CANCELLED.store(true, std::sync::atomic::Ordering::Relaxed))?;
    match Cli::parse().command {
        Command::Prepare {
            package,
            work,
            serial,
            fastboot,
            root_key,
            system_key,
            signing,
        } => {
            let fb = Fastboot {
                program: fastboot,
                serial,
            };
            match gb_installer::prepare(Prepare {
                package: &package,
                work: &work,
                fastboot: &fb,
                tools: &signing.tools(),
                root_key: &root_key,
                system_key: &system_key,
            }) {
                Ok(plan) => {
                    println!("{}", serde_json::to_string_pretty(&plan)?);
                    println!(
                        "Prepared only. Review install-plan.json; firmware has not been flashed."
                    );
                }
                Err(error) => {
                    eprintln!("Preparation blocked; firmware was not flashed. {error:#}");
                    return Err(error);
                }
            }
        }
        Command::Flash {
            work,
            serial,
            fastboot,
            execute,
        } => {
            let plan = gb_installer::load_plan(&work)?;
            ensure!(plan.serial == serial, "plan belongs to a different serial");
            for args in gb_installer::commands(&plan, &work) {
                println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"program":fastboot,"args":([vec!["-s".to_owned(),serial.clone()],args].concat())})
                    )?
                );
            }
            if execute {
                gb_installer::flash(
                    &work,
                    &Fastboot {
                        program: fastboot,
                        serial,
                    },
                    |p| {
                        println!(
                            "This writes nine slot-A partitions on {}. Keep your stock backup and recovery method ready. No userdata formatting, relocking or automatic system reboot is performed.",
                            p.serial
                        );
                        print!("Type FLASH {} to proceed: ", p.serial);
                        io::stdout().flush()?;
                        let mut answer = String::new();
                        io::stdin().read_line(&mut answer)?;
                        Ok(answer.trim() == format!("FLASH {}", p.serial))
                    },
                )?;
                println!(
                    "Images written. Use the documented stock-recovery procedure; boot and hardware validation remain required."
                );
            } else {
                println!(
                    "Dry run only. Add --execute for device rechecks and an interactive confirmation."
                );
            }
        }
        Command::Template {
            image,
            output,
            key,
            signing,
        } => {
            signing.tools().resign(&image, &output, &key, 0)?;
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
