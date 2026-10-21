//! Explicit host-tool boundaries. Never executes a firmware-supplied program.
pub mod guest_display;
pub mod guest_display_lifecycle;
pub mod guest_handoff;
pub mod phone_link_setup;
pub mod terminal_network;
pub mod terminal_tabs;
pub mod terminal_ui;
pub mod terminal_workload;
use anyhow::{Context, Result, ensure};
use gb_core::{ToolResult, hash_file, run_tool};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum Sandbox {
    #[default]
    Bubblewrap,
    Docker {
        image: String,
    },
}
impl Sandbox {
    pub fn validate(&self) -> Result<()> {
        if let Self::Docker { image } = self {
            ensure!(
                image
                    .strip_prefix("sha256:")
                    .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())),
                "Docker sandbox requires an immutable local sha256 image ID, never a mutable tag"
            );
        }
        Ok(())
    }
}
pub fn host_tool(path: &Path, inputs: &[&Path]) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .context("configured host tool unavailable")?;
    ensure!(path.is_file(), "host tool must be a regular file");
    for input in inputs {
        let root = input.canonicalize()?;
        ensure!(
            path != root && !(root.is_dir() && path.starts_with(&root)),
            "refusing to execute a tool from firmware input"
        );
    }
    Ok(path)
}
pub fn identity(tool: &Path, sandbox: &Sandbox) -> Result<Value> {
    sandbox.validate()?;
    let version = run_tool(tool, &["--version".into()], Duration::from_secs(5))
        .or_else(|_| run_tool(tool, &["-V".into()], Duration::from_secs(5)))
        .map(|v| format!("{}{}", v.stdout, v.stderr))
        .unwrap_or_else(|_| "version flag unavailable; binary digest identifies tool".into());
    let libraries = linked_libraries(tool)?;
    let mut dependencies = std::collections::BTreeMap::new();
    let mut mounts = std::collections::BTreeMap::new();
    for library in libraries {
        let sha = hash_file(&library.path)?;
        dependencies.insert(library.path.display().to_string(), sha.clone());
        mounts.insert(library.name, json!({"path":library.path,"sha256":sha}));
    }
    let runtime = match sandbox {
        Sandbox::Bubblewrap => run_tool(
            Path::new("bwrap"),
            &["--version".into()],
            Duration::from_secs(5),
        )?,
        Sandbox::Docker { image } => {
            let found = run_tool(
                Path::new("docker"),
                &[
                    "image".into(),
                    "inspect".into(),
                    "--format".into(),
                    "{{.Id}}".into(),
                    image.clone(),
                ],
                Duration::from_secs(10),
            )?;
            ensure!(found.stdout.trim() == image, "Docker image ID mismatch");
            run_tool(
                Path::new("docker"),
                &[
                    "version".into(),
                    "--format".into(),
                    "{{.Client.Version}}/{{.Server.Version}}".into(),
                ],
                Duration::from_secs(10),
            )?
        }
    };
    Ok(
        json!({"binary_sha256":hash_file(tool)?,"version":version,"shared_libraries":dependencies,"library_mounts":mounts,"sandbox":sandbox,"runtime_version":runtime.stdout.trim()}),
    )
}
struct Library {
    name: String,
    path: PathBuf,
}
fn linked_libraries(tool: &Path) -> Result<Vec<Library>> {
    let libs = run_tool(
        Path::new("ldd"),
        &[tool.display().to_string()],
        Duration::from_secs(5),
    )?;
    let mut dependencies = std::collections::BTreeMap::new();
    for token in libs
        .stdout
        .split_whitespace()
        .filter(|s| s.starts_with('/'))
    {
        let path = Path::new(token);
        let name = path
            .file_name()
            .context("linked library filename")?
            .to_str()
            .context("non-UTF8 linked library name")?
            .to_string();
        ensure!(
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b)),
            "unsupported linked library name"
        );
        let path = path.canonicalize()?;
        ensure!(path.is_file(), "linked library is not a regular file");
        if let Some(old) = dependencies.insert(name, path.clone()) {
            ensure!(old == path, "conflicting linked library basenames");
        }
    }
    ensure!(
        !libs.stdout.contains("not found"),
        "host-tool dependency unavailable"
    );
    Ok(dependencies
        .into_iter()
        .map(|(name, path)| Library { name, path })
        .collect())
}
fn mount(source: &Path, dest: &str, readonly: bool) -> Result<String> {
    let source = source.canonicalize()?;
    let source = source.to_str().context("non-UTF8 mount path")?;
    ensure!(
        !source.contains([',', '\n']),
        "unsupported mount path separator"
    );
    Ok(format!(
        "type=bind,src={source},dst={dest}{}",
        if readonly { ",readonly" } else { "" }
    ))
}
pub fn run(
    sandbox: &Sandbox,
    tool: &Path,
    args: Vec<String>,
    input: &Path,
    output: &Path,
    timeout: Duration,
) -> Result<ToolResult> {
    run_filtered(sandbox, tool, args, input, output, timeout, None)
}
pub fn run_filtered(
    sandbox: &Sandbox,
    tool: &Path,
    args: Vec<String>,
    input: &Path,
    output: &Path,
    timeout: Duration,
    stderr_filter: Option<fn(&str) -> bool>,
) -> Result<ToolResult> {
    run_bound(
        sandbox,
        tool,
        args,
        Inputs {
            primary: input,
            extra: &[],
            source_date_epoch: Some(0),
        },
        output,
        timeout,
        stderr_filter,
    )
}
pub struct ReadOnlyInput<'a> {
    pub name: &'a str,
    pub path: &'a Path,
}
pub struct Inputs<'a> {
    pub primary: &'a Path,
    pub extra: &'a [ReadOnlyInput<'a>],
    /// Omit the wrapper override when preserving existing filesystem mtimes.
    pub source_date_epoch: Option<u64>,
}
pub fn run_mounted(
    sandbox: &Sandbox,
    tool: &Path,
    args: Vec<String>,
    inputs: Inputs<'_>,
    output: &Path,
    timeout: Duration,
) -> Result<ToolResult> {
    run_bound(sandbox, tool, args, inputs, output, timeout, None)
}
fn run_bound(
    sandbox: &Sandbox,
    tool: &Path,
    args: Vec<String>,
    inputs: Inputs<'_>,
    output: &Path,
    timeout: Duration,
    stderr_filter: Option<fn(&str) -> bool>,
) -> Result<ToolResult> {
    let input = inputs.primary;
    sandbox.validate()?;
    ensure!(
        output.is_dir(),
        "tool output must be an existing staging directory"
    );
    let mut sources = vec![input.canonicalize()?];
    let mut names = std::collections::BTreeSet::new();
    for extra in inputs.extra {
        ensure!(
            !extra.name.is_empty()
                && ![".", ".."].contains(&extra.name)
                && extra
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                && names.insert(extra.name),
            "invalid or duplicate extra read-only input name"
        );
        sources.push(extra.path.canonicalize()?);
    }
    let input_paths: Vec<_> = sources.iter().map(|p| p.as_path()).collect();
    let tool_path = host_tool(tool, &input_paths)?;
    let tool = tool_path.as_path();
    let libraries = linked_libraries(tool)?;
    for library in &libraries {
        ensure!(
            sources.iter().all(|source| library.path != *source
                && !(source.is_dir() && library.path.starts_with(source))),
            "refusing host-tool dependency from firmware input"
        );
    }
    match sandbox {
        Sandbox::Bubblewrap => {
            let mut command = vec![
                "--unshare-all".into(),
                "--die-with-parent".into(),
                "--new-session".into(),
                "--clearenv".into(),
            ];
            for dir in ["/usr", "/lib", "/lib64", "/bin"] {
                if Path::new(dir).exists() {
                    command.extend(["--ro-bind".into(), dir.into(), dir.into()]);
                }
            }
            command.extend(["--dir".into(), "/host-libs".into()]);
            command.extend(["--dir".into(), "/inputs".into()]);
            for extra in inputs.extra {
                command.extend([
                    "--ro-bind".into(),
                    extra.path.canonicalize()?.display().to_string(),
                    format!("/inputs/{}", extra.name),
                ]);
            }
            for library in &libraries {
                command.extend([
                    "--ro-bind".into(),
                    library.path.display().to_string(),
                    format!("/host-libs/{}", library.name),
                ]);
            }
            command.extend([
                "--setenv".into(),
                "LD_LIBRARY_PATH".into(),
                "/host-libs".into(),
            ]);
            command.extend([
                "--proc".into(),
                "/proc".into(),
                "--dev".into(),
                "/dev".into(),
                "--tmpfs".into(),
                "/tmp".into(),
                "--ro-bind".into(),
                input.canonicalize()?.display().to_string(),
                "/input.img".into(),
                "--bind".into(),
                output.canonicalize()?.display().to_string(),
                "/output".into(),
                "--ro-bind".into(),
                tool.display().to_string(),
                "/host-tool".into(),
                "--setenv".into(),
                "LC_ALL".into(),
                "C".into(),
                "--setenv".into(),
                "TZ".into(),
                "UTC".into(),
                "--".into(),
                "/host-tool".into(),
            ]);
            if let Some(epoch) = inputs.source_date_epoch {
                let end = command.len() - 2;
                command.splice(
                    end..end,
                    [
                        "--setenv".into(),
                        "SOURCE_DATE_EPOCH".into(),
                        epoch.to_string(),
                    ],
                );
            }
            command.extend(args);
            gb_core::run_tool_filtered(Path::new("bwrap"), &command, timeout, stderr_filter)
                .context("bubblewrap failed; no unsandboxed fallback")
        }
        Sandbox::Docker { image } => {
            // A generated name permits bounded cleanup even when the CLI is killed on timeout.
            let token = tempfile::Builder::new()
                .prefix("gb-image-tool-")
                .tempdir()?;
            let name = token
                .path()
                .file_name()
                .context("container name")?
                .to_string_lossy()
                .into_owned();
            let mut command = vec![
                "run".into(),
                "--rm".into(),
                "--pull=never".into(),
                "--name".into(),
                name.clone(),
                "--label".into(),
                "gb.porting.image-tool=true".into(),
                "--network=none".into(),
                "--read-only".into(),
                "--cap-drop=ALL".into(),
                "--security-opt=no-new-privileges".into(),
                "--no-healthcheck".into(),
                "--pids-limit=128".into(),
                "--memory=2g".into(),
                "--cpus=4".into(),
                "--stop-timeout=1".into(),
                "--user".into(),
                format!("{}:{}", unsafe { libc::geteuid() }, unsafe {
                    libc::getegid()
                }),
                "--tmpfs".into(),
                "/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777".into(),
                "--env=LC_ALL=C".into(),
                "--env=TZ=UTC".into(),
            ];
            if let Some(epoch) = inputs.source_date_epoch {
                command.push(format!("--env=SOURCE_DATE_EPOCH={epoch}"));
            }
            for dir in ["/usr", "/lib", "/lib64", "/bin"] {
                if Path::new(dir).exists() {
                    command.extend(["--mount".into(), mount(Path::new(dir), dir, true)?]);
                }
            }
            for library in &libraries {
                command.extend([
                    "--mount".into(),
                    mount(&library.path, &format!("/host-libs/{}", library.name), true)?,
                ]);
            }
            command.push("--env=LD_LIBRARY_PATH=/host-libs".into());
            for extra in inputs.extra {
                command.extend([
                    "--mount".into(),
                    mount(extra.path, &format!("/inputs/{}", extra.name), true)?,
                ]);
            }
            for (src, dst, ro) in [
                (input, "/input.img", true),
                (output, "/output", false),
                (tool, "/host-tool", true),
            ] {
                command.extend(["--mount".into(), mount(src, dst, ro)?]);
            }
            command.extend(["--entrypoint=/host-tool".into(), image.clone()]);
            command.extend(args);
            let result =
                gb_core::run_tool_filtered(Path::new("docker"), &command, timeout, stderr_filter);
            // run_tool observes cancellation; cleanup must still run after cancellation.
            let cleanup = std::process::Command::new("docker")
                .args(["rm", "--force", &name])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            if let Ok(mut child) = cleanup {
                let start = std::time::Instant::now();
                while child.try_wait()?.is_none() {
                    if start.elapsed() > Duration::from_secs(10) {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            result.context("Docker image tool failed; no unsandboxed fallback")
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_images_and_input_tools() {
        assert!(
            Sandbox::Docker {
                image: "debian:latest".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            Sandbox::Docker {
                image: format!("sha256:{}", "a".repeat(64))
            }
            .validate()
            .is_ok()
        );
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("tool");
        std::fs::write(&p, "do not execute").unwrap();
        assert!(host_tool(&p, &[t.path()]).is_err());
        assert!(host_tool(&p, &[&p]).is_err());
    }
}
