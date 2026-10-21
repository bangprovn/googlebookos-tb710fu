//! Validates an existing receipt; never contacts a device or patches an image.
use anyhow::{Result, ensure};
use std::io::Read;
fn main() -> Result<()> {
    let mut text = String::new();
    std::io::stdin().take(4097).read_to_string(&mut text)?;
    ensure!(text.len() <= 4096, "shader receipt budget");
    let value = gb_framework::guest_graphics::validate_shader(&text)?;
    println!(
        "{}",
        serde_json::json!({"shader":value,"reported_virgl_shader_readback_verified":true,"external_runtime_context_verified":false,"physical_gpu_acceleration_verified":false,"guest_desktop_verified":false,"full_port_verified":false})
    );
    Ok(())
}
