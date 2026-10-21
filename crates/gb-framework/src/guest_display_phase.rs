//! Versioned crop-only phase capture; no image or physical scanout qualification.
use crate::functional_probe::{BuildRequest, build_owned_sources};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const PREFIX: &str = "GB_GUEST_DISPLAY_PHASE_V1:";
pub fn build(request: &BuildRequest, output: &Path) -> Result<serde_json::Value> {
    build_owned_sources(
        request,
        output,
        &[
            (
                "GuestDisplayPhaseProbe.java",
                include_str!("guest_display_phase/GuestDisplayPhaseProbe.java"),
            ),
            (
                "PhasePatternContract.java",
                include_str!("guest_display_phase/PhasePatternContract.java"),
            ),
        ],
        Some(2000),
    )
}
pub fn extent(phase: u8) -> Result<[u32; 2]> {
    ensure!(phase <= 2, "phase must be 0..2");
    Ok(if phase == 1 { [480, 360] } else { [640, 480] })
}
pub fn contract_digest(phase: u8) -> Result<String> {
    let [w, h] = extent(phase)?;
    Ok(gb_core::digest(format!("GB_VULKAN_LIFECYCLE_V1:{phase}:{w}:{h}:border=8:palette=19,67,139;203,37,91;47,181,113;211,173,53:rotation={phase}").as_bytes()))
}
fn hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn boot(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn bounds(c: [u32; 4]) -> Result<[u32; 2]> {
    let [l, t, r, b] = c;
    ensure!(
        r > l && b > t && r <= 32768 && b <= 32768,
        "invalid crop bounds"
    );
    let w = r - l;
    let h = b - t;
    ensure!(
        (32..=4096).contains(&w)
            && (32..=4096).contains(&h)
            && u64::from(w) * u64::from(h) <= 8 * 1024 * 1024,
        "crop allocation budget"
    );
    Ok([w, h])
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedContext {
    pub schema_version: u32,
    pub android_boot_id: String,
    pub android_user: u32,
    pub terminal_uid: u32,
    pub source_crop: [u32; 4],
    pub observed_elapsed_ms: u64,
    pub pattern_phase: u8,
    pub buffer_width: u32,
    pub buffer_height: u32,
    pub capture_token: String,
    pub fixture_sha256: String,
    pub contract_sha256: String,
}
impl ExpectedContext {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && boot(&self.android_boot_id)
                && self.android_user <= 214
                && self.terminal_uid / 100000 == self.android_user
                && (10000..20000).contains(&(self.terminal_uid % 100000))
                && self.observed_elapsed_ms <= i64::MAX as u64
                && hex(&self.capture_token, 32)
                && hex(&self.fixture_sha256, 64),
            "capture identity/token budget"
        );
        bounds(self.source_crop)?;
        ensure!(
            [self.buffer_width, self.buffer_height] == extent(self.pattern_phase)?
                && self.contract_sha256 == contract_digest(self.pattern_phase)?,
            "phase/extent/contract mismatch"
        );
        Ok(())
    }
    /// Arguments only; root owns staging, exact native context and device invocation.
    pub fn arguments(&self) -> Result<Vec<String>> {
        self.validate()?;
        Ok(vec![
            self.android_boot_id.clone(),
            self.android_user.to_string(),
            self.terminal_uid.to_string(),
            self.source_crop[0].to_string(),
            self.source_crop[1].to_string(),
            self.source_crop[2].to_string(),
            self.source_crop[3].to_string(),
            "0".into(),
            self.observed_elapsed_ms.to_string(),
            self.pattern_phase.to_string(),
            self.buffer_width.to_string(),
            self.buffer_height.to_string(),
            self.capture_token.clone(),
            self.fixture_sha256.clone(),
        ])
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    OwnedPatternSamplesMatched,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureApi {
    Internal,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u32,
    pub status: CaptureStatus,
    pub sampled_per_quadrant: u32,
    pub matched: [u32; 4],
    pub max_channel_errors: [u32; 4],
    pub tolerance: u32,
    pub crop_width: u32,
    pub crop_height: u32,
    pub source_crop_and_uid_verified: bool,
    pub identity_endpoints_verified: bool,
    pub buffers_released: bool,
    pub logical_display_width: u32,
    pub logical_display_height: u32,
    pub logical_bounds_verified: bool,
    pub capture_api_profile: CaptureApi,
    pub bordered_locator: bool,
    pub located_relative_bounds: [u32; 4],
    pub uniform_scale_eighths: u32,
    pub palette_pixels: u32,
    pub border_pixels: u32,
    pub pattern_phase: u8,
    pub buffer_width: u32,
    pub buffer_height: u32,
    pub capture_token: String,
    pub fixture_sha256: String,
    pub contract_sha256: String,
    /// Counts are indexed by fixed palette color, not quadrant or arbitrary RGB.
    pub known_palette_counts: [u32; 4],
    pub android_boot_id: String,
    pub android_user: u32,
    pub terminal_uid: u32,
    pub source_crop: [u32; 4],
    pub observed_elapsed_ms: u64,
    pub captured_elapsed_ms: u64,
    pub raw_pixels_exported: bool,
    pub image_saved: bool,
    pub physical_panel_verified: bool,
    pub full_port_verified: bool,
}
pub fn inspect_capture(text: &str, expected: &ExpectedContext) -> Result<Observation> {
    expected.validate()?;
    ensure!(text.len() <= 8192, "capture receipt budget");
    // Typed direct deserialization rejects duplicate and unknown fields. No Value
    // roundtrip, identifier-bearing extensions, or unqualified refusal accepted.
    let body = text.strip_prefix(PREFIX).unwrap_or(text);
    let r: Observation = serde_json::from_str(body)?;
    ensure!(
        r.schema_version == 1
            && r.android_boot_id == expected.android_boot_id
            && r.android_user == expected.android_user
            && r.terminal_uid == expected.terminal_uid
            && r.source_crop == expected.source_crop
            && r.observed_elapsed_ms == expected.observed_elapsed_ms
            && r.pattern_phase == expected.pattern_phase
            && r.buffer_width == expected.buffer_width
            && r.buffer_height == expected.buffer_height
            && r.capture_token == expected.capture_token
            && r.fixture_sha256 == expected.fixture_sha256
            && r.contract_sha256 == expected.contract_sha256,
        "capture phase/context/token/digest mismatch"
    );
    ensure!(
        r.captured_elapsed_ms >= r.observed_elapsed_ms
            && r.captured_elapsed_ms - r.observed_elapsed_ms <= 15000,
        "stale capture geometry/context"
    );
    ensure!(
        r.source_crop_and_uid_verified
            && r.identity_endpoints_verified
            && r.buffers_released
            && r.logical_bounds_verified
            && r.bordered_locator
            && !r.raw_pixels_exported
            && !r.image_saved
            && !r.physical_panel_verified
            && !r.full_port_verified,
        "capture scope/cleanup mismatch"
    );
    ensure!(
        (1..=4096).contains(&r.logical_display_width)
            && (1..=4096).contains(&r.logical_display_height)
            && r.source_crop[2] <= r.logical_display_width
            && r.source_crop[3] <= r.logical_display_height,
        "crop outside actual logical display"
    );
    ensure!(
        [r.crop_width, r.crop_height] == bounds(r.source_crop)?
            && r.sampled_per_quadrant == 16
            && r.matched == [16; 4]
            && r.tolerance == 8
            && r.max_channel_errors.iter().all(|x| *x <= 8),
        "capture exact grid/sample/tolerance mismatch"
    );
    let s = r.uniform_scale_eighths;
    ensure!((4..=32).contains(&s), "uniform scale outside .5..4");
    let [l, t, right, b] = r.located_relative_bounds;
    ensure!(
        l > 0
            && t > 0
            && right > l
            && b > t
            && right < r.crop_width
            && b < r.crop_height
            && right - l == r.buffer_width * s / 8
            && b - t == r.buffer_height * s / 8,
        "located phase extent/edges mismatch"
    );
    let inner_w = (r.buffer_width - 16) * s / 8;
    let inner_h = (r.buffer_height - 16) * s / 8;
    let top = (r.buffer_height / 2 * s).div_ceil(8) - s;
    let left = (r.buffer_width / 2 * s).div_ceil(8) - s;
    let quads = [
        left * top,
        (inner_w - left) * top,
        left * (inner_h - top),
        (inner_w - left) * (inner_h - top),
    ];
    let mut counts = [0; 4];
    for (q, n) in quads.into_iter().enumerate() {
        counts[(q + usize::from(r.pattern_phase)) % 4] = n;
    }
    ensure!(
        r.known_palette_counts == counts
            && r.palette_pixels == inner_w * inner_h
            && r.border_pixels
                == (r.buffer_width * s / 8) * (r.buffer_height * s / 8) - inner_w * inner_h,
        "phase-specific palette/border totals mismatch"
    );
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn expected(p: u8) -> ExpectedContext {
        let [w, h] = extent(p).unwrap();
        ExpectedContext {
            schema_version: 1,
            android_boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            android_user: 11,
            terminal_uid: 1110248,
            source_crop: [0, 190, 3200, 1860],
            observed_elapsed_ms: 1000,
            pattern_phase: p,
            buffer_width: w,
            buffer_height: h,
            capture_token: format!("{p:032x}"),
            fixture_sha256: "b".repeat(64),
            contract_sha256: contract_digest(p).unwrap(),
        }
    }
    fn observation(e: &ExpectedContext) -> Observation {
        let mut r: Observation=serde_json::from_str(r#"{"schema_version":1,"status":"owned_pattern_samples_matched","sampled_per_quadrant":16,"matched":[16,16,16,16],"max_channel_errors":[0,0,0,0],"tolerance":8,"crop_width":3200,"crop_height":1670,"source_crop_and_uid_verified":true,"identity_endpoints_verified":true,"buffers_released":true,"logical_display_width":3200,"logical_display_height":2000,"logical_bounds_verified":true,"capture_api_profile":"internal","bordered_locator":true,"located_relative_bounds":[100,100,740,580],"uniform_scale_eighths":8,"palette_pixels":289536,"border_pixels":17664,"pattern_phase":0,"buffer_width":640,"buffer_height":480,"capture_token":"00000000000000000000000000000000","fixture_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","contract_sha256":"","known_palette_counts":[72384,72384,72384,72384],"android_boot_id":"12345678-1234-1234-1234-123456789abc","android_user":11,"terminal_uid":1110248,"source_crop":[0,190,3200,1860],"observed_elapsed_ms":1000,"captured_elapsed_ms":1050,"raw_pixels_exported":false,"image_saved":false,"physical_panel_verified":false,"full_port_verified":false}"#).unwrap();
        r.pattern_phase = e.pattern_phase;
        r.buffer_width = e.buffer_width;
        r.buffer_height = e.buffer_height;
        r.capture_token = e.capture_token.clone();
        r.contract_sha256 = e.contract_sha256.clone();
        r.located_relative_bounds = [100, 100, 100 + e.buffer_width, 100 + e.buffer_height];
        r.palette_pixels = (e.buffer_width - 16) * (e.buffer_height - 16);
        r.border_pixels = e.buffer_width * e.buffer_height - r.palette_pixels;
        r.known_palette_counts = [r.palette_pixels / 4; 4];
        r
    }
    #[test]
    fn phase_capture_accepts_three_exact_scopes_and_contract_digests_differ() {
        let digests = [
            "8f6469453bbd9da94bfb16b7a8f881445d85141851602c70200e8913c47d9e65",
            "c8d7057e4de2d55f67f4b84015a323e6dba9188bc871836d069c690d2dcde28b",
            "e88e8d13efb7060c53713697450806f414fe33feecc348f4222284bfa346febe",
        ];
        for p in 0..3 {
            assert_eq!(contract_digest(p).unwrap(), digests[usize::from(p)]);
            let e = expected(p);
            let r = observation(&e);
            let text = serde_json::to_string(&r).unwrap();
            assert_eq!(
                inspect_capture(&(PREFIX.to_owned() + &text), &e).unwrap(),
                r
            );
            assert_eq!(e.arguments().unwrap().len(), 14);
        }
        assert_ne!(contract_digest(0).unwrap(), contract_digest(2).unwrap());
        assert!(contract_digest(3).is_err());
    }
    #[test]
    fn phase_capture_rejects_stale_restore_wrong_digest_extent_and_private_fields() {
        let e = expected(2);
        let old = observation(&expected(0));
        assert!(inspect_capture(&serde_json::to_string(&old).unwrap(), &e).is_err());
        for (k, v) in [
            ("pattern_phase", json!(0)),
            ("buffer_width", json!(480)),
            ("contract_sha256", json!("c".repeat(64))),
            ("fixture_sha256", json!("c".repeat(64))),
            ("capture_token", json!("c".repeat(32))),
            ("known_palette_counts", json!([39904, 39904, 39904, 39904])),
            ("palette_pixels", json!(159616)),
            ("border_pixels", json!(0)),
            ("matched", json!([16, 15, 16, 16])),
            ("max_channel_errors", json!([0, 9, 0, 0])),
            ("uniform_scale_eighths", json!(33)),
            ("located_relative_bounds", json!([0, 0, 640, 480])),
            ("captured_elapsed_ms", json!(16001)),
            ("buffers_released", json!(false)),
            ("raw_pixels_exported", json!(true)),
            ("display_sample_rgb", json!([1, 2, 3])),
        ] {
            let mut v0 = serde_json::to_value(observation(&e)).unwrap();
            v0[k] = v;
            assert!(inspect_capture(&v0.to_string(), &e).is_err(), "{k}");
        }
    }
    #[test]
    fn phase_capture_shrunken_odd_scale_has_asymmetric_known_counts() {
        let e = expected(1);
        let mut r = observation(&e);
        r.uniform_scale_eighths = 7;
        r.located_relative_bounds = [100, 100, 520, 415];
        r.palette_pixels = 122206;
        r.border_pixels = 10094;
        r.known_palette_counts = [30450, 30653, 30653, 30450];
        assert!(inspect_capture(&serde_json::to_string(&r).unwrap(), &e).is_ok());
        r.known_palette_counts = [30551; 4];
        assert!(inspect_capture(&serde_json::to_string(&r).unwrap(), &e).is_err());
    }
    #[test]
    fn phase_capture_duplicate_fields_and_overcaps_refuse_before_qualification() {
        let e = expected(0);
        let text = serde_json::to_string(&observation(&e)).unwrap();
        assert!(inspect_capture(&text.replacen('{', "{\"pattern_phase\":0,", 1), &e).is_err());
        let request = serde_json::to_string(&e).unwrap();
        assert!(
            serde_json::from_str::<ExpectedContext>(&request.replacen(
                '{',
                "{\"pattern_phase\":0,",
                1
            ))
            .is_err()
        );
        assert!(inspect_capture(&" ".repeat(8193), &e).is_err());
        let mut bad = e.clone();
        bad.source_crop = [0, 0, 4096, 2049];
        assert!(bad.validate().is_err());
        bad = e.clone();
        bad.pattern_phase = 3;
        assert!(bad.validate().is_err());
    }
}
