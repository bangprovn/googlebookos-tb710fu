"""Offline Rust serde regressions over the pinned actual crosvm struct.

The strict receiver is the four-field contract recovered from the pinned donor
virtmgr; it is a host contract model, not execution of donor firmware or Binder.
Default tests use tracked, licensed inputs and need no ignored source/artifacts.
"""
from pathlib import Path
import argparse
import hashlib
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/display_parameters_compat_null.rs'
PATCH = ROOT / 'patches/tb710fu/crosvm/display-parameters-compat-null.patch'
BASE_STRUCT_SHA = 'f629ff0c0c9eaf27bd25bce6340cf7cd3ac265b4da77565030f425815e492f79'
ACTUAL_SOURCE = None


def actual_struct(text):
    position = text.index('pub struct DisplayParameters')
    start = text.rindex('#[derive', 0, position)
    end = text.index('\nimpl DisplayParameters', position) if '\nimpl DisplayParameters' in text[position:] else text.index('// ACTUAL_STRUCT_END', position)
    return text[start:end].rstrip() + '\n'


def baseline():
    text = actual_struct(FIXTURE.read_text())
    assert hashlib.sha256(text.encode()).hexdigest() == BASE_STRUCT_SHA
    return text


def patched():
    text = baseline()
    for axis in ('horizontal', 'vertical'):
        old = '#[serde(rename = "' + axis + '-dpi")]'
        new = '#[serde(rename = "' + axis + '-dpi", skip_serializing_if = "Option::is_none")]'
        assert text.count(old) == 1
        text = text.replace(old, new)
    return text


RUST_TESTS = r'''
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayMode { Windowed(u32,u32) }
impl Default for DisplayMode { fn default() -> Self { Self::Windowed(1280,720) } }
fn default_refresh_rate() -> u32 { 60 }
// Strict installed donor field contract, not the donor executable/API itself.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all="kebab-case")]
struct DonorParameters { mode: DisplayMode, hidden: bool, refresh_rate: u32, dpi:(u32,u32) }
fn normalized() -> Value {
    json!({"mode":{"windowed":[1280,720]},"hidden":false,"refresh-rate":60,"dpi":[160,160]})
}
#[test]
fn baseline_emits_two_null_compat_fields_rejected_by_donor_contract() {
    let value: baseline::DisplayParameters = serde_json::from_value(normalized()).unwrap();
    let wire=serde_json::to_value(value).unwrap();
    assert_eq!(wire.as_object().unwrap().len(),6);
    assert!(wire["horizontal-dpi"].is_null() && wire["vertical-dpi"].is_null());
    let error=serde_json::from_value::<DonorParameters>(wire).unwrap_err().to_string();
    assert!(error.contains("unknown field") && error.contains("horizontal-dpi"),"{error}");
}
#[test]
fn patched_four_field_result_preserves_actual_display_values() {
    let value: patched::DisplayParameters = serde_json::from_value(normalized()).unwrap();
    let wire=serde_json::to_value(value).unwrap();
    assert_eq!(wire,normalized());
    let donor:DonorParameters=serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(donor.mode,DisplayMode::Windowed(1280,720));assert!(!donor.hidden);
    assert_eq!(donor.refresh_rate,60);assert_eq!(donor.dpi,(160,160));
    let older:baseline::DisplayParameters=serde_json::from_value(wire).unwrap();
    assert!(older.__horizontal_dpi_compat.is_none() && older.__vertical_dpi_compat.is_none());
}
#[test]
fn legacy_dpi_deserialization_and_nonempty_serialization_are_retained() {
    let legacy=json!({"mode":{"windowed":[1280,720]},"hidden":false,"refresh-rate":60,
                      "horizontal-dpi":200,"vertical-dpi":210});
    let a:baseline::DisplayParameters=serde_json::from_value(legacy.clone()).unwrap();
    let b:patched::DisplayParameters=serde_json::from_value(legacy).unwrap();
    assert_eq!(a.__horizontal_dpi_compat,b.__horizontal_dpi_compat);
    assert_eq!(a.__vertical_dpi_compat,b.__vertical_dpi_compat);
    assert_eq!((b.__horizontal_dpi_compat,b.__vertical_dpi_compat),(Some(200),Some(210)));
    assert!(b.dpi.is_none());
    let wire=serde_json::to_value(b).unwrap();
    assert_eq!(wire["horizontal-dpi"],200);assert_eq!(wire["vertical-dpi"],210);
}
#[test]
fn omission_is_independent_for_each_compat_axis() {
    let mut value:patched::DisplayParameters=serde_json::from_value(normalized()).unwrap();
    value.__horizontal_dpi_compat=Some(123);
    let wire=serde_json::to_value(&value).unwrap();
    assert_eq!(wire["horizontal-dpi"],123);assert!(wire.get("vertical-dpi").is_none());
    value.__horizontal_dpi_compat=None;value.__vertical_dpi_compat=Some(124);
    let wire=serde_json::to_value(value).unwrap();
    assert_eq!(wire["vertical-dpi"],124);assert!(wire.get("horizontal-dpi").is_none());
}
#[test]
fn explicit_null_input_and_unknown_field_rejection_remain_unchanged() {
    let mut value=normalized();value["horizontal-dpi"]=Value::Null;value["vertical-dpi"]=Value::Null;
    let p:patched::DisplayParameters=serde_json::from_value(value.clone()).unwrap();
    assert!(p.__horizontal_dpi_compat.is_none() && p.__vertical_dpi_compat.is_none());
    value["unexpected-width"]=json!(3200);
    assert!(serde_json::from_value::<baseline::DisplayParameters>(value.clone()).is_err());
    assert!(serde_json::from_value::<patched::DisplayParameters>(value).is_err());
}
'''


class CompatNullTests(unittest.TestCase):
    def test_patch_only_adds_two_none_serialization_conditions(self):
        lines = PATCH.read_text().splitlines()
        added = [s[1:] for s in lines if s.startswith('+') and not s.startswith('+++')]
        removed = [s[1:] for s in lines if s.startswith('-') and not s.startswith('---')]
        self.assertEqual(removed, ['    #[serde(rename = "' + a + '-dpi")]' for a in ('horizontal','vertical')])
        self.assertEqual(added, ['    #[serde(rename = "' + a + '-dpi", skip_serializing_if = "Option::is_none")]' for a in ('horizontal','vertical')])
        self.assertIn('deny_unknown_fields', patched())

    def test_actual_struct_serde_regressions_offline(self):
        # Remove ONLY the unrelated CLI key-value derive; serde and every field/
        # attribute remain verbatim from the actual source snapshot.
        modules=''
        for name,text in [('baseline',baseline()),('patched',patched())]:
            self.assertEqual(text.count(', FromKeyValues'),1)
            modules += 'mod '+name+' { use super::*;\n'+text.replace(', FromKeyValues','')+'}\n'
        with tempfile.TemporaryDirectory(prefix='gb-display-compat-') as tmp:
            folder=Path(tmp);(folder/'src').mkdir()
            (folder/'Cargo.toml').write_text('[package]\nname="owned-display-compat-regression"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\nserde={version="=1.0.229",features=["derive"]}\nserde_json="=1.0.154"\n')
            (folder/'src/lib.rs').write_text(RUST_TESTS+'\n'+modules)
            result=subprocess.run(['cargo','test','--offline','--quiet','--manifest-path',str(folder/'Cargo.toml')],
                                  capture_output=True,text=True,timeout=90,env=dict(os.environ))
        self.assertEqual(result.returncode,0,result.stderr[-5000:])
        self.assertIn('5 passed; 0 failed',result.stdout)

    def test_optional_actual_patched_source_matches_exact_snapshot(self):
        if ACTUAL_SOURCE is None:
            self.skipTest('pass --actual-source for ignored source binding; defaults remain clean-clone-safe')
        self.assertEqual(actual_struct(ACTUAL_SOURCE.read_text()),patched())
        self.assertEqual(hashlib.sha256(ACTUAL_SOURCE.read_bytes()).hexdigest(),
                         '540496f30b78989bba11646f6a0cb2f9ef428f9793e278361022e196dcc71051')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--actual-source',type=Path)
    args,remaining=parser.parse_known_args();ACTUAL_SOURCE=args.actual_source
    unittest.main(argv=[__file__,*remaining])
