#!/usr/bin/env python3
"""Compile the actual patched mapper method with a host-only fake IPC client.

No mirrored remove implementation, whole VMM build, IPC, firmware or GPU calls.
The baseline method must fail the same ownership-retention regression.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT/'patches/tb710fu/crosvm'
SOURCE = ROOT/'artifacts/source/crosvm-android16qpr2-backend/external/crosvm'

PREFIX = r'''
#![deny(warnings)]
use std::cell::{Cell,RefCell};
use std::collections::{BTreeMap,VecDeque};
mod anyhow { pub type Result<T> = std::result::Result<T,String>; }
trait Context<T> { fn context(self,message:&str) -> anyhow::Result<T>; }
impl<T> Context<T> for Option<T> {
    fn context(self,message:&str) -> anyhow::Result<T> { self.ok_or_else(|| message.to_owned()) }
}
impl<T,E:std::fmt::Display> Context<T> for Result<T,E> {
    fn context(self,message:&str) -> anyhow::Result<T> { self.map_err(|error| format!("{message}: {error}")) }
}
#[derive(Debug,Copy,Clone,PartialEq,Eq)]
struct VmMemoryRegionId(u64);
struct VmMemoryClient {
    outcomes: RefCell<VecDeque<Result<(),&'static str>>>,
    calls: RefCell<Vec<VmMemoryRegionId>>,
    completed: Cell<usize>,
}
impl VmMemoryClient {
    fn unregister_memory(&self,id:VmMemoryRegionId) -> Result<(),&'static str> {
        self.calls.borrow_mut().push(id);
        let outcome=self.outcomes.borrow_mut().pop_front().unwrap_or(Ok(()));
        if outcome.is_ok() { self.completed.set(self.completed.get()+1); }
        outcome
    }
}
struct VmRequester { mappings:BTreeMap<u64,VmMemoryRegionId>,vm_memory_client:VmMemoryClient }
trait SharedMemoryMapper { fn remove_mapping(&mut self,offset:u64) -> anyhow::Result<()>; }
impl SharedMemoryMapper for VmRequester {
'''
SUFFIX = r'''
}
fn requester(outcomes:Vec<Result<(),&'static str>>) -> VmRequester {
    VmRequester {
        mappings:BTreeMap::from([(0x2000,VmMemoryRegionId(41)),(0x8000,VmMemoryRegionId(99))]),
        vm_memory_client:VmMemoryClient {
            outcomes:RefCell::new(outcomes.into()),calls:RefCell::new(Vec::new()),completed:Cell::new(0)
        }
    }
}
#[test]
fn failed_then_successful_explicit_retry_keeps_original_id() {
    let mut mapper=requester(vec![Err("simulated reclaim refusal"),Ok(())]);
    let error=mapper.remove_mapping(0x2000).unwrap_err();
    assert!(error.contains("unregister_memory failed") && error.contains("simulated reclaim refusal"));
    assert_eq!(mapper.mappings.get(&0x2000),Some(&VmMemoryRegionId(41)));
    assert_eq!(mapper.mappings.get(&0x8000),Some(&VmMemoryRegionId(99)));
    assert_eq!(*mapper.vm_memory_client.calls.borrow(),vec![VmMemoryRegionId(41)]);
    assert_eq!(mapper.vm_memory_client.completed.get(),0);
    mapper.remove_mapping(0x2000).unwrap();
    assert!(!mapper.mappings.contains_key(&0x2000));
    assert_eq!(mapper.mappings.get(&0x8000),Some(&VmMemoryRegionId(99)));
    assert_eq!(*mapper.vm_memory_client.calls.borrow(),vec![VmMemoryRegionId(41),VmMemoryRegionId(41)]);
    assert_eq!(mapper.vm_memory_client.completed.get(),1);
    assert_eq!(mapper.remove_mapping(0x2000).unwrap_err(),"invalid offset");
    assert_eq!(mapper.vm_memory_client.calls.borrow().len(),2);
    assert_eq!(mapper.vm_memory_client.completed.get(),1);
}
#[test]
fn unknown_offset_never_requests_unregister() {
    let mut mapper=requester(vec![Err("must never be requested")]);
    let before=mapper.mappings.clone();
    assert_eq!(mapper.remove_mapping(0xdead).unwrap_err(),"invalid offset");
    assert_eq!(mapper.mappings,before);
    assert!(mapper.vm_memory_client.calls.borrow().is_empty());
    assert_eq!(mapper.vm_memory_client.outcomes.borrow().len(),1);
}
#[test]
fn successful_unregister_retires_once_and_preserves_other_offset() {
    let mut mapper=requester(vec![Ok(())]);
    mapper.remove_mapping(0x2000).unwrap();
    assert_eq!(mapper.mappings.len(),1);
    assert_eq!(mapper.mappings.get(&0x8000),Some(&VmMemoryRegionId(99)));
    assert!(mapper.remove_mapping(0x2000).is_err());
    assert_eq!(*mapper.vm_memory_client.calls.borrow(),vec![VmMemoryRegionId(41)]);
    assert_eq!(mapper.vm_memory_client.completed.get(),1);
}
#[test]
fn repeated_failures_never_erase_ownership_or_retry_automatically() {
    let mut mapper=requester(vec![Err("one"),Err("two"),Err("three")]);
    for attempts in 1..=3 {
        assert!(mapper.remove_mapping(0x2000).is_err());
        assert_eq!(mapper.mappings.get(&0x2000),Some(&VmMemoryRegionId(41)));
        assert_eq!(mapper.vm_memory_client.calls.borrow().len(),attempts);
        assert_eq!(mapper.vm_memory_client.completed.get(),0);
    }
}
'''


class UnregisterOwnership(unittest.TestCase):
    def test_exact_round_trip_and_actual_rust_method_retry_ownership(self):
        digest = lambda data: hashlib.sha256(data).hexdigest()
        manifest = json.loads((PATCHES/'shared-memory-unregister-ownership.json').read_text())
        entry, = manifest['files']
        patch = PATCHES/'shared-memory-unregister-ownership.patch'
        self.assertEqual(digest(patch.read_bytes()), manifest['patch_sha256'])
        base = (SOURCE/entry['path']).read_bytes()
        self.assertEqual(digest(base), entry['sha256'])
        with tempfile.TemporaryDirectory(prefix='gb-unregister-ownership-') as directory:
            work = Path(directory)
            path = work/entry['path']
            path.parent.mkdir(parents=True)
            path.write_bytes(base)
            for reverse, key in [(False,'result_sha256'),(True,'sha256'),(False,'result_sha256')]:
                command = ['patch','--batch','--fuzz=0','-p1','-i',str(patch)]
                if reverse:
                    command.append('--reverse')
                result = subprocess.run(command,cwd=work,capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(digest(path.read_bytes()),entry[key])
            patched = path.read_text()
            for name, source in [('base',base.decode()),('patched',patched)]:
                owner = source.index('impl SharedMemoryMapper for VmRequester {')
                start = source.index('    fn remove_mapping(&mut self, offset: u64)',owner)
                end = source.index('\n    fn as_raw_descriptor(',start)
                # This is the actual source method, with no body substitution.
                method = source[start:end]
                rust = work/(name+'.rs');binary = work/name
                rust.write_text(PREFIX+method+SUFFIX)
                built = subprocess.run(['rustc','--edition=2021','--test','-D','warnings',str(rust),'-o',str(binary)],
                                       capture_output=True,text=True,timeout=30)
                self.assertEqual(built.returncode,0,built.stdout+built.stderr)
                command = [str(binary),'--nocapture']
                if name == 'base':
                    command.append('failed_then_successful_explicit_retry_keeps_original_id')
                tested = subprocess.run(command,capture_output=True,text=True,timeout=10)
                if name == 'base':
                    self.assertEqual(tested.returncode,101,tested.stdout+tested.stderr)
                    self.assertIn('left: None',tested.stderr)
                    self.assertIn('1 failed',tested.stdout)
                else:
                    self.assertEqual(tested.returncode,0,tested.stdout+tested.stderr)
                    self.assertIn('4 passed',tested.stdout)
                    self.assertEqual(tested.stderr,'')


if __name__ == '__main__':
    unittest.main()
