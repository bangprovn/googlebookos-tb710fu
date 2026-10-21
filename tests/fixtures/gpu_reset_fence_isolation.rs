// BEGIN PINNED UPSTREAM LICENSE (BSD-3-Clause)
// Copyright 2017 The ChromiumOS Authors
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// END PINNED UPSTREAM LICENSE
//
// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file of the pinned upstream crosvm repository.
//
// Offline feasibility fixture only, not a production backport. The allocator
// below is copied verbatim from Droid-VM/crosvm commit
// 3a099579ac7b0c42cd249e6bebfe32c8f44e3625. Forwarding methods are inserted
// verbatim from checksum-pinned local source by the Python harness.
// All renderer handles, queues and IPC are stand-ins; no GPU/FD/device calls.
#![deny(warnings)]
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

mod anyhow { pub type Result<T> = std::result::Result<T, String>; }
trait Context<T> { fn context(self, message: &str) -> anyhow::Result<T>; }
impl<T> Context<T> for Result<T, String> {
    fn context(self, message: &str) -> anyhow::Result<T> {
        self.map_err(|error| format!("{message}: {error}"))
    }
}
#[derive(PartialEq)]
enum VirtioGpuRing { Global, ContextSpecific { ctx_id: u32, ring_idx: u8 } }
#[derive(Default)]
struct FenceState { last_fence_id: u64 }
impl FenceState {
// BEGIN VERBATIM UPSTREAM ALLOCATOR
    fn allocate_fence_id(&mut self, ring: &VirtioGpuRing) -> Option<u64> {
        let id = self.last_fence_id.checked_add(1)?;
        // The legacy virgl global-fence callback carries only 32 bits. Never
        // wrap it into an ID that could refer to another queue generation.
        if *ring == VirtioGpuRing::Global && id > u32::MAX as u64 {
            return None;
        }
        self.last_fence_id = id;
        Some(id)
    }
// END VERBATIM UPSTREAM ALLOCATOR
}
#[derive(Debug, PartialEq)]
enum RutabagaError { InvalidComponent, InvalidContextId, InvalidRutabagaHandle }
type RutabagaResult<T> = Result<T, RutabagaError>;
#[derive(Debug, PartialEq)]
enum GpuResponse { OkNoData, Error(RutabagaError) }
use GpuResponse::OkNoData;
impl From<RutabagaError> for GpuResponse {
    fn from(error: RutabagaError) -> Self { Self::Error(error) }
}
type VirtioGpuResult = Result<GpuResponse, GpuResponse>;
struct RutabagaHandle { os_handle: u64 }
impl RutabagaHandle {
    #[cfg(fence_passing_option1)]
    fn try_clone(&self) -> RutabagaResult<Self> { Ok(Self { os_handle: self.os_handle }) }
}
#[derive(Debug, PartialEq)]
enum ResourceInfo { Fence { handle: u64 } }
#[derive(Debug, PartialEq)]
enum ResourceResponse { Resource(ResourceInfo), Invalid }
fn to_safe_descriptor(handle: u64) -> u64 { handle }
#[derive(Clone)]
struct MockRenderer {
    fences: Rc<RefCell<BTreeMap<u64, u64>>>,
    exports: Rc<RefCell<Vec<u64>>>,
    submissions: Rc<RefCell<Vec<Vec<u64>>>>,
}
impl MockRenderer {
    fn export_fence(&self, id: u64) -> RutabagaResult<RutabagaHandle> {
        self.exports.borrow_mut().push(id);
        self.fences.borrow().get(&id).copied()
            .map(|os_handle| RutabagaHandle { os_handle })
            .ok_or(RutabagaError::InvalidRutabagaHandle)
    }
    fn submit_cmd(&mut self, _commands: &mut [u8], ids: &[u64], _handles: Vec<RutabagaHandle>)
        -> RutabagaResult<()> {
        self.submissions.borrow_mut().push(ids.to_vec());
        if ids.iter().all(|id| self.fences.borrow().contains_key(id)) { Ok(()) }
        else { Err(RutabagaError::InvalidRutabagaHandle) }
    }
}
struct Rutabaga {
    default_component: u32,
    components: BTreeMap<u32, MockRenderer>,
    contexts: BTreeMap<u32, MockRenderer>,
    #[cfg(fence_passing_option1)]
    shareable_fences: BTreeMap<u64, RutabagaHandle>,
}
impl Rutabaga {
// ACTUAL_RUTABAGA_EXPORT
// ACTUAL_RUTABAGA_SUBMIT
}
struct VirtioGpu { rutabaga: Rutabaga }
impl VirtioGpu {
// ACTUAL_VIRTIO_EXPORT
// ACTUAL_VIRTIO_SUBMIT
    fn export_resource(&mut self, _id: u32) -> ResourceResponse { ResourceResponse::Invalid }
}
enum ResourceRequest { GetBuffer { id: u32 }, GetFence { seqno: u64 } }
struct Tube { request: RefCell<Option<ResourceRequest>>, sent: RefCell<Vec<ResourceResponse>> }
impl Tube {
    fn recv(&self) -> Result<ResourceRequest, String> {
        self.request.borrow_mut().take().ok_or_else(|| "empty mock request".into())
    }
    fn send(&self, response: &ResourceResponse) -> Result<(), String> {
        match response {
            ResourceResponse::Resource(ResourceInfo::Fence { handle }) =>
                self.sent.borrow_mut().push(ResourceResponse::Resource(ResourceInfo::Fence { handle: *handle })),
            ResourceResponse::Invalid => self.sent.borrow_mut().push(ResourceResponse::Invalid),
        }
        Ok(())
    }
}
struct Frontend { virtio_gpu: VirtioGpu }
impl Frontend {
// ACTUAL_RESOURCE_BRIDGE
}
fn setup(fences: &[(u64, u64)]) -> (Frontend, MockRenderer) {
    let renderer = MockRenderer {
        fences: Rc::new(RefCell::new(fences.iter().copied().collect())),
        exports: Rc::new(RefCell::new(Vec::new())),
        submissions: Rc::new(RefCell::new(Vec::new())),
    };
    let rutabaga = Rutabaga {
        default_component: 1,
        components: BTreeMap::from([(1, renderer.clone())]),
        contexts: BTreeMap::from([(9, renderer.clone())]),
        #[cfg(fence_passing_option1)]
        shareable_fences: fences.iter().map(|(id, handle)| (*id, RutabagaHandle { os_handle: *handle })).collect(),
    };
    (Frontend { virtio_gpu: VirtioGpu { rutabaga } }, renderer)
}
fn export(frontend: &mut Frontend, id: u64) -> ResourceResponse {
    let tube = Tube { request: RefCell::new(Some(ResourceRequest::GetFence { seqno: id })), sent: RefCell::new(Vec::new()) };
    frontend.process_resource_bridge(&tube).unwrap();
    let result = tube.sent.borrow_mut().pop().unwrap();
    result
}
#[test]
fn unchanged_guest_renderer_id_exports_the_requested_fence() {
    let (mut frontend, _) = setup(&[(42, 4200)]);
    assert_eq!(export(&mut frontend, 42), ResourceResponse::Resource(ResourceInfo::Fence { handle: 4200 }));
}
#[test]
fn isolated_allocator_breaks_guest_id_export_lookup() {
    let mut state = FenceState::default();
    let renderer_id = state.allocate_fence_id(&VirtioGpuRing::Global).unwrap();
    assert_ne!(renderer_id, 42);
    let (mut frontend, _) = setup(&[(renderer_id, 4200)]);
    assert_eq!(export(&mut frontend, 42), ResourceResponse::Invalid);
    assert_eq!(export(&mut frontend, renderer_id), ResourceResponse::Resource(ResourceInfo::Fence { handle: 4200 }));
}
#[test]
fn overlapping_guest_id_can_export_another_submissions_fence() {
    let mut state = FenceState::default();
    let first_renderer_id = state.allocate_fence_id(&VirtioGpuRing::Global).unwrap(); // guest42
    let second_guest_id = first_renderer_id;
    let second_renderer_id = state.allocate_fence_id(&VirtioGpuRing::Global).unwrap(); // guest1
    let (mut frontend, _) = setup(&[(first_renderer_id, 4200), (second_renderer_id, 100)]);
    assert_eq!(export(&mut frontend, second_guest_id), ResourceResponse::Resource(ResourceInfo::Fence { handle: 4200 }));
    assert_ne!(export(&mut frontend, second_guest_id), ResourceResponse::Resource(ResourceInfo::Fence { handle: 100 }));
}
#[test]
fn unchanged_input_fence_ids_reach_the_matching_renderer_entry() {
    let (mut frontend, renderer) = setup(&[(42, 4200)]);
    assert_eq!(frontend.virtio_gpu.submit_command(9, &mut [0; 4], &[42]), Ok(OkNoData));
    assert_eq!(*renderer.submissions.borrow(), vec![vec![42]]);
}
#[test]
fn remapping_requires_input_fence_translation_too() {
    let mut state = FenceState::default();
    let id = state.allocate_fence_id(&VirtioGpuRing::Global).unwrap();
    let (mut frontend, _) = setup(&[(id, 4200)]);
    assert_eq!(frontend.virtio_gpu.submit_command(9, &mut [0; 4], &[42]), Err(GpuResponse::Error(RutabagaError::InvalidRutabagaHandle)));
    assert_eq!(frontend.virtio_gpu.submit_command(9, &mut [0; 4], &[id]), Ok(OkNoData));
}
#[test]
fn unaffected_buffer_export_control_and_unknown_context_remain_errors() {
    let (mut frontend, _) = setup(&[]);
    let tube = Tube { request: RefCell::new(Some(ResourceRequest::GetBuffer { id: 3 })), sent: RefCell::new(Vec::new()) };
    frontend.process_resource_bridge(&tube).unwrap();
    assert_eq!(*tube.sent.borrow(), vec![ResourceResponse::Invalid]);
    assert_eq!(frontend.virtio_gpu.submit_command(99, &mut [], &[]), Err(GpuResponse::Error(RutabagaError::InvalidContextId)));
}
#[test]
fn actual_upstream_allocator_refuses_callback_width_wrap() {
    let mut state = FenceState { last_fence_id: u32::MAX as u64 };
    assert_eq!(state.allocate_fence_id(&VirtioGpuRing::Global), None);
    let ring = VirtioGpuRing::ContextSpecific { ctx_id: 9, ring_idx: 1 };
    assert_eq!(state.allocate_fence_id(&ring), Some(u32::MAX as u64 + 1));
    state.last_fence_id = u64::MAX;
    assert_eq!(state.allocate_fence_id(&ring), None);
}
