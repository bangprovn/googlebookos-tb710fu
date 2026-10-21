// SPDX-License-Identifier: Apache-2.0
// HYPOTHETICAL PROTOCOL MODEL ONLY. No production ABI, API, driver, IPC, FD,
// GPU, synchronization or resource implementation is supplied by this file.
// Toy bounds exercise required identity/publication/retirement invariants;
// passing them does not show that current Mesa, virtgpu or virgl implements ACKs.
#![deny(warnings)]
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key { epoch: u64, context: u32, resource: u32, serial: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Client { Waiting, Exposed, Failed }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Host { Pending, Committed, Retired }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reply { Committed, Refused }
struct Entry { client: Client, host: Host, bytes: u64, held: bool, reply: Option<Reply> }
struct Model { negotiated: bool, epoch: u64, serial: u64, entries: BTreeMap<Key, Entry> }
impl Model {
    fn new(negotiated: bool) -> Self {
        Self { negotiated, epoch: 1, serial: 0, entries: BTreeMap::new() }
    }
    fn request(&mut self, context: u32, resource: u32, bytes: u64) -> Option<Key> {
        // Finite tombstones are intentionally conservative; no unsafe ID reuse.
        if !self.negotiated || bytes == 0 || bytes > 100 || self.entries.len() >= 16
            || self.entries.values().filter(|e| e.host == Host::Pending).count() >= 4
            || self.entries.iter().any(|(k, e)| k.epoch == self.epoch && k.context == context
                && k.resource == resource && e.host != Host::Retired) {
            return None;
        }
        self.serial = self.serial.checked_add(1)?;
        let key = Key { epoch: self.epoch, context, resource, serial: self.serial };
        self.entries.insert(key, Entry { client: Client::Waiting, host: Host::Pending,
            bytes, held: false, reply: None });
        Some(key)
    }
    fn usage(&self) -> (usize, u64) {
        self.entries.values().filter(|e| e.held).fold((0, 0), |(n, b), e| (n + 1, b + e.bytes))
    }
    fn host_decide(&mut self, key: Key, supported: bool) -> Option<Reply> {
        let (slots, bytes) = self.usage();
        let entry = self.entries.get_mut(&key)?;
        if entry.host != Host::Pending { return None; }
        // Commit includes all native import/texture bookkeeping in this model.
        // Real integration must prove transactional cleanup before Refused.
        let admitted = supported && slots < 4 && entry.bytes <= 100 - bytes;
        let reply = if admitted { Reply::Committed } else { Reply::Refused };
        entry.host = if admitted { Host::Committed } else { Host::Retired };
        entry.held = admitted;
        entry.reply = Some(reply);
        Some(reply)
    }
    fn deliver_reply(&mut self, key: Key, reply: Reply) -> bool {
        if key.epoch != self.epoch { return false; }
        let Some(entry) = self.entries.get_mut(&key) else { return false; };
        // A real ACK must be the matching trusted transaction response, not an
        // inferred generic fence event or caller-invented status.
        if entry.client != Client::Waiting || entry.reply != Some(reply) { return false; }
        if reply == Reply::Committed && (entry.host != Host::Committed || !entry.held) { return false; }
        entry.client = if reply == Reply::Committed { Client::Exposed } else { Client::Failed };
        true
    }
    fn timeout(&mut self, key: Key) {
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.client == Client::Waiting { entry.client = Client::Failed; }
        }
        // Timeout alone never retires native ownership or releases credits.
    }
    fn host_retirement_confirmed(&mut self, key: Key) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.host = Host::Retired;
            entry.held = false;
        }
    }
    fn begin_reset(&mut self) {
        self.epoch = self.epoch.checked_add(1).expect("test epochs bounded");
        for entry in self.entries.values_mut() { entry.client = Client::Failed; }
        // Old backing remains charged until reset has stopped all native users.
    }
    fn old_epoch_retirement_confirmed(&mut self, old_epoch: u64) {
        for (key, entry) in &mut self.entries {
            if key.epoch == old_epoch { entry.host = Host::Retired; entry.held = false; }
        }
    }
    fn assert_bounds(&self) {
        let (slots, bytes) = self.usage();
        assert!(slots <= 4 && bytes <= 100 && self.entries.len() <= 16);
        assert!(self.entries.values().all(|e| !e.held || e.host == Host::Committed));
    }
}

#[test]
fn missing_negotiation_cannot_advertise_ack_success() {
    let mut m = Model::new(false);
    assert!(m.request(9, 59, 40).is_none());
    assert_eq!(m.usage(), (0, 0));
}
#[test]
fn completion_without_matching_success_never_exposes_resource() {
    let mut m = Model::new(true);
    let k = m.request(9, 59, 40).unwrap();
    // Generic fence completion is intentionally not an input to publication.
    assert!(!m.deliver_reply(k, Reply::Committed));
    assert_eq!(m.entries[&k].client, Client::Waiting);
    assert_eq!(m.host_decide(k, false), Some(Reply::Refused));
    assert!(!m.deliver_reply(k, Reply::Committed));
    assert!(m.deliver_reply(k, Reply::Refused));
    assert_eq!(m.entries[&k].client, Client::Failed);
    m.assert_bounds();
}
#[test]
fn reordered_and_mismatched_transaction_replies_cannot_cross_publish() {
    for reverse in [false, true] {
        let mut m = Model::new(true);
        let a = m.request(9, 59, 20).unwrap();
        let b = m.request(9, 60, 20).unwrap();
        m.host_decide(a, true); m.host_decide(b, true);
        assert!(!m.deliver_reply(Key { serial: 99, ..a }, Reply::Committed));
        assert!(!m.deliver_reply(Key { context: 10, ..a }, Reply::Committed));
        for key in if reverse { [b, a] } else { [a, b] } {
            assert!(m.deliver_reply(key, Reply::Committed));
        }
        assert_eq!(m.entries[&a].client, Client::Exposed);
        assert_eq!(m.entries[&b].client, Client::Exposed);
        m.assert_bounds();
    }
}
#[test]
fn timeout_and_late_commit_hold_backing_until_confirmed_retirement() {
    for commit_before_timeout in [false, true] {
        let mut m = Model::new(true);
        let k = m.request(9, 59, 40).unwrap();
        if commit_before_timeout { m.host_decide(k, true); }
        m.timeout(k);
        if !commit_before_timeout { m.host_decide(k, true); }
        assert_eq!(m.usage(), (1, 40));
        assert!(!m.deliver_reply(k, Reply::Committed));
        assert_eq!(m.entries[&k].client, Client::Failed);
        m.host_retirement_confirmed(k);
        m.host_retirement_confirmed(k);
        assert_eq!(m.usage(), (0, 0));
        m.assert_bounds();
    }
}
#[test]
fn duplicates_and_conflicting_status_never_resurrect_or_release_twice() {
    let mut m = Model::new(true);
    let k = m.request(9, 59, 40).unwrap();
    m.host_decide(k, true);
    assert!(m.deliver_reply(k, Reply::Committed));
    assert!(!m.deliver_reply(k, Reply::Committed));
    assert!(!m.deliver_reply(k, Reply::Refused));
    assert_eq!(m.usage(), (1, 40));
    m.host_retirement_confirmed(k);
    assert!(!m.deliver_reply(k, Reply::Committed));
    assert_eq!(m.usage(), (0, 0));
    let retired_before_delivery = m.request(9, 60, 40).unwrap();
    m.host_decide(retired_before_delivery, true);
    m.host_retirement_confirmed(retired_before_delivery);
    assert!(!m.deliver_reply(retired_before_delivery, Reply::Committed));
    m.assert_bounds();
}
#[test]
fn expected_capacity_refusal_is_client_local_and_other_resource_progresses() {
    let mut m = Model::new(true);
    let a = m.request(9, 59, 60).unwrap();
    m.host_decide(a, true); m.deliver_reply(a, Reply::Committed);
    let b = m.request(9, 60, 60).unwrap();
    assert_eq!(m.host_decide(b, true), Some(Reply::Refused));
    assert!(m.deliver_reply(b, Reply::Refused));
    assert_eq!(m.entries[&a].client, Client::Exposed);
    assert_eq!(m.usage(), (1, 60));
    m.host_retirement_confirmed(a);
    let c = m.request(9, 61, 60).unwrap();
    m.host_decide(c, true); assert!(m.deliver_reply(c, Reply::Committed));
    m.assert_bounds();
}
#[test]
fn reset_and_resource_reuse_reject_old_ack_and_keep_old_backing_charged() {
    let mut m = Model::new(true);
    let old = m.request(9, 59, 40).unwrap();
    m.host_decide(old, true);
    m.begin_reset();
    assert_eq!(m.usage(), (1, 40));
    let new = m.request(9, 59, 40).unwrap();
    m.host_decide(new, true);
    assert!(!m.deliver_reply(old, Reply::Committed));
    assert_eq!(m.entries[&new].client, Client::Waiting);
    m.old_epoch_retirement_confirmed(old.epoch);
    assert_eq!(m.usage(), (1, 40));
    assert!(m.deliver_reply(new, Reply::Committed));
    m.assert_bounds();
}
#[test]
fn malformed_requests_and_pending_record_limits_fail_closed() {
    let mut m = Model::new(true);
    assert!(m.request(9, 1, 0).is_none()); assert!(m.request(9, 1, 101).is_none());
    let first = m.request(9, 1, 1).unwrap();
    assert!(m.request(9, 1, 1).is_none());
    for id in 2..=4 { m.request(9, id, 1).unwrap(); }
    assert!(m.request(9, 5, 1).is_none());
    m.host_decide(first, false); m.deliver_reply(first, Reply::Refused);
    for id in 5..=16 {
        let k = m.request(9, id, 1).unwrap();
        m.host_decide(k, false); m.deliver_reply(k, Reply::Refused);
    }
    assert!(m.request(9, 17, 1).is_none());
    m.assert_bounds();
}
