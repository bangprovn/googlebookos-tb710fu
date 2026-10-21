'use strict';
// Host-only actual-asset regression; native-like IDL handler slot uses Node's
// real EventTarget dispatcher. This does not identify an installed frontend.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const base = fs.readFileSync('/case/base.js', 'utf8');
const fixed = fs.readFileSync('/case/fixed.js', 'utf8');
assert.equal(crypto.createHash('sha256').update(base).digest('hex'),
  '880df2a09c1f7a82ad9d0e00d660a3e32453dc7e2d3bb27e9ad5504565988e4a');
assert.equal(crypto.createHash('sha256').update(fixed).digest('hex'),
  '265ed6763de4a854d0fbaaea7cbcfac9850ad191050491f1843de4205274528d');

function setup(asset, options = {}) {
  const counters = {setterCalls: 0, registrations: 0, logs: 0};
  class Socket extends EventTarget {
    #handler = null;
    get onmessage() { return this.#handler; }
    set onmessage(fn) {
      if (options.throwOnSet) throw new Error('native setter rejected');
      counters.setterCalls++;
      if (this.#handler) EventTarget.prototype.removeEventListener.call(this, 'message', this.#handler);
      this.#handler = typeof fn === 'function' ? fn : null;
      if (this.#handler) {
        EventTarget.prototype.addEventListener.call(this, 'message', this.#handler);
        counters.registrations++;
      }
    }
  }
  if (options.noDescriptor) delete Socket.prototype.onmessage;
  const descriptor = Object.getOwnPropertyDescriptor(Socket.prototype, 'onmessage');
  const window = {WebSocket: Socket};
  if (asset) vm.runInNewContext(asset, {window,
    console: {log() {counters.logs++;}, error() {throw new Error('sanitizer error');}},
    TextDecoder, TextEncoder, ArrayBuffer, MessageEvent,
  }, {timeout: 1000, contextCodeGeneration: {strings: false, wasm: false}});
  return {socket: new window.WebSocket(), counters, descriptor};
}
function deliver(socket, data) { socket.dispatchEvent(new MessageEvent('message', {data})); }
const cases = [];
function test(name, fn) { fn(); cases.push(name); }

test('baseline_native_registration_and_clear', () => {
  const {socket, counters} = setup(null); let count = 0;
  const fn = () => {count++;}; socket.onmessage = fn;
  assert.equal(socket.onmessage, fn); deliver(socket, 'data');
  socket.onmessage = null; deliver(socket, 'data');
  assert.equal(count, 1); assert.equal(counters.registrations, 1);
});
test('original_actual_asset_negative_no_native_registration', () => {
  const {socket, counters} = setup(base); let count = 0;
  socket.onmessage = () => {count++;}; deliver(socket, 'data');
  assert.equal(typeof socket.onmessage, 'function');
  assert.equal(count, 0); assert.equal(counters.setterCalls, 0);
});
test('fixed_delivery_and_assigned_getter_identity', () => {
  const {socket, counters} = setup(fixed); let count = 0;
  const fn = function(event) {assert.equal(this, socket); assert.equal(event.data, 'data'); count++;};
  socket.onmessage = fn; assert.equal(socket.onmessage, fn); deliver(socket, 'data');
  assert.equal(count, 1); assert.equal(counters.registrations, 1);
});
test('replacement_clear_noncallable_no_duplicate_delivery', () => {
  const {socket} = setup(fixed); let old = 0; let current = 0;
  const first = () => {old++;}; const second = () => {current++;};
  socket.onmessage = first; socket.onmessage = second; assert.equal(socket.onmessage, second);
  deliver(socket, 'data'); assert.equal(old, 0); assert.equal(current, 1);
  socket.onmessage = null; assert.equal(socket.onmessage, null); deliver(socket, 'data');
  socket.onmessage = second; socket.onmessage = {}; assert.equal(socket.onmessage, null); deliver(socket, 'data');
  assert.equal(current, 1);
});
test('setter_throw_preserves_native_exception_and_identity', () => {
  const {socket} = setup(fixed, {throwOnSet: true});
  assert.throws(() => {socket.onmessage = () => {};}, /native setter rejected/);
  assert.equal(socket.onmessage, null);
});
test('native_descriptor_bypass_getter_is_not_stale', () => {
  const {socket, descriptor} = setup(fixed); let count = 0;
  socket.onmessage = () => {};
  const direct = () => {count++;}; descriptor.set.call(socket, direct);
  assert.equal(socket.onmessage, direct); deliver(socket, 'data'); assert.equal(count, 1);
});
test('original_and_fixed_addEventListener_ASCII_OSC0_controls', () => {
  for (const asset of [base, fixed]) {
    const {socket} = setup(asset); let count = 0;
    const osc = '\x1b]0;GB_UNIT_ASCII\x07';
    socket.addEventListener('message', function(event) {assert.equal(this, socket); assert.equal(event.data, osc); count++;});
    deliver(socket, osc); assert.equal(count, 1);
  }
});
test('fixed_onmessage_string_binary_and_view_sanitizer', () => {
  const {socket} = setup(fixed); let count = 0;
  socket.onmessage = event => {
    const text = typeof event.data === 'string' ? event.data : new TextDecoder().decode(event.data);
    assert.equal(text, '\x1b]2;GB_UNIT_ASCII\x1b\\'); count++;
  };
  const text = '\x1b]2;GB_UNIT_\x01ASCII\x1b\\';
  deliver(socket, text); deliver(socket, new TextEncoder().encode(text).buffer); deliver(socket, new TextEncoder().encode(text));
  assert.equal(count, 3);
});
test('missing_native_descriptor_preserves_unwrapped_default_property', () => {
  const {socket} = setup(fixed, {noDescriptor: true});
  assert.equal(Object.getOwnPropertyDescriptor(socket, 'onmessage'), undefined);
});
console.log(JSON.stringify({schema_version: 1, passed_cases: cases.length, cases,
  host_only: true, installed_frontend_assignment_verified: false,
  browser_equivalence_verified: false, runtime_root_cause_verified: false}));
