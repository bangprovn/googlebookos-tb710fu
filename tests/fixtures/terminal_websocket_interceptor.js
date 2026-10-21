/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

(function() {
    if (window.WebSocket && !window.WebSocket.isProxy) {
        function sanitizeOscTitle(bufferOrString) {
            try {
                if (typeof bufferOrString === 'string') {
                    if (bufferOrString.includes('\x1b]')) {
                        return bufferOrString.replace(/\x1b\]([0-9]+);([\s\S]*?)(\x07|\x1b\\)/g, function(match, cmd, payload, term) {
                            const cleanPayload = payload.replace(/[\x00-\x1f\x7f]/g, '');
                            return '\x1b]' + cmd + ';' + cleanPayload + term;
                        });
                    }
                } else if (bufferOrString instanceof ArrayBuffer || ArrayBuffer.isView(bufferOrString)) {
                    let text = new TextDecoder().decode(bufferOrString);
                    if (text.includes('\x1b]')) {
                        text = text.replace(/\x1b\]([0-9]+);([\s\S]*?)(\x07|\x1b\\)/g, function(match, cmd, payload, term) {
                            const cleanPayload = payload.replace(/[\x00-\x1f\x7f]/g, '');
                            return '\x1b]' + cmd + ';' + cleanPayload + term;
                        });
                        const encoded = new TextEncoder().encode(text);
                        return bufferOrString instanceof ArrayBuffer ? encoded.buffer : encoded;
                    }
                }
            } catch (e) {
                console.error('Error sanitizing OSC sequence in WebSocket:', e);
            }
            return bufferOrString;
        }

        window.WebSocket = new Proxy(window.WebSocket, {
            construct: function(target, args) {
                var instance = Reflect.construct(target, args);
                window.ttydSocket = instance;

                var origAddEventListener = instance.addEventListener;
                instance.addEventListener = function(type, listener, options) {
                    if (type === 'message') {
                        var wrappedListener = function(event) {
                            var cleanData = sanitizeOscTitle(event.data);
                            var newEvent = new MessageEvent('message', {
                                data: cleanData,
                                origin: event.origin,
                                lastEventId: event.lastEventId,
                                source: event.source,
                                ports: event.ports
                            });
                            listener.call(this, newEvent);
                        };
                        return origAddEventListener.call(this, type, wrappedListener, options);
                    }
                    return origAddEventListener.call(this, type, listener, options);
                };

                let _onmessage = null;
                Object.defineProperty(instance, 'onmessage', {
                    get: function() { return _onmessage; },
                    set: function(fn) {
                        if (!fn) { _onmessage = null; return; }
                        _onmessage = function(event) {
                            var cleanData = sanitizeOscTitle(event.data);
                            var newEvent = new MessageEvent('message', {
                                data: cleanData,
                                origin: event.origin,
                                lastEventId: event.lastEventId,
                                source: event.source,
                                ports: event.ports
                            });
                            fn.call(this, newEvent);
                        };
                    }
                });

                return instance;
            }
        });
        window.WebSocket.isProxy = true;
        console.log('WebSocket intercepted and OSC title sanitizer installed');
    }
})();
