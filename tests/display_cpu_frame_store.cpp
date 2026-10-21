// SPDX-License-Identifier: Apache-2.0
#include "../patches/tb710fu/crosvm/display-cpu-frame-store.h"

#include <algorithm>
#include <cassert>
#include <limits>
#include <vector>

int main() {
    GbCpuFrameStore frames;
    assert(frames.beginFrame() == nullptr);
    assert(!frames.publishFrame());
    assert(!frames.configure(0, 3));
    assert(!frames.configure(3, 0));
    assert(!frames.configure(std::numeric_limits<uint32_t>::max(), 2));
    assert(!frames.configure(8192, 8192));
    assert(frames.configure(4, 3));
    assert(frames.completedPixels() == nullptr);

    auto* back = frames.beginFrame();
    assert(back != nullptr);
    assert(frames.beginFrame() == nullptr);
    assert(!frames.configure(2, 2)); // Never invalidate an outstanding producer borrow.
    std::fill(back, back + 12, 0x102030ff);
    assert(frames.completedPixels() == nullptr);
    assert(frames.publishFrame());
    assert(!frames.publishFrame());

    // A consumer can be destroyed/recreated with no guest update. Its replacement
    // receives a complete previous frame, not zeroed or partially written pixels.
    std::vector<uint32_t> window(frames.completedPixels(), frames.completedPixels() + 12);
    window.clear();
    auto* next = frames.beginFrame();
    assert(next != nullptr && next != frames.completedPixels());
    std::fill(next, next + 6, 0xaabbccff); // Deliberately incomplete next frame.
    window.assign(frames.completedPixels(), frames.completedPixels() + 12);
    assert(std::all_of(window.begin(), window.end(), [](auto p) { return p == 0x102030ff; }));
    std::fill(next + 6, next + 12, 0xaabbccff);
    assert(frames.publishFrame());
    window.assign(frames.completedPixels(), frames.completedPixels() + 12);
    assert(std::all_of(window.begin(), window.end(), [](auto p) { return p == 0xaabbccff; }));

    // Repeated background updates retain the newest complete frame and never
    // expose producer storage. No consumer/Android window pointer is retained.
    for (uint32_t color = 0; color < 1024; ++color) {
        auto* pixels = frames.beginFrame();
        assert(pixels != nullptr && pixels != frames.completedPixels());
        std::fill(pixels, pixels + 12, color);
        assert(frames.publishFrame());
        assert(frames.completedPixels()[11] == color);
    }

    assert(frames.configure(7, 2));
    assert(frames.width() == 7 && frames.height() == 2);
    assert(frames.completedPixels() == nullptr);
    auto* resized = frames.beginFrame();
    std::fill(resized, resized + 14, 0x556677ff);
    assert(frames.publishFrame());
    assert(frames.completedPixels()[13] == 0x556677ff);
}
