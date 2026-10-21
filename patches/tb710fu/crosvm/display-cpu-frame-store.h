// SPDX-License-Identifier: Apache-2.0
// Owned front/back RGBA frames for the pinned mica CPU display transport.
// The caller serializes methods. A borrowed back pointer stays valid from
// beginFrame() until publishFrame(); consumers may read only the completed front.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

class GbCpuFrameStore {
public:
    // Bound untrusted guest geometry before multiplication or allocation.
    static constexpr uint32_t kMaxDimension = 8192;
    static constexpr size_t kMaxPixels = 16 * 1024 * 1024;

    bool configure(uint32_t width, uint32_t height) {
        if (mWriting || width == 0 || height == 0 || width > kMaxDimension ||
            height > kMaxDimension || static_cast<size_t>(width) * height > kMaxPixels) {
            return false;
        }
        const size_t pixels = static_cast<size_t>(width) * height;
        mFront.resize(pixels);
        mBack.resize(pixels);
        mWidth = width;
        mHeight = height;
        mValid = false; // A modeset must never replay pixels with stale geometry.
        return true;
    }

    uint32_t* beginFrame() {
        if (mWriting || mBack.empty()) return nullptr;
        mWriting = true;
        return mBack.data();
    }

    bool publishFrame() {
        if (!mWriting) return false;
        mFront.swap(mBack);
        mWriting = false;
        mValid = true;
        return true;
    }

    const uint32_t* completedPixels() const { return mValid ? mFront.data() : nullptr; }
    uint32_t width() const { return mWidth; }
    uint32_t height() const { return mHeight; }

private:
    std::vector<uint32_t> mFront;
    std::vector<uint32_t> mBack;
    uint32_t mWidth = 0;
    uint32_t mHeight = 0;
    bool mWriting = false;
    bool mValid = false;
};
