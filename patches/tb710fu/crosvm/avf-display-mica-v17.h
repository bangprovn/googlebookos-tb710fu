// SPDX-License-Identifier: Apache-2.0
// Scope the private display wire adapter; never fall back after a mediated failure.
#ifndef GB_AVF_DISPLAY_MICA_V17_H
#define GB_AVF_DISPLAY_MICA_V17_H
#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>
#include <system_error>

enum class GbAvfDisplayMode { Legacy, MicaV17, Invalid };
inline GbAvfDisplayMode gbAvfDisplayMode(const char* value) {
    if (value == nullptr) return GbAvfDisplayMode::Legacy;
    return std::string_view(value) == "mica_v17" ? GbAvfDisplayMode::MicaV17
                                               : GbAvfDisplayMode::Invalid;
}
inline std::optional<int32_t> gbAvfDisplayCid(std::string_view value) {
    if (value.empty() || value.size() > 10 || value.front() == '0') return std::nullopt;
    uint32_t cid = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), cid);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || cid < 3 ||
        cid > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) return std::nullopt;
    return static_cast<int32_t>(cid);
}
#endif
