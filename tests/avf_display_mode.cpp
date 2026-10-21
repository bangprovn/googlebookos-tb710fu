// SPDX-License-Identifier: Apache-2.0
#include "../patches/tb710fu/crosvm/avf-display-mica-v17.h"
#include <cassert>
#include <string_view>
int main() {
    assert(gbAvfDisplayMode(nullptr) == GbAvfDisplayMode::Legacy);
    assert(gbAvfDisplayMode("mica_v17") == GbAvfDisplayMode::MicaV17);
    for (const auto value : {"", "true", "1", "mica_v16", "mica_v17 ", "legacy"})
        assert(gbAvfDisplayMode(value) == GbAvfDisplayMode::Invalid);
    for (const auto value : {"", "0", "1", "2", "02048", "-1", "+2048", "debian", "2048 ",
                            "2048/", "2147483648", "4294967295", "4294967296", "99999999999"})
        assert(!gbAvfDisplayCid(value).has_value());
    assert(gbAvfDisplayCid("3") == 3);
    assert(gbAvfDisplayCid("2048") == 2048);
    assert(gbAvfDisplayCid("2049") == 2049);
    assert(gbAvfDisplayCid("2147483647") == 2147483647);
}
