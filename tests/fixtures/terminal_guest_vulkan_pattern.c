/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Googlebook port framework contributors.
 * Test-only companion to the separately pinned Apache-2.0 Vulkan-Tools cube.c.
 * Include after Vulkan dispatch declarations; it owns no device/input/library.
 */
static bool gb_pattern_fullscreen_ready;

static bool gb_pattern_selection_valid(void) {
    const char *pattern = getenv("GB_VKCUBE_PATTERN_V1");
    const char *fixed = getenv("GB_VKCUBE_OWNED_FIXED_V1");
    const char *fullscreen = getenv("GB_VKCUBE_PATTERN_FULLSCREEN_V1");
    return pattern && !strcmp(pattern, "fixed-quadrants-v1") &&
           fixed && !strcmp(fixed, "owned-fixed-v1") &&
           fullscreen && !strcmp(fullscreen, "owned-centered-v1") &&
           !getenv("GB_VKCUBE_OWNED_RESIZE_V1");
}

/* xdg-shell fullscreen configure dimensions are maxima, not buffer size.
 * A smaller surface is centered by the compositor with compositor-owned fill.
 * Only an initial undecided 0-or-fixed configure may precede actual fullscreen.
 * Never accept leaving fullscreen, maximize, or growing the actual image. */
static bool gb_pattern_configure(int32_t width, int32_t height, bool fullscreen,
                                 bool maximized, uint32_t previous_configures) {
    if (maximized || previous_configures >= 64) return false;
    if (!fullscreen)
        return !gb_pattern_fullscreen_ready && previous_configures == 0 &&
               (width == 0 || width == 640) && (height == 0 || height == 480);
    if (width < 640 || width > 3200 || height < 480 || height > 2000) return false;
    gb_pattern_fullscreen_ready = true;
    return true;
}

/* Coordinates are client-image pixels: TL, TR, BL, BR. UNORM is checked by
 * the pinned parent's fixed-window swapchain guard; no sRGB reinterpretation. */
static bool gb_pattern_clear(VkCommandBuffer cmd, uint32_t width, uint32_t height) {
    static const uint8_t rgb[4][3] = {
        {19, 67, 139}, {203, 37, 91}, {47, 181, 113}, {211, 173, 53}
    };
    if (width != 640 || height != 480) return false;
    for (uint32_t quadrant = 0; quadrant < 4; quadrant++) {
        VkClearAttachment attachment = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .colorAttachment = 0,
            .clearValue.color.float32 = {
                rgb[quadrant][0] / 255.0f,
                rgb[quadrant][1] / 255.0f,
                rgb[quadrant][2] / 255.0f, 1.0f
            }
        };
        VkClearRect rect = {
            .rect = { .offset = {(int32_t)(quadrant % 2) * 320,
                                (int32_t)(quadrant / 2) * 240},
                      .extent = {320, 240} },
            .baseArrayLayer = 0,
            .layerCount = 1
        };
        vkCmdClearAttachments(cmd, 1, &attachment, 1, &rect);
    }
    const VkClearAttachment border = {
        .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT, .colorAttachment = 0,
        .clearValue.color.float32 = {11 / 255.0f, 13 / 255.0f, 17 / 255.0f, 1.0f}
    };
    const VkClearRect edges[4] = {
        {.rect = {.offset = {0, 0}, .extent = {640, 8}}, .layerCount = 1},
        {.rect = {.offset = {0, 472}, .extent = {640, 8}}, .layerCount = 1},
        {.rect = {.offset = {0, 8}, .extent = {8, 464}}, .layerCount = 1},
        {.rect = {.offset = {632, 8}, .extent = {8, 464}}, .layerCount = 1}
    };
    vkCmdClearAttachments(cmd, 1, &border, 4, edges);
    return true;
}

/* Bounded API witnesses only: successful queuing does not prove scanout,
 * visibility, compositor retirement, correct colours, or guest execution. */
static void gb_pattern_present(uint32_t frame, VkResult result) {
    if (result != VK_SUCCESS) return;
    if (frame != 1 && frame != 120 && frame != 600 && frame != 1200 &&
        frame != 1800 && frame != 2400 && frame != 3600) return;
    printf("GB_VULKAN_PATTERN_PRESENT:{\"schema_version\":1,\"phase\":0,\"frame\":%u,"
           "\"width\":640,\"height\":480,\"queue_present_result\":0,"
           "\"presentation_verified\":false}\n", frame);
    fflush(stdout);
}
