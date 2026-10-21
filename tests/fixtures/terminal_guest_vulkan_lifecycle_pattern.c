/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Googlebook port framework contributors.
 * Source-only companion for a separately versioned owned Wayland regression.
 * The integration must re-record command buffers after each real swapchain
 * recreation. These helpers do not create/resize a window or authorize capture.
 */
struct gb_lifecycle_pattern {
    unsigned phase, creations, queued_phases;
    bool awaiting_create;
};

static bool gb_lifecycle_extent(unsigned phase, uint32_t width, uint32_t height) {
    if (phase > 2) return false;
    return phase == 1 ? width == 480 && height == 360 : width == 640 && height == 480;
}

/* Each successful step needs a real oldSwapchain-based recreation. No skipped
 * phase, duplicate creation, image-budget relaxation or API-only capture claim. */
static bool gb_lifecycle_create(struct gb_lifecycle_pattern *s, bool old_swapchain,
                                uint32_t width, uint32_t height, uint32_t images) {
    if (!s || s->phase > 2 || !s->awaiting_create || s->creations != s->phase ||
        !images || images > 4 || old_swapchain != (s->phase != 0) ||
        !gb_lifecycle_extent(s->phase, width, height)) return false;
    s->creations++;
    s->awaiting_create = false;
    return true;
}

/* Return true once after successful API queuing in the current generation.
 * This is NOT a scanout, color, retirement or external capture witness. */
static bool gb_lifecycle_queue(struct gb_lifecycle_pattern *s, VkResult result) {
    if (!s || s->phase > 2 || s->awaiting_create || s->creations != s->phase + 1 ||
        result != VK_SUCCESS || (s->queued_phases & (1u << s->phase))) return false;
    s->queued_phases |= 1u << s->phase;
    return true;
}

static bool gb_lifecycle_advance(struct gb_lifecycle_pattern *s, unsigned next_phase) {
    if (!s || s->phase >= 2 || next_phase != s->phase + 1 || s->awaiting_create ||
        s->creations != s->phase + 1 || !(s->queued_phases & (1u << s->phase))) return false;
    s->phase = next_phase;
    s->awaiting_create = true;
    return true;
}

static bool gb_lifecycle_complete(const struct gb_lifecycle_pattern *s) {
    return s && s->phase == 2 && s->creations == 3 && !s->awaiting_create && s->queued_phases == 7;
}

/* Same four known colors and8px border as the qualified static fixture.
 * Rotating their positions makes the restored640x480 phase differ from phase0:
 * a retained stale frame cannot satisfy the expected later palette order.
 * Call while recording the NEW generation's renderpass, before EndRenderPass.
 */
static bool gb_lifecycle_clear(VkCommandBuffer cmd, unsigned phase,
                               uint32_t width, uint32_t height) {
    static const uint8_t rgb[4][3] = {
        {19,67,139}, {203,37,91}, {47,181,113}, {211,173,53}
    };
    if (!gb_lifecycle_extent(phase,width,height)) return false;
    const uint32_t half_width = width / 2, half_height = height / 2;
    for (unsigned quadrant = 0; quadrant < 4; quadrant++) {
        const unsigned color = (quadrant + phase) % 4;
        VkClearAttachment attachment = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT, .colorAttachment = 0,
            .clearValue.color.float32 = {rgb[color][0]/255.0f, rgb[color][1]/255.0f,
                                        rgb[color][2]/255.0f, 1.0f}
        };
        VkClearRect rect = {
            .rect = {.offset = {(int32_t)(quadrant%2)*half_width, (int32_t)(quadrant/2)*half_height},
                     .extent = {half_width,half_height}},
            .baseArrayLayer = 0, .layerCount = 1
        };
        vkCmdClearAttachments(cmd,1,&attachment,1,&rect);
    }
    const VkClearAttachment border = {
        .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT, .colorAttachment = 0,
        .clearValue.color.float32 = {11/255.0f,13/255.0f,17/255.0f,1.0f}
    };
    const VkClearRect edges[4] = {
        {.rect={.offset={0,0},.extent={width,8}},.layerCount=1},
        {.rect={.offset={0,(int32_t)height-8},.extent={width,8}},.layerCount=1},
        {.rect={.offset={0,8},.extent={8,height-16}},.layerCount=1},
        {.rect={.offset={(int32_t)width-8,8},.extent={8,height-16}},.layerCount=1}
    };
    vkCmdClearAttachments(cmd,1,&border,4,edges);
    return true;
}
