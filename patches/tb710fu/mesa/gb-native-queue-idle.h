/* SPDX-License-Identifier: MIT
 * Process-scoped diagnostic, not a permanent presentation policy.
 * vkQueueWaitIdle has no timeout; the owned child must have an outer deadline.
 */
#ifndef GB_NATIVE_QUEUE_IDLE_H
#define GB_NATIVE_QUEUE_IDLE_H
#include <string.h>
#include <vulkan/vulkan.h>

static inline VkResult
gb_native_queue_idle_v1(VkQueue queue, const char *mode, const char *present_mode,
                        PFN_vkQueueWaitIdle wait_idle)
{
   if (!mode)
      return VK_SUCCESS;
   if (strcmp(mode, "idle") || !present_mode || strcmp(present_mode, "cpu") ||
       !wait_idle)
      return VK_ERROR_FEATURE_NOT_PRESENT;
   return wait_idle(queue);
}
#endif
