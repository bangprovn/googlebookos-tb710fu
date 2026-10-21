/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include "gb-native-queue-idle.h"
static unsigned calls;
static VkResult result;
static VKAPI_ATTR VkResult VKAPI_CALL wait_idle(VkQueue queue)
{
   assert(queue == (VkQueue)(uintptr_t)1);
   calls++;
   return result;
}
int main(void)
{
   VkQueue queue = (VkQueue)(uintptr_t)1;
   assert(gb_native_queue_idle_v1(queue, NULL, NULL, NULL) == VK_SUCCESS);
   assert(calls == 0);
   const char *modes[] = {"", "unknown", "cpu", "idle-extra"};
   for (unsigned i = 0; i < 4; i++)
      assert(gb_native_queue_idle_v1(queue, modes[i], "cpu", wait_idle) == VK_ERROR_FEATURE_NOT_PRESENT);
   assert(gb_native_queue_idle_v1(queue, "idle", NULL, wait_idle) == VK_ERROR_FEATURE_NOT_PRESENT);
   assert(gb_native_queue_idle_v1(queue, "idle", "sw", wait_idle) == VK_ERROR_FEATURE_NOT_PRESENT);
   assert(gb_native_queue_idle_v1(queue, "idle", "cpu", NULL) == VK_ERROR_FEATURE_NOT_PRESENT);
   assert(calls == 0);
   result = VK_SUCCESS;
   assert(gb_native_queue_idle_v1(queue, "idle", "cpu", wait_idle) == VK_SUCCESS);
   result = VK_ERROR_DEVICE_LOST;
   assert(gb_native_queue_idle_v1(queue, "idle", "cpu", wait_idle) == result);
   assert(calls == 2);
   return 0;
}
