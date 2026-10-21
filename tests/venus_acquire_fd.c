/* SPDX-License-Identifier: MIT
 * Real descriptor ownership checks; callbacks model Vulkan's consume-on-success
 * contract. These checks establish no GPU/fence/presentation capability.
 */
#define VK_NO_PROTOTYPES
#include "../patches/tb710fu/mesa/gb-wsi-acquire-fd.h"
#include <assert.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>

static unsigned sem_calls, fence_calls;
static bool fail_sem, fail_fence, fail_dup;
static int duplicate;
static int dup_fd(int fd)
{
   if (fail_dup) { errno = EMFILE; return -1; }
   duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 3);
   return duplicate;
}
static VKAPI_ATTR VkResult VKAPI_CALL
sem_import(VkDevice dev, const VkImportSemaphoreFdInfoKHR *info)
{
   (void)dev;
   ++sem_calls;
   assert(info->flags == VK_SEMAPHORE_IMPORT_TEMPORARY_BIT);
   assert(info->handleType == VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT);
   assert(fcntl(info->fd, F_GETFD) >= 0);
   if (fail_sem) return VK_ERROR_INVALID_EXTERNAL_HANDLE;
   close(info->fd);
   return VK_SUCCESS;
}
static VKAPI_ATTR VkResult VKAPI_CALL
fence_import(VkDevice dev, const VkImportFenceFdInfoKHR *info)
{
   (void)dev;
   ++fence_calls;
   assert(info->flags == VK_FENCE_IMPORT_TEMPORARY_BIT);
   assert(info->handleType == VK_EXTERNAL_FENCE_HANDLE_TYPE_SYNC_FD_BIT);
   assert(fcntl(info->fd, F_GETFD) >= 0);
   if (fail_fence) return VK_ERROR_INVALID_EXTERNAL_HANDLE;
   close(info->fd);
   return VK_SUCCESS;
}
int main(void)
{
   for (unsigned mode = 0; mode < 7; ++mode) {
      int pipes[2]; assert(pipe(pipes) == 0);
      sem_calls = fence_calls = 0; duplicate = -1;
      fail_sem = mode == 3; fail_fence = mode == 4; fail_dup = mode == 5;
      VkAcquireNextImageInfoKHR acquire = {.sType = VK_STRUCTURE_TYPE_ACQUIRE_NEXT_IMAGE_INFO_KHR};
      if (mode != 1 && mode != 6) acquire.semaphore = (VkSemaphore)(uintptr_t)1;
      if (mode != 0 && mode != 6) acquire.fence = (VkFence)(uintptr_t)2;
      VkResult result = gb_wsi_import_acquire_fd(VK_NULL_HANDLE, &acquire, pipes[0], dup_fd, sem_import, fence_import);
      assert(result == (mode < 3 ? VK_SUCCESS : mode == 5 ? VK_ERROR_TOO_MANY_OBJECTS :
                        mode == 6 ? VK_ERROR_INITIALIZATION_FAILED : VK_ERROR_INVALID_EXTERNAL_HANDLE));
      errno = 0; assert(fcntl(pipes[0], F_GETFD) == -1 && errno == EBADF);
      if (duplicate >= 0) { errno = 0; assert(fcntl(duplicate, F_GETFD) == -1 && errno == EBADF); }
      assert(sem_calls == (mode == 1 || mode >= 5 ? 0 : 1));
      assert(fence_calls == (mode == 1 || mode == 2 || mode == 4 ? 1 : 0));
      close(pipes[1]);
   }
   puts("PASS: seven acquire-FD ownership paths; no GPU verdict");
   return 0;
}
