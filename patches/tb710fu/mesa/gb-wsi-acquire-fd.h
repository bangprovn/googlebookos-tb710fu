/* SPDX-License-Identifier: MIT
 * FD ownership adapted from Mesa vn_AcquireNextImage2KHR, upstream
 * 211c21725ce27cd7c2ac17114395cb74b55d3018 (Copyright Google LLC).
 * The caller transfers ownership of sync_fd, including on failure.
 */
#ifndef GB_WSI_ACQUIRE_FD_H
#define GB_WSI_ACQUIRE_FD_H

#include <errno.h>
#include <unistd.h>
#include <vulkan/vulkan.h>

static inline VkResult
gb_wsi_import_acquire_fd(VkDevice device, const VkAcquireNextImageInfoKHR *acquire,
                        int sync_fd, int (*duplicate_fd)(int),
                        PFN_vkImportSemaphoreFdKHR import_semaphore,
                        PFN_vkImportFenceFdKHR import_fence)
{
   int sem_fd = -1, fence_fd = -1;
   VkResult result = VK_SUCCESS;
   if (sync_fd < 0)
      return VK_ERROR_INVALID_EXTERNAL_HANDLE;
   if (acquire->semaphore != VK_NULL_HANDLE) {
      sem_fd = sync_fd;
      if (acquire->fence != VK_NULL_HANDLE) {
         fence_fd = duplicate_fd(sync_fd);
         if (fence_fd < 0) {
            result = errno == EMFILE ? VK_ERROR_TOO_MANY_OBJECTS
                                     : VK_ERROR_OUT_OF_HOST_MEMORY;
            goto out;
         }
      }
   } else if (acquire->fence != VK_NULL_HANDLE) {
      fence_fd = sync_fd;
   } else {
      close(sync_fd);
      return VK_ERROR_INITIALIZATION_FAILED;
   }
   if (sem_fd >= 0) {
      const VkImportSemaphoreFdInfoKHR info = {
         .sType = VK_STRUCTURE_TYPE_IMPORT_SEMAPHORE_FD_INFO_KHR,
         .semaphore = acquire->semaphore,
         .flags = VK_SEMAPHORE_IMPORT_TEMPORARY_BIT,
         .handleType = VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT,
         .fd = sem_fd,
      };
      result = import_semaphore(device, &info);
      if (result != VK_SUCCESS)
         goto out;
      sem_fd = -1; /* successful import consumed the descriptor */
   }
   if (fence_fd >= 0) {
      const VkImportFenceFdInfoKHR info = {
         .sType = VK_STRUCTURE_TYPE_IMPORT_FENCE_FD_INFO_KHR,
         .fence = acquire->fence,
         .flags = VK_FENCE_IMPORT_TEMPORARY_BIT,
         .handleType = VK_EXTERNAL_FENCE_HANDLE_TYPE_SYNC_FD_BIT,
         .fd = fence_fd,
      };
      result = import_fence(device, &info);
      if (result != VK_SUCCESS)
         goto out;
      fence_fd = -1;
   }
out:
   if (sem_fd >= 0)
      close(sem_fd);
   if (fence_fd >= 0)
      close(fence_fd);
   return result;
}

#endif
