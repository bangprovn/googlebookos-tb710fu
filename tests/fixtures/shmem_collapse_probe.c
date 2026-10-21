/* SPDX-License-Identifier: Apache-2.0
 * Owned, bounded SHM preparation control. No VM/firmware/device ioctls.
 * Test one 8 MiB memfd, preserve its bytes across four MADV_COLLAPSE calls,
 * and report only this process's own mapping counters.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif
#define PMD_BYTES (2UL << 20)
#define BYTES (8UL << 20)

static int fail(const char *stage) {
    printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"%s\",\"errno\":%d}\n", stage, errno);
    return 1;
}

static long elapsed_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
}

int main(void) {
    const struct rlimit cores = {0, 0};
    if (setrlimit(RLIMIT_CORE, &cores)) return fail("core_limit");
    alarm(20);
    if (sysconf(_SC_PAGESIZE) != 4096) { errno = ENOTSUP; return fail("page_size"); }
    int fd = memfd_create("gb-owned-collapse-control", MFD_CLOEXEC);
    if (fd < 0) return fail("memfd");
    if (ftruncate(fd, BYTES)) return fail("truncate");
    void *reservation = mmap(NULL, BYTES + PMD_BYTES, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED) return fail("reserve");
    uintptr_t aligned = ((uintptr_t)reservation + PMD_BYTES - 1) & ~(PMD_BYTES - 1);
    unsigned char *bytes = mmap((void *)aligned, BYTES, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_FIXED, fd, 0);
    if (bytes == MAP_FAILED) return fail("map");
    size_t lead = aligned - (uintptr_t)reservation;
    size_t tail = PMD_BYTES - lead;
    if (lead && munmap(reservation, lead)) return fail("unmap_lead");
    if (tail && munmap(bytes + BYTES, tail)) return fail("unmap_tail");
    for (size_t i = 0; i < BYTES; i++) bytes[i] = (unsigned char)(i * 37 + i / 4096);
    int results[4], errors[4];
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return fail("clock_start");
    for (size_t i = 0; i < 4; i++) {
        errno = 0;
        results[i] = madvise(bytes + i * PMD_BYTES, PMD_BYTES, MADV_COLLAPSE);
        errors[i] = results[i] ? errno : 0;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return fail("clock_end");
    for (size_t i = 0; i < BYTES; i++)
        if (bytes[i] != (unsigned char)(i * 37 + i / 4096)) { errno = EIO; return fail("content_preservation"); }
    unsigned long shmem_pmd_kb = 0, file_pmd_kb = 0, rss_kb = 0;
    FILE *maps = fopen("/proc/self/smaps", "re");
    if (!maps) return fail("own_smaps");
    char line[512];
    int selected = 0, found = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2) {
            selected = lo == aligned && hi == aligned + BYTES;
            found += selected;
        } else if (selected) {
            if (sscanf(line, "ShmemPmdMapped: %lu kB", &shmem_pmd_kb) == 1) continue;
            if (sscanf(line, "FilePmdMapped: %lu kB", &file_pmd_kb) == 1) continue;
            (void)sscanf(line, "Rss: %lu kB", &rss_kb);
        }
    }
    if (ferror(maps) || fclose(maps) || found != 1) { errno = EIO; return fail("own_smaps_mapping"); }
    if (munmap(bytes, BYTES) || close(fd)) return fail("cleanup");
    printf("{\"schema_version\":1,\"status\":\"completed\",\"bytes\":%lu,\"content_preserved\":true,"
           "\"collapse_result\":[%d,%d,%d,%d],\"collapse_errno\":[%d,%d,%d,%d],"
           "\"elapsed_ms\":%ld,\"shmem_pmd_mapped_kb\":%lu,\"file_pmd_mapped_kb\":%lu,\"rss_kb\":%lu,"
           "\"gunyah_share_tested\":false,\"firmware_written\":false}\n",
           BYTES, results[0], results[1], results[2], results[3], errors[0], errors[1], errors[2], errors[3],
           elapsed_ms(start, end), shmem_pmd_kb, file_pmd_kb, rss_kb);
    return 0;
}
