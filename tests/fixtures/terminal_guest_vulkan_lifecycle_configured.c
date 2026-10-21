/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Googlebook port framework contributors.
 * Included only by the separately generated owned lifecycle cube candidate,
 * after demo_draw/demo_resize. Never include in the qualified static binary.
 */
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <time.h>

static double gb_lifecycle_deadline;
static unsigned gb_lifecycle_acks;
/* Tracks the latest toplevel configure and its following surface ACK separately
 * from upstream ever-configured state. Cleared by every toplevel callback. */
static bool gb_lifecycle_configure_surface_acked;

static double gb_lifecycle_now(void) {
    struct timespec ts={0};
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) gb_owned_resize_refuse("lifecycle_clock");
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static void gb_lifecycle_stdin_init(void) {
    const char *token = getenv("GB_VKCUBE_LIFECYCLE_V1");
    struct stat st;
    int flags = fcntl(STDIN_FILENO, F_GETFL);
    if (!token || strcmp(token,"owned-three-phase-v1") ||
        getenv("GB_VKCUBE_OWNED_SOAK_V1") || fstat(STDIN_FILENO,&st) ||
        !S_ISFIFO(st.st_mode) || flags < 0 || (flags&O_ACCMODE)!=O_RDONLY ||
        fcntl(STDIN_FILENO,F_SETFL,flags|O_NONBLOCK))
        gb_owned_resize_refuse("lifecycle_token_or_owned_pipe");
    gb_lifecycle_deadline = gb_lifecycle_now() + 55.0;
}

/* Flush/dispatch the initial fullscreen negotiation BEFORE initial preparation.
 * Vulkan may have queued default-queue events without dispatching our listeners.
 * Neither a fullscreen toplevel event alone nor a surface ACK alone authorizes
 * image creation/presentation. This wait owns no image and never calls resize.
 * 5s is clipped to the same 55s cooperative lifecycle authorization deadline;
 * the external process supervisor still bounds synchronous library calls. */
static void gb_lifecycle_wait_initial_configure(struct demo *demo) {
    if (demo->prepared || gb_lifecycle.phase || gb_lifecycle.creations || gb_lifecycle_acks)
        gb_owned_resize_refuse("lifecycle_bounded_initial_state");
    int (*get_fd)(struct wl_display *) = (int (*)(struct wl_display *))dlsym(demo->wayland_library,"wl_display_get_fd");
    void (*cancel_read)(struct wl_display *) = (void (*)(struct wl_display *))dlsym(demo->wayland_library,"wl_display_cancel_read");
    if (!get_fd || !cancel_read) gb_owned_resize_refuse("lifecycle_wayland_poll_api");
    const int wayland_fd = get_fd(demo->wayland_display);
    if (wayland_fd < 0 || wayland_fd == STDIN_FILENO) gb_owned_resize_refuse("lifecycle_wayland_fd");
    double deadline = gb_lifecycle_now() + 5.0;
    if (deadline > gb_lifecycle_deadline) deadline = gb_lifecycle_deadline;
    while (gb_lifecycle_now() < deadline) {
        unsigned dispatched=0;
        while (wl_display_prepare_read(demo->wayland_display) != 0) {
            if (++dispatched>64 || wl_display_dispatch_pending(demo->wayland_display)<0)
                gb_owned_resize_refuse("lifecycle_pending_events");
        }
        if (gb_pattern_fullscreen_ready && demo->xdg_surface_has_been_configured &&
            gb_lifecycle_configure_surface_acked && gb_lifecycle_now()<deadline) {
            cancel_read(demo->wayland_display);return;
        }
        if (wl_display_flush(demo->wayland_display)<0 && errno!=EAGAIN) {
            cancel_read(demo->wayland_display);gb_owned_resize_refuse("lifecycle_flush");
        }
        struct pollfd event={.fd=wayland_fd,.events=POLLIN};
        int result=poll(&event,1,50);
        if (result<0) {
            cancel_read(demo->wayland_display);
            if (errno==EINTR) continue;
            gb_owned_resize_refuse("lifecycle_poll");
        }
        if (event.revents & POLLIN) {
            if (wl_display_read_events(demo->wayland_display)<0)
                gb_owned_resize_refuse("lifecycle_wayland_read");
        } else cancel_read(demo->wayland_display);
        if (event.revents & (POLLERR|POLLHUP|POLLNVAL) ||
            wl_display_dispatch_pending(demo->wayland_display)<0 || demo->quit)
            gb_owned_resize_refuse("lifecycle_wayland_state");
        if (gb_pattern_fullscreen_ready && demo->xdg_surface_has_been_configured &&
            gb_lifecycle_configure_surface_acked && gb_lifecycle_now()<deadline) return;
    }
    gb_owned_resize_refuse("pattern_fullscreen_not_confirmed");
}

static void gb_lifecycle_created(bool old_swapchain, uint32_t width, uint32_t height, uint32_t images) {
    if (!gb_lifecycle_create(&gb_lifecycle,old_swapchain,width,height,images))
        gb_owned_resize_refuse("lifecycle_create_sequence");
    printf("GB_VULKAN_LIFECYCLE_CREATE:{\"schema_version\":2,\"phase\":%u,\"width\":%u,\"height\":%u,\"images\":%u,\"old_swapchain_supplied\":%s,\"swapchain_generation\":%u,\"presentation_verified\":false}\n",
           gb_lifecycle.phase,width,height,images,old_swapchain?"true":"false",gb_lifecycle.creations);
    fflush(stdout);
}

static void gb_lifecycle_present(struct demo *demo, VkResult result) {
    if (result != VK_SUCCESS || !gb_lifecycle_queue(&gb_lifecycle,result))
        gb_owned_resize_refuse("lifecycle_queue_present");
    printf("GB_VULKAN_LIFECYCLE_PRESENT:{\"schema_version\":2,\"phase\":%u,\"width\":%d,\"height\":%d,\"frame\":%d,\"swapchain_generation\":%u,\"queue_present_result\":0,\"presentation_verified\":false}\n",
           gb_lifecycle.phase,demo->width,demo->height,demo->curFrame+1,gb_lifecycle.creations);
    fflush(stdout);
}

/* The exact parent acknowledgement is a protocol event, not an independent
 * pixel/scanout witness. Parent must bind each ACK to its strict capture receipt.
 * Continue normal Wayland dispatch while holding the unchanged displayed phase.
 */
static void gb_lifecycle_wait_ack(struct demo *demo) {
    int (*get_fd)(struct wl_display *) = (int (*)(struct wl_display *))dlsym(demo->wayland_library,"wl_display_get_fd");
    void (*cancel_read)(struct wl_display *) = (void (*)(struct wl_display *))dlsym(demo->wayland_library,"wl_display_cancel_read");
    if (!get_fd || !cancel_read) gb_owned_resize_refuse("lifecycle_wayland_poll_api");
    const int wayland_fd = get_fd(demo->wayland_display);
    if (wayland_fd < 0 || wayland_fd == STDIN_FILENO) gb_owned_resize_refuse("lifecycle_wayland_fd");
    double deadline = gb_lifecycle_now() + 20.0;
    if (deadline > gb_lifecycle_deadline) deadline = gb_lifecycle_deadline;
    char bytes[6];size_t used=0;
    while (gb_lifecycle_now() < deadline) {
        unsigned dispatched=0;
        while (wl_display_prepare_read(demo->wayland_display) != 0) {
            if (++dispatched>64 || wl_display_dispatch_pending(demo->wayland_display)<0)
                gb_owned_resize_refuse("lifecycle_pending_events");
        }
        if (wl_display_flush(demo->wayland_display)<0 && errno!=EAGAIN) {
            cancel_read(demo->wayland_display);gb_owned_resize_refuse("lifecycle_flush");
        }
        struct pollfd fds[2]={{.fd=STDIN_FILENO,.events=POLLIN},{.fd=wayland_fd,.events=POLLIN}};
        int result=poll(fds,2,50);
        if (result<0) {
            cancel_read(demo->wayland_display);
            if (errno==EINTR) continue;
            gb_owned_resize_refuse("lifecycle_poll");
        }
        if (fds[1].revents & POLLIN) {
            if (wl_display_read_events(demo->wayland_display)<0)
                gb_owned_resize_refuse("lifecycle_wayland_read");
        } else cancel_read(demo->wayland_display);
        if (fds[1].revents & (POLLERR|POLLHUP|POLLNVAL) ||
            wl_display_dispatch_pending(demo->wayland_display)<0 || demo->quit)
            gb_owned_resize_refuse("lifecycle_wayland_state");
        if (fds[0].revents & (POLLERR|POLLNVAL)) gb_owned_resize_refuse("lifecycle_ack_pipe");
        if (fds[0].revents & (POLLIN|POLLHUP)) {
            ssize_t count=read(STDIN_FILENO,bytes+used,sizeof(bytes)-used);
            if (count<0 && (errno==EAGAIN || errno==EINTR)) continue;
            if (count<=0) gb_owned_resize_refuse("lifecycle_ack_eof");
            used+=(size_t)count;
            if (used>5) gb_owned_resize_refuse("lifecycle_ack_extra");
            if (used==5) {
                if (memcmp(bytes,"ACK",3) || bytes[3]!=(char)('0'+gb_lifecycle.phase) || bytes[4]!='\n' ||
                    gb_lifecycle_acks!=gb_lifecycle.phase || gb_lifecycle_now()>=deadline)
                    gb_owned_resize_refuse("lifecycle_ack_sequence");
                gb_lifecycle_acks++;
                printf("GB_VULKAN_LIFECYCLE_ACK:{\"schema_version\":2,\"phase\":%u,\"ack_index\":%u,\"presentation_verified\":false}\n",gb_lifecycle.phase,gb_lifecycle_acks);
                fflush(stdout);return;
            }
        }
    }
    gb_owned_resize_refuse("lifecycle_ack_deadline");
}

static void demo_run(struct demo *demo) {
    if (demo->frameCount!=3600 || !demo->prepared || demo->pause)
        gb_owned_resize_refuse("lifecycle_bounded_initial_state");
    for (unsigned phase=0;phase<3;phase++) {
        if (gb_lifecycle.phase!=phase || !gb_lifecycle_extent(phase,demo->width,demo->height) ||
            demo->curFrame>=demo->frameCount || gb_lifecycle_now()>=gb_lifecycle_deadline)
            gb_owned_resize_refuse("lifecycle_draw_state");
        demo_draw(demo);
        demo->curFrame++;
        if (!(gb_lifecycle.queued_phases & (1u<<phase))) gb_owned_resize_refuse("lifecycle_no_queue_witness");
        gb_lifecycle_wait_ack(demo);
        if (phase<2) {
            if (!gb_lifecycle_advance(&gb_lifecycle,phase+1)) gb_owned_resize_refuse("lifecycle_advance");
            demo->width=phase==0?480:640;demo->height=phase==0?360:480;
            demo->gb_owned_resize.width=demo->width;demo->gb_owned_resize.height=demo->height;
            /* This authentic upstream path frees old commands/resources, creates
             * a swapchain with oldSwapchain, then demo_prepare re-records clears. */
            demo_resize(demo);
            if (!demo->prepared || gb_lifecycle.awaiting_create || gb_lifecycle.creations!=phase+2)
                gb_owned_resize_refuse("lifecycle_reprepare_incomplete");
        }
    }
    if (!gb_lifecycle_complete(&gb_lifecycle) || gb_lifecycle_acks!=3 || demo->curFrame!=3)
        gb_owned_resize_refuse("lifecycle_incomplete");
}

/* Called AFTER normal upstream demo_cleanup returns. Still no explicit
 * presentation-engine retirement guarantee; parent must require exit0 as well. */
static void gb_lifecycle_completed(struct demo *demo) {
    if (!gb_lifecycle_complete(&gb_lifecycle) || gb_lifecycle_acks!=3 || demo->curFrame!=3)
        gb_owned_resize_refuse("lifecycle_cleanup_state");
    puts("GB_VULKAN_LIFECYCLE_COMPLETED:{\"schema_version\":2,\"phases\":3,\"acknowledgements\":3,\"swapchain_generations\":3,\"frames\":3,\"presentation_verified\":false,\"explicit_present_retirement_verified\":false}");
    fflush(stdout);
}
