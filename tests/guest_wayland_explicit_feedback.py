#!/usr/bin/env python3
"""Exercise the actual opt-in Mesa feedback selector without opening a GPU.

The exact patch is applied to a temporary copy of the pinned Mesa source. Its
real selector, default-feedback callbacks and modifier-set comparison use small
list-storage stand-ins under ASan/UBSan. This qualifies selection logic, not
Wayland protocol decoding, a complete Mesa build or physical presentation.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'patches/tb710fu/mesa/guest-wayland-explicit-feedback.patch'
MANIFEST = PATCH.with_suffix('.json')
BASE = ROOT / 'artifacts/source/mesa-25.0.7-debian-pool-v1/mesa-25.0.7/src/vulkan/wsi/wsi_common_wayland.c'


def function(source, name):
    position = source.index(name + '(')
    start = source.rfind('\nstatic ', 0, position) + 1
    brace = source.index('{', position)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


STORAGE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
typedef unsigned VkFormat;
#define VK_FORMAT_R8G8B8A8_UNORM 37u
#define VK_FORMAT_B8G8R8A8_UNORM 44u
#define DRM_FORMAT_MOD_LINEAR UINT64_C(0)
#define DRM_FORMAT_MOD_INVALID UINT64_C(0x00ffffffffffffff)
#define DRM_FORMAT_ARGB8888 UINT32_C(0x34325241)
#define DRM_FORMAT_XRGB8888 UINT32_C(0x34325258)
#define DRM_FORMAT_ABGR8888 UINT32_C(0x34324241)
#define DRM_FORMAT_XBGR8888 UINT32_C(0x34324258)
#define WSI_WL_FMT_ALPHA 1u
#define WSI_WL_FMT_OPAQUE 2u
struct u_vector { void *data; uint32_t length, element_size; };
struct util_dynarray { void *data; uint32_t length; };
struct wl_array { size_t size; void *data; };
struct zwp_linux_dmabuf_feedback_v1;
#define wl_array_for_each(item, array) \
   for (item = (array)->data; (char *)item < (char *)(array)->data + (array)->size; item++)
#define u_vector_foreach(item, vector) \
   for (uint32_t vi = 0; vi < (vector)->length && \
        ((item = (void *)((char *)(vector)->data + vi * (vector)->element_size)), true); vi++)
#define util_dynarray_foreach(array, type, item) \
   for (uint32_t di = 0; di < (array)->length; di++) \
      for (type *item = &((type *)(array)->data)[di]; item; item = NULL)
struct wsi_wl_format { VkFormat vk_format; uint32_t flags; struct u_vector modifiers; };
struct dmabuf_feedback_tranche { dev_t target_device; uint32_t flags; struct u_vector formats; };
struct dmabuf_feedback { dev_t main_device; struct util_dynarray tranches; };
struct wsi_device {
   bool supports_modifiers;
   struct { bool hasRender, hasPrimary; int64_t renderMajor, renderMinor, primaryMajor, primaryMinor; } drm_info;
};
struct wsi_wayland { struct wsi_device *wsi; };
struct wsi_wl_display {
   struct wsi_wayland *wsi_wl;
   bool sw, same_gpu;
   void *wl_dmabuf;
   dev_t main_device;
   dev_t gb_feedback_target_device;
   uint8_t gb_pending_linear_formats, gb_default_linear_formats;
   struct u_vector formats;
   struct { unsigned size; struct { uint32_t format, padding; uint64_t modifier; } *data; } format_table;
};
struct wsi_wl_surface { struct wsi_wl_display *display; struct dmabuf_feedback dmabuf_feedback; };
static uint32_t wl_drm_format_for_vk_format(VkFormat format, bool alpha) {
   if (format == VK_FORMAT_B8G8R8A8_UNORM) return alpha ? DRM_FORMAT_ARGB8888 : DRM_FORMAT_XRGB8888;
   assert(format == VK_FORMAT_R8G8B8A8_UNORM);
   return alpha ? DRM_FORMAT_ABGR8888 : DRM_FORMAT_XBGR8888;
}
static void wsi_wl_display_add_drm_format_modifier(struct wsi_wl_display *display,
                                                  struct u_vector *formats,
                                                  uint32_t format, uint64_t modifier) {
   (void)display; (void)formats; (void)format; (void)modifier;
}
'''


SCENARIOS = r'''
static struct u_vector vector(void *data, uint32_t count, uint32_t size) {
   return (struct u_vector){ data, count, size };
}
static void record_default(struct wsi_wl_display *display, dev_t target, uint8_t raw_linear_mask, bool commit) {
   dev_t main_device = display->main_device;
   struct wl_array device = { sizeof(dev_t), &main_device };
   default_dmabuf_feedback_main_device(display,NULL,&device);
   device.data = &target;
   default_dmabuf_feedback_tranche_target_device(display,NULL,&device);
   const uint32_t formats[] = { DRM_FORMAT_ARGB8888, DRM_FORMAT_XRGB8888,
                               DRM_FORMAT_ABGR8888, DRM_FORMAT_XBGR8888 };
   __typeof__(*display->format_table.data) table[4];
   uint16_t indices[] = {0,1,2,3};
   for (unsigned i=0;i<4;i++) {
      table[i].format=formats[i]; table[i].padding=0;
      table[i].modifier=(raw_linear_mask & (1u << i)) ? DRM_FORMAT_MOD_LINEAR : DRM_FORMAT_MOD_INVALID;
   }
   display->format_table.data=table; display->format_table.size=sizeof(table);
   struct wl_array array = {sizeof(indices), indices};
   default_dmabuf_feedback_tranche_formats(display,NULL,&array);
   if (commit) default_dmabuf_feedback_done(display,NULL);
   display->format_table.data=NULL;
}
int main(int argc, char **argv) {
   assert(argc == 2);
   const char *test = argv[1];
   assert(setenv("GB_WSI_EXPLICIT_FEEDBACK_V1", "qualified-linear-rgbx-v1", 1) == 0);
   uint64_t global_mods[] = { UINT64_C(123), DRM_FORMAT_MOD_LINEAR };
   uint64_t explicit_mods[] = { UINT64_C(456), DRM_FORMAT_MOD_LINEAR };
   struct wsi_wl_format global = { VK_FORMAT_B8G8R8A8_UNORM, 3, vector(global_mods, 2, sizeof(uint64_t)) };
   struct wsi_wl_format empty = { VK_FORMAT_B8G8R8A8_UNORM, 3, vector(explicit_mods, 0, sizeof(uint64_t)) };
   struct wsi_wl_format explicit = { VK_FORMAT_B8G8R8A8_UNORM, 3, vector(explicit_mods, 2, sizeof(uint64_t)) };
   struct wsi_device wsi = { .supports_modifiers = true,
      .drm_info = { .hasRender = true, .hasPrimary = true,
                   .renderMajor = 226, .renderMinor = 128, .primaryMajor = 226, .primaryMinor = 0 } };
   struct wsi_wayland wayland = { &wsi };
   struct wsi_wl_display display = { .wsi_wl = &wayland, .same_gpu = true,
      .wl_dmabuf = &wsi, .main_device = makedev(226,128),
      .formats = vector(&global, 1, sizeof(global)) };
   record_default(&display,display.main_device,15,true);
   assert(display.gb_default_linear_formats == 15);
   struct dmabuf_feedback_tranche tranches[] = {
      { .target_device = display.main_device, .formats = vector(&empty,1,sizeof(empty)) },
      { .target_device = display.main_device, .formats = vector(&explicit,1,sizeof(explicit)) }
   };
   struct wsi_wl_surface surface = { .display = &display,
      .dmabuf_feedback = { .main_device = display.main_device,
         .tranches = { tranches, 1 } } };
   VkFormat format = VK_FORMAT_B8G8R8A8_UNORM;
   bool alpha = false, expected = true;
   if (!strcmp(test,"initial_global")) surface.dmabuf_feedback.main_device = 0;
   else if (!strcmp(test,"empty_surface_global_linear") || !strcmp(test,"feedback_effective_equal")) { }
   else if (!strcmp(test,"later_explicit") || !strcmp(test,"feedback_surface_preference_equal")) {
      surface.dmabuf_feedback.tranches.length = 2;
   } else if (!strcmp(test,"wrong_target_skipped")) {
      tranches[0].target_device = makedev(227,128);
      tranches[0].formats = vector(&explicit,1,sizeof(explicit));
   } else if (!strcmp(test,"primary_identity")) {
      wsi.drm_info.hasRender = false; display.main_device = makedev(226,0);
      surface.dmabuf_feedback.main_device = display.main_device;
      tranches[0].target_device = display.main_device;
      record_default(&display,display.main_device,15,true);
   } else if (!strcmp(test,"rgba_alpha")) {
      format = global.vk_format = empty.vk_format = VK_FORMAT_R8G8B8A8_UNORM; alpha = true;
   } else if (!strcmp(test,"argb_only_alpha")) {
      alpha = true; record_default(&display,display.main_device,1,true);
   } else if (!strcmp(test,"xrgb_only_opaque")) {
      record_default(&display,display.main_device,2,true);
   } else {
      expected = false;
      if (!strcmp(test,"unset")) assert(unsetenv("GB_WSI_EXPLICIT_FEEDBACK_V1") == 0);
      else if (!strcmp(test,"empty_opt_in")) assert(setenv("GB_WSI_EXPLICIT_FEEDBACK_V1","",1) == 0);
      else if (!strcmp(test,"unknown_opt_in")) assert(setenv("GB_WSI_EXPLICIT_FEEDBACK_V1","qualified-linear-rgbx-v2",1) == 0);
      else if (!strcmp(test,"no_identity")) wsi.drm_info.hasRender = wsi.drm_info.hasPrimary = false;
      else if (!strcmp(test,"identity_mismatch")) display.main_device = makedev(227,128);
      else if (!strcmp(test,"zero_default_device")) display.main_device = 0;
      else if (!strcmp(test,"different_surface_device")) surface.dmabuf_feedback.main_device = makedev(226,0);
      else if (!strcmp(test,"different_gpu")) display.same_gpu = false;
      else if (!strcmp(test,"software")) display.sw = true;
      else if (!strcmp(test,"no_dmabuf")) display.wl_dmabuf = NULL;
      else if (!strcmp(test,"no_modifiers")) wsi.supports_modifiers = false;
      else if (!strcmp(test,"unsupported_format")) format = 50;
      else if (!strcmp(test,"implicit_is_not_linear")) { global_mods[0] = DRM_FORMAT_MOD_INVALID; global.modifiers.length = 1; }
      else if (!strcmp(test,"nonlinear_is_not_linear")) global.modifiers.length = 1;
      else if (!strcmp(test,"empty_global")) global.modifiers.length = 0;
      else if (!strcmp(test,"missing_global_format")) display.formats.length = 0;
      else if (!strcmp(test,"wrong_global_format")) global.vk_format = VK_FORMAT_R8G8B8A8_UNORM;
      else if (!strcmp(test,"wrong_global_alpha")) global.flags = WSI_WL_FMT_ALPHA;
      else if (!strcmp(test,"other_device_default")) record_default(&display,makedev(227,128),15,true);
      else if (!strcmp(test,"implicit_default_after_explicit")) record_default(&display,display.main_device,0,true);
      else if (!strcmp(test,"pending_default_not_committed")) {
         record_default(&display,display.main_device,15,false);
         assert(display.gb_pending_linear_formats == 15);
         assert(display.gb_default_linear_formats == 0);
      }
      else if (!strcmp(test,"wrong_default_alpha_mask")) display.gb_default_linear_formats=1;
      else if (!strcmp(test,"render_to_primary_pending")) {
         display.main_device = makedev(226,0);
         surface.dmabuf_feedback.main_device = display.main_device;
         record_default(&display,display.main_device,15,false);
         assert(display.gb_default_linear_formats == 0);
      }
      else if (!strcmp(test,"primary_to_render_pending")) {
         display.main_device = makedev(226,0);
         record_default(&display,display.main_device,15,true);
         display.main_device = makedev(226,128);
         surface.dmabuf_feedback.main_device = display.main_device;
         record_default(&display,display.main_device,15,false);
         assert(display.gb_default_linear_formats == 0);
      }
      else if (!strcmp(test,"argb_linear_xrgb_implicit") || !strcmp(test,"feedback_lost_raw_format")) {
         surface.dmabuf_feedback.tranches.length = 2;
         record_default(&display,display.main_device,1,true);
      }
      else if (!strcmp(test,"abgr_linear_xbgr_implicit")) {
         format = global.vk_format = VK_FORMAT_R8G8B8A8_UNORM;
         empty.vk_format = explicit.vk_format = format;
         surface.dmabuf_feedback.tranches.length = 2;
         record_default(&display,display.main_device,4,true);
      }
      else if (!strcmp(test,"xrgb_linear_argb_implicit")) {
         alpha = true; surface.dmabuf_feedback.tranches.length = 2;
         record_default(&display,display.main_device,2,true);
      }
      else if (!strcmp(test,"xbgr_linear_abgr_implicit")) {
         format = global.vk_format = VK_FORMAT_R8G8B8A8_UNORM;
         empty.vk_format = explicit.vk_format = format;
         alpha = true; surface.dmabuf_feedback.tranches.length = 2;
         record_default(&display,display.main_device,8,true);
      }
      else { assert(!"Unknown scenario"); }
   }
   const struct wsi_wl_format saved_global = global, saved_empty = empty, saved_explicit = explicit;
   const uint64_t saved_global_mods[] = {global_mods[0], global_mods[1]};
   const uint64_t saved_explicit_mods[] = {explicit_mods[0], explicit_mods[1]};
   uint32_t count = 999;
   const uint64_t *modifiers = explicit_mods;
   bool result = gb_wl_explicit_feedback_modifiers(&surface,format,alpha,&count,&modifiers);
   assert(result == expected);
   if (!expected) { assert(count == 0 && modifiers == NULL); }
   else {
      assert(count == 1 && modifiers && modifiers[0] == DRM_FORMAT_MOD_LINEAR);
      assert(modifiers != global_mods && modifiers != explicit_mods);
   }
   if (!strcmp(test,"feedback_effective_equal") || !strcmp(test,"feedback_surface_preference_equal")) {
      const uint64_t old[] = {DRM_FORMAT_MOD_LINEAR};
      assert(sets_of_modifiers_are_the_same(count,modifiers,1,old));
   }
   assert(!memcmp(&global,&saved_global,sizeof(global)));
   assert(!memcmp(&empty,&saved_empty,sizeof(empty)));
   assert(!memcmp(&explicit,&saved_explicit,sizeof(explicit)));
   assert(!memcmp(global_mods,saved_global_mods,sizeof(global_mods)));
   assert(!memcmp(explicit_mods,saved_explicit_mods,sizeof(explicit_mods)));
   return 0;
}
'''


class ExplicitFeedback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text())
        cls.work = tempfile.TemporaryDirectory(prefix='gb-explicit-feedback-')
        cls.directory = Path(cls.work.name)
        source = Path(os.environ.get('GB_MESA_WAYLAND_SOURCE', str(BASE)))
        if not source.is_file():
            cls.work.cleanup()
            raise unittest.SkipTest('Pinned Mesa source is required; set GB_MESA_WAYLAND_SOURCE')
        original = source.read_bytes()
        assert hashlib.sha256(original).hexdigest() == cls.manifest['base_sha256']
        assert hashlib.sha256(PATCH.read_bytes()).hexdigest() == cls.manifest['patch_sha256']
        staged = cls.directory / cls.manifest['base_file']
        staged.parent.mkdir(parents=True)
        staged.write_bytes(original)
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)],
                       cwd=cls.directory, check=True, capture_output=True, timeout=5)
        cls.patched = staged.read_text()
        assert hashlib.sha256(staged.read_bytes()).hexdigest() == cls.manifest['result_sha256']
        subprocess.run(['patch', '--batch', '--fuzz=0', '-R', '-p1', '-i', str(PATCH)],
                       cwd=cls.directory, check=True, capture_output=True, timeout=5)
        assert staged.read_bytes() == original
        begin = cls.patched.index('/* GB_WL_EXPLICIT_FEEDBACK_V1_BEGIN')
        end = cls.patched.index('/* GB_WL_EXPLICIT_FEEDBACK_V1_END */')
        helper = cls.patched[begin:end]
        c = cls.directory / 'selector.c'
        tracking = ''.join(function(cls.patched, name) for name in [
            'gb_wl_linear_format_bit', 'default_dmabuf_feedback_main_device',
            'default_dmabuf_feedback_tranche_target_device',
            'default_dmabuf_feedback_tranche_formats', 'default_dmabuf_feedback_done'])
        c.write_text(STORAGE + function(cls.patched, 'find_format') + tracking + helper +
                     function(cls.patched, 'sets_of_modifiers_are_the_same') + SCENARIOS)
        cls.binary = cls.directory / 'selector'
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(c), '-o', str(cls.binary)], check=True, capture_output=True, timeout=20)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def scenarios(self, names):
        for name in names:
            with self.subTest(name=name):
                result = subprocess.run([str(self.binary), name], capture_output=True, text=True,
                                        timeout=3, env=dict(os.environ,
                                        ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                        UBSAN_OPTIONS='halt_on_error=1'))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout + result.stderr, '')

    def test_qualified_selection_limits_global_and_surface_vectors_to_linear(self):
        self.scenarios(['initial_global', 'empty_surface_global_linear', 'later_explicit',
                        'wrong_target_skipped', 'primary_identity', 'rgba_alpha',
                        'argb_only_alpha', 'xrgb_only_opaque'])

    def test_refuses_missing_identity_formats_and_implicit_only_support(self):
        self.scenarios(['no_identity', 'identity_mismatch', 'zero_default_device',
                        'different_surface_device', 'different_gpu', 'software',
                        'no_dmabuf', 'no_modifiers', 'unsupported_format',
                        'implicit_is_not_linear', 'nonlinear_is_not_linear',
                        'empty_global', 'missing_global_format', 'wrong_global_format',
                        'wrong_global_alpha', 'other_device_default',
                        'implicit_default_after_explicit', 'pending_default_not_committed',
                        'wrong_default_alpha_mask'])

    def test_only_exact_opt_in_enables_helper(self):
        self.scenarios(['unset', 'empty_opt_in', 'unknown_opt_in'])

    def test_feedback_compares_same_effective_set(self):
        self.scenarios(['feedback_effective_equal', 'feedback_surface_preference_equal',
                        'feedback_lost_raw_format'])

    def test_new_default_device_generation_invalidates_committed_proof(self):
        self.scenarios(['render_to_primary_pending', 'primary_to_render_pending'])

    def test_merged_surface_alpha_flags_cannot_qualify_raw_format(self):
        self.scenarios(['argb_linear_xrgb_implicit', 'abgr_linear_xbgr_implicit',
                        'xrgb_linear_argb_implicit', 'xbgr_linear_abgr_implicit'])

    def test_allocation_and_feedback_share_helper_and_opt_out_remains(self):
        allocation = function(self.patched, 'wsi_wl_surface_create_swapchain')
        feedback = function(self.patched, 'surface_dmabuf_feedback_done')
        for body in [allocation, feedback]:
            self.assertEqual(body.count('gb_wl_explicit_feedback_modifiers('), 1)
            self.assertIn('gb_wl_explicit_feedback_enabled()', body)
            self.assertIn('pick_format_from_surface_dmabuf_feedback(', body)
        self.assertIn('result = VK_ERROR_FORMAT_NOT_SUPPORTED;', allocation)
        self.assertIn('gb_wl_explicit_feedback_enabled() && wsi_device->sw', allocation)
        self.assertIn('else if (wsi_wl_surface->display->wl_dmabuf && wsi_device->supports_modifiers)', allocation)
        self.assertIn('chain->suboptimal = true;', feedback)


if __name__ == '__main__':
    unittest.main()
