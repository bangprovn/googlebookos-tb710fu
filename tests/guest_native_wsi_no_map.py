#!/usr/bin/env python3
"""Pinned actual Mesa classifier/BO-init/MapMemory with ASan/UBSan stand-ins.

No GPU, Wayland connection, full Mesa build, Android operation or firmware write.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'artifacts/source/mesa-25.0.7-debian-pool-v1/mesa-25.0.7'
PATCHES = ROOT/'patches/tb710fu/mesa'


def function(source, name):
    start = source.index(name+'(')
    start = source.rfind('\n', 0, start)+1
    previous = source.rfind('\n', 0, start-1)+1
    if source[previous:start].strip() in ['static inline VkResult', 'VkResult', 'static VkResult', 'static uint32_t']:
        start = previous
    brace = source.index('{', start)
    depth = 1
    end = brace+1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


class NativeWsiNoMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='gb-native-wsi-no-map-')
        tree = Path(cls.work.name)
        cls.manifest = json.loads((PATCHES/'guest-native-wsi-no-map.json').read_text())
        digest = lambda value: hashlib.sha256(value).hexdigest()
        for relative, expected in cls.manifest['support_inputs'].items():
            assert digest((ROOT/relative).read_bytes()) == expected, relative
        for entry in cls.manifest['files']:
            data = (ROOT/entry['base_path']).read_bytes()
            assert digest(data) == entry['sha256'], entry['path']
            destination = tree/entry['path']
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        patch = PATCHES/'guest-native-wsi-no-map.patch'
        assert digest(patch.read_bytes()) == cls.manifest['patch_sha256']
        for reverse, key in [(False, 'result_sha256'), (True, 'sha256'), (False, 'result_sha256')]:
            args = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)]
            if reverse:
                args.append('--reverse')
            subprocess.run(args, cwd=tree, check=True, capture_output=True, timeout=10)
            for entry in cls.manifest['files']:
                assert digest((tree/entry['path']).read_bytes()) == entry[key]
        cls.files = {entry['path']: (tree/entry['path']).read_text() for entry in cls.manifest['files']}
        memory = cls.files['src/virtio/vulkan/vn_device_memory.c']
        helper = memory.split('/* GB_NATIVE_WSI_NO_MAP_V1_BEGIN', 1)[1]
        helper = helper[helper.index('enum gb_native_wsi_map_policy'):].split('/* GB_NATIVE_WSI_NO_MAP_V1_END */', 1)[0]
        image_header = cls.files['src/virtio/vulkan/vn_image.h']
        image = image_header[image_header.index('struct vn_image {'):].split('VK_DEFINE_NONDISP_HANDLE_CASTS', 1)[0]
        memory_header = cls.files['src/virtio/vulkan/vn_device_memory.h']
        memory_struct = memory_header[memory_header.index('struct vn_device_memory {'):].split('VK_DEFINE_NONDISP_HANDLE_CASTS', 1)[0]
        renderer = (SOURCE/'src/virtio/vulkan/vn_renderer_virtgpu.c').read_text()
        bo_flags = function(renderer, 'virtgpu_bo_blob_flags')
        program = PRELUDE+image+memory_struct+STUBS+bo_flags+BO_STUB+helper
        program += function(memory, 'vn_device_memory_bo_init')+'\n'
        program += ALLOC_STUBS+function(memory, 'vn_AllocateMemory')+'\n'
        program += function(memory, 'vn_MapMemory')+'\n'+SCENARIOS
        (tree/'mock.c').write_text(program)
        cls.binary = tree/'mock'
        build = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                '-Wno-unused-parameter', '-fsanitize=address,undefined',
                                '-fno-omit-frame-pointer', '-g', '-I'+str(SOURCE/'include'),
                                str(tree/'mock.c'), '-o', str(cls.binary)],
                               capture_output=True, text=True, timeout=30)
        if build.returncode:
            cls.work.cleanup()
            raise AssertionError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def scenario(self, name):
        run = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10,
                             env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                      UBSAN_OPTIONS='halt_on_error=1'))
        self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
        self.assertEqual(run.stderr, '')
        self.assertIn('PASS '+name, run.stdout)

    def test_exact_patch_and_internal_identity_never_inherited_by_alias(self):
        wsi = self.files['src/virtio/vulkan/vn_wsi.c']
        common = function(wsi, 'vn_wsi_create_image')
        alias = function(wsi, 'vn_wsi_create_image_from_swapchain')
        self.assertIn('img->wsi.gb_internal_created = true;', common)
        self.assertNotIn('gb_internal_created', alias)
        self.assertEqual(wsi.count('gb_internal_created = true'), 1)
        self.assertIn('gb_wsi_acquire_compositor_fence', wsi)
        memory = self.files['src/virtio/vulkan/vn_device_memory.c']
        allocate = function(memory, 'vn_AllocateMemory')
        self.assertIn('if (pnext->sType == VK_STRUCTURE_TYPE_WSI_MEMORY_ALLOCATE_INFO_MESA)', allocate)
        self.assertIn('private_wsi_memory = true;', allocate)
        self.assertIn('VK_ERROR_FORMAT_NOT_SUPPORTED', allocate)
        self.assertIn('mem->base.base.import_handle_type || mem->base.base.ahardware_buffer', allocate)
        map_memory = function(memory, 'vn_MapMemory')
        self.assertLess(map_memory.index('if (mem->gb_native_wsi_no_map)'), map_memory.index('const bool need_bo'))
        self.assertNotIn('propertyFlags =', memory)

    def test_exact_tokens_and_default_general_copy_prime_paths(self):
        self.scenario('defaults')

    def test_qualified_image_transport_flags_preserve_export_and_memory_properties(self):
        self.scenario('qualified')

    def test_ineligible_native_images_refuse_before_transport(self):
        self.scenario('refusals')

    def test_private_map_never_creates_or_recreates_a_mappable_bo(self):
        self.scenario('map_forbidden')

    def test_ordinary_mapping_and_failure_propagation_remain(self):
        self.scenario('ordinary_map')

    def test_bo_failures_do_not_silently_change_private_policy(self):
        self.scenario('allocation_failures')

    def test_actual_allocate_dispatch_connects_private_tag_policy_and_transport(self):
        self.scenario('allocation_dispatch')


PRELUDE = r'''#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan_core.h>
#include "drm-uapi/drm_fourcc.h"
#include "drm-uapi/virtgpu_drm.h"
#define VK_STRUCTURE_TYPE_WSI_MEMORY_ALLOCATE_INFO_MESA ((VkStructureType)1000001003)
#define VN_TRACE_FUNC() ((void)0)
struct vk_image {
 VkImageCreateFlags create_flags; VkImageType image_type; VkFormat format;
 VkExtent3D extent; uint32_t mip_levels, array_layers; VkSampleCountFlagBits samples;
 VkExternalMemoryHandleTypeFlags external_handle_types;
};
struct vn_image_base { struct vk_image base; };
struct vn_image_memory_requirements { int unused; };
struct vk_device_memory { VkDeviceSize size; uint32_t memory_type_index; VkExternalMemoryHandleTypeFlags export_handle_types,import_handle_type; void *ahardware_buffer; };
struct vn_device_memory_base { struct vk_device_memory base; uint64_t id; };
struct vn_renderer_bo { int marker; };
struct vn_renderer { struct { bool has_guest_vram; } info; };
struct virtgpu { bool supports_cross_device; };
struct wsi_device { bool sw, supports_modifiers; };
struct vn_physical_device {
 struct wsi_device wsi_device; VkPhysicalDeviceMemoryProperties memory_properties;
 struct { VkExternalMemoryHandleTypeFlagBits renderer_handle_type; } external_memory;
};
struct vn_device { struct vn_physical_device *physical_device; struct vn_renderer *renderer; void *instance, *primary_ring; struct { struct { int unused; } base; } base; };
'''

STUBS = r'''
static struct vn_image *vn_image_from_handle(VkImage image) { return (void *)image; }
static struct vn_device *vn_device_from_handle(VkDevice dev) { return (void *)dev; }
static struct vn_device_memory *vn_device_memory_from_handle(VkDeviceMemory mem) { return (void *)mem; }
static const void *find_struct(const void *chain,VkStructureType type) {
 for(const VkBaseInStructure *p=chain;p;p=p->pNext) {
  if(p->sType==type) return p;
 }
 return NULL;
}
#define vk_find_struct_const(chain,type) find_struct(chain,VK_STRUCTURE_TYPE_##type)
#define vk_foreach_struct_const(p,chain) for(const VkBaseInStructure *p=(chain);p;p=p->pNext)
static unsigned waits, creates, maps, roundtrips;
static unsigned selection_logs;
static void vn_log(void *instance,const char *message,...) {(void)message;selection_logs++;}
static VkResult wait_result=VK_SUCCESS,create_result=VK_SUCCESS,roundtrip_result=VK_SUCCESS;
static VkMemoryPropertyFlags recorded_properties;
static VkExternalMemoryHandleTypeFlags recorded_external;
static uint32_t recorded_blob_flags;
static struct virtgpu gpu={.supports_cross_device=true};
static struct vn_renderer_bo bo;
static unsigned char backing[4096];
static void *map_result=backing;
static VkResult vn_device_memory_wait_alloc(struct vn_device *dev,struct vn_device_memory *mem) { waits++; return wait_result; }
static VkResult vn_error(void *instance,VkResult result) { return result; }
static void *vn_renderer_bo_map(struct vn_renderer *renderer,struct vn_renderer_bo *value) { maps++; return map_result; }
static VkResult vn_ring_submit_roundtrip(void *ring,uint64_t *seqno) { roundtrips++;*seqno=123;return roundtrip_result; }
'''

BO_STUB = r'''
static VkResult vn_renderer_bo_create_from_device_memory(struct vn_renderer *renderer,
 VkDeviceSize size,uint64_t id,VkMemoryPropertyFlags flags,VkExternalMemoryHandleTypeFlags external,struct vn_renderer_bo **out) {
 creates++;recorded_properties=flags;recorded_external=external;
 recorded_blob_flags=virtgpu_bo_blob_flags(&gpu,flags,external);
 if(create_result==VK_SUCCESS) *out=&bo;
 return create_result;
}
'''

ALLOC_STUBS = r'''
static unsigned native_allocations,common_destroys,import_calls;
static const VkMemoryAllocateInfo *received_alloc_info;
static struct vn_device_memory *vk_device_memory_create(void *device,const VkMemoryAllocateInfo *info,const VkAllocationCallbacks *callbacks,size_t size) {
 struct vn_device_memory *value=calloc(1,size);assert(value);
 value->base.base.size=info->allocationSize;value->base.base.memory_type_index=info->memoryTypeIndex;
 const VkExportMemoryAllocateInfo *external=vk_find_struct_const(info->pNext,EXPORT_MEMORY_ALLOCATE_INFO);
 if(external) value->base.base.export_handle_types=external->handleTypes;
 const VkImportMemoryFdInfoKHR *import=vk_find_struct_const(info->pNext,IMPORT_MEMORY_FD_INFO_KHR);
 if(import) value->base.base.import_handle_type=import->handleType;
 return value;
}
static void vk_device_memory_destroy(void *device,const VkAllocationCallbacks *callbacks,struct vk_device_memory *value) {common_destroys++;free(value);}
static void vn_object_set_id(struct vn_device_memory *mem,uint64_t id,VkObjectType type) {mem->base.id=id;}
static uint64_t vn_get_next_obj_id(void) {return 42;}
static VkDeviceMemory vn_device_memory_to_handle(struct vn_device_memory *mem) {return (VkDeviceMemory)mem;}
static VkResult vn_android_device_import_ahb(struct vn_device *dev,struct vn_device_memory *mem,const VkMemoryDedicatedAllocateInfo *info) {import_calls++;return VK_SUCCESS;}
static VkResult vn_device_memory_import_dma_buf(struct vn_device *dev,struct vn_device_memory *mem,const VkMemoryAllocateInfo *info,bool force_unmappable,int fd) {import_calls++;return VK_SUCCESS;}
static VkResult vn_device_memory_alloc(struct vn_device *dev,struct vn_device_memory *mem,const VkMemoryAllocateInfo *info) {
 native_allocations++;received_alloc_info=info;
 return mem->base.base.export_handle_types?vn_device_memory_bo_init(dev,mem):VK_SUCCESS;
}
static void vn_device_memory_emit_report(struct vn_device *dev,struct vn_device_memory *mem,bool alloc,VkResult result) {}
'''

SCENARIOS = r'''
static struct vn_renderer renderer;
static struct vn_physical_device physical={
 .wsi_device={.supports_modifiers=true},
 .external_memory={.renderer_handle_type=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT},
 .memory_properties={.memoryTypeCount=1,.memoryTypes={{.propertyFlags=7}}},
};
static struct vn_device dev={.physical_device=&physical,.renderer=&renderer};
static struct vn_image image={
 .base={.base={.image_type=VK_IMAGE_TYPE_2D,.format=VK_FORMAT_R8G8B8A8_UNORM,
 .extent={640,480,1},.mip_levels=1,.array_layers=1,.samples=VK_SAMPLE_COUNT_1_BIT,
 .create_flags=VK_IMAGE_CREATE_ALIAS_BIT,.external_handle_types=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT}},
 .wsi={.is_wsi=true,.gb_internal_created=true,.tiling_override=VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT,.drm_format_modifier=DRM_FORMAT_MOD_LINEAR},
};
static VkExportMemoryAllocateInfo export_info={.sType=VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO,.handleTypes=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
static VkMemoryAllocateInfo alloc={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,.pNext=&export_info,.allocationSize=1228800};
static VkMemoryDedicatedAllocateInfo dedicated={.sType=VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO};
static struct vn_device_memory memory={.base={.base={.size=4096,.export_handle_types=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT},.id=17}};
static enum gb_native_wsi_map_policy policy(bool tag,bool imported) { return gb_native_wsi_no_map_policy(&dev,&alloc,&dedicated,tag,imported); }
static void select_mode(void) {
 assert(setenv("GB_VENUS_NATIVE_WSI_NO_MAP_V1","private-linear-rgbx-v1",1)==0);
 assert(setenv("GB_WSI_EXPLICIT_FEEDBACK_V1","qualified-linear-rgbx-v1",1)==0);
}
static void no_driver_calls(void) { assert(!creates && !waits && !maps && !roundtrips); }
int main(int argc,char **argv) {
 assert(argc==2);dedicated.image=(VkImage)&image;
 if(!strcmp(argv[1],"defaults")) {
  unsetenv("GB_VENUS_NATIVE_WSI_NO_MAP_V1");unsetenv("GB_WSI_EXPLICIT_FEEDBACK_V1");
  assert(policy(true,false)==GB_NATIVE_WSI_MAP_DEFAULT);
  const char *bad[]={"", "1", "private-linear-rgbx-v1 ", " private-linear-rgbx-v1", "private-linear-rgbx-v1-extra"};
  for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {setenv("GB_VENUS_NATIVE_WSI_NO_MAP_V1",bad[i],1);assert(policy(true,false)==GB_NATIVE_WSI_MAP_DEFAULT);}
  select_mode();assert(policy(false,false)==GB_NATIVE_WSI_MAP_DEFAULT);
  physical.wsi_device.sw=true;assert(policy(true,false)==GB_NATIVE_WSI_MAP_DEFAULT);physical.wsi_device.sw=false;
  dedicated.image=VK_NULL_HANDLE;dedicated.buffer=(VkBuffer)1;assert(policy(true,false)==GB_NATIVE_WSI_MAP_DEFAULT);
  dedicated.image=(VkImage)&image;dedicated.buffer=VK_NULL_HANDLE;
  image.wsi.is_prime_blit_src=true;assert(policy(true,false)==GB_NATIVE_WSI_MAP_DEFAULT);
  no_driver_calls();
 } else if(!strcmp(argv[1],"qualified")) {
  select_mode();assert(policy(true,false)==GB_NATIVE_WSI_MAP_FORBIDDEN);
  for(unsigned cross=0;cross<2;cross++) {
   gpu.supports_cross_device=cross;
   image.base.base.format=cross?VK_FORMAT_B8G8R8A8_UNORM:VK_FORMAT_R8G8B8A8_UNORM;
   assert(policy(true,false)==GB_NATIVE_WSI_MAP_FORBIDDEN);
   memory.gb_native_wsi_no_map=true;
   VkMemoryAllocateInfo saved=alloc;VkPhysicalDeviceMemoryProperties props=physical.memory_properties;
   assert(vn_device_memory_bo_init(&dev,&memory)==VK_SUCCESS && memory.base_bo==&bo);
   assert(recorded_properties==(7 & ~VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT));
   assert(recorded_external==VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT);
   assert(recorded_blob_flags==(VIRTGPU_BLOB_FLAG_USE_SHAREABLE|(cross?VIRTGPU_BLOB_FLAG_USE_CROSS_DEVICE:0)));
   assert(!memcmp(&saved,&alloc,sizeof(alloc)) && !memcmp(&props,&physical.memory_properties,sizeof(props)));
  }
  assert(selection_logs==2);
  for(unsigned i=0;i<20;i++) assert(vn_device_memory_bo_init(&dev,&memory)==VK_SUCCESS);
  assert(selection_logs==16);
 } else if(!strcmp(argv[1],"refusals")) {
  select_mode();assert(policy(true,true)==GB_NATIVE_WSI_MAP_REFUSED);
  unsetenv("GB_WSI_EXPLICIT_FEEDBACK_V1");assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);select_mode();
  setenv("GB_WSI_EXPLICIT_FEEDBACK_V1","qualified-linear-rgbx-v1-extra",1);assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);select_mode();
  dedicated.image=VK_NULL_HANDLE;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);dedicated.image=(VkImage)&image;
  image.wsi.gb_internal_created=false;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.wsi.gb_internal_created=true;
  image.wsi.is_wsi=false;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.wsi.is_wsi=true;
  image.wsi.memory=&memory;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.wsi.memory=NULL;
  image.wsi.drm_format_modifier=DRM_FORMAT_MOD_INVALID;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);
  image.wsi.drm_format_modifier=1;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.wsi.drm_format_modifier=DRM_FORMAT_MOD_LINEAR;
  image.wsi.tiling_override=VK_IMAGE_TILING_LINEAR;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.wsi.tiling_override=VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT;
  image.base.base.format=VK_FORMAT_R8G8B8A8_SRGB;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.base.base.format=VK_FORMAT_R8G8B8A8_UNORM;
  image.base.base.image_type=VK_IMAGE_TYPE_3D;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.base.base.image_type=VK_IMAGE_TYPE_2D;
  image.base.base.extent.depth=2;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.base.base.extent.depth=1;
  image.base.base.extent.width=0;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);
  image.base.base.extent.width=8193;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);
  image.base.base.extent.width=8192;image.base.base.extent.height=8192;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);
  image.base.base.extent.width=640;image.base.base.extent.height=480;
  image.base.base.array_layers=2;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.base.base.array_layers=1;
  image.base.base.mip_levels=2;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.base.base.mip_levels=1;
  image.base.base.samples=VK_SAMPLE_COUNT_2_BIT;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.base.base.samples=VK_SAMPLE_COUNT_1_BIT;
  image.base.base.create_flags|=VK_IMAGE_CREATE_PROTECTED_BIT;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.base.base.create_flags=VK_IMAGE_CREATE_ALIAS_BIT;
  image.base.base.external_handle_types=0;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);image.base.base.external_handle_types=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT;
  physical.wsi_device.supports_modifiers=false;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);physical.wsi_device.supports_modifiers=true;
  renderer.info.has_guest_vram=true;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);renderer.info.has_guest_vram=false;
  physical.external_memory.renderer_handle_type=VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);physical.external_memory.renderer_handle_type=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT;
  alloc.allocationSize=0;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);
  alloc.allocationSize=33554433;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);alloc.allocationSize=1228800;
  alloc.pNext=NULL;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);alloc.pNext=&export_info;
  export_info.handleTypes|=VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT;assert(policy(true,false)==GB_NATIVE_WSI_MAP_REFUSED);
  no_driver_calls();
 } else if(!strcmp(argv[1],"map_forbidden")) {
  memory.gb_native_wsi_no_map=true;
  for(unsigned existing=0;existing<2;existing++) {
   memory.base_bo=existing?&bo:NULL;void *pointer=(void *)1;
   assert(vn_MapMemory((VkDevice)&dev,(VkDeviceMemory)&memory,0,VK_WHOLE_SIZE,0,&pointer)==VK_ERROR_MEMORY_MAP_FAILED);
   assert(pointer==NULL && memory.base_bo==(existing?&bo:NULL));no_driver_calls();
  }
 } else if(!strcmp(argv[1],"ordinary_map")) {
  memory.base.base.export_handle_types=0;void *pointer=NULL;
  assert(vn_MapMemory((VkDevice)&dev,(VkDeviceMemory)&memory,16,32,0,&pointer)==VK_SUCCESS);
  assert(pointer==backing+16 && memory.map_end==48 && creates==1 && waits==1 && maps==1 && !roundtrips);
  assert(recorded_properties==7 && recorded_blob_flags==VIRTGPU_BLOB_FLAG_USE_MAPPABLE);
  assert(selection_logs==0);
  memory.base_bo=NULL;map_result=NULL;
  assert(vn_MapMemory((VkDevice)&dev,(VkDeviceMemory)&memory,0,VK_WHOLE_SIZE,0,&pointer)==VK_ERROR_MEMORY_MAP_FAILED);
  assert(roundtrips==1 && memory.bo_roundtrip_seqno_valid && memory.bo_roundtrip_seqno==123);
  assert(vn_MapMemory((VkDevice)&dev,(VkDeviceMemory)&memory,0,VK_WHOLE_SIZE,0,&pointer)==VK_ERROR_MEMORY_MAP_FAILED && roundtrips==1);
 } else if(!strcmp(argv[1],"allocation_failures")) {
  memory.gb_native_wsi_no_map=true;wait_result=VK_ERROR_OUT_OF_HOST_MEMORY;
  assert(vn_device_memory_bo_init(&dev,&memory)==wait_result && creates==0 && memory.base_bo==NULL);
  wait_result=VK_SUCCESS;create_result=VK_ERROR_OUT_OF_DEVICE_MEMORY;
  assert(vn_device_memory_bo_init(&dev,&memory)==create_result && creates==1 && memory.base_bo==NULL);
  assert(selection_logs==0);
  assert(recorded_blob_flags==(VIRTGPU_BLOB_FLAG_USE_SHAREABLE|VIRTGPU_BLOB_FLAG_USE_CROSS_DEVICE));
  void *pointer=(void *)1;assert(vn_MapMemory((VkDevice)&dev,(VkDeviceMemory)&memory,0,VK_WHOLE_SIZE,0,&pointer)==VK_ERROR_MEMORY_MAP_FAILED);
  assert(pointer==NULL && creates==1 && !maps && !roundtrips && memory.gb_native_wsi_no_map);
 } else if(!strcmp(argv[1],"allocation_dispatch")) {
  select_mode();VkBaseInStructure tag={.sType=VK_STRUCTURE_TYPE_WSI_MEMORY_ALLOCATE_INFO_MESA};
  export_info.pNext=&tag;dedicated.pNext=&export_info;alloc.pNext=&dedicated;
  VkMemoryAllocateInfo saved=alloc;VkMemoryDedicatedAllocateInfo saved_dedicated=dedicated;
  VkPhysicalDeviceMemoryProperties saved_properties=physical.memory_properties;
  VkDeviceMemory handle=VK_NULL_HANDLE;
  assert(vn_AllocateMemory((VkDevice)&dev,&alloc,NULL,&handle)==VK_SUCCESS);
  struct vn_device_memory *created=vn_device_memory_from_handle(handle);
  assert(created && created->gb_native_wsi_no_map && created->base_bo==&bo && native_allocations==1);
  assert(received_alloc_info==&alloc && recorded_blob_flags==(VIRTGPU_BLOB_FLAG_USE_SHAREABLE|VIRTGPU_BLOB_FLAG_USE_CROSS_DEVICE));
  assert(!memcmp(&saved,&alloc,sizeof(alloc)) && !memcmp(&saved_dedicated,&dedicated,sizeof(dedicated)));
  assert(!memcmp(&saved_properties,&physical.memory_properties,sizeof(saved_properties)));
  void *pointer=(void *)1;unsigned before_creates=creates;
  assert(vn_MapMemory((VkDevice)&dev,handle,0,VK_WHOLE_SIZE,0,&pointer)==VK_ERROR_MEMORY_MAP_FAILED && pointer==NULL && creates==before_creates);
  vk_device_memory_destroy(NULL,NULL,&created->base.base);
  /* An application external image lacks the private WSI tag: keep HOST_VISIBLE. */
  export_info.pNext=NULL;handle=VK_NULL_HANDLE;
  assert(vn_AllocateMemory((VkDevice)&dev,&alloc,NULL,&handle)==VK_SUCCESS);
  created=vn_device_memory_from_handle(handle);assert(created && !created->gb_native_wsi_no_map);
  assert(recorded_properties==7 && (recorded_blob_flags&VIRTGPU_BLOB_FLAG_USE_MAPPABLE));
  vk_device_memory_destroy(NULL,NULL,&created->base.base);
  /* Software/copy stays mapped even when the process selects this token. */
  export_info.pNext=&tag;physical.wsi_device.sw=true;
  assert(vn_AllocateMemory((VkDevice)&dev,&alloc,NULL,&handle)==VK_SUCCESS);
  created=vn_device_memory_from_handle(handle);assert(created && !created->gb_native_wsi_no_map);
  vk_device_memory_destroy(NULL,NULL,&created->base.base);physical.wsi_device.sw=false;
  /* A native private allocation with insufficient proof fails before host work. */
  before_creates=creates;unsigned before_allocations=native_allocations;
  image.wsi.gb_internal_created=false;handle=VK_NULL_HANDLE;
  assert(vn_AllocateMemory((VkDevice)&dev,&alloc,NULL,&handle)==VK_ERROR_FORMAT_NOT_SUPPORTED);
  assert(handle==VK_NULL_HANDLE && native_allocations==before_allocations && creates==before_creates && !import_calls);
  assert(common_destroys==4);
 } else assert(!"unknown scenario");
 printf("PASS %s\n",argv[1]);return 0;
}
'''


if __name__ == '__main__':
    unittest.main()
