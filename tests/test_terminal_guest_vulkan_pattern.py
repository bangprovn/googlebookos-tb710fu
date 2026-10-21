"""Actual owned C helper with Vulkan-call mocks; no driver or device execution."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

FIXTURE = Path(__file__).resolve().parent / 'fixtures/terminal_guest_vulkan_pattern.c'
MOCK = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
typedef void *VkCommandBuffer;
typedef int VkResult;
#define VK_SUCCESS 0
#define VK_IMAGE_ASPECT_COLOR_BIT 1
union Clear { float float32[4]; };
typedef struct { uint32_t aspectMask, colorAttachment; union { union Clear color; } clearValue; } VkClearAttachment;
typedef struct { struct { struct {int32_t x,y;} offset; struct {uint32_t width,height;} extent;} rect; uint32_t baseArrayLayer,layerCount; } VkClearRect;
static unsigned calls;
static const unsigned want[4][3]={{19,67,139},{203,37,91},{47,181,113},{211,173,53}};
static void vkCmdClearAttachments(VkCommandBuffer cmd,uint32_t ac,const VkClearAttachment *a,uint32_t rc,const VkClearRect *r) {
    assert(cmd==(void *)1 && ac==1 && calls<5);
    assert(a->aspectMask==VK_IMAGE_ASPECT_COLOR_BIT && a->colorAttachment==0);
    assert(a->clearValue.color.float32[3]==1.0f);
    if (calls<4) {
        assert(rc==1);
        for(unsigned j=0;j<3;j++) assert((unsigned)(a->clearValue.color.float32[j]*255.0f+0.5f)==want[calls][j]);
        assert(r->rect.offset.x==(int32_t)(calls%2)*320 && r->rect.offset.y==(int32_t)(calls/2)*240);
        assert(r->rect.extent.width==320 && r->rect.extent.height==240 && r->baseArrayLayer==0 && r->layerCount==1);
    } else {
        const int geometry[4][4]={{0,0,640,8},{0,472,640,8},{0,8,8,464},{632,8,8,464}};
        const unsigned rgb[3]={11,13,17};assert(rc==4);
        for(unsigned j=0;j<3;j++) assert((unsigned)(a->clearValue.color.float32[j]*255.0f+0.5f)==rgb[j]);
        for(unsigned i=0;i<4;i++) {
            assert(r[i].rect.offset.x==geometry[i][0] && r[i].rect.offset.y==geometry[i][1]);
            assert(r[i].rect.extent.width==(unsigned)geometry[i][2] && r[i].rect.extent.height==(unsigned)geometry[i][3]);
            assert(r[i].baseArrayLayer==0 && r[i].layerCount==1);
        }
    }
    calls++;
}
#include "terminal_guest_vulkan_pattern.c"
int main(void) {
    unsetenv("GB_VKCUBE_PATTERN_V1");unsetenv("GB_VKCUBE_OWNED_FIXED_V1");unsetenv("GB_VKCUBE_OWNED_RESIZE_V1");
    unsetenv("GB_VKCUBE_PATTERN_FULLSCREEN_V1");
    assert(!gb_pattern_selection_valid());
    setenv("GB_VKCUBE_PATTERN_V1","fixed-quadrants-v1",1);assert(!gb_pattern_selection_valid());
    setenv("GB_VKCUBE_OWNED_FIXED_V1","owned-fixed-v1",1);assert(!gb_pattern_selection_valid());
    setenv("GB_VKCUBE_PATTERN_FULLSCREEN_V1","owned-centered-v1",1);assert(gb_pattern_selection_valid());
    setenv("GB_VKCUBE_PATTERN_FULLSCREEN_V1","owned-centered-v1-near",1);assert(!gb_pattern_selection_valid());
    setenv("GB_VKCUBE_PATTERN_FULLSCREEN_V1","owned-centered-v1",1);
    setenv("GB_VKCUBE_PATTERN_V1","fixed-quadrants-v1-near",1);assert(!gb_pattern_selection_valid());
    setenv("GB_VKCUBE_PATTERN_V1","fixed-quadrants-v1",1);
    setenv("GB_VKCUBE_OWNED_RESIZE_V1","",1);assert(!gb_pattern_selection_valid());unsetenv("GB_VKCUBE_OWNED_RESIZE_V1");
    assert(!gb_pattern_clear((void *)1,0,480));assert(!gb_pattern_clear((void *)1,641,480));
    assert(!gb_pattern_clear((void *)1,640,481));assert(calls==0);
    assert(gb_pattern_clear((void *)1,640,480));assert(calls==5);
    assert(gb_pattern_configure(0,0,false,false,0));assert(!gb_pattern_fullscreen_ready);
    assert(!gb_pattern_configure(0,0,false,false,1));
    assert(!gb_pattern_configure(639,480,true,false,0));assert(!gb_pattern_fullscreen_ready);
    assert(!gb_pattern_configure(640,479,true,false,0));
    assert(!gb_pattern_configure(0,0,true,false,0));
    assert(!gb_pattern_configure(3201,480,true,false,0));assert(!gb_pattern_configure(640,2001,true,false,0));
    assert(!gb_pattern_configure(1280,800,true,true,0));assert(!gb_pattern_configure(1280,800,true,false,64));
    assert(gb_pattern_configure(1280,800,true,false,0));assert(gb_pattern_fullscreen_ready);
    assert(!gb_pattern_configure(640,480,false,false,1));
    assert(gb_pattern_configure(640,480,true,false,1));
    assert(gb_pattern_configure(3200,2000,true,false,63));
    for(uint32_t frame=1;frame<=3600;frame++) gb_pattern_present(frame,VK_SUCCESS);
    gb_pattern_present(1,-1);gb_pattern_present(0,VK_SUCCESS);gb_pattern_present(3601,VK_SUCCESS);
    return 0;
}
'''

class PatternTests(unittest.TestCase):
    def test_actual_clear_calls_selection_extent_and_bounded_present_records(self):
        compiler = shutil.which('cc')
        if compiler is None:
            self.skipTest('host C compiler unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary)
            (folder/'mock.c').write_text(MOCK)
            binary=folder/'mock'
            subprocess.run([compiler,'-std=c11','-Wall','-Wextra','-Werror','-I'+str(FIXTURE.parent),
                            str(folder/'mock.c'),'-o',str(binary)],check=True,capture_output=True,timeout=15)
            result=subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=5,
                                  env=dict(os.environ))
        import json
        records=[json.loads(line.split(':',1)[1]) for line in result.stdout.splitlines()]
        self.assertEqual([row['frame'] for row in records],[1,120,600,1200,1800,2400,3600])
        for row in records:
            self.assertEqual(row,dict(schema_version=1,phase=0,frame=row['frame'],width=640,height=480,
                                      queue_present_result=0,presentation_verified=False))
        self.assertEqual(result.stderr,'')

if __name__=='__main__': unittest.main()
