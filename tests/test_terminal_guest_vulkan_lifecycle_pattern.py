"""Source-only actual C helpers; mocked calls, no Vulkan/device lifecycle run."""
from pathlib import Path
import os, shutil, subprocess, tempfile, unittest

FIXTURE=Path(__file__).parent/'fixtures/terminal_guest_vulkan_lifecycle_pattern.c'
MOCK=r'''
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
typedef void *VkCommandBuffer;
typedef int VkResult;
#define VK_SUCCESS 0
#define VK_IMAGE_ASPECT_COLOR_BIT 1
typedef struct {uint32_t aspectMask,colorAttachment;union {union {float float32[4];} color;} clearValue;} VkClearAttachment;
typedef struct {struct {struct {int32_t x,y;} offset;struct {uint32_t width,height;} extent;} rect;uint32_t baseArrayLayer,layerCount;} VkClearRect;
static unsigned calls,phase,w,h;
static const unsigned rgb[4][3]={{19,67,139},{203,37,91},{47,181,113},{211,173,53}};
static void vkCmdClearAttachments(VkCommandBuffer cmd,uint32_t ac,const VkClearAttachment *a,uint32_t rc,const VkClearRect *r){
 assert(cmd==(void*)1&&ac==1&&calls<5&&a->aspectMask==VK_IMAGE_ASPECT_COLOR_BIT&&a->colorAttachment==0&&a->clearValue.color.float32[3]==1);
 if(calls<4){assert(rc==1);unsigned color=(calls+phase)%4;
  for(unsigned i=0;i<3;i++)assert((unsigned)(a->clearValue.color.float32[i]*255+.5f)==rgb[color][i]);
  assert(r->rect.offset.x==(int32_t)(calls%2*w/2)&&r->rect.offset.y==(int32_t)(calls/2*h/2)&&r->rect.extent.width==w/2&&r->rect.extent.height==h/2&&r->baseArrayLayer==0&&r->layerCount==1);
 }else{assert(rc==4);const unsigned b[3]={11,13,17};for(unsigned i=0;i<3;i++)assert((unsigned)(a->clearValue.color.float32[i]*255+.5f)==b[i]);
  const int xy[4][2]={{0,0},{0,h-8},{0,8},{w-8,8}};const unsigned wh[4][2]={{w,8},{w,8},{8,h-16},{8,h-16}};
  for(unsigned i=0;i<4;i++)assert(r[i].rect.offset.x==xy[i][0]&&r[i].rect.offset.y==xy[i][1]&&r[i].rect.extent.width==wh[i][0]&&r[i].rect.extent.height==wh[i][1]&&r[i].baseArrayLayer==0&&r[i].layerCount==1);
 }calls++;
}
#include "terminal_guest_vulkan_lifecycle_pattern.c"
int main(void){
 struct gb_lifecycle_pattern s={.awaiting_create=true};
 assert(!gb_lifecycle_complete(&s)&&!gb_lifecycle_queue(&s,0)&&!gb_lifecycle_advance(&s,1));
 for(phase=0;phase<3;phase++){
  w=phase==1?480:640;h=phase==1?360:480;
  assert(!gb_lifecycle_create(&s,phase!=0,w,h,0)&&!gb_lifecycle_create(&s,phase!=0,w,h,5));
  assert(!gb_lifecycle_create(&s,phase==0,w,h,4)&&!gb_lifecycle_create(&s,phase!=0,w+1,h,4));
  assert(gb_lifecycle_create(&s,phase!=0,w,h,4));
  assert(!gb_lifecycle_create(&s,phase!=0,w,h,4)&&!gb_lifecycle_queue(&s,-1));
  calls=0;assert(!gb_lifecycle_clear((void*)1,phase,w+1,h)&&calls==0);
  assert(gb_lifecycle_clear((void*)1,phase,w,h)&&calls==5);
  assert(gb_lifecycle_queue(&s,0)&&!gb_lifecycle_queue(&s,0));
  if(phase<2){assert(!gb_lifecycle_advance(&s,phase)&&!gb_lifecycle_advance(&s,phase+2));assert(gb_lifecycle_advance(&s,phase+1));}
 }
 assert(gb_lifecycle_complete(&s)&&!gb_lifecycle_advance(&s,3));
 calls=0;assert(!gb_lifecycle_clear((void*)1,3,640,480)&&calls==0);
 assert(!gb_lifecycle_create(0,false,640,480,4)&&!gb_lifecycle_queue(0,0)&&!gb_lifecycle_advance(0,1)&&!gb_lifecycle_complete(0));
 return 0;
}
'''

class Tests(unittest.TestCase):
    def test_actual_draw_geometry_palette_and_monotonic_api_state(self):
        cc=shutil.which('cc')
        if not cc:self.skipTest('C compiler unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp);(b/'mock.c').write_text(MOCK)
            subprocess.run([cc,'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                '-fno-omit-frame-pointer','-I'+str(FIXTURE.parent),str(b/'mock.c'),'-o',str(b/'mock')],
                check=True,capture_output=True,timeout=15)
            subprocess.run([str(b/'mock')],check=True,capture_output=True,timeout=5,
                env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))

if __name__=='__main__':unittest.main()
