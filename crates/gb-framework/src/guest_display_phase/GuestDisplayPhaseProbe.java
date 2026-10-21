package org.googlebook.port.guestdisplayphase;

import android.graphics.Bitmap;
import android.graphics.Rect;
import android.hardware.HardwareBuffer;
import android.os.Process;
import android.os.SystemClock;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Shell-owned single crop, never a screenshot file or uncropped fallback. */
public final class GuestDisplayPhaseProbe {
    private static final String PACKAGE = "com.android.virtualization.terminal";
    private static final AtomicReference<java.lang.Process> child = new AtomicReference<>();
    private static String phase = "arguments";
    private static boolean captureRequested, bufferCleanupVerified;
    private GuestDisplayPhaseProbe() {}
    private static void check(boolean b) { PhasePatternContract.require(b); }
    private static Object call(Class<?> cls, Object target, String name, Class<?>[] types,
            Object... args) throws Exception {
        return cls.getMethod(name, types).invoke(target, args);
    }
    private static String smallFile(String path) throws Exception {
        byte[] bytes = new byte[128];
        try (FileInputStream in = new FileInputStream(path)) {
            int n = in.read(bytes); check(n > 0 && n < bytes.length && in.read() == -1);
            return new String(bytes,0,n,StandardCharsets.US_ASCII).trim();
        }
    }
    private static void focus(int user) throws Exception {
        java.lang.Process p = new ProcessBuilder("/system/bin/dumpsys","window")
            .redirectErrorStream(true).start();
        child.set(p);
        int total = 0, fields = 0, matches = 0;
        try (InputStreamReader in = new InputStreamReader(p.getInputStream(),StandardCharsets.UTF_8)) {
            StringBuilder line = new StringBuilder(); int c;
            while ((c=in.read()) != -1) {
                check(++total <= 2*1024*1024);
                if (c == '\n') {
                    String s = line.toString();
                    if (s.contains("mCurrentFocus=")) { fields++; if (PhasePatternContract.focusLine(s,user)) matches++; }
                    line.setLength(0);
                } else { check(line.length() < 8192); line.append((char)c); }
            }
            check(line.length() == 0 && p.waitFor(1,TimeUnit.SECONDS) && p.exitValue()==0);
            check(fields == 1 && matches == 1);
        } finally { p.destroyForcibly(); child.compareAndSet(p,null); }
    }
    private static int[] identity(String boot,int user,int uid,long observed,int l,int t,int r,int b) throws Exception {
        check(Process.myUid()==2000 && "u:r:shell:s0".equals(smallFile("/proc/self/attr/current")));
        check(boot.equals(smallFile("/proc/sys/kernel/random/boot_id")));
        PhasePatternContract.freshness(observed,SystemClock.elapsedRealtime());
        check(Boolean.TRUE.equals(call(Class.forName("android.os.SELinux"),null,
            "isSELinuxEnforced",new Class<?>[0])));
        check(Integer.valueOf(user).equals(call(Class.forName("android.app.ActivityManager"),null,
            "getCurrentUser",new Class<?>[0])));
        Object pm = call(Class.forName("android.app.AppGlobals"),null,"getPackageManager",new Class<?>[0]);
        check(Integer.valueOf(uid).equals(call(Class.forName("android.content.pm.IPackageManager"),pm,
            "getPackageUid",new Class<?>[]{String.class,long.class,int.class},PACKAGE,0L,user)));
        focus(user);
        Class<?> dmType=Class.forName("android.hardware.display.DisplayManagerGlobal");
        Object dm=call(dmType,null,"getInstance",new Class<?>[0]);
        check(dm!=null);
        Object info=call(dmType,dm,"getDisplayInfo",new Class<?>[]{int.class},0);
        check(info!=null);
        Class<?> infoType=Class.forName("android.view.DisplayInfo");
        int width=infoType.getField("logicalWidth").getInt(info);
        int height=infoType.getField("logicalHeight").getInt(info);
        PhasePatternContract.logicalBounds(l,t,r,b,width,height);
        return new int[]{width,height};
    }
    private static void capture(String boot,int user,int uid,int l,int t,int r,int b,long observed,int patternPhase,int bufferWidth,int bufferHeight,String captureToken,String fixtureSha) throws Exception {
        Bitmap hardware = null, pixels = null; HardwareBuffer buffer = null;
        Object shot = null;
        int[] matched = new int[4], errors = new int[4],paletteCounts=new int[4];
        boolean cleanup = true;
        int displayWidth=0,displayHeight=0;
        int sampleL=0,sampleT=0,sampleR=r-l,sampleB=b-t,scale=0,palettePixels=0,borderPixels=0;
        try {
            // Explicit caller-selected API profile. Never retry a capture through another API.
            String api="android.window.ScreenCaptureInternal";
            phase = "capture_class";
            Class<?> sc = Class.forName(api);
            phase = "capture_args_class";
            Class<?> argsType = Class.forName(api+"$CaptureArgs");
            phase = "capture_builder_class";
            Class<?> builderType = Class.forName(api+"$CaptureArgs$Builder");
            phase = "capture_listener_class";
            Class<?> listenerType = Class.forName(api+"$ScreenCaptureListener");
            phase = "capture_builder_constructor";
            Object builder = builderType.getConstructor().newInstance();
            Rect rect = new Rect(l,t,r,b);
            phase = "capture_builder_crop";
            call(builderType,builder,"setSourceCrop",new Class<?>[]{Rect.class},rect);
            phase = "capture_builder_uid";
            call(builderType,builder,"setUid",new Class<?>[]{long.class},(long)uid);
            phase = "capture_builder_scale";
            call(builderType,builder,"setFrameScale",new Class<?>[]{float.class},1.0f);
            phase = "capture_builder_format";
            call(builderType,builder,"setPixelFormat",new Class<?>[]{int.class},1); // RGBA_8888
            phase = "capture_builder_secure";
            Class<?> params=Class.forName("android.window.ScreenCapture$ScreenCaptureParams");
            check(params.getField("SECURE_CONTENT_POLICY_REDACT").getInt(null)==0
                && params.getField("PROTECTED_CONTENT_POLICY_REDACT").getInt(null)==0);
            call(builderType,builder,"setSecureContentPolicy",new Class<?>[]{int.class},0);
            phase = "capture_builder_protected";
            call(builderType,builder,"setProtectedContentPolicy",new Class<?>[]{int.class},0);
            phase = "capture_builder_build";
            Object args = call(builderType,builder,"build",new Class<?>[0]);
            // Refuse any API/implementation shape that cannot prove the nonempty crop+UID contract.
            phase = "capture_field_crop";
            check(rect.equals(argsType.getField("mSourceCrop").get(args)));
            phase = "capture_field_uid";
            check(argsType.getField("mUid").getLong(args)==uid);
            phase = "capture_field_scale";
            check(argsType.getField("mFrameScaleX").getFloat(args)==1.0f
                && argsType.getField("mFrameScaleY").getFloat(args)==1.0f);
            phase = "capture_field_protection";
            check(argsType.getField("mPixelFormat").getInt(args)==1);
            check(argsType.getField("mSecureContentPolicy").getInt(args)==0
                && argsType.getField("mProtectedContentPolicy").getInt(args)==0);
            phase = "capture_listener_create";
            Object listener = call(sc,null,"createSyncCaptureListener",new Class<?>[0]);
            phase = "capture_window_service";
            // WindowManagerGlobal also initializes app animation-scale shared memory.
            // A standalone shell process has no such application attachment. Obtain
            // the same window Binder directly, retaining the shell caller identity.
            Object binder = call(Class.forName("android.os.ServiceManager"),null,
                "getService",new Class<?>[]{String.class},"window");
            check(binder instanceof android.os.IBinder);
            Object wm = call(Class.forName("android.view.IWindowManager$Stub"),null,
                "asInterface",new Class<?>[]{android.os.IBinder.class},binder);
            check(wm!=null);
            phase = "capture_window_signature";
            Method request = Class.forName("android.view.IWindowManager").getMethod("captureDisplay",
                int.class,argsType,listenerType);
            phase = "pre_capture_identity";
            int[] display=identity(boot,user,uid,observed,l,t,r,b);
            displayWidth=display[0];displayHeight=display[1];
            phase = "capture";
            // Logical display 0 ONLY; exact crop+UID were checked above. No retry or fallback.
            captureRequested=true;
            request.invoke(wm,0,args,listener);
            shot = call(Class.forName(api+"$SynchronousScreenCaptureListener"),
                listener,"getBuffer",new Class<?>[0]);
            check(shot != null);
            Class<?> shotType = Class.forName(api+"$ScreenshotHardwareBuffer");
            buffer = (HardwareBuffer)call(shotType,shot,"getHardwareBuffer",new Class<?>[0]);
            check(buffer != null);
            check(!Boolean.TRUE.equals(call(shotType,shot,"containsSecureLayers",new Class<?>[0])));
            // Verify allocation dimensions BEFORE CPU mapping or copy. A bad API cannot expand it.
            check(buffer.getWidth()==r-l && buffer.getHeight()==b-t);
            hardware = (Bitmap)call(shotType,shot,"asBitmap",new Class<?>[0]);
            check(hardware != null && hardware.getWidth()==r-l && hardware.getHeight()==b-t);
            pixels = hardware.copy(Bitmap.Config.ARGB_8888,false);
            check(pixels != null && pixels.getWidth()==r-l && pixels.getHeight()==b-t
                && pixels.getAllocationByteCount() <= 8*1024*1024*4);
            phase = "sample";
            {
                final Bitmap owned=pixels;final int width=r-l;
                PhasePatternContract.Located region=PhasePatternContract.locate(r-l,b-t,patternPhase,bufferWidth,bufferHeight,new PhasePatternContract.Rows(){
                    public void read(int y,int[] row) {owned.getPixels(row,0,width,0,y,width,1);}
                });
                sampleL=region.left;sampleT=region.top;sampleR=region.right;sampleB=region.bottom;
                scale=region.scaleEighths;palettePixels=region.palettePixels;borderPixels=region.borderPixels;
                paletteCounts=region.paletteCounts;
            }
            for (int q=0;q<4;q++) for (int y=0;y<4;y++) for (int x=0;x<4;x++) {
                int color=pixels.getPixel(sampleL+PhasePatternContract.coordinate(sampleR-sampleL,q%2,x),
                    sampleT+PhasePatternContract.coordinate(sampleB-sampleT,q/2,y));
                if (PhasePatternContract.matches(color,q,patternPhase)) matched[q]++;
                errors[q]=Math.max(errors[q],PhasePatternContract.maxError(color,q,patternPhase));
            }
            phase = "post_capture_identity";
            int[] after=identity(boot,user,uid,observed,l,t,r,b);
            check(after[0]==displayWidth && after[1]==displayHeight);
        } finally {
            // Every owned object gets its cleanup attempt even if an earlier cleanup throws.
            try { if(pixels!=null) pixels.recycle(); } catch(Throwable e) { cleanup=false; }
            try { if(hardware!=null) hardware.recycle(); } catch(Throwable e) { cleanup=false; }
            try {
                if(shot instanceof AutoCloseable) ((AutoCloseable)shot).close(); // includes optional gainmap
                else if(buffer!=null) buffer.close();
            } catch(Throwable e) { cleanup=false; }
            if(!cleanup) {phase="buffer_cleanup";check(false);}
            bufferCleanupVerified=true;
        }
        boolean ok=true;for(int n:matched)ok &= n==16;
        System.out.println("GB_GUEST_DISPLAY_PHASE_V1:{\"schema_version\":1,\"status\":\""
            +(ok?"owned_pattern_samples_matched":"owned_pattern_samples_mismatched")
            +"\",\"sampled_per_quadrant\":16,\"matched\":["+matched[0]+","+matched[1]+","+matched[2]+","+matched[3]
            +"],\"max_channel_errors\":["+errors[0]+","+errors[1]+","+errors[2]+","+errors[3]
            +"],\"tolerance\":8,\"crop_width\":"+(r-l)+",\"crop_height\":"+(b-t)
            +",\"source_crop_and_uid_verified\":true,\"identity_endpoints_verified\":true,\"buffers_released\":true"
            +",\"logical_display_width\":"+displayWidth+",\"logical_display_height\":"+displayHeight
            +",\"logical_bounds_verified\":true"
            +",\"capture_api_profile\":\"internal\""
            +",\"bordered_locator\":true"+",\"located_relative_bounds\":["+sampleL+","+sampleT+","+sampleR+","+sampleB
            +"],\"uniform_scale_eighths\":"+scale+",\"palette_pixels\":"+palettePixels+",\"border_pixels\":"+borderPixels
            +",\"pattern_phase\":"+patternPhase+",\"buffer_width\":"+bufferWidth+",\"buffer_height\":"+bufferHeight
            +",\"capture_token\":\""+captureToken+"\",\"fixture_sha256\":\""+fixtureSha+"\",\"contract_sha256\":\""+PhasePatternContract.contractDigest(patternPhase)+"\""
            +",\"known_palette_counts\":["+paletteCounts[0]+","+paletteCounts[1]+","+paletteCounts[2]+","+paletteCounts[3]+"]"
            +",\"android_boot_id\":\""+boot+"\",\"android_user\":"+user+",\"terminal_uid\":"+uid
            +",\"source_crop\":["+l+","+t+","+r+","+b+"],\"observed_elapsed_ms\":"+observed
            +",\"captured_elapsed_ms\":"+SystemClock.elapsedRealtime()
            +",\"raw_pixels_exported\":false,\"image_saved\":false,\"physical_panel_verified\":false,\"full_port_verified\":false}");
        if(!ok)System.exit(2);
    }
    public static void main(String[] a) {
        Thread deadline = new Thread(new Runnable(){ public void run(){
            try { Thread.sleep(10000); } catch(InterruptedException e) { return; }
            java.lang.Process p=child.get();if(p!=null)p.destroyForcibly();
            Runtime.getRuntime().halt(124); // no success receipt on hung Binder/driver/diagnostic I/O
        }},"gb-crop-deadline");
        deadline.setDaemon(true);deadline.start();
        int exit=0;
        try {
            check(a.length==14 && a[0].matches("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"));
            for(int i=1;i<12;i++)check(a[i].matches("0|[1-9][0-9]{0,12}"));
            check(a[12].matches("[0-9a-f]{32}") && a[13].matches("[0-9a-f]{64}"));
            int user=Integer.parseInt(a[1]),uid=Integer.parseInt(a[2]);
            int l=Integer.parseInt(a[3]),t=Integer.parseInt(a[4]),r=Integer.parseInt(a[5]),b=Integer.parseInt(a[6]);
            check(a[7].equals("0"));
            int patternPhase=Integer.parseInt(a[9]),width=Integer.parseInt(a[10]),height=Integer.parseInt(a[11]);
            PhasePatternContract.owner(user,uid);PhasePatternContract.bounds(l,t,r,b);
            PhasePatternContract.frame(patternPhase,width,height);
            capture(a[0],user,uid,l,t,r,b,Long.parseLong(a[8]),patternPhase,width,height,a[12],a[13]);
        } catch(Throwable refused) {
            // Class only, never exception messages, cause contents or stack traces.
            String error=refused.getClass().getSimpleName();
            if(!error.matches("[A-Za-z][A-Za-z0-9_]{0,63}"))error="Throwable";
            Throwable cause=refused;
            for(int i=0;i<8 && cause.getCause()!=null && cause.getCause()!=cause;i++)cause=cause.getCause();
            String rootError=cause.getClass().getSimpleName();
            if(!rootError.matches("[A-Za-z][A-Za-z0-9_]{0,63}"))rootError="Throwable";
            System.out.println("GB_GUEST_DISPLAY_PHASE_V1:{\"schema_version\":1,\"status\":\"unknown_refused\",\"phase\":\""
                +phase+"\",\"error_type\":\""+error+"\",\"root_error_type\":\""+rootError
                +"\",\"capture_requested\":"+captureRequested+",\"buffer_cleanup_verified\":"+bufferCleanupVerified
                +(refused instanceof PhasePatternContract.LocatorRefused?",\"locator\":"+((PhasePatternContract.LocatorRefused)refused).diagnosticJson():"")
                +",\"raw_pixels_exported\":false,\"image_saved\":false,\"full_port_verified\":false}");
            exit=2;
        } finally {deadline.interrupt();java.lang.Process p=child.get();if(p!=null)p.destroyForcibly();}
        System.exit(exit);
    }
}
