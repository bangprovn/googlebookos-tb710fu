// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Choreographer;
import android.view.PixelCopy;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLongArray;
import org.json.JSONArray;
import org.json.JSONObject;

/** Reads only this Activity's fixed diagnostic window region; never another app/screen. */
final class DisplayProbe {
    private static final int BUDGET_MS=12000, BITMAP_BYTES=DisplayPattern.SIZE*DisplayPattern.SIZE*4;
    private static final class Failure extends Exception {
        final String code;
        Failure(String code) { this.code=code; }
    }
    private static final class OwnedView extends View {
        final Session owner;
        final Paint paint=new Paint();
        int phase;
        OwnedView(Activity activity,Session owner) { super(activity);this.owner=owner; }
        @Override protected void onSizeChanged(int w,int h,int oldw,int oldh) {
            super.onSizeChanged(w,h,oldw,oldh);
            if(w==DisplayPattern.SIZE && h==DisplayPattern.SIZE)owner.sized.countDown();
        }
        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            owner.canvasHardware.compareAndSet(true,canvas.isHardwareAccelerated());
            if(owner.draws.incrementAndGet()>16) {owner.drawBudget.set(true);return;}
            for(int q=0;q<4;q++) {
                paint.setColor(DisplayPattern.color(phase,q));
                int x=(q%2)*DisplayPattern.SIZE/2,y=(q/2)*DisplayPattern.SIZE/2;
                canvas.drawRect(x,y,x+DisplayPattern.SIZE/2,y+DisplayPattern.SIZE/2,paint);
            }
        }
    }
    private static final class Copy {
        final Bitmap bitmap=Bitmap.createBitmap(DisplayPattern.SIZE,DisplayPattern.SIZE,Bitmap.Config.ARGB_8888);
        final CountDownLatch done=new CountDownLatch(1);
        boolean completed,abandoned,released,requested;
        int code=-1;
        synchronized void finish(int status) {
            code=status;completed=true;
            if(abandoned) release();
            done.countDown();
        }
        synchronized void release() {
            if(!released) {bitmap.eraseColor(0);bitmap.recycle();released=true;}
        }
        synchronized void markRequested() {requested=true;}
        synchronized void abandon() {
            abandoned=true;
            // A running PixelCopy cannot be cancelled. Its callback releases the
            // destination later; never recycle memory while a copy may write it.
            if(completed || !requested)release();
        }
        synchronized int inspect(int phase) throws Failure {
            if(!completed || code!=PixelCopy.SUCCESS) throw new Failure("pixel_copy_error");
            int matching=0;
            try {
                for(int j=0;j<DisplayPattern.GRID;j++) for(int i=0;i<DisplayPattern.GRID;i++) {
                    int x=DisplayPattern.sampleCoordinate(i),y=DisplayPattern.sampleCoordinate(j);
                    if(DisplayPattern.matches(bitmap.getPixel(x,y),DisplayPattern.expected(phase,x,y)))matching++;
                }
            } finally {release();}
            return matching;
        }
        synchronized boolean released() {return released;}
        synchronized boolean pending() {return requested && !completed;}
        synchronized int status() {return code;}
    }
    private static final class Session {
        final Activity activity;
        final Handler ui=new Handler(Looper.getMainLooper());
        final AtomicBoolean active=new AtomicBoolean(true),canvasHardware=new AtomicBoolean(true),drawBudget=new AtomicBoolean();
        final AtomicInteger draws=new AtomicInteger(),frames=new AtomicInteger(),commits=new AtomicInteger();
        final Choreographer.FrameCallback[] frameCallbacks=new Choreographer.FrameCallback[DisplayPattern.PHASES];
        final Runnable[] commitCallbacks=new Runnable[DisplayPattern.PHASES];
        final AtomicLongArray frameTimes=new AtomicLongArray(DisplayPattern.PHASES);
        final CountDownLatch sized=new CountDownLatch(1);
        final long deadline=SystemClock.elapsedRealtime()+BUDGET_MS;
        volatile OwnedView view;
        volatile boolean viewHardware,uiCleaned,viewRemoved;
        Session(Activity activity) {this.activity=activity;}
        void await(CountDownLatch latch,int limit,String code) throws Exception {
            long remaining=Math.min(limit,deadline-SystemClock.elapsedRealtime());
            if(remaining<=0 || !latch.await(remaining,TimeUnit.MILLISECONDS))throw new Failure(code);
        }
        void onUi(final Runnable work) throws Exception {
            final CountDownLatch done=new CountDownLatch(1);
            final AtomicBoolean failed=new AtomicBoolean();
            if(!ui.post(new Runnable(){@Override public void run(){
                try {if(active.get())work.run();else failed.set(true);}
                catch(Throwable failure){failed.set(true);}
                finally {done.countDown();}
            }}))throw new Failure("ui_deadline");
            await(done,1000,"ui_deadline");
            if(failed.get())throw new Failure("api_exception");
        }
        void install() throws Exception {
            onUi(new Runnable(){@Override public void run(){
                if(activity.isFinishing() || activity.isDestroyed())throw new IllegalStateException();
                FrameLayout root=new FrameLayout(activity);root.setBackgroundColor(0xff000000);
                view=new OwnedView(activity,Session.this);
                FrameLayout.LayoutParams params=new FrameLayout.LayoutParams(DisplayPattern.SIZE,DisplayPattern.SIZE);
                params.gravity=android.view.Gravity.CENTER;
                root.addView(view,params);activity.setContentView(root);
            }});
            await(sized,1500,"ui_deadline");
        }
        void render(final int phase) throws Exception {
            final CountDownLatch committed=new CountDownLatch(1);
            onUi(new Runnable(){@Override public void run(){
                if(view==null || !view.isAttachedToWindow() || view.getWidth()!=DisplayPattern.SIZE || view.getHeight()!=DisplayPattern.SIZE)
                    throw new IllegalStateException();
                viewHardware=view.isHardwareAccelerated();
                view.phase=phase;
                frameCallbacks[phase]=new Choreographer.FrameCallback(){@Override public void doFrame(long time){
                    if(active.get()){frameTimes.set(phase,time);frames.incrementAndGet();}
                }};
                commitCallbacks[phase]=new Runnable(){@Override public void run(){
                    if(active.get()){commits.incrementAndGet();committed.countDown();}
                }};
                Choreographer.getInstance().postFrameCallback(frameCallbacks[phase]);
                view.getViewTreeObserver().registerFrameCommitCallback(commitCallbacks[phase]);
                view.invalidate();
            }});
            await(committed,2000,"frame_deadline");
            if(!viewHardware || !canvasHardware.get())throw new Failure("hardware_unavailable");
        }
        void request(final Copy copy) throws Exception {
            onUi(new Runnable(){@Override public void run(){
                // No caller-provided Window/Surface/rectangle. The only source
                // is the same Activity's private diagnostic View rectangle.
                int[] location=new int[2];view.getLocationInWindow(location);
                View decor=activity.getWindow().getDecorView();
                if(!view.isAttachedToWindow() || view.getWidth()!=DisplayPattern.SIZE || view.getHeight()!=DisplayPattern.SIZE
                        || location[0]<0 || location[1]<0 || location[0]+DisplayPattern.SIZE>decor.getWidth()
                        || location[1]+DisplayPattern.SIZE>decor.getHeight())throw new IllegalStateException();
                Rect rect=new Rect(location[0],location[1],location[0]+DisplayPattern.SIZE,location[1]+DisplayPattern.SIZE);
                copy.markRequested();
                PixelCopy.request(activity.getWindow(),rect,copy.bitmap,new PixelCopy.OnPixelCopyFinishedListener(){
                    @Override public void onPixelCopyFinished(int status){copy.finish(status);}
                },ui);
            }});
        }
        void cleanup() {
            active.set(false);
            final CountDownLatch done=new CountDownLatch(1);
            ui.post(new Runnable(){@Override public void run(){
                try {
                    for(int i=0;i<DisplayPattern.PHASES;i++) {
                        if(frameCallbacks[i]!=null)Choreographer.getInstance().removeFrameCallback(frameCallbacks[i]);
                        if(view!=null && commitCallbacks[i]!=null && view.getViewTreeObserver().isAlive())
                            view.getViewTreeObserver().unregisterFrameCommitCallback(commitCallbacks[i]);
                    }
                    if(view!=null && view.getParent() instanceof ViewGroup)((ViewGroup)view.getParent()).removeView(view);
                    viewRemoved=view==null || view.getParent()==null;uiCleaned=true;
                } catch(Throwable ignored) {uiCleaned=false;}
                finally {done.countDown();}
            }});
            try {done.await(1500,TimeUnit.MILLISECONDS);}catch(InterruptedException ignored){Thread.currentThread().interrupt();}
        }
    }
    static JSONObject run(Activity activity) throws Exception {
        long started=SystemClock.elapsedRealtime();Session session=new Session(activity);
        String failure="none";int phases=0,successes=0,sampled=0,matching=0,lastCode=-1,peak=0;
        Copy current=null;boolean timedOut=false;
        try {
            session.install();
            for(int phase=0;phase<DisplayPattern.PHASES;phase++) {
                session.render(phase);
                current=new Copy();peak=Math.max(peak,current.bitmap.getAllocationByteCount());
                if(peak!=BITMAP_BYTES)throw new Failure("api_exception");
                session.request(current);session.await(current.done,2000,"copy_deadline");
                lastCode=current.status();
                if(lastCode==PixelCopy.SUCCESS)successes++;
                int count=current.inspect(phase);sampled+=DisplayPattern.SAMPLES;matching+=count;
                if(count!=DisplayPattern.SAMPLES)throw new Failure("pattern_mismatch");
                phases++;
            }
        } catch(Failure refused) {failure=refused.code;timedOut=failure.endsWith("deadline");}
        catch(InterruptedException interrupted) {failure="interrupted";Thread.currentThread().interrupt();}
        catch(Throwable unavailable) {failure="api_exception";}
        finally {
            try {if(current!=null)current.abandon();}
            catch(Throwable cleanupFailure){failure="api_exception";}
            finally {session.cleanup();}
        }
        boolean increasing=true;
        for(int i=0;i<DisplayPattern.PHASES;i++)increasing &= session.frameTimes.get(i)>0 && (i==0 || session.frameTimes.get(i)>session.frameTimes.get(i-1));
        boolean released=current==null || current.released(),pending=current!=null && current.pending();
        boolean passed=failure.equals("none") && phases==3 && successes==3 && sampled==768 && matching==768
            && session.frames.get()==3 && session.commits.get()==3 && increasing && session.draws.get()>=3
            && !session.drawBudget.get() && session.viewHardware && session.canvasHardware.get()
            && released && !pending && session.uiCleaned && session.viewRemoved;
        JSONObject row=new JSONObject().put("operation","owned_window_render_readback").put("state",passed?"compatible":"unknown")
            .put("failure",failure).put("width",DisplayPattern.SIZE).put("height",DisplayPattern.SIZE)
            .put("phases_completed",phases).put("draw_calls",Math.min(session.draws.get(),17)).put("draw_budget_exceeded",session.drawBudget.get())
            .put("frame_callbacks",session.frames.get()).put("frame_commit_callbacks",session.commits.get()).put("frame_timestamps_increasing",increasing)
            .put("hardware_accelerated_view",session.viewHardware).put("hardware_accelerated_canvas",session.canvasHardware.get())
            .put("pixel_copy_successes",successes).put("last_pixel_copy_result",lastCode).put("sampled_pixels",sampled).put("matching_pixels",matching)
            .put("color_tolerance",DisplayPattern.TOLERANCE).put("owned_bitmap_peak_bytes",peak).put("bitmap_released",released).put("pixel_copy_pending",pending)
            .put("ui_cleanup_completed",session.uiCleaned).put("owned_view_removed",session.viewRemoved).put("timed_out",timedOut)
            .put("work_budget_ms",BUDGET_MS).put("elapsed_ms",SystemClock.elapsedRealtime()-started)
            .put("owned_source_only",true).put("raw_pixels_saved_or_exported",false).put("other_windows_captured",false);
        return new JSONObject().put("status","observed").put("owned_window_only",true).put("settings_changed",false)
            .put("physical_panel_verified",false).put("physical_touch_verified",false).put("external_display_verified",false)
            .put("results",new JSONArray().put(row));
    }
}
