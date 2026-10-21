// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Process;
import android.os.SystemClock;
import android.util.Size;
import android.view.WindowManager;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONArray;
import org.json.JSONObject;

/** Foreground, unprivileged app operations. No photos, audio or raw sensor traces saved. */
public final class HardwareProbeActivity extends Activity {
    private final AtomicBoolean started = new AtomicBoolean();
    private volatile Thread worker;
    private String runId;
    private String suite;
    private static void require(boolean ok) {
        if (!ok) throw new IllegalStateException("probe assertion failed");
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        runId = getIntent().getStringExtra("run_id");
        if (runId == null || !runId.matches("[a-f0-9]{32}")) { finish(); return; }
        suite = getIntent().getStringExtra("suite");
        if (suite == null) suite="all";
        if (!suite.equals("all") && !suite.equals("sensors") && !suite.equals("cameras") && !suite.equals("audio") && !suite.equals("audio_capture_pattern") && !suite.equals("auth_bound_keys") && !suite.equals("power") && !suite.equals("network") && !suite.equals("usb_inventory") && !suite.equals("display") && !suite.equals("bluetooth_status") && !suite.equals("bluetooth_le_scan")) { finish(); return; }
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        TextView text = new TextView(this);
        text.setText(suite.equals("power") ? "Googlebook power diagnostics\n\nReading battery and thermal APIs. No settings are changed.\nThis does not test charging performance, thermal control or suspend." : "Googlebook hardware diagnostics\n\nRunning the selected sensor, camera, quiet audio or app-owned key test.\nNo photos or audio recordings are saved.");
        if(suite.equals("network")) text.setText("Googlebook network diagnostics\n\nReading default-network APIs and requesting one fixed HTTPS 204 endpoint.\nNo network settings or radios are changed. No network identifiers or content are saved.");
        if(suite.equals("usb_inventory")) text.setText("Googlebook USB inventory\n\nReading anonymous attached-device and class counts only.\nNo devices are opened and no USB permissions are requested.\nHost operation, Type-C roles and Power Delivery remain unverified.");
        if(suite.equals("display")) text.setText("Googlebook owned-window rendering diagnostics\n\nDrawing and reading only this app’s fixed diagnostic pattern.\nNo screen or other app capture, physical panel, touch or external display qualification.");
        if(suite.equals("bluetooth_status")) text.setText("Googlebook Bluetooth status\n\nReading anonymous adapter state with a bounded state-change listener.\nNo device discovery, pairing, connections or radio changes. Bluetooth functionality remains unverified.");
        if(suite.equals("bluetooth_le_scan")) text.setText("Googlebook anonymous passive BLE observation\n\nOne 5-second low-power scan. Only callback counts; no peer data, pairing, connections or radio changes. Zero callbacks does not prove radio functionality.");
        text.setTextSize(24); text.setPadding(48,48,48,48); setContentView(text);
    }
    @Override public void onResume() {
        super.onResume();
        if (runId == null || !started.compareAndSet(false,true)) return;
        worker = new Thread(new Runnable() { @Override public void run() {
            try {
                Thread.sleep(600); // Activity and while-in-use camera permission become foreground.
                JSONObject report = new JSONObject().put("schema_version",1)
                    .put("probe","owned_android_hardware_v1").put("run_id",runId)
                    .put("uid",Process.myUid()).put("package",getPackageName())
                    .put("fingerprint",android.os.Build.FINGERPRINT).put("suite",suite);
                try { report.put("sensors", (suite.equals("all") || suite.equals("sensors")) ? sensors() : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("sensors",new JSONObject().put("state","unknown").put("error_class",e.getClass().getName())); }
                try { report.put("cameras", (suite.equals("all") || suite.equals("cameras")) ? cameras() : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("cameras",new JSONObject().put("state","unknown").put("error_class",e.getClass().getName())); }
                try { report.put("audio", suite.equals("audio_capture_pattern") ? AudioProbe.capturePattern(HardwareProbeActivity.this,new Runnable() {
                    @Override public void run() {
                        try (FileOutputStream stream=openFileOutput("ready-"+runId,MODE_PRIVATE)) {
                            stream.write("GB_AUDIO_CAPTURE_READY\n".getBytes(StandardCharsets.US_ASCII));
                        } catch(IOException failure) { throw new IllegalStateException("readiness publication failed"); }
                    }
                }) : (suite.equals("all") || suite.equals("audio")) ? AudioProbe.run(HardwareProbeActivity.this) : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("audio",new JSONObject().put("state","unknown").put("error_class",e.getClass().getName())); }
                try { report.put("keystore", suite.equals("auth_bound_keys") ? AuthKeyProbe.run(HardwareProbeActivity.this,runId) : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("keystore",new JSONObject().put("state","unknown").put("error_class",e.getClass().getName())); }
                try { report.put("power", suite.equals("power") ? PowerProbe.run(HardwareProbeActivity.this) : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("power",new JSONObject().put("state","unknown")); }
                try { report.put("network", suite.equals("network") ? NetworkProbe.run(HardwareProbeActivity.this) : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("network",new JSONObject().put("state","unknown")); }
                try { report.put("usb", suite.equals("usb_inventory") ? UsbProbe.run(HardwareProbeActivity.this) : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("usb",new JSONObject().put("state","unknown")); }
                try { report.put("display", suite.equals("display") ? DisplayProbe.run(HardwareProbeActivity.this) : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("display",new JSONObject().put("state","unknown")); }
                try { report.put("bluetooth", suite.equals("bluetooth_status") ? BluetoothProbe.run(HardwareProbeActivity.this) : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("bluetooth",new JSONObject().put("state","unknown")); }
                try { report.put("bluetooth_le_scan", suite.equals("bluetooth_le_scan") ? BluetoothLeScanProbe.run(HardwareProbeActivity.this) : new JSONObject().put("status","not_requested")); }
                catch (Throwable e) { report.put("bluetooth_le_scan",new JSONObject().put("state","unknown")); }
                report.put("physical_rotation_or_calibration_verified",false)
                    .put("camera_image_quality_verified",false).put("user_content_collected",false)
                    .put("full_port_verified",false).put("elapsed_realtime_ms",SystemClock.elapsedRealtime());
                byte[] encoded = report.toString().getBytes(StandardCharsets.UTF_8);
                require(encoded.length < 65536);
                File destination = new File(getFilesDir(),"gb-"+runId+".json");
                require(!destination.exists());
                File temporary = new File(getFilesDir(),"gb-"+runId+".tmp");
                try (FileOutputStream out = new FileOutputStream(temporary)) { out.write(encoded); out.getFD().sync(); }
                require(temporary.renameTo(destination));
            } catch (Throwable ignored) {
                // No exception messages or user/device data go into global logcat.
            } finally { runOnUiThread(new Runnable() { @Override public void run() { HardwareProbeActivity.this.finishAndRemoveTask(); } }); }
        } },"gb-owned-hardware");
        worker.start();
    }
    @Override public void onDestroy() {
        Thread thread = worker;
        if (thread != null && thread.isAlive()) thread.interrupt();
        super.onDestroy();
    }

    private static final class Samples {
        final Sensor sensor;
        volatile boolean registered;
        int count, nonfinite;
        long first, last;
        boolean increasing = true;
        double minimum = Double.POSITIVE_INFINITY, maximum = Double.NEGATIVE_INFINITY;
        Samples(Sensor sensor, boolean registered) { this.sensor=sensor; this.registered=registered; }
        synchronized void accept(SensorEvent event) {
            if (count > 1000) return;
            if (count > 0 && event.timestamp <= last) increasing=false;
            if (count == 0) first=event.timestamp;
            last=event.timestamp; count++;
            double magnitude=0;
            for (float value : event.values) {
                if (Float.isNaN(value) || Float.isInfinite(value)) { nonfinite++; return; }
                magnitude += (double)value*value;
            }
            magnitude=Math.sqrt(magnitude);
            minimum=Math.min(minimum,magnitude); maximum=Math.max(maximum,magnitude);
        }
        synchronized JSONObject report(int type) throws Exception {
            boolean onchange = sensor != null && sensor.getReportingMode() != Sensor.REPORTING_MODE_CONTINUOUS;
            long age=SystemClock.elapsedRealtimeNanos()-last;
            boolean delivered = registered && count >= (onchange ? 1 : 2) && increasing && nonfinite == 0
                && last > 0 && age>=0 && age < TimeUnit.SECONDS.toNanos(10);
            JSONObject result = new JSONObject().put("type",type).put("state",delivered?"compatible":"unknown")
                .put("scope","Bounded event delivery and finite values; not calibration or controlled physical motion")
                .put("exposed",sensor!=null).put("registered",registered).put("events",count)
                .put("strictly_increasing_timestamps",increasing).put("nonfinite_values",nonfinite);
            if (sensor != null) result.put("name",sensor.getName()).put("vendor",sensor.getVendor())
                .put("reporting_mode",sensor.getReportingMode());
            if (minimum != Double.POSITIVE_INFINITY) result.put("minimum_value_magnitude",minimum).put("maximum_value_magnitude",maximum);
            return result;
        }
    }
    private JSONObject sensors() throws Exception {
        SensorManager manager=(SensorManager)getSystemService(Context.SENSOR_SERVICE);
        require(manager!=null);
        HandlerThread thread=new HandlerThread("gb-owned-sensors"); thread.start();
        Handler handler=new Handler(thread.getLooper());
        Map<Integer,Samples> samples=new HashMap<>();
        SensorEventListener listener=new SensorEventListener() {
            @Override public void onSensorChanged(SensorEvent event) { synchronized(samples) { Samples s=samples.get(event.sensor.getType()); if(s!=null) s.accept(event); } }
            @Override public void onAccuracyChanged(Sensor sensor,int accuracy) {}
        };
        int[] types={Sensor.TYPE_ACCELEROMETER,Sensor.TYPE_GYROSCOPE,Sensor.TYPE_ROTATION_VECTOR,
            Sensor.TYPE_LIGHT,Sensor.TYPE_PROXIMITY,Sensor.TYPE_MAGNETIC_FIELD,
            Sensor.TYPE_GAME_ROTATION_VECTOR,Sensor.TYPE_GRAVITY,Sensor.TYPE_LINEAR_ACCELERATION};
        try {
            for(int type:types) {
                Sensor sensor=manager.getDefaultSensor(type);
                Samples sample=new Samples(sensor,false);
                synchronized(samples) { samples.put(type,sample); }
                boolean registered=sensor!=null && manager.registerListener(listener,sensor,SensorManager.SENSOR_DELAY_GAME,handler);
                sample.registered=registered;
            }
            Thread.sleep(2500);
        } finally { manager.unregisterListener(listener); thread.quitSafely(); thread.join(1000); }
        JSONArray results=new JSONArray();
        for(int type:types) results.put(samples.get(type).report(type));
        return new JSONObject().put("status","observed").put("sample_window_ms",2500).put("results",results);
    }

    private JSONObject cameras() throws Exception {
        if(checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED)
            return new JSONObject().put("state","unknown").put("reason","owned_app_camera_permission_missing");
        CameraManager manager=(CameraManager)getSystemService(Context.CAMERA_SERVICE);
        require(manager!=null);
        String[] ids=manager.getCameraIdList();
        require(ids.length<=16);
        JSONArray results=new JSONArray();
        for(int i=0;i<ids.length;i++) {
            if(i>=4) results.put(new JSONObject().put("id",ids[i]).put("state","unknown").put("reason","per_run_camera_budget"));
            else results.put(camera(manager,ids[i]));
        }
        return new JSONObject().put("status",ids.length==0?"no_public_camera_ids":"observed").put("results",results);
    }
    private JSONObject camera(CameraManager manager,String id) throws Exception {
        JSONObject result=new JSONObject().put("id",id).put("state","unknown")
            .put("scope","Three bounded YUV frame deliveries; pixel content is not read or saved");
        HandlerThread thread=new HandlerThread("gb-owned-camera"); thread.start();
        Handler handler=new Handler(thread.getLooper());
        AtomicBoolean aborted=new AtomicBoolean();
        AtomicReference<CameraDevice> device=new AtomicReference<>();
        AtomicReference<CameraCaptureSession> session=new AtomicReference<>();
        AtomicInteger error=new AtomicInteger();
        CountDownLatch opened=new CountDownLatch(1),configured=new CountDownLatch(1),frames=new CountDownLatch(1),closed=new CountDownLatch(1);
        ImageReader reader=null;
        final int[] images={0}; final long[] timestamps={0,0}; final boolean[] valid={true};
        try {
            result.put("phase","characteristics");
            CameraCharacteristics characteristics=manager.getCameraCharacteristics(id);
            result.put("lens_facing",characteristics.get(CameraCharacteristics.LENS_FACING))
                .put("hardware_level",characteristics.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL));
            StreamConfigurationMap formats=characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            require(formats!=null);
            Size[] sizes=formats.getOutputSizes(ImageFormat.YUV_420_888);
            require(sizes!=null && sizes.length<=256);
            Size chosen=null; long distance=Long.MAX_VALUE;
            for(Size size:sizes) {
                long pixels=(long)size.getWidth()*size.getHeight();
                if(size.getWidth()<160 || size.getHeight()<120 || size.getWidth()>1280 || size.getHeight()>720) continue;
                long difference=Math.abs(pixels-640*480);
                if(difference<distance) { chosen=size; distance=difference; }
            }
            if(chosen==null) return result.put("reason","bounded_yuv_geometry_not_exposed");
            result.put("width",chosen.getWidth()).put("height",chosen.getHeight());
            reader=ImageReader.newInstance(chosen.getWidth(),chosen.getHeight(),ImageFormat.YUV_420_888,2);
            reader.setOnImageAvailableListener(new ImageReader.OnImageAvailableListener() { @Override public void onImageAvailable(ImageReader source) {
                try(Image image=source.acquireLatestImage()) {
                    if(image==null) return;
                    synchronized(images) {
                        if(images[0]>=16) return;
                        long timestamp=image.getTimestamp();
                        valid[0] &= image.getFormat()==ImageFormat.YUV_420_888 && image.getWidth()>=160 && image.getHeight()>=120
                            && image.getPlanes().length==3 && image.getPlanes()[0].getBuffer().remaining()>0
                            && timestamp>timestamps[1];
                        if(images[0]==0) timestamps[0]=timestamp;
                        timestamps[1]=timestamp; images[0]++;
                        if(images[0]>=3) frames.countDown();
                    }
                } catch(Throwable ignored) { error.compareAndSet(0,-4); frames.countDown(); }
            } },handler);
            result.put("phase","open");
            manager.openCamera(id,new CameraDevice.StateCallback() {
                @Override public void onOpened(CameraDevice camera) { if(aborted.get()) camera.close(); else device.set(camera); opened.countDown(); }
                @Override public void onDisconnected(CameraDevice camera) { error.compareAndSet(0,-2); camera.close(); opened.countDown(); frames.countDown(); }
                @Override public void onError(CameraDevice camera,int code) { error.compareAndSet(0,code); camera.close(); opened.countDown(); frames.countDown(); }
                @Override public void onClosed(CameraDevice camera) { closed.countDown(); }
            },handler);
            require(opened.await(4,TimeUnit.SECONDS) && device.get()!=null && error.get()==0);
            result.put("phase","configure");
            device.get().createCaptureSession(Collections.singletonList(reader.getSurface()),new CameraCaptureSession.StateCallback() {
                @Override public void onConfigured(CameraCaptureSession configuredSession) { if(aborted.get()) configuredSession.close(); else session.set(configuredSession); configured.countDown(); }
                @Override public void onConfigureFailed(CameraCaptureSession failedSession) { error.compareAndSet(0,-3); failedSession.close(); configured.countDown(); }
            },handler);
            require(configured.await(4,TimeUnit.SECONDS) && session.get()!=null && error.get()==0);
            result.put("phase","repeating_request");
            CaptureRequest.Builder request=device.get().createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            request.addTarget(reader.getSurface());
            session.get().setRepeatingRequest(request.build(),null,handler);
            result.put("phase","await_frames");
            require(frames.await(4,TimeUnit.SECONDS));
            synchronized(images) {
                require(images[0]>=3 && valid[0] && error.get()==0);
                result.put("state","compatible").put("frames_delivered",images[0])
                    .put("phase","frames_verified")
                    .put("increasing_frame_timestamps",true).put("yuv_structure_valid",true)
                    .put("pixel_content_read",false).put("images_saved",false);
            }
        } catch(Throwable failure) {
            result.put("error_class",failure.getClass().getName()).put("camera_error_code",error.get());
            if(failure instanceof CameraAccessException) result.put("camera_access_reason",((CameraAccessException)failure).getReason());
        } finally {
            aborted.set(true);
            CameraCaptureSession active=session.get(); if(active!=null) { try{active.stopRepeating();}catch(Throwable ignored){} active.close(); }
            CameraDevice camera=device.get(); if(camera!=null) {
                camera.close();
                boolean closeObserved=closed.await(2,TimeUnit.SECONDS);
                result.put("close_callback_observed",closeObserved);
                if(!closeObserved) result.put("state","unknown").put("reason","owned_camera_close_not_observed");
            }
            if(reader!=null) { reader.setOnImageAvailableListener(null,null); reader.close(); }
            thread.quitSafely(); thread.join(1000);
        }
        return result;
    }
}
