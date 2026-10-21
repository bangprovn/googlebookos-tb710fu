// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import org.json.JSONObject;

/** Public status only, never device enumeration, discovery, pairing or radio changes.
 * https://developer.android.com/reference/android/bluetooth/BluetoothAdapter#getState()
 * https://developer.android.com/develop/background-work/background-tasks/broadcasts
 * CONNECT is the sole Bluetooth permission. State broadcasts contain no remote device.
 */
final class BluetoothProbe {
    private static final int WINDOW_MS=2000, MAX_CALLBACKS=32;
    private static boolean valid(int state) { return state>=10 && state<=13; }
    private static JSONObject base() throws Exception {
        return new JSONObject().put("status","unavailable").put("state","unknown")
            .put("scope","public_api_status_only").put("reason","api_exception")
            .put("classic_feature_declared",JSONObject.NULL).put("le_feature_declared",JSONObject.NULL)
            .put("connect_permission_granted",false).put("adapter_present",JSONObject.NULL)
            .put("state_before",JSONObject.NULL).put("state_after",JSONObject.NULL)
            .put("state_matches_at_checks",JSONObject.NULL).put("window_budget_ms",WINDOW_MS)
            .put("window_elapsed_ms",0).put("elapsed_ms",0)
            .put("receiver_registered",false).put("receiver_cleanup_attempted",false).put("receiver_removed",false)
            .put("callback_thread_stopped",true).put("callback_count",0)
            .put("valid_transition_callbacks",0).put("invalid_state_callback",false)
            .put("callback_budget_exceeded",false).put("read_only",true)
            .put("identifiers_collected",false).put("user_content_collected",false)
            .put("radio_change_requested",false).put("discovery_or_scan_started",false)
            .put("paired_devices_accessed",false).put("socket_opened",false)
            .put("functionality_verified",false).put("radio_transition_verified",false);
    }
    static JSONObject run(Context context) throws Exception {
        final JSONObject out=base();
        final long started=SystemClock.elapsedRealtime();
        HandlerThread thread=null;
        BroadcastReceiver receiver=null;
        boolean registered=false, interrupted=false;
        final Object lock=new Object();
        final int[] counts=new int[2];
        final boolean[] invalid={false}, exceeded={false}, active={false};
        final long[] deadline={0};
        try {
            PackageManager features=context.getPackageManager();
            if(features!=null) out.put("classic_feature_declared",features.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH))
                .put("le_feature_declared",features.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE));
            boolean permission=context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)==PackageManager.PERMISSION_GRANTED;
            out.put("connect_permission_granted",permission);
            if(!permission) { out.put("reason","permission_denied"); return out; }
            BluetoothManager manager=(BluetoothManager)context.getSystemService(Context.BLUETOOTH_SERVICE);
            if(manager==null) { out.put("reason","manager_unavailable"); return out; }
            BluetoothAdapter adapter=manager.getAdapter();
            out.put("adapter_present",adapter!=null);
            if(adapter==null) { out.put("reason","adapter_unavailable"); return out; }
            int before=adapter.getState();
            if(!valid(before)) { out.put("reason","invalid_state"); return out; }
            out.put("state_before",before);
            thread=new HandlerThread("gb-owned-bluetooth-status");
            thread.start(); out.put("callback_thread_stopped",false);
            Handler handler=new Handler(thread.getLooper());
            receiver=new BroadcastReceiver() {
                @Override public void onReceive(Context ignored,Intent intent) {
                    if(intent==null || !BluetoothAdapter.ACTION_STATE_CHANGED.equals(intent.getAction())) return;
                    synchronized(lock) {
                        if(!active[0] || SystemClock.elapsedRealtime()>deadline[0]) return;
                        if(counts[0]>=MAX_CALLBACKS) { exceeded[0]=true; return; }
                        counts[0]++;
                        int state=intent.getIntExtra(BluetoothAdapter.EXTRA_STATE,-1);
                        int previous=intent.getIntExtra(BluetoothAdapter.EXTRA_PREVIOUS_STATE,-1);
                        if(!valid(state) || !valid(previous)) invalid[0]=true;
                        else if(state!=previous) counts[1]++;
                    }
                }
            };
            long begin=SystemClock.elapsedRealtime();
            synchronized(lock) { active[0]=true; deadline[0]=begin+WINDOW_MS; }
            IntentFilter filter=new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED);
            // Bluetooth broadcasts can originate from its privileged app UID rather
            // than system UID. This protected action needs an exported receiver;
            // constrain senders to CONNECT and never inspect any device-bearing action.
            if(Build.VERSION.SDK_INT>=33)
                context.registerReceiver(receiver,filter,Manifest.permission.BLUETOOTH_CONNECT,handler,Context.RECEIVER_EXPORTED);
            else context.registerReceiver(receiver,filter,Manifest.permission.BLUETOOTH_CONNECT,handler);
            registered=true; out.put("receiver_registered",true);
            try { Thread.sleep(WINDOW_MS); }
            finally {
                synchronized(lock) { active[0]=false; }
                out.put("window_elapsed_ms",Math.max(0,SystemClock.elapsedRealtime()-begin));
            }
            int after=adapter.getState();
            if(!valid(after)) out.put("reason","invalid_state");
            else out.put("state_after",after).put("state_matches_at_checks",before==after)
                .put("reason","bounded_status_complete");
        } catch(InterruptedException stopped) {
            interrupted=true; out.put("reason","interrupted");
        } catch(SecurityException denied) { out.put("reason","permission_denied"); }
        catch(RuntimeException unavailable) { out.put("reason","api_exception"); }
        finally {
            synchronized(lock) { active[0]=false; }
            if(receiver!=null) {
                // Even a registration exception can leave its remote outcome
                // ambiguous. Always try removal; never call that an acknowledged
                // registration/removal when registerReceiver did not return.
                out.put("receiver_cleanup_attempted",true);
                try { context.unregisterReceiver(receiver); if(registered) out.put("receiver_removed",true); }
                catch(RuntimeException failure) { if(registered) out.put("reason","cleanup_incomplete"); }
            }
            if(thread!=null) {
                thread.quitSafely();
                try { thread.join(1000); }
                catch(InterruptedException stopped) { interrupted=true; }
                out.put("callback_thread_stopped",!thread.isAlive());
                if(thread.isAlive()) out.put("reason","cleanup_incomplete");
            }
            synchronized(lock) {
                out.put("callback_count",counts[0]).put("valid_transition_callbacks",counts[1])
                    .put("invalid_state_callback",invalid[0]).put("callback_budget_exceeded",exceeded[0]);
            }
            long elapsed=Math.max(0,SystemClock.elapsedRealtime()-started);
            out.put("elapsed_ms",elapsed);
            if(out.getString("reason").equals("bounded_status_complete")) {
                long window=out.getLong("window_elapsed_ms");
                if(invalid[0]) out.put("reason","invalid_state");
                else if(exceeded[0]) out.put("reason","callback_budget_exceeded");
                else if(window<WINDOW_MS || window>3500 || elapsed>6000) out.put("reason","window_mismatch");
                else if(interrupted) out.put("reason","interrupted");
                else out.put("status","observed");
            }
            if(interrupted) Thread.currentThread().interrupt();
        }
        return out;
    }
}
