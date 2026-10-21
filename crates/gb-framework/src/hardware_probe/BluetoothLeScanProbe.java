// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.SystemClock;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import org.json.JSONObject;

/** Explicit, one-shot anonymous BLE observation, never peer inspection.
 * Public passive scanning was added in API 36.1; the pinned build SDK is older.
 * Reflect ONLY these documented public API members, with no active fallback:
 * https://developer.android.com/reference/android/bluetooth/le/ScanSettings.Builder#setScanType(int)
 * https://developer.android.com/reference/android/bluetooth/le/ScanSettings#SCAN_TYPE_PASSIVE
 * https://developer.android.com/develop/connectivity/bluetooth/bt-permissions
 * neverForLocation is intentional; some beacons may be filtered. Unfiltered
 * scanning may pause when the screen turns off. Counts cannot qualify RF,
 * continuous scanning, any particular peer, pairing, or Phone Link discovery.
 */
final class BluetoothLeScanProbe {
    private static final int WINDOW_MS=5000, DRAIN_MS=200, MAX_CALLBACKS=1024;
    private static boolean valid(int state) { return state>=10 && state<=13; }
    private static String failure(int code) {
        switch(code) {
            case 1:return "already_started";
            case 2:return "application_registration_failed";
            case 3:return "internal_error";
            case 4:return "feature_unsupported";
            case 5:return "out_of_hardware_resources";
            case 6:return "scanning_too_frequently";
            default:return "invalid_code";
        }
    }
    private static JSONObject base() throws Exception {
        return new JSONObject().put("status","unavailable").put("state","unknown")
            .put("scope","anonymous_passive_le_scan_window").put("reason","api_exception")
            .put("connect_permission_granted",false).put("scan_permission_granted",false)
            .put("le_feature_declared",JSONObject.NULL).put("adapter_present",JSONObject.NULL)
            .put("state_before",JSONObject.NULL).put("state_after",JSONObject.NULL)
            .put("state_matches_at_checks",JSONObject.NULL).put("passive_api_verified",false)
            .put("scan_mode","low_power").put("scan_type","passive")
            .put("never_for_location",true).put("window_budget_ms",WINDOW_MS)
            .put("window_elapsed_ms",0).put("drain_budget_ms",DRAIN_MS).put("drain_elapsed_ms",0)
            .put("elapsed_ms",0).put("scan_start_attempted",false).put("scan_start_returned",false)
            .put("scan_stop_attempted",false).put("scan_stop_returned",false)
            .put("result_callback_count",0).put("batch_callback_count",0).put("failure_callback_count",0)
            .put("late_callback_count",0).put("late_failure_count",0).put("scan_failure",JSONObject.NULL)
            .put("invalid_failure_code",false).put("callback_budget_exceeded",false)
            .put("callback_gate_closed",true).put("identifiers_collected",false)
            .put("payloads_inspected",false).put("rssi_collected",false).put("batch_entries_inspected",false)
            .put("user_content_collected",false).put("radio_change_requested",false)
            .put("paired_devices_accessed",false).put("advertising_started",false).put("connection_opened",false)
            .put("rf_verified",false).put("peer_verified",false).put("phone_link_verified",false);
    }
    static JSONObject run(Context context) throws Exception {
        final JSONObject out=base();
        final long started=SystemClock.elapsedRealtime();
        final Object lock=new Object();
        // No ScanResult getters, List operations, references or peer fields are retained.
        final int[] counts=new int[5]; // result, batch, failure, late, late failure
        final String[] error={null};
        final boolean[] invalid={false}, exceeded={false}, accepting={false};
        final long[] deadline={0};
        BluetoothLeScanner scanner=null;
        boolean attempted=false, interrupted=false;
        final ScanCallback callback=new ScanCallback() {
            private void count(int kind,int code) {
                synchronized(lock) {
                    if(!accepting[0]) return;
                    int total=0; for(int n:counts) total+=n;
                    if(total>=MAX_CALLBACKS) { exceeded[0]=true; lock.notifyAll(); return; }
                    boolean late=SystemClock.elapsedRealtime()>=deadline[0];
                    if(late) counts[kind==2?4:3]++; else counts[kind]++;
                    if(kind==2) {
                        String named=failure(code);
                        if(named.equals("invalid_code")) invalid[0]=true;
                        if(error[0]==null) error[0]=named;
                        // Keep only the first fixed enum; later different codes remain failures.
                        lock.notifyAll();
                    }
                }
            }
            @Override public void onScanResult(int ignored,ScanResult neverRead) { count(0,0); }
            @Override public void onBatchScanResults(List<ScanResult> neverRead) { count(1,0); }
            @Override public void onScanFailed(int code) { count(2,code); }
        };
        try {
            PackageManager pm=context.getPackageManager();
            if(pm!=null) out.put("le_feature_declared",pm.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE));
            boolean connect=context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)==PackageManager.PERMISSION_GRANTED;
            boolean scan=context.checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN)==PackageManager.PERMISSION_GRANTED;
            out.put("connect_permission_granted",connect).put("scan_permission_granted",scan);
            if(!connect || !scan) { out.put("reason","permission_denied"); return out; }
            BluetoothManager manager=(BluetoothManager)context.getSystemService(Context.BLUETOOTH_SERVICE);
            if(manager==null) { out.put("reason","manager_unavailable"); return out; }
            BluetoothAdapter adapter=manager.getAdapter(); out.put("adapter_present",adapter!=null);
            if(adapter==null) { out.put("reason","adapter_unavailable"); return out; }
            int before=adapter.getState();
            if(!valid(before)) { out.put("reason","invalid_state"); return out; }
            out.put("state_before",before);
            if(before!=BluetoothAdapter.STATE_ON) { out.put("reason","adapter_not_on"); return out; }
            ScanSettings.Builder builder=new ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES).setReportDelay(0);
            int passive=ScanSettings.class.getField("SCAN_TYPE_PASSIVE").getInt(null);
            ScanSettings.Builder.class.getMethod("setScanType",int.class).invoke(builder,passive);
            ScanSettings settings=builder.build();
            if(((Integer)ScanSettings.class.getMethod("getScanType").invoke(settings)).intValue()!=passive) {
                out.put("reason","passive_api_unavailable"); return out;
            }
            out.put("passive_api_verified",true);
            scanner=adapter.getBluetoothLeScanner();
            if(scanner==null) { out.put("reason","scanner_unavailable"); return out; }
            long begin=SystemClock.elapsedRealtime();
            synchronized(lock) { accepting[0]=true; deadline[0]=begin+WINDOW_MS; }
            attempted=true; out.put("scan_start_attempted",true).put("callback_gate_closed",false);
            try {
                scanner.startScan(null,settings,callback);
                // A void API return is not a controller/RF acknowledgement.
                out.put("scan_start_returned",true);
                synchronized(lock) {
                    long remaining;
                    while(error[0]==null && !exceeded[0] && (remaining=deadline[0]-SystemClock.elapsedRealtime())>0)
                        lock.wait(remaining);
                }
            } finally { out.put("window_elapsed_ms",Math.max(0,SystemClock.elapsedRealtime()-begin)); }
            int after=adapter.getState();
            if(!valid(after)) out.put("reason","invalid_state");
            else out.put("state_after",after).put("state_matches_at_checks",before==after)
                .put("reason",after==BluetoothAdapter.STATE_ON?"bounded_scan_window_complete":"adapter_state_changed");
        } catch(InterruptedException stopped) { interrupted=true; out.put("reason","interrupted"); }
        catch(NoSuchFieldException|NoSuchMethodException|IllegalAccessException unavailable) { out.put("reason","passive_api_unavailable"); }
        catch(InvocationTargetException unavailable) { out.put("reason","passive_api_unavailable"); }
        catch(SecurityException denied) { out.put("reason","permission_denied"); }
        catch(RuntimeException unavailable) { out.put("reason","api_exception"); }
        finally {
            if(attempted && scanner!=null) {
                out.put("scan_stop_attempted",true);
                try { scanner.stopScan(callback); out.put("scan_stop_returned",true); }
                catch(RuntimeException failure) { out.put("reason","cleanup_incomplete"); }
                // Bounded observation of already-delayed callbacks, not proof of quiescence.
                long drain=SystemClock.elapsedRealtime();
                try { Thread.sleep(DRAIN_MS); }
                catch(InterruptedException stopped) { interrupted=true; }
                out.put("drain_elapsed_ms",Math.max(0,SystemClock.elapsedRealtime()-drain));
            }
            synchronized(lock) {
                accepting[0]=false;
                out.put("callback_gate_closed",true).put("result_callback_count",counts[0])
                    .put("batch_callback_count",counts[1]).put("failure_callback_count",counts[2])
                    .put("late_callback_count",counts[3]).put("late_failure_count",counts[4])
                    .put("scan_failure",error[0]==null?JSONObject.NULL:error[0])
                    .put("invalid_failure_code",invalid[0]).put("callback_budget_exceeded",exceeded[0]);
            }
            long elapsed=Math.max(0,SystemClock.elapsedRealtime()-started); out.put("elapsed_ms",elapsed);
            if(out.getString("reason").equals("bounded_scan_window_complete")) {
                if(error[0]!=null) out.put("reason",invalid[0]?"invalid_failure_code":"scan_failed");
                else if(exceeded[0]) out.put("reason","callback_budget_exceeded");
                else if(interrupted) out.put("reason","interrupted");
                else if(out.getLong("window_elapsed_ms")<WINDOW_MS || out.getLong("window_elapsed_ms")>6500
                    || out.getLong("drain_elapsed_ms")<DRAIN_MS || out.getLong("drain_elapsed_ms")>1500 || elapsed>9000)
                    out.put("reason","window_mismatch");
                else out.put("status","observed");
            }
            if(interrupted) Thread.currentThread().interrupt();
        }
        return out;
    }
}
