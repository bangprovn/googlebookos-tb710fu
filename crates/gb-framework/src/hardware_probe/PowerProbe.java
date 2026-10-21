// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.PowerManager;
import android.os.SystemClock;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;

/** Public API reads only; no thermal load, settings, wake lock or battery control.
 * API contracts: developer.android.com/reference/android/os/{BatteryManager,PowerManager}
 */
final class PowerProbe {
    private static JSONObject row(String operation) throws Exception {
        return new JSONObject().put("operation",operation).put("state","unknown")
            .put("availability","unavailable_or_unsupported");
    }
    private static Object integer(int value) { return value==Integer.MIN_VALUE ? JSONObject.NULL : value; }
    private static boolean status(int value) { return value>=0 && value<=6; }

    static JSONObject run(Context context) throws Exception {
        JSONArray results=new JSONArray();
        JSONObject battery=row("battery_snapshot").put("present",JSONObject.NULL)
            .put("status_code",JSONObject.NULL).put("level",JSONObject.NULL)
            .put("scale",JSONObject.NULL).put("temperature_decic",JSONObject.NULL)
            .put("temperature_unit","tenths_degree_celsius");
        try {
            // A null receiver reads only the sticky intent; it registers no receiver.
            Intent intent=context.registerReceiver(null,new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if(intent!=null) {
                boolean present=intent.hasExtra(BatteryManager.EXTRA_PRESENT) && intent.getBooleanExtra(BatteryManager.EXTRA_PRESENT,false);
                int code=intent.getIntExtra(BatteryManager.EXTRA_STATUS,Integer.MIN_VALUE);
                int level=intent.getIntExtra(BatteryManager.EXTRA_LEVEL,Integer.MIN_VALUE);
                int scale=intent.getIntExtra(BatteryManager.EXTRA_SCALE,Integer.MIN_VALUE);
                int temperature=intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE,Integer.MIN_VALUE);
                battery.put("present",present).put("status_code",integer(code)).put("level",integer(level))
                    .put("scale",integer(scale)).put("temperature_decic",integer(temperature));
                boolean valid=present && code>=2 && code<=5 && scale>0 && scale<=10000
                    && level>=0 && level<=scale && temperature>=-1000 && temperature<=2000;
                battery.put("availability",valid?"available":"invalid_or_unknown_reading")
                    .put("state",valid?"compatible":"unknown");
            }
        } catch(RuntimeException unavailable) { battery.put("availability","api_exception"); }
        results.put(battery);

        JSONObject charge=row("charge_counter").put("value_uah",JSONObject.NULL)
            .put("unit","microampere_hours");
        try {
            BatteryManager manager=(BatteryManager)context.getSystemService(Context.BATTERY_SERVICE);
            if(manager!=null) {
                int value=manager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER);
                // targetSdk >= 28: Integer.MIN_VALUE means unavailable/unsupported, never zero.
                charge.put("value_uah",integer(value));
                if(value!=Integer.MIN_VALUE) charge.put("availability",value>=0?"available":"invalid_or_unknown_reading")
                    .put("state",value>=0?"compatible":"unknown");
            }
        } catch(RuntimeException unavailable) { charge.put("availability","api_exception"); }
        results.put(charge);

        PowerManager manager=(PowerManager)context.getSystemService(Context.POWER_SERVICE);
        JSONObject thermal=row("thermal_status").put("direct_before",JSONObject.NULL).put("direct_after",JSONObject.NULL)
            .put("listener_registered",false).put("listener_removed",false).put("callbacks",0)
            .put("last_callback_status",JSONObject.NULL).put("callbacks_valid",true)
            .put("callback_budget_exceeded",false).put("executor_stopped",true).put("window_ms",0);
        if(manager!=null) {
            final int[] count={0},last={Integer.MIN_VALUE};
            AtomicBoolean valid=new AtomicBoolean(true),overBudget=new AtomicBoolean();
            ThreadPoolExecutor executor=new ThreadPoolExecutor(1,1,0,TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<Runnable>(16),new RejectedExecutionHandler() {
                    @Override public void rejectedExecution(Runnable task,ThreadPoolExecutor pool) { overBudget.set(true); }
                });
            PowerManager.OnThermalStatusChangedListener listener=new PowerManager.OnThermalStatusChangedListener() {
                @Override public void onThermalStatusChanged(int value) {
                    synchronized(count) {
                        if(count[0]>=32) { overBudget.set(true); return; }
                        count[0]++; last[0]=value; if(!status(value)) valid.set(false);
                    }
                }
            };
            boolean registered=false,removed=false,stopped=false;
            int before=Integer.MIN_VALUE,after=Integer.MIN_VALUE;
            long start=SystemClock.elapsedRealtime();
            try {
                before=manager.getCurrentThermalStatus();
                manager.addThermalStatusListener(executor,listener); registered=true;
                Thread.sleep(2000);
                after=manager.getCurrentThermalStatus();
            } catch(RuntimeException unavailable) { thermal.put("availability","api_exception"); }
            finally {
                try { if(registered) { manager.removeThermalStatusListener(listener); removed=true; } }
                catch(RuntimeException unavailable) { thermal.put("availability","api_exception"); }
                finally { executor.shutdownNow(); stopped=executor.awaitTermination(1000,TimeUnit.MILLISECONDS); }
            }
            long elapsed=SystemClock.elapsedRealtime()-start;
            synchronized(count) {
                boolean ok=status(before) && status(after) && registered && removed && stopped
                    && count[0]>0 && valid.get() && !overBudget.get() && elapsed>=2000 && elapsed<=10000;
                thermal.put("direct_before",integer(before)).put("direct_after",integer(after))
                    .put("listener_registered",registered).put("listener_removed",removed).put("executor_stopped",stopped)
                    .put("callbacks",count[0]).put("last_callback_status",integer(last[0]))
                    .put("callbacks_valid",valid.get()).put("callback_budget_exceeded",overBudget.get()).put("window_ms",elapsed)
                    .put("state",ok?"compatible":"unknown");
                if(ok) thermal.put("availability","available");
            }
        }
        results.put(thermal);

        JSONObject headroom=row("thermal_headroom").put("value",JSONObject.NULL).put("forecast_seconds",0).put("read_count",0);
        try {
            if(manager!=null) {
                headroom.put("read_count",1);
                float value=manager.getThermalHeadroom(0); // One query, no forecast/calibration claim.
                if(Float.isInfinite(value) || value<0) headroom.put("availability","invalid_or_unknown_reading");
                else if(!Float.isNaN(value))
                    headroom.put("value",value).put("availability","available").put("state","compatible");
            }
        } catch(RuntimeException unavailable) { headroom.put("availability","api_exception"); }
        results.put(headroom);
        return new JSONObject().put("status","observed").put("read_only",true)
            .put("settings_changed",false).put("wake_lock_acquired",false)
            .put("charging_performance_verified",false).put("battery_calibration_verified",false)
            .put("thermal_control_verified",false).put("suspend_resume_verified",false).put("results",results);
    }
}
