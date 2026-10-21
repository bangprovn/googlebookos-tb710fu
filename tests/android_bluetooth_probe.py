#!/usr/bin/env python3
"""Host-only Bluetooth lifecycle faults with owned Android stubs, never ADB.

Uses only the pinned JDK from an existing hardware BuildRequest. The stubs exercise
our control flow; they do not emulate Android binder, broadcasts or Bluetooth RF.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("build_request", type=Path)
args = parser.parse_args()
tools = json.loads(args.build_request.read_text())["java"]["tools"]
for name in ("java", "javac"):
    path = Path(tools[name]["path"])
    if not path.is_absolute():
        path = args.build_request.parent / path
    assert path.is_file() and not path.is_symlink()
    with path.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == tools[name]["sha256"]
    tools[name]["path"] = str(path.resolve())

SOURCES = {
"android/Manifest.java": '''package android; public class Manifest {public static class permission {public static final String BLUETOOTH_CONNECT="android.permission.BLUETOOTH_CONNECT";}}''',
"android/content/pm/PackageManager.java": '''package android.content.pm; public class PackageManager {public static final int PERMISSION_GRANTED=0;public static final String FEATURE_BLUETOOTH="bt",FEATURE_BLUETOOTH_LE="ble";public boolean hasSystemFeature(String value){return true;}}''',
"android/bluetooth/BluetoothAdapter.java": '''package android.bluetooth; public class BluetoothAdapter {public static final String ACTION_STATE_CHANGED="state",EXTRA_STATE="current",EXTRA_PREVIOUS_STATE="previous";public int before=12,after=12,calls;public boolean failAfter;public int getState(){if(calls++==0)return before;if(failAfter)throw new IllegalStateException();return after;}}''',
"android/bluetooth/BluetoothManager.java": '''package android.bluetooth; public class BluetoothManager {public BluetoothAdapter adapter=new BluetoothAdapter();public BluetoothAdapter getAdapter(){return adapter;}}''',
"android/content/Intent.java": '''package android.content; public class Intent {public int current=12,previous=11;public String getAction(){return "state";}public int getIntExtra(String key,int fallback){return key.equals("current")?current:previous;}}''',
"android/content/IntentFilter.java": '''package android.content; public class IntentFilter {public IntentFilter(String action){if(!action.equals("state"))throw new AssertionError();}}''',
"android/content/BroadcastReceiver.java": '''package android.content; public abstract class BroadcastReceiver {public abstract void onReceive(Context context,Intent intent);}''',
"android/content/Context.java": '''package android.content;
import android.bluetooth.*;import android.content.pm.*;import android.os.*;
public class Context {
 public static final String BLUETOOTH_SERVICE="bluetooth";public static final int RECEIVER_EXPORTED=2;
 public int permission,registered,removed,callbacks;public boolean failRegister,failRemove,invalidCallback;
 public BluetoothManager manager=new BluetoothManager();
 public PackageManager getPackageManager(){return new PackageManager();}
 public int checkSelfPermission(String name){if(!name.equals("android.permission.BLUETOOTH_CONNECT"))throw new AssertionError();return permission;}
 public Object getSystemService(String name){if(!name.equals(BLUETOOTH_SERVICE))throw new AssertionError();return manager;}
 public Intent registerReceiver(BroadcastReceiver receiver,IntentFilter filter,String permission,Handler handler){return registerReceiver(receiver,filter,permission,handler,RECEIVER_EXPORTED);}
 public Intent registerReceiver(BroadcastReceiver receiver,IntentFilter filter,String permission,Handler handler,int flags){
  if(flags!=RECEIVER_EXPORTED||!permission.equals("android.permission.BLUETOOTH_CONNECT"))throw new AssertionError();
  if(failRegister)throw new IllegalStateException();registered++;
  for(int i=0;i<callbacks;i++){Intent event=new Intent();if(invalidCallback)event.current=999;receiver.onReceive(this,event);}return null;
 }
 public void unregisterReceiver(BroadcastReceiver receiver){removed++;if(failRemove)throw new IllegalStateException();}
}''',
"android/os/Build.java": '''package android.os;public class Build {public static class VERSION {public static int SDK_INT=36;}}''',
"android/os/SystemClock.java": '''package android.os;public class SystemClock {public static long elapsedRealtime(){return System.nanoTime()/1000000;}}''',
"android/os/Handler.java": '''package android.os;public class Handler {public Handler(Object looper){}}''',
"android/os/HandlerThread.java": '''package android.os;public class HandlerThread extends Thread {private volatile boolean done;public HandlerThread(String name){super(name);}public Object getLooper(){return this;}public boolean quitSafely(){done=true;interrupt();return true;}public void run(){while(!done){try{Thread.sleep(100);}catch(InterruptedException e){}}}}''',
"org/json/JSONObject.java": '''package org.json;import java.util.*;public class JSONObject {public static final Object NULL=new Object();private final Map<String,Object> values=new HashMap<>();public JSONObject put(String key,Object value){values.put(key,value);return this;}public Object get(String key){return values.get(key);}public String getString(String key){return (String)get(key);}public long getLong(String key){return ((Number)get(key)).longValue();}}''',
"org/googlebook/port/hardwareprobe/BluetoothSelfTest.java": '''package org.googlebook.port.hardwareprobe;
import android.content.*;import android.os.*;import org.json.*;
public class BluetoothSelfTest {
 static void check(boolean value){if(!value)throw new AssertionError("Bluetooth lifecycle fixture");}
 static boolean yes(JSONObject value,String key){return Boolean.TRUE.equals(value.get(key));}
 static void unknown(JSONObject value,String reason){check(value.getString("status").equals("unavailable"));check(value.getString("reason").equals(reason));check(!yes(value,"functionality_verified"));check(!yes(value,"radio_transition_verified"));}
 static void stopped(JSONObject value){check(yes(value,"callback_thread_stopped"));}
 public static void main(String[]args)throws Exception {
  Context c=new Context();JSONObject r=BluetoothProbe.run(c);
  check(r.getString("status").equals("observed"));check(c.registered==1&&c.removed==1);stopped(r);
  check(r.getLong("callback_count")==0&&r.getLong("window_elapsed_ms")>=2000);
  check(!yes(r,"functionality_verified")&&!yes(r,"radio_transition_verified"));
  c=new Context();c.permission=-1;r=BluetoothProbe.run(c);unknown(r,"permission_denied");check(c.manager.adapter.calls==0&&c.registered==0);stopped(r);
  c=new Context();c.manager=null;r=BluetoothProbe.run(c);unknown(r,"manager_unavailable");stopped(r);
  c=new Context();c.manager.adapter=null;r=BluetoothProbe.run(c);unknown(r,"adapter_unavailable");check(Boolean.FALSE.equals(r.get("adapter_present")));stopped(r);
  c=new Context();c.manager.adapter.before=999;r=BluetoothProbe.run(c);unknown(r,"invalid_state");check(r.get("state_before")==JSONObject.NULL&&c.registered==0);stopped(r);
  c=new Context();c.failRegister=true;r=BluetoothProbe.run(c);unknown(r,"api_exception");check(c.registered==0&&c.removed==1&&yes(r,"receiver_cleanup_attempted")&&!yes(r,"receiver_removed"));stopped(r);
  c=new Context();c.manager.adapter.failAfter=true;r=BluetoothProbe.run(c);unknown(r,"api_exception");check(c.removed==1&&yes(r,"receiver_removed"));stopped(r);
  c=new Context();c.failRemove=true;r=BluetoothProbe.run(c);unknown(r,"cleanup_incomplete");check(c.removed==1&&!yes(r,"receiver_removed"));stopped(r);
  c=new Context();c.callbacks=1;c.invalidCallback=true;r=BluetoothProbe.run(c);unknown(r,"invalid_state");check(r.getLong("callback_count")==1&&yes(r,"invalid_state_callback")&&c.removed==1);stopped(r);
  c=new Context();c.callbacks=33;r=BluetoothProbe.run(c);unknown(r,"callback_budget_exceeded");check(r.getLong("callback_count")==32&&yes(r,"callback_budget_exceeded")&&c.removed==1);stopped(r);
  c=new Context();Thread.currentThread().interrupt();r=BluetoothProbe.run(c);unknown(r,"interrupted");check(c.removed==1&&Thread.interrupted());stopped(r);
  for(Thread t:Thread.getAllStackTraces().keySet())check(!t.isAlive()||!t.getName().equals("gb-owned-bluetooth-status"));
  System.out.println("PASS:11 owned Bluetooth lifecycle cases;permission/absence/enums/register/read/remove/interruption/callback budget;no Android or RF proof");
 }
}''',
}
with tempfile.TemporaryDirectory(prefix="gb-bluetooth-host-") as temporary:
    base = Path(temporary)
    paths = []
    for relative, text in SOURCES.items():
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        paths.append(str(path))
    paths.append(str(ROOT / "crates/gb-framework/src/hardware_probe/BluetoothProbe.java"))
    env = {key: value for key, value in os.environ.items() if key not in
           ("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")}
    subprocess.run([tools["javac"]["path"], "-d", str(base), *paths], env=env,
                   check=True, timeout=30)
    subprocess.run([tools["java"]["path"], "-cp", str(base),
                    "org.googlebook.port.hardwareprobe.BluetoothSelfTest"], env=env,
                   check=True, timeout=30)
