#!/usr/bin/env python3
"""Host-only passive BLE lifecycle faults with owned Android stubs, never ADB.

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
"android/Manifest.java": '''package android;public class Manifest {public static class permission {public static final String BLUETOOTH_CONNECT="connect",BLUETOOTH_SCAN="scan";}}''',
"android/content/pm/PackageManager.java": '''package android.content.pm;public class PackageManager {public static final int PERMISSION_GRANTED=0;public static final String FEATURE_BLUETOOTH_LE="ble";public boolean hasSystemFeature(String x){return true;}}''',
"android/os/SystemClock.java": '''package android.os;public class SystemClock {public static long offset;public static long elapsedRealtime(){return System.nanoTime()/1000000+offset;}}''',
"android/content/Context.java": '''package android.content;import android.bluetooth.*;import android.content.pm.*;
public class Context {public static final String BLUETOOTH_SERVICE="bluetooth";public int connect,scan;public BluetoothManager manager=new BluetoothManager();
public PackageManager getPackageManager(){return new PackageManager();}public Object getSystemService(String n){return manager;}
public int checkSelfPermission(String n){if(n.equals("connect"))return connect;if(n.equals("scan"))return scan;throw new AssertionError();}}''',
"android/bluetooth/BluetoothManager.java": '''package android.bluetooth;public class BluetoothManager {public BluetoothAdapter adapter=new BluetoothAdapter();public BluetoothAdapter getAdapter(){return adapter;}}''',
"android/bluetooth/BluetoothAdapter.java": '''package android.bluetooth;import android.bluetooth.le.*;public class BluetoothAdapter {public static final int STATE_ON=12;public int before=12,after=12,calls;public boolean failAfter;public BluetoothLeScanner scanner=new BluetoothLeScanner();public int getState(){if(calls++==0)return before;if(failAfter)throw new IllegalStateException();return after;}public BluetoothLeScanner getBluetoothLeScanner(){return scanner;}}''',
"android/bluetooth/le/ScanSettings.java": '''package android.bluetooth.le;public class ScanSettings {public static final int SCAN_MODE_LOW_POWER=0,CALLBACK_TYPE_ALL_MATCHES=1,SCAN_TYPE_PASSIVE=1;public static boolean failApi,wrongReadback;private int type;
public int getScanType(){return wrongReadback?2:type;}
public static class Builder {private int type;public Builder setScanMode(int v){if(v!=0)throw new AssertionError();return this;}public Builder setCallbackType(int v){if(v!=1)throw new AssertionError();return this;}public Builder setReportDelay(long v){if(v!=0)throw new AssertionError();return this;}public Builder setScanType(int v){if(failApi)throw new IllegalStateException();if(v!=1)throw new AssertionError();type=v;return this;}public ScanSettings build(){ScanSettings s=new ScanSettings();s.type=type;return s;}}}''',
"android/bluetooth/le/ScanResult.java": '''package android.bluetooth.le;public class ScanResult {public Object getDevice(){throw new AssertionError("peer inspected");}public Object getScanRecord(){throw new AssertionError("payload inspected");}public int getRssi(){throw new AssertionError("RSSI inspected");}public String toString(){throw new AssertionError("result exported");}}''',
"android/bluetooth/le/ScanCallback.java": '''package android.bluetooth.le;import java.util.*;public abstract class ScanCallback {public void onScanResult(int t,ScanResult r){}public void onBatchScanResults(List<ScanResult> r){}public void onScanFailed(int e){}}''',
"android/bluetooth/le/BluetoothLeScanner.java": '''package android.bluetooth.le;import java.util.*;
public class BluetoothLeScanner {public int starts,stops,results,failCode;public boolean failStart,failStop,batch,lateFailure,lateResult,overrun;public ScanCallback retained;
public void startScan(Object filters,ScanSettings settings,ScanCallback callback){starts++;retained=callback;if(filters!=null||settings.getScanType()!=1)throw new AssertionError();if(failStart)throw new IllegalStateException();for(int i=0;i<results;i++)callback.onScanResult(1,new ScanResult());if(batch)callback.onBatchScanResults(new AbstractList<ScanResult>(){public int size(){throw new AssertionError("batch inspected");}public ScanResult get(int i){throw new AssertionError("batch inspected");}});if(failCode!=0)callback.onScanFailed(failCode);if(overrun)android.os.SystemClock.offset+=7000;}
public void stopScan(ScanCallback callback){stops++;if(callback!=retained)throw new AssertionError();if(lateFailure)callback.onScanFailed(3);if(lateResult)callback.onScanResult(1,new ScanResult());if(failStop)throw new IllegalStateException();}}''',
"org/json/JSONObject.java": '''package org.json;import java.util.*;public class JSONObject {public static final Object NULL=new Object();private final Map<String,Object> values=new HashMap<>();public JSONObject put(String key,Object value){values.put(key,value);return this;}public Object get(String key){return values.get(key);}public String getString(String key){return (String)get(key);}public long getLong(String key){return ((Number)get(key)).longValue();}}''',
"org/googlebook/port/hardwareprobe/BleSelfTest.java": '''package org.googlebook.port.hardwareprobe;import android.content.*;import android.bluetooth.le.*;import org.json.*;
public class BleSelfTest {
static void check(boolean x){if(!x)throw new AssertionError("BLE owned lifecycle fixture");}
static boolean yes(JSONObject r,String k){return Boolean.TRUE.equals(r.get(k));}
static void scope(JSONObject r){for(String k:new String[]{"identifiers_collected","payloads_inspected","rssi_collected","batch_entries_inspected","rf_verified","peer_verified","phone_link_verified"})check(!yes(r,k));check(yes(r,"callback_gate_closed"));}
static void unknown(JSONObject r,String reason){check(r.getString("status").equals("unavailable"));check(r.getString("reason").equals(reason));scope(r);}
static void stopped(Context c,JSONObject r){check(c.manager.adapter.scanner.stops==1&&yes(r,"scan_stop_attempted"));}
public static void main(String[] a)throws Exception{
 Context c=new Context();JSONObject r=BluetoothLeScanProbe.run(c);check(r.getString("status").equals("observed"));check(r.getLong("result_callback_count")==0);stopped(c,r);scope(r);
 // Late callbacks after the closed gate may not mutate an emitted observation.
 c.manager.adapter.scanner.retained.onScanFailed(3);check(r.getLong("failure_callback_count")==0&&r.get("scan_failure")==JSONObject.NULL);
 c=new Context();c.manager.adapter.scanner.results=1;c.manager.adapter.scanner.batch=true;r=BluetoothLeScanProbe.run(c);check(r.getString("status").equals("observed")&&r.getLong("result_callback_count")==1&&r.getLong("batch_callback_count")==1);scope(r);
 c=new Context();c.scan=-1;r=BluetoothLeScanProbe.run(c);unknown(r,"permission_denied");check(c.manager.adapter.calls==0&&c.manager.adapter.scanner.starts==0);
 c=new Context();c.manager=null;r=BluetoothLeScanProbe.run(c);unknown(r,"manager_unavailable");
 c=new Context();c.manager.adapter=null;r=BluetoothLeScanProbe.run(c);unknown(r,"adapter_unavailable");
 c=new Context();c.manager.adapter.before=10;r=BluetoothLeScanProbe.run(c);unknown(r,"adapter_not_on");check(c.manager.adapter.scanner.starts==0);
 c=new Context();c.manager.adapter.before=99;r=BluetoothLeScanProbe.run(c);unknown(r,"invalid_state");
 c=new Context();c.manager.adapter.scanner=null;r=BluetoothLeScanProbe.run(c);unknown(r,"scanner_unavailable");
 c=new Context();ScanSettings.failApi=true;r=BluetoothLeScanProbe.run(c);unknown(r,"passive_api_unavailable");check(c.manager.adapter.scanner.starts==0);ScanSettings.failApi=false;
 c=new Context();ScanSettings.wrongReadback=true;r=BluetoothLeScanProbe.run(c);unknown(r,"passive_api_unavailable");check(c.manager.adapter.scanner.starts==0);ScanSettings.wrongReadback=false;
 c=new Context();c.manager.adapter.scanner.failStart=true;r=BluetoothLeScanProbe.run(c);unknown(r,"api_exception");stopped(c,r);check(!yes(r,"scan_start_returned")&&yes(r,"scan_stop_returned"));
 c=new Context();c.manager.adapter.scanner.failCode=6;r=BluetoothLeScanProbe.run(c);unknown(r,"scan_failed");check(r.get("scan_failure").equals("scanning_too_frequently"));stopped(c,r);
 c=new Context();c.manager.adapter.scanner.failCode=99;r=BluetoothLeScanProbe.run(c);unknown(r,"invalid_failure_code");check(yes(r,"invalid_failure_code"));stopped(c,r);
 c=new Context();c.manager.adapter.scanner.results=1025;r=BluetoothLeScanProbe.run(c);unknown(r,"callback_budget_exceeded");check(r.getLong("result_callback_count")==1024);stopped(c,r);
 c=new Context();c.manager.adapter.scanner.lateFailure=true;r=BluetoothLeScanProbe.run(c);unknown(r,"scan_failed");check(r.getLong("late_failure_count")==1);stopped(c,r);
 c=new Context();c.manager.adapter.scanner.failStop=true;r=BluetoothLeScanProbe.run(c);unknown(r,"cleanup_incomplete");check(!yes(r,"scan_stop_returned"));stopped(c,r);
 c=new Context();c.manager.adapter.scanner.overrun=true;r=BluetoothLeScanProbe.run(c);unknown(r,"window_mismatch");android.os.SystemClock.offset=0;stopped(c,r);
 c=new Context();Thread.currentThread().interrupt();r=BluetoothLeScanProbe.run(c);unknown(r,"interrupted");check(Thread.interrupted());stopped(c,r);
 System.out.println("PASS:18 owned BLE lifecycle cases; no Android binder/RF proof");
}}
''',
}
with tempfile.TemporaryDirectory(prefix="gb-ble-host-") as temporary:
    base = Path(temporary)
    paths = []
    for relative, text in SOURCES.items():
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        paths.append(str(path))
    paths.append(str(ROOT / "crates/gb-framework/src/hardware_probe/BluetoothLeScanProbe.java"))
    env = {key: value for key, value in os.environ.items() if key not in
           ("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")}
    subprocess.run([tools["javac"]["path"], "-d", str(base), *paths], env=env, check=True, timeout=30)
    subprocess.run([tools["java"]["path"], "-cp", str(base), "org.googlebook.port.hardwareprobe.BleSelfTest"],
                   env=env, check=True, timeout=60)
    # An older public runtime API must refuse before start, never use ACTIVE.
    settings = base / "android/bluetooth/le/ScanSettings.java"
    settings.write_text(settings.read_text().replace(
        "SCAN_MODE_LOW_POWER=0,CALLBACK_TYPE_ALL_MATCHES=1,SCAN_TYPE_PASSIVE=1",
        "SCAN_MODE_LOW_POWER=0,CALLBACK_TYPE_ALL_MATCHES=1"))
    missing = base / "org/googlebook/port/hardwareprobe/BleMissingApiTest.java"
    missing.write_text('''package org.googlebook.port.hardwareprobe;import android.content.*;import org.json.*;
public class BleMissingApiTest {public static void main(String[] a)throws Exception {Context c=new Context();JSONObject r=BluetoothLeScanProbe.run(c);if(!r.getString("status").equals("unavailable")||!r.getString("reason").equals("passive_api_unavailable")||c.manager.adapter.scanner.starts!=0||c.manager.adapter.scanner.stops!=0)throw new AssertionError();System.out.println("PASS:missing public passive API refuses without scan fallback");}}''')
    subprocess.run([tools["javac"]["path"], "-cp", str(base), "-d", str(base), str(settings), str(missing)],
                   env=env, check=True, timeout=30)
    subprocess.run([tools["java"]["path"], "-cp", str(base), "org.googlebook.port.hardwareprobe.BleMissingApiTest"],
                   env=env, check=True, timeout=10)
