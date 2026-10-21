#!/usr/bin/env python3
"""Compile/execute actual UsbProbe with bounded public-API fakes; no APK/ADB/USB.

The stubs are intentionally limited to aggregate descriptor APIs. Forbidden
identifier/open/permission methods throw, and names in map keys never leave it.
"""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/gb-framework/src/hardware_probe/UsbProbe.java"

STUBS = {
    "android/content/Context.java": r'''package android.content;
import android.content.pm.PackageManager;
public class Context {
 public static final String USB_SERVICE="usb";
 private final PackageManager pm;private final Object manager;
 public Context(PackageManager pm,Object manager){this.pm=pm;this.manager=manager;}
 public PackageManager getPackageManager(){return pm;}
 public Object getSystemService(String name){if(!USB_SERVICE.equals(name))throw new AssertionError();return manager;}
}''',
    "android/content/pm/PackageManager.java": r'''package android.content.pm;
public class PackageManager {
 public static final String FEATURE_USB_HOST="android.hardware.usb.host";
 public boolean declared=true,fail=false;
 public boolean hasSystemFeature(String feature){if(!FEATURE_USB_HOST.equals(feature))throw new AssertionError();if(fail)throw new SecurityException("secret");return declared;}
}''',
    "android/hardware/usb/UsbManager.java": r'''package android.hardware.usb;
import java.util.HashMap;
public class UsbManager {
 public HashMap<String,UsbDevice> devices=new HashMap<>();public boolean fail=false;
 public HashMap<String,UsbDevice> getDeviceList(){if(fail)throw new SecurityException("secret");return devices;}
 public Object openDevice(UsbDevice d){throw new AssertionError("open forbidden");}
 public void requestPermission(Object...args){throw new AssertionError("permission forbidden");}
}''',
    "android/hardware/usb/UsbDevice.java": r'''package android.hardware.usb;
public class UsbDevice {
 private final int code,count;private final UsbConfiguration[] configs;
 public UsbDevice(int code,UsbConfiguration...configs){this(code,configs.length,configs);}
 public UsbDevice(int code,int count,UsbConfiguration[] configs){this.code=code;this.count=count;this.configs=configs;}
 public int getDeviceClass(){return code;}public int getConfigurationCount(){return count;}
 public UsbConfiguration getConfiguration(int i){return configs[i];}
 public int getVendorId(){throw new AssertionError("identifier forbidden");}
 public int getProductId(){throw new AssertionError("identifier forbidden");}
 public String getSerialNumber(){throw new AssertionError("identifier forbidden");}
 public String getProductName(){throw new AssertionError("identifier forbidden");}
 public String getDeviceName(){throw new AssertionError("identifier forbidden");}
 public String toString(){throw new AssertionError("identifier forbidden");}
}''',
    "android/hardware/usb/UsbConfiguration.java": r'''package android.hardware.usb;
public class UsbConfiguration {
 private final int count;private final UsbInterface[] interfaces;
 public UsbConfiguration(UsbInterface...interfaces){this(interfaces.length,interfaces);}
 public UsbConfiguration(int count,UsbInterface[] interfaces){this.count=count;this.interfaces=interfaces;}
 public int getInterfaceCount(){return count;}public UsbInterface getInterface(int i){return interfaces[i];}
 public String getName(){throw new AssertionError("identifier forbidden");}
}''',
    "android/hardware/usb/UsbInterface.java": r'''package android.hardware.usb;
public class UsbInterface {
 private final int code;public UsbInterface(int code){this.code=code;}public int getInterfaceClass(){return code;}
 public int getId(){throw new AssertionError("address forbidden");}
 public int getEndpointCount(){throw new AssertionError("unrequested endpoint inventory");}
 public Object getEndpoint(int i){throw new AssertionError("address forbidden");}
 public String getName(){throw new AssertionError("identifier forbidden");}
}''',
    "org/json/JSONObject.java": r'''package org.json;
import java.util.LinkedHashMap;import java.util.Map;
public class JSONObject {
 public static final Object NULL=new Object();private final Map<String,Object> values=new LinkedHashMap<>();
 public JSONObject put(String key,Object value){values.put(key,value);return this;}
 static String encode(Object value){
  if(value==null||value==NULL)return "null";
  if(value instanceof String)return "\""+((String)value).replace("\\","\\\\").replace("\"","\\\"")+"\"";
  return value.toString();
 }
 public String toString(){StringBuilder s=new StringBuilder("{");for(Map.Entry<String,Object> e:values.entrySet()){if(s.length()>1)s.append(',');s.append(encode(e.getKey())).append(':').append(encode(e.getValue()));}return s.append('}').toString();}
}''',
    "org/json/JSONArray.java": r'''package org.json;
import java.util.ArrayList;import java.util.List;
public class JSONArray {
 private final List<Object> values=new ArrayList<>();public JSONArray put(Object value){values.add(value);return this;}
 public String toString(){StringBuilder s=new StringBuilder("[");for(Object value:values){if(s.length()>1)s.append(',');s.append(JSONObject.encode(value));}return s.append(']').toString();}
}''',
    "org/googlebook/port/hardwareprobe/UsbHostFixture.java": r'''package org.googlebook.port.hardwareprobe;
import android.content.Context;import android.content.pm.PackageManager;import android.hardware.usb.*;
public final class UsbHostFixture {
 static UsbConfiguration config(int...codes){UsbInterface[] entries=new UsbInterface[codes.length];for(int i=0;i<codes.length;i++)entries[i]=new UsbInterface(codes[i]);return new UsbConfiguration(entries);}
 public static void main(String[] args)throws Exception{
  PackageManager pm=new PackageManager();UsbManager manager=new UsbManager();Object service=manager;
  String mode=args[0];
  if(mode.equals("attached")){manager.devices.put("secret-usb-address-A",new UsbDevice(9,config(8,3),config(3)));manager.devices.put("secret-usb-address-B",new UsbDevice(0,config(8)));}
  else if(mode.equals("host_false"))pm.declared=false;
  else if(mode.equals("feature_exception"))pm.fail=true;
  else if(mode.equals("manager_missing"))service=null;
  else if(mode.equals("api_exception"))manager.fail=true;
  else if(mode.equals("devices_over")){for(int i=0;i<33;i++)manager.devices.put("secret"+i,new UsbDevice(0));}
  else if(mode.equals("configs_over"))manager.devices.put("secret",new UsbDevice(0,129,new UsbConfiguration[0]));
  else if(mode.equals("interfaces_over"))manager.devices.put("secret",new UsbDevice(0,new UsbConfiguration(513,new UsbInterface[0])));
  else if(mode.equals("class_invalid"))manager.devices.put("secret",new UsbDevice(256));
  else if(mode.equals("interface_invalid"))manager.devices.put("secret",new UsbDevice(0,config(-1)));
  else if(mode.equals("null_device"))manager.devices.put("secret",null);
  else if(mode.equals("null_config"))manager.devices.put("secret",new UsbDevice(0,new UsbConfiguration[]{null}));
  else if(mode.equals("null_interface"))manager.devices.put("secret",new UsbDevice(0,new UsbConfiguration(new UsbInterface[]{null})));
  else if(mode.equals("boundary")){
   UsbInterface[] entries=new UsbInterface[512];for(int i=0;i<entries.length;i++)entries[i]=new UsbInterface(i%256);
   manager.devices.put("secret",new UsbDevice(255,new UsbConfiguration(entries)));
  }
  else if(!mode.equals("empty"))throw new AssertionError("unknown fixture");
  System.out.println(UsbProbe.run(new Context(pm,service)));
 }
}''',
}

class UsbPublicApiFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="gb-usb-public-api-")
        cls.path = Path(cls.work.name)
        for name, text in STUBS.items():
            path = cls.path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        destination = cls.path / "org/googlebook/port/hardwareprobe/UsbProbe.java"
        destination.write_bytes(SOURCE.read_bytes())
        javac = shutil.which("javac")
        cls.java = shutil.which("java")
        if not javac or not cls.java:
            raise RuntimeError("host JDK required; no Android APK build is performed")
        subprocess.run([javac, "-Xlint:all", "-Werror", "-d", str(cls.path / "classes"),
                        *map(str, cls.path.rglob("*.java"))], check=True, capture_output=True, text=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def observe(self, mode):
        result = subprocess.run([self.java, "-cp", str(self.path / "classes"),
                                 "org.googlebook.port.hardwareprobe.UsbHostFixture", mode],
                                check=True, capture_output=True, text=True, timeout=5)
        self.assertLess(len(result.stdout), 16384)
        self.assertNotIn("secret", result.stdout)
        self.assertEqual(result.stderr, "")
        value = json.loads(result.stdout)
        self.assertEqual(value["state"], "unknown")
        self.assertEqual(value["scope"], "public_api_inventory_only")
        self.assertTrue(value["read_only"])
        for key in ["permission_requested", "device_opened", "transfer_performed", "role_or_settings_changed",
                    "identifiers_collected", "content_collected", "host_functionality_verified", "typec_or_pd_verified"]:
            self.assertFalse(value[key], key)
        return value

    def test_empty_and_feature_declaration_are_not_functional_qualification(self):
        for mode, expected in [("empty", True), ("host_false", False), ("feature_exception", None)]:
            value = self.observe(mode)
            self.assertEqual(value["status"], "observed")
            self.assertEqual(value["host_feature_declared"], expected)
            self.assertEqual(value["attached_device_count"], 0)
            self.assertEqual(value["device_class_counts"], [])
            self.assertEqual(value["interface_class_counts"], [])

    def test_multiple_configurations_aggregate_only_class_counts(self):
        value = self.observe("attached")
        self.assertEqual(value["attached_device_count"], 2)
        self.assertEqual(value["configuration_descriptor_count"], 3)
        self.assertEqual(value["interface_descriptor_count"], 4)
        self.assertEqual(value["device_class_counts"], [{"usb_class": 0, "count": 1}, {"usb_class": 9, "count": 1}])
        self.assertEqual(value["interface_class_counts"], [{"usb_class": 3, "count": 2}, {"usb_class": 8, "count": 2}])
        boundary = self.observe("boundary")
        self.assertEqual(boundary["interface_descriptor_count"], 512)
        self.assertEqual(len(boundary["interface_class_counts"]), 256)
        self.assertTrue(all(row["count"] == 2 for row in boundary["interface_class_counts"]))

    def test_unavailable_invalid_and_over_budget_discard_partial_metadata(self):
        for mode, reason in [("manager_missing", "usb_manager_unavailable"), ("api_exception", "api_exception"),
                             ("devices_over", "budget_exceeded"), ("configs_over", "budget_exceeded"),
                             ("interfaces_over", "budget_exceeded"), ("class_invalid", "invalid_descriptor"),
                             ("interface_invalid", "invalid_descriptor"), ("null_device", "invalid_descriptor"),
                             ("null_config", "invalid_descriptor"), ("null_interface", "invalid_descriptor")]:
            value = self.observe(mode)
            self.assertEqual(value["status"], "unavailable", mode)
            self.assertEqual(value["reason"], reason, mode)
            self.assertEqual(value["observation_budget_exceeded"], reason == "budget_exceeded", mode)
            self.assertFalse(value["inventory_complete"])
            for key in ["attached_device_count", "configuration_descriptor_count", "interface_descriptor_count"]:
                self.assertIsNone(value[key])
            self.assertEqual(value["device_class_counts"], [])
            self.assertEqual(value["interface_class_counts"], [])

    def test_source_uses_only_selected_inventory_and_no_identifier_or_io_api(self):
        source = SOURCE.read_text()
        for forbidden in ["getVendorId(", "getProductId(", "getSerialNumber(", "getProductName(", "getDeviceName(",
                          "getManufacturerName(", "getId(", "getName(", "getEndpoint(", "openDevice(", "requestPermission(",
                          "controlTransfer(", "bulkTransfer(", "keySet(", "entrySet(", "toString("]:
            self.assertNotIn(forbidden, source)
        activity = (SOURCE.parent / "HardwareProbeActivity.java").read_text()
        self.assertIn('suite.equals("usb_inventory") ? UsbProbe.run', activity)
        self.assertNotIn('suite.equals("all") || suite.equals("usb_inventory")', activity)

if __name__ == "__main__":
    unittest.main(verbosity=2)
