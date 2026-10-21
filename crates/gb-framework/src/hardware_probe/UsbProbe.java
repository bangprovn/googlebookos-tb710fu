// SPDX-License-Identifier: Apache-2.0
package org.googlebook.port.hardwareprobe;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.usb.UsbConfiguration;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Anonymous API snapshot only; never open devices, request permission or transfer.
 * Public contracts: https://developer.android.com/reference/android/hardware/usb/UsbManager
 * and UsbDevice/UsbConfiguration/UsbInterface. Device-list keys are never inspected.
 */
final class UsbProbe {
    private static final int MAX_DEVICES=32, MAX_CONFIGURATIONS=128, MAX_INTERFACES=512;

    private static JSONObject base(Object feature) throws Exception {
        return new JSONObject().put("status","unavailable").put("state","unknown")
            .put("scope","public_api_inventory_only").put("host_feature_declared",feature)
            .put("reason","api_exception").put("inventory_complete",false)
            .put("attached_device_count",JSONObject.NULL)
            .put("configuration_descriptor_count",JSONObject.NULL)
            .put("interface_descriptor_count",JSONObject.NULL)
            .put("device_class_counts",new JSONArray()).put("interface_class_counts",new JSONArray())
            .put("observation_budget_exceeded",false).put("read_only",true)
            .put("permission_requested",false).put("device_opened",false)
            .put("transfer_performed",false).put("role_or_settings_changed",false)
            .put("identifiers_collected",false).put("content_collected",false)
            .put("host_functionality_verified",false).put("typec_or_pd_verified",false);
    }
    private static JSONArray histogram(int[] counts) throws Exception {
        JSONArray result=new JSONArray();
        for(int code=0;code<256;code++) if(counts[code]>0)
            result.put(new JSONObject().put("usb_class",code).put("count",counts[code]));
        return result;
    }
    private static JSONObject failed(Object feature,String reason) throws Exception {
        return base(feature).put("reason",reason)
            .put("observation_budget_exceeded",reason.equals("budget_exceeded"));
    }
    static JSONObject run(Context context) throws Exception {
        Object feature=JSONObject.NULL;
        try {
            PackageManager manager=context.getPackageManager();
            if(manager!=null) feature=manager.hasSystemFeature(PackageManager.FEATURE_USB_HOST);
        } catch(RuntimeException unavailable) { /* Preserve unknown declaration. */ }
        try {
            UsbManager manager=(UsbManager)context.getSystemService(Context.USB_SERVICE);
            if(manager==null) return failed(feature,"usb_manager_unavailable");
            // Android returns its descriptor snapshot; do not inspect map keys,
            // peripheral identifiers, endpoint addresses or raw descriptor/payload bytes.
            Map<String,UsbDevice> devices=manager.getDeviceList();
            if(devices==null) return failed(feature,"api_exception");
            int count=devices.size();
            if(count<0 || count>MAX_DEVICES) return failed(feature,"budget_exceeded");
            int[] deviceClasses=new int[256], interfaceClasses=new int[256];
            int observed=0, configurations=0, interfaces=0;
            for(UsbDevice device:devices.values()) {
                if(++observed>MAX_DEVICES) return failed(feature,"budget_exceeded");
                if(device==null) return failed(feature,"invalid_descriptor");
                int code=device.getDeviceClass(), configs=device.getConfigurationCount();
                if(code<0 || code>255 || configs<0) return failed(feature,"invalid_descriptor");
                if(configs>MAX_CONFIGURATIONS-configurations) return failed(feature,"budget_exceeded");
                deviceClasses[code]++;configurations+=configs;
                for(int c=0;c<configs;c++) {
                    UsbConfiguration config=device.getConfiguration(c);
                    if(config==null) return failed(feature,"invalid_descriptor");
                    int entries=config.getInterfaceCount();
                    if(entries<0) return failed(feature,"invalid_descriptor");
                    if(entries>MAX_INTERFACES-interfaces) return failed(feature,"budget_exceeded");
                    interfaces+=entries;
                    for(int i=0;i<entries;i++) {
                        UsbInterface entry=config.getInterface(i);
                        if(entry==null) return failed(feature,"invalid_descriptor");
                        int interfaceClass=entry.getInterfaceClass();
                        if(interfaceClass<0 || interfaceClass>255) return failed(feature,"invalid_descriptor");
                        interfaceClasses[interfaceClass]++;
                    }
                }
            }
            if(observed!=count) return failed(feature,"api_exception");
            // Configurations include alternate interfaces; these aggregate
            // descriptor counts never claim active interface/host/Type-C/PD use.
            return base(feature).put("status","observed").put("reason","snapshot_complete")
                .put("inventory_complete",true).put("attached_device_count",count)
                .put("configuration_descriptor_count",configurations)
                .put("interface_descriptor_count",interfaces)
                .put("device_class_counts",histogram(deviceClasses))
                .put("interface_class_counts",histogram(interfaceClasses));
        } catch(RuntimeException unavailable) { return failed(feature,"api_exception"); }
    }
}
