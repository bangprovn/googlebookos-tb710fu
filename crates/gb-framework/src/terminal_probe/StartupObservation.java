package org.googlebook.port.terminalprobe;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import java.io.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;

/** Runs only the original app and its existing owner-staged profile, then reads
 * its public state flow. No heap dump, field mutation, payload receiver or APK patch. */
final class StartupObservation {
    static String describe(Throwable error) {
        StringBuilder text=new StringBuilder();
        Set<Throwable> seen=Collections.newSetFromMap(new IdentityHashMap<Throwable,Boolean>());
        for(int depth=0;error!=null && depth<8 && seen.add(error);depth++,error=error.getCause()) {
            String message=String.valueOf(error.getMessage()).replace('\n',' ').replace('\r',' ');
            text.append(error.getClass().getName()).append(": ")
                .append(message.substring(0,Math.min(1800,message.length()))).append('\n');
            StackTraceElement[] frames=error.getStackTrace();
            for(int i=0;i<Math.min(10,frames.length);i++)text.append(" at ").append(frames[i]).append('\n');
        }
        return text.substring(0,Math.min(24000,text.length()));
    }
    private static JSONObject readConfig(File config) throws Exception {
        Path path=config.toPath();
        if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS) || Files.size(path)>65536)
            throw new IOException("existing owner profile required");
        byte[] bytes;
        try(InputStream in=Files.newInputStream(path,LinkOption.NOFOLLOW_LINKS)) {
            ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] block=new byte[4096];int n;
            while((n=in.read(block))!=-1) {if(out.size()+n>65536)throw new IOException("config bound");out.write(block,0,n);}
            bytes=out.toByteArray();
        }
        return new JSONObject(new String(bytes,"UTF-8"));
    }
    static Map<String,String> observe(Instrumentation probe,Context target,String id,int memory,JSONObject immutableManifest) throws Exception {
        File config=new File(new File(new File(target.getFilesDir(),"gb-port"),id),"vm_config.json");
        JSONObject json=readConfig(config);
        if(!json.getBoolean("protected") || json.getInt("memory_mib")!=memory
                || !json.getString("name").equals("gb-"+id))throw new SecurityException("owner profile differs");
        if(immutableManifest!=null)config=ImmutableBootConfig.prepare(config,json,immutableManifest);
        Intent intent=new Intent(Intent.ACTION_MAIN).setClassName(target.getPackageName(),
            "com.android.virtualization.terminal.new2.ui.MainActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra("com.android.virtualization.terminal.EXTRA_CONFIG_PATH",config.getAbsolutePath());
        Map<String,String> result=new LinkedHashMap<>();
        result.put("startup_config_path",config.getAbsolutePath());
        result.put("immutable_boot_files",Boolean.toString(immutableManifest!=null));
        return launch(probe,target,intent,result);
    }
    static Map<String,String> observeDefault(Instrumentation probe,Context target,int memory) throws Exception {
        File config=new File(new File(target.getFilesDir(),"linux"),"vm_config.json");
        JSONObject json=readConfig(config);
        if(json.optBoolean("protected",true))throw new SecurityException("default config must declare a normal unprotected VM");
        int configured=target.getSharedPreferences("terminal_settings",Context.MODE_PRIVATE).getInt("memory_mib",0);
        if(configured!=memory || configured<64 || configured>2048)
            throw new SecurityException("default app memory preference differs from requested cap");
        Map<String,String> result=new LinkedHashMap<>();
        result.put("default_app_launch","true");
        result.put("configured_memory_mib",Integer.toString(configured));
        result.put("default_config_protected","false");
        result.put("default_install_marker_present",Boolean.toString(new File(config.getParentFile(),"completed").isFile()));
        Intent intent=new Intent(Intent.ACTION_MAIN).setClassName(target.getPackageName(),
            "com.android.virtualization.terminal.new2.ui.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        return launch(probe,target,intent,result);
    }
    private static Map<String,String> launch(Instrumentation probe,Context target,Intent intent,Map<String,String> result) throws Exception {
        result.putAll(RuntimeInspection.collect());
        probe.startActivitySync(intent);
        ClassLoader loader=target.getClassLoader();
        Class<?> controller=Class.forName("com.android.virtualization.terminal.new2.core.VmController",true,loader);
        Object instance=controller.getField("INSTANCE").get(null);
        Object flow=controller.getMethod("getVmState").invoke(instance);
        Method value=Class.forName("kotlinx.coroutines.flow.StateFlow",true,loader).getMethod("getValue");
        long deadline=System.nanoTime()+30_000_000_000L;
        long runningSince=0;
        while(System.nanoTime()<deadline) {
            Object state=value.invoke(flow);String name=state.getClass().getName();
            result.put("observed_state_class",name);
            // Running is published before crosvm finishes building the VM.
            // Reject a short-lived transition as evidence of sustained startup.
            if(!name.endsWith("$Running"))runningSince=0;
            if(name.endsWith("$Error")) {
                // This donor obfuscates the Kotlin getter. Read exactly one
                // non-static Throwable field; never enumerate unrelated objects.
                Field causeField=null;
                Field[] fields=state.getClass().getDeclaredFields();
                if(fields.length>32)throw new IOException("state field bound");
                for(Field field:fields) {
                    if(!Modifier.isStatic(field.getModifiers()) && Throwable.class.isAssignableFrom(field.getType())) {
                        if(causeField!=null)throw new IOException("ambiguous error cause");
                        causeField=field;
                    }
                }
                if(causeField==null)throw new IOException("error state missing Throwable field");
                causeField.setAccessible(true);
                Object cause=causeField.get(state);
                if(!(cause instanceof Throwable))throw new IOException("error state missing Throwable");
                result.put("startup_exception_chain",describe((Throwable)cause));
                result.put("observation","startup_error_observed");return result;
            }
            if(name.endsWith("$Running")) {
                long now=System.nanoTime();
                if(runningSince==0)runningSince=now;
                long elapsed=(now-runningSince)/1_000_000L;
                result.put("continuous_running_ms",Long.toString(elapsed));
                if(elapsed>=10000) {
                    result.put("observation","sustained_running_state_not_guest_qualification");return result;
                }
            }
            Thread.sleep(200);
        }
        result.put("observation","startup_state_deadline");return result;
    }
}
