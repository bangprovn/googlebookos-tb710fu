package org.googlebook.port.terminalprobe;

import android.app.Instrumentation;
import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Owner development instrumentation; runs with Terminal's own UID, never root. */
public final class TerminalProbe extends Instrumentation {
    private static final String TARGET = "com.android.virtualization.terminal";
    @Override public void callApplicationOnCreate(Application app) {
        // This isolated instrumentation only inspects or stages files. Running
        // Terminal's initializer here races onStart and writes CE certificates
        // even while locked. A normal, non-instrumented launch is unchanged.
    }
    private static final class DeadlineInput extends FilterInputStream {
        private final Socket socket; private final long deadline;
        DeadlineInput(Socket socket, long deadline) throws IOException {
            super(socket.getInputStream()); this.socket=socket; this.deadline=deadline;
        }
        private void limit() throws IOException {
            long left=(deadline-System.nanoTime())/1000000L;
            if(left<=0)throw new SocketTimeoutException("total transfer deadline");
            socket.setSoTimeout((int)Math.min(30000L,Math.max(1L,left)));
        }
        @Override public int read() throws IOException {limit();return in.read();}
        @Override public int read(byte[] b,int off,int len) throws IOException {limit();return in.read(b,off,len);}
    }
    @Override public void onCreate(Bundle args) { super.onCreate(args); start(); }
    private static byte[] bounded(InputStream in, int limit) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); byte[] b = new byte[8192]; int n;
        while ((n = in.read(b)) >= 0) {
            if (out.size() + n > limit) throw new IOException("metadata limit");
            out.write(b, 0, n);
        }
        return out.toByteArray();
    }
    private static void write(File file, byte[] bytes) throws Exception {
        try (FileChannel channel = FileChannel.open(file.toPath(), StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            Channels.newOutputStream(channel).write(bytes); channel.force(true);
        }
    }
    private void status(String text) {
        Bundle b = new Bundle(); b.putString("stage", text); sendStatus(1, b);
    }
    @SuppressWarnings("deprecation")
    @Override public void onStart() {
        Bundle result = new Bundle(); result.putString("status", "failed");
        try {
            Context target = getTargetContext();
            JSONObject manifest;
            try (InputStream in = getContext().getAssets().open("payload-manifest.json")) {
                manifest = new JSONObject(new String(bounded(in, 65536), "UTF-8"));
            }
            int uid = android.os.Process.myUid();
            int user = manifest.getInt("android_user");
            String id = manifest.getString("id");
            if (!TARGET.equals(target.getPackageName()) || uid / 100000 != user
                    || !id.matches("[a-z0-9-]{1,64}")
                    || !Build.FINGERPRINT.equals(manifest.getString("donor_fingerprint")))
                throw new SecurityException("target identity differs");
            result.putInt("target_uid",uid);
            String action = manifest.optString("action", "stage_guest");
            if (action.equals("inspect_runtime") || action.equals("inspect_console")) {
                // This branch never calls getFilesDir, opens a receiver, or runs a VM,
                // including if the owner unlocks concurrently with the observation.
                result.putBoolean("runtime_inspection_only", action.equals("inspect_runtime"));
                result.putBoolean("user_unlocked", target.getSystemService(android.os.UserManager.class).isUserUnlocked());
                for (Map.Entry<String,String> entry : RuntimeInspection.collect().entrySet())
                    result.putString(entry.getKey(), entry.getValue());
                if (action.equals("inspect_console")) {
                    for (Map.Entry<String,String> entry : ConsoleInspection.collect().entrySet())
                        result.putString(entry.getKey(), entry.getValue());
                    result.putString("status", "console_inspected");
                    result.putBoolean("terminal_working_verified", false);
                    finish(-1,result); return;
                }
                result.putString("status", "runtime_inspected");
                finish(-1,result); return;
            }
            if (!action.equals("stage_guest") && !action.equals("observe_startup")
                    && !action.equals("observe_immutable_startup") && !action.equals("observe_default_startup")
                    && !action.equals("restore_default_console")) throw new IllegalArgumentException("unknown probe action");
            if (!target.getSystemService(android.os.UserManager.class).isUserUnlocked()) {
                result.putString("status","user_unlock_required");
                result.putString("error","Unlock the selected Android user on the device before staging.");
                finish(0,result); return;
            }
            if (action.equals("restore_default_console")) {
                // Undo only the fixed raw-console preference written by StageGuest.
                // No application initializer, certificates, guest payloads or VM launch.
                int expectedMemory=manifest.getInt("memory_mib");
                SharedPreferences prefs=target.getSharedPreferences("terminal_settings",Context.MODE_PRIVATE);
                int configured=prefs.getInt("memory_mib",0);
                String before=prefs.getString("console_type","ttyd");
                if(configured!=expectedMemory || configured<64 || configured>2048
                        || !(before.equals("virtio_console") || before.equals("ttyd")))
                    throw new SecurityException("unexpected memory or console preference");
                File linux=new File(target.getFilesDir(),"linux");
                JSONObject config;
                try(InputStream in=new FileInputStream(new File(linux,"vm_config.json"))) {
                    config=new JSONObject(new String(bounded(in,65536),"UTF-8"));
                }
                if(config.optBoolean("protected",true) || !new File(linux,"completed").isFile())
                    throw new SecurityException("normal installed guest prerequisite differs");
                if(!before.equals("ttyd") && !prefs.edit().putString("console_type","ttyd").commit())
                    throw new IOException("console preference commit failed");
                if(!prefs.getString("console_type","").equals("ttyd"))
                    throw new IOException("console preference readback failed");
                result.putString("status","default_console_restored");
                result.putString("previous_console_type",before);
                result.putString("console_type","ttyd");
                result.putInt("memory_mib",configured);
                result.putBoolean("preferences_modified",!before.equals("ttyd"));
                result.putBoolean("guest_started",false);
                result.putBoolean("guest_payloads_modified",false);
                result.putBoolean("terminal_working_verified",false);
                finish(-1,result);return;
            }
            if (action.equals("observe_startup") || action.equals("observe_immutable_startup")
                    || action.equals("observe_default_startup")) {
                int observedMemory=manifest.getInt("memory_mib");
                if(observedMemory<64 || observedMemory>2048)throw new IllegalArgumentException("memory bounds");
                // Ordinary app initialization is needed for this action only,
                // after the normal owner-unlock guard and on the main thread.
                final Application app=(Application)target.getApplicationContext();
                runOnMainSync(new Runnable() { @Override public void run() {
                    TerminalProbe.super.callApplicationOnCreate(app);
                } });
                Map<String,String> observation=action.equals("observe_default_startup")
                    ? StartupObservation.observeDefault(this,target,observedMemory)
                    : StartupObservation.observe(this,target,id,observedMemory,
                        action.equals("observe_immutable_startup") ? manifest : null);
                for(Map.Entry<String,String> entry:observation.entrySet())
                    result.putString(entry.getKey(),entry.getValue());
                result.putString("status","startup_observed");
                result.putString("terminal_working_verified","false");
                finish(-1,result);return;
            }
            int memory = manifest.getInt("memory_mib"), port = manifest.getInt("port");
            String guestMode=manifest.optString("guest_mode","diagnostic_shell");
            if(!guestMode.equals("diagnostic_shell") && !guestMode.equals("normal_console"))
                throw new IllegalArgumentException("unknown guest mode");
            boolean normalConsole=guestMode.equals("normal_console");
            if (memory < 64 || memory > 2048 || port < 1024 || port > 65535)
                throw new IllegalArgumentException("profile bounds");
            File parent = new File(target.getFilesDir(), "gb-port");
            if (!parent.isDirectory() && !parent.mkdir()) throw new IOException("profile parent: "+parent);
            int attempt = manifest.optInt("staging_attempt", 0);
            if (attempt < 0 || attempt > 999) throw new IllegalArgumentException("staging attempt bounds");
            File staging = new File(parent, ".pending-" + id + (attempt == 0 ? "" : "-attempt-" + attempt)),
                published = new File(parent, id);
            if (staging.exists() || published.exists() || !staging.mkdir())
                throw new IOException("profile already exists");
            Map<String, PayloadReceiver.Item> items = new TreeMap<>();
            JSONObject inputs = manifest.getJSONObject("payloads");
            String[][] names = {{"kernel","guest-kernel.img"},{"initrd","initrd.img"},
                {"rootfs","root_part"},{"instance","instance.img"}};
            long required = 64 * 1024 * 1024;
            for (String[] pair : names) {
                JSONObject spec = inputs.getJSONObject(pair[0]);
                PayloadReceiver.Item item = new PayloadReceiver.Item(pair[1], spec.getLong("bytes"), spec.getString("sha256"));
                required = Math.addExact(required, item.bytes); items.put(pair[0], item);
            }
            if (target.getFilesDir().getUsableSpace() < required) throw new IOException("insufficient app storage");
            Set<String> completed = new HashSet<>();
            long deadline = System.nanoTime() + 600L * 1000000000L;
            try (ServerSocket server = new ServerSocket()) {
                server.bind(new InetSocketAddress("127.0.0.1", port)); server.setSoTimeout(60000);
                status("listening:" + port);
                while (completed.size() < items.size()) {
                    if (System.nanoTime() > deadline) throw new IOException("transfer deadline");
                    try (Socket socket = server.accept()) {
                        if (!socket.getInetAddress().isLoopbackAddress()) throw new SecurityException("loopback only");
                        socket.setSoTimeout(30000);
                        String stored = PayloadReceiver.receive(new DeadlineInput(socket,deadline), socket.getOutputStream(),
                            items, completed, staging);
                        status("verified:" + stored);
                    }
                }
            }
            if (manifest.has("cache_advisor_sha256")) {
                CacheAdvisor.advise(getContext(),manifest.getString("cache_advisor_sha256"),staging,items);
                result.putString("owned_file_cache_advice","submitted; residency not guaranteed");
            }
            SharedPreferences prefs = target.getSharedPreferences("terminal_settings", Context.MODE_PRIVATE);
            File prefsFile = new File(new File(target.getDataDir(), "shared_prefs"), "terminal_settings.xml");
            if (prefsFile.isFile()) {
                byte[] backup;
                try (InputStream in = new FileInputStream(prefsFile)) { backup = bounded(in, 2 * 1024 * 1024); }
                write(new File(staging, "terminal_settings.before.xml"), backup);
                result.putString("preferences_backup_sha256", PayloadReceiver.hex(MessageDigest.getInstance("SHA-256").digest(backup)));
            }
            JSONObject vm = new JSONObject();
            vm.put("name", "gb-"+id).put("protected", true).put("memory_mib", memory)
                .put("cpu_topology", "one_cpu").put("platform_version", "~1.0")
                .put("kernel", new File(published,"guest-kernel.img").getAbsolutePath())
                .put("initrd", new File(published,"initrd.img").getAbsolutePath())
                .put("params", normalConsole ? "root=/dev/vdb1 rw rootwait console=hvc0 panic=0" : "root=/dev/vdb1 ro rootwait init=/bin/sh console=hvc0 panic=0")
                .put("console_input_device", "hvc0").put("debuggable", true)
                .put("console_out", true).put("connect_console", true).put("use_virtio_console", true)
                .put("network", false).put("auto_memory_balloon", false);
            JSONObject instance = new JSONObject().put("label","vm-instance")
                .put("path",new File(published,"instance.img").getAbsolutePath()).put("writable",true);
            JSONObject root = new JSONObject().put("label","ROOT")
                .put("path",new File(published,"root_part").getAbsolutePath()).put("writable",normalConsole)
                .put("guid","D578426D-3A55-45EA-9D4C-1440F71724D1");
            vm.put("disks",new JSONArray()
                .put(new JSONObject().put("writable",true).put("partitions",new JSONArray().put(instance)))
                .put(new JSONObject().put("writable",normalConsole).put("partitions",new JSONArray().put(root))));
            File config = new File(staging,"vm_config.json"); write(config,vm.toString(2).getBytes("UTF-8"));
            if (!staging.renameTo(published)) throw new IOException("atomic profile publication");
            result.putInt("previous_memory_mib",prefs.getInt("memory_mib",0));
            if (!prefs.edit().putInt("memory_mib",memory).putString("console_type","virtio_console").commit())
                throw new IOException("preferences commit failed; backup retained");
            result.putString("status","configured"); result.putString("config_path",new File(published,"vm_config.json").getAbsolutePath());
            result.putInt("target_uid",uid); result.putInt("memory_mib",memory);
            result.putString("guest_mode",guestMode);
            result.putString("original_vm_data_modified","false"); result.putString("terminal_runtime_verified","false");
            finish(-1,result);
        } catch (Exception error) {
            result.putString("error",error.getClass().getSimpleName()+": "+error.getMessage()); finish(0,result);
        }
    }
}
