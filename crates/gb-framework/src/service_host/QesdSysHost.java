package org.googlebook.port.qesdsys;

import android.content.Context;
import android.os.Build;
import android.os.IBinder;
import android.os.Looper;
import android.os.Process;
import android.os.Parcel;
import android.content.pm.PackageManager;
import android.util.Log;
import dalvik.system.PathClassLoader;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicBoolean;

/** Init-managed host for the unchanged, pinned owner-stock QesdSys implementation.
 * No APK install, signature substitution, permission-result emulation or root UID.
 * Requires a separately validated domain, VINTF declaration and framework IPC.
 */
public final class QesdSysHost {
    private static final String TAG = "GB-QESDSYS";
    private static final String NAME = "vendor.qti.qesdsys.IQesdSys/default";
    private static final String DESCRIPTOR = "vendor.qti.qesdsys.IQesdSys";
    private static final String HASH = "60370da086910c28180728ea367e33077d921e8f";
    private static final AtomicBoolean initialized = new AtomicBoolean(false);
    private static String phase = "identity";
    // Retain the implementation, class loader and system context for process lifetime.
    private static Object implementation;
    private static PathClassLoader loader;
    private static Context context;

    private static void require(boolean value) {
        if (!value) throw new IllegalStateException("host contract refused");
    }
    private static String property(String name) throws Exception {
        return (String) Class.forName("android.os.SystemProperties")
            .getMethod("get", String.class).invoke(null, name);
    }
    private static String domain() throws Exception {
        return new String(Files.readAllBytes(Paths.get("/proc/self/attr/current")),
            StandardCharsets.US_ASCII).trim();
    }
    private static Context systemContext() throws Exception {
        Class<?> activity = Class.forName("android.app.ActivityThread");
        Object thread = activity.getMethod("systemMain").invoke(null);
        return (Context) activity.getMethod("getSystemContext").invoke(thread);
    }
    /** Shell-only, read-only runtime preflight: no stock APK or service publication. */
    @SuppressWarnings("deprecation")
    private static void inspectRuntime() throws Exception {
        require(Process.myUid() == 2000);
        Looper.prepareMainLooper();
        require("android".equals(systemContext().getPackageName()));
        int executableDataMaps = 0, privateRuntimeMaps = 0, lines = 0;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream("/proc/self/maps"), StandardCharsets.US_ASCII))) {
            String line;
            while ((line = reader.readLine()) != null) {
                require(++lines < 16384 && line.length() < 4096);
                String[] fields = line.split("\\s+", 6);
                require(fields.length >= 5 && fields[1].length() == 4);
                if (fields[1].charAt(2) == 'x' && fields.length == 6
                        && fields[5].startsWith("/data/")) {
                    executableDataMaps++;
                    if (fields[5].startsWith("/data/local/tmp/gb-qesdsys-runtime-")
                            && fields[5].endsWith("/lib64/libandroid_runtime.so")) privateRuntimeMaps++;
                }
            }
        }
        require(domain().equals("u:r:shell:s0"));
        System.out.println("GB_QESDSYS_RUNTIME_PREFLIGHT uid=2000 context_created=true executable_data_maps="
            + executableDataMaps + " private_runtime_test_maps=" + privateRuntimeMaps
            + " stock_apk_loaded=false service_published=false");
    }
    /** Real IPC read test. Never replaces the vendor manager's singleton callback. */
    @SuppressWarnings("deprecation")
    private static void probeInterface() throws Exception {
        require(Process.myUid() == 2000 && domain().equals("u:r:shell:s0"));
        Looper.prepareMainLooper();
        Context check = systemContext();
        phase = "interface_probe_identity";
        // A shell app_process is not an ActivityManager-managed application.
        // Use the stock interface's explicit PID-zero UID lookup, after checking
        // the real installed shell package. UID remains the calling shell UID.
        String[] packages = check.getPackageManager().getPackagesForUid(Process.myUid());
        require(packages != null && java.util.Arrays.asList(packages).contains("com.android.shell"));
        final int permissionPid = 0;
        IBinder remote = (IBinder) Class.forName("android.os.ServiceManager")
            .getMethod("checkService", String.class).invoke(null, NAME);
        require(remote != null && DESCRIPTOR.equals(remote.getInterfaceDescriptor()));
        String[] permissions = {"android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE"};
        boolean[] expected = new boolean[permissions.length];
        for (int i = 0; i < permissions.length; i++) expected[i] =
            check.checkPermission(permissions[i], permissionPid, Process.myUid()) == PackageManager.PERMISSION_GRANTED;
        require(expected[0] && !expected[1]);
        for (int transaction : new int[] {16777215, 16777214, 2}) {
            phase = "interface_probe_transaction_" + transaction;
            Parcel request = Parcel.obtain(), reply = Parcel.obtain();
            try {
                request.writeInterfaceToken(DESCRIPTOR);
                if (transaction == 2) {
                    request.writeInt(permissionPid); request.writeInt(Process.myUid());
                    // Read checks only: do not register permission monitoring.
                    request.writeStringList(java.util.Arrays.asList(
                        permissions[0] + "?monitor=false", permissions[1] + "?monitor=false"));
                }
                require(remote.transact(transaction, request, reply, 0));
                reply.readException();
                if (transaction == 16777215) require(reply.readInt() == 4);
                else if (transaction == 16777214) require(HASH.equals(reply.readString()));
                else require(java.util.Arrays.equals(expected, reply.createBooleanArray()));
                require(reply.dataAvail() == 0);
            } finally { request.recycle(); reply.recycle(); }
        }
        System.out.println("GB_QESDSYS_IPC_PROBE version=4 hash_verified=true granted_permission=true denied_permission=false callback_modified=false uid_only_lookup=true permission_monitoring=false");
    }
    private static void checkInput(String path, String expected) throws Exception {
        require(path.equals("/system_ext/gb-qesdsys/FrameworksUtilsSysService.apk"));
        require(Files.isRegularFile(Paths.get(path), LinkOption.NOFOLLOW_LINKS));
        require(new File(path).getCanonicalPath().equals(path));
        require(expected.matches("[0-9a-f]{64}"));
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long total = 0;
        try (FileInputStream input = new FileInputStream(path)) {
            byte[] buffer = new byte[8192]; int count;
            while ((count = input.read(buffer)) != -1) {
                total += count;
                require(total <= 1024 * 1024);
                digest.update(buffer, 0, count);
            }
        }
        require(total > 0);
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest.digest()) hex.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        require(expected.equals(hex.toString()));
    }
    @SuppressWarnings("deprecation")
    public static void main(String[] args) {
        try {
            if (args.length == 1 && args[0].equals("--inspect-runtime")) {
                phase = "runtime_preflight";
                inspectRuntime();
                return;
            }
            if (args.length == 1 && args[0].equals("--probe-interface")) {
                phase = "interface_probe";
                probeInterface();
                return;
            }
            require(args.length == 3 && Process.myUid() == 1000);
            require(Build.FINGERPRINT.equals(args[2]));
            require("1".equals(property("sys.boot_completed")));
            require(domain().equals("u:r:gb_qesdsys:s0"));
            phase = "input";
            checkInput(args[0], args[1]);
            Class<?> manager = Class.forName("android.os.ServiceManager");
            Method checkService = manager.getMethod("checkService", String.class);
            require(checkService.invoke(null, NAME) == null);
            Thread watchdog = new Thread(new Runnable() {
                public void run() {
                    try { Thread.sleep(20000); } catch (InterruptedException ignored) { return; }
                    if (!initialized.get()) {
                        Log.e(TAG, "initialization deadline exceeded");
                        Process.killProcess(Process.myPid());
                    }
                }
            }, "gb-qesdsys-deadline");
            watchdog.setDaemon(true); watchdog.start();
            phase = "context";
            Looper.prepareMainLooper();
            context = systemContext();
            require("android".equals(context.getPackageName()));
            phase = "implementation";
            loader = new PathClassLoader(args[0], QesdSysHost.class.getClassLoader());
            Class<?> type = loader.loadClass("vendor.qti.frameworks.utils.QesdkSysServiceImpl");
            implementation = type.getConstructor(Context.class).newInstance(context);
            IBinder binder = (IBinder) implementation;
            require(DESCRIPTOR.equals(binder.getInterfaceDescriptor()));
            require(Integer.valueOf(4).equals(type.getMethod("getInterfaceVersion").invoke(implementation)));
            require(HASH.equals(type.getMethod("getInterfaceHash").invoke(implementation)));
            phase = "publication";
            manager.getMethod("addService", String.class, IBinder.class).invoke(null, NAME, binder);
            require(checkService.invoke(null, NAME) != null);
            initialized.set(true); watchdog.interrupt();
            Log.i(TAG, "unchanged stock IQesdSys v4 published; uid=1000; initialization verified; client operations unqualified");
            Looper.loop();
            throw new IllegalStateException("main looper returned");
        } catch (Throwable failure) {
            // Bounded diagnostic: never log requested permission lists, packages or signing data.
            Throwable cause = failure.getCause() == null ? failure : failure.getCause();
            Log.e(TAG, "startup refused phase=" + phase + " error=" + cause.getClass().getSimpleName());
            Process.killProcess(Process.myPid());
        }
    }
}
