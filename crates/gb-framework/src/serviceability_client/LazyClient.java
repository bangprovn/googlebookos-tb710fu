package org.googlebook.port.serviceability;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.Executor;

/** Tips-only lazy transport. Never supplies a service result or registration value. */
public final class LazyClient {
    private static final String TIPS = "com.google.android.desktop.tips";
    private static final String[] PACKAGES = {
        "vendor.google.desktop.serviceability", "com.android.desktop.serviceability"
    };
    private static final String[] SERVICES = {
        "vendor.google.desktop.serviceability.VendorServiceabilityService",
        "com.android.desktop.serviceability.ServiceabilityService"
    };
    private static final String[] INTERFACES = {
        "vendor.google.desktop.serviceability.IVendorServiceabilityService",
        "vendor.google.desktop.serviceability.IServiceabilityService"
    };
    // Callbacks run on the Binder delivery thread, never a blocked main looper.
    // They do no waiting or remote operation; no per-manager executor thread leaks.
    private static final Executor CALLBACKS = new Executor() {
        public void execute(Runnable command) { command.run(); }
    };
    private static final long ACQUIRE_MS = 1000;

    private LazyClient() {}

    public static boolean isTips(Context context) {
        Context app = context.getApplicationContext();
        return app != null && TIPS.equals(app.getPackageName());
    }

    /** Index0 vendor, index1 system, matching the original constructor ordering. */
    public static Object[] create(Context context) {
        if (!isTips(context)) throw new IllegalArgumentException("Tips context required");
        State state = new State(context.getApplicationContext());
        Object[] result = new Object[2];
        try {
            for (int i = 0; i < 2; i++) {
                Class<?> iface = Class.forName(INTERFACES[i], false, LazyClient.class.getClassLoader());
                result[i] = Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[]{iface},
                        new Handler(state, i));
            }
        } catch (ReflectiveOperationException e) {
            throw unavailable("client interface unavailable", e);
        }
        return result;
    }

    private static IllegalStateException unavailable(String reason, Throwable cause) {
        return new IllegalStateException("Serviceability unavailable: " + reason, cause);
    }

    private static final class Handler implements InvocationHandler {
        private final State state;
        private final int index;
        Handler(State state, int index) { this.state = state; this.index = index; }

        public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
            if (method.getDeclaringClass() == Object.class) {
                if (method.getName().equals("equals")) return proxy == arguments[0];
                if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
                if (method.getName().equals("toString")) return "LazyServiceabilityClient";
                throw new AssertionError("unexpected Object method");
            }
            Connections connections = state.acquire();
            try {
                // The original interface Method is invoked on its real Stub.asInterface result.
                // No automatic retry: a failed mutating Binder RPC must never be replayed.
                return method.invoke(connections.services[index], arguments);
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (cause instanceof android.os.DeadObjectException) {
                    try { connections.close(); }
                    catch (RuntimeException cleanup) { cause.addSuppressed(cleanup); }
                }
                throw cause;
            }
        }
    }

    private static final class State {
        private final Context context;
        private Connections ready;
        private boolean acquiring;
        State(Context context) { this.context = context; }

        Connections acquire() {
            long deadline = SystemClock.elapsedRealtime() + ACQUIRE_MS;
            synchronized (this) {
                if (ready != null && ready.live()) return ready;
                if (Looper.myLooper() != null && Looper.myLooper() == Looper.getMainLooper())
                    throw unavailable("acquisition requires a worker thread", null);
                while (acquiring) {
                    waitUntil(this, deadline);
                    if (ready != null && ready.live()) return ready;
                }
                acquiring = true;
            }
            Connections attempt = new Connections(context);
            try {
                // Preserve authentic vendor-first prerequisite, including for VPD reads.
                attempt.bind(0, deadline);
                attempt.bind(1, deadline);
                synchronized (this) {
                    if (!attempt.live()) throw unavailable("connection lost", null);
                    ready = attempt;
                }
                return attempt;
            } catch (RuntimeException | Error failure) {
                try { attempt.close(); }
                catch (RuntimeException cleanup) { failure.addSuppressed(cleanup); }
                throw failure;
            } finally {
                synchronized (this) { acquiring = false; notifyAll(); }
            }
        }
    }

    private static void waitUntil(Object lock, long deadline) {
        long left = deadline - SystemClock.elapsedRealtime();
        if (left <= 0) throw unavailable("acquisition timed out", null);
        try { lock.wait(left); }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw unavailable("acquisition interrupted", e);
        }
    }

    private static final class Connections {
        private final Context context;
        final Object[] services = new Object[2];
        private final ServiceConnection[] callbacks = new ServiceConnection[2];
        private final boolean[] returned = new boolean[2];
        private final boolean[] attempted = new boolean[2];
        private final boolean[] released = new boolean[2];
        private boolean closed;
        private RuntimeException failure;

        Connections(Context context) {
            this.context = context;
            for (int i = 0; i < 2; i++) {
                final int index = i;
                callbacks[i] = new ServiceConnection() {
                    public void onServiceConnected(ComponentName name, IBinder binder) {
                        synchronized (Connections.this) {
                            if (closed) return;
                            try {
                                Class<?> stub = Class.forName(INTERFACES[index] + "$Stub", false,
                                        LazyClient.class.getClassLoader());
                                services[index] = stub.getMethod("asInterface", IBinder.class)
                                        .invoke(null, binder);
                                if (services[index] == null)
                                    failure = unavailable("null service interface", null);
                            } catch (ReflectiveOperationException e) {
                                failure = unavailable("service interface conversion failed", e);
                            }
                            Connections.this.notifyAll();
                        }
                    }
                    public void onServiceDisconnected(ComponentName name) { lost(); }
                    public void onNullBinding(ComponentName name) { lost(); }
                    public void onBindingDied(ComponentName name) { lost(); }
                    private void lost() {
                        synchronized (Connections.this) {
                            failure = unavailable("connection lost", null);
                            Connections.this.notifyAll();
                        }
                        close();
                    }
                };
            }
        }

        void bind(int index, long deadline) {
            synchronized (this) {
                if (closed || failure != null) throw unavailable("connection lost", failure);
                if (SystemClock.elapsedRealtime() >= deadline)
                    throw unavailable("acquisition timed out", null);
                attempted[index] = true;
            }
            boolean accepted;
            try {
                accepted = context.bindService(new Intent().setComponent(
                        new ComponentName(PACKAGES[index], SERVICES[index])),
                        Context.BIND_AUTO_CREATE, CALLBACKS, callbacks[index]);
            } finally {
                synchronized (this) { returned[index] = true; }
                // A synchronous/late callback can close while bindService itself is returning.
                releaseClosed();
            }
            if (!accepted) throw unavailable("service binding rejected", null);
            synchronized (this) {
                while (services[index] == null && failure == null && !closed)
                    waitUntil(this, deadline);
                if (failure != null) throw failure;
                if (closed) throw unavailable("connection lost", null);
            }
        }

        synchronized boolean live() {
            return !closed && failure == null && services[0] != null && services[1] != null;
        }

        void close() {
            synchronized (this) { closed = true; notifyAll(); }
            releaseClosed();
        }

        private void releaseClosed() {
            RuntimeException cleanupFailure = null;
            for (int i = 0; i < 2; i++) {
                boolean release;
                synchronized (this) {
                    release = closed && attempted[i] && returned[i] && !released[i];
                    if (release) released[i] = true;
                }
                if (release) {
                    try { context.unbindService(callbacks[i]); }
                    catch (IllegalArgumentException notRegistered) { /* rejected/denied bind */ }
                    catch (RuntimeException failed) {
                        if (cleanupFailure == null) cleanupFailure = failed;
                        else cleanupFailure.addSuppressed(failed);
                    }
                }
            }
            if (cleanupFailure != null) throw cleanupFailure;
        }
    }
}
