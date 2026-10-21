#!/usr/bin/env python3
"""Owned Java helper with fake Android transports only; never executes donor code."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
STUBS = {
    "android/os/IBinder.java": "package android.os; public interface IBinder {}",
    "android/os/RemoteException.java": "package android.os; public class RemoteException extends Exception { public RemoteException(String m){super(m);} }",
    "android/os/DeadObjectException.java": "package android.os; public class DeadObjectException extends RemoteException { public DeadObjectException(){super(\"dead\");} }",
    "android/os/SystemClock.java": "package android.os; public final class SystemClock { public static long elapsedRealtime(){return System.nanoTime()/1000000;} }",
    "android/os/Looper.java": "package android.os; public final class Looper { private static final Looper MAIN=new Looper(); private static final ThreadLocal<Looper> CURRENT=new ThreadLocal<>(); public static Looper getMainLooper(){return MAIN;} public static Looper myLooper(){return CURRENT.get();} public static void markMain(){CURRENT.set(MAIN);} public static void clear(){CURRENT.remove();} }",
    "android/content/ComponentName.java": "package android.content; public final class ComponentName { public final String pkg,cls; public ComponentName(String p,String c){pkg=p;cls=c;} }",
    "android/content/Intent.java": "package android.content; public final class Intent { public ComponentName component; public Intent setComponent(ComponentName c){component=c;return this;} }",
    "android/content/ServiceConnection.java": "package android.content; import android.os.IBinder; public interface ServiceConnection { void onServiceConnected(ComponentName n,IBinder b); void onServiceDisconnected(ComponentName n); default void onNullBinding(ComponentName n){} default void onBindingDied(ComponentName n){} }",
    "android/content/Context.java": "package android.content; import java.util.concurrent.Executor; public abstract class Context { public static final int BIND_AUTO_CREATE=1; public Context getApplicationContext(){return this;} public abstract String getPackageName(); public abstract boolean bindService(Intent i,int f,Executor e,ServiceConnection c); public abstract void unbindService(ServiceConnection c); }",
}
for name in ("IVendorServiceabilityService", "IServiceabilityService"):
    STUBS[f"vendor/google/desktop/serviceability/{name}.java"] = f"""package vendor.google.desktop.serviceability;
import android.os.*;
public interface {name} {{
 String value() throws RemoteException;
 String getUbindAttribute() throws RemoteException;
 IBinder asBinder();
 void register(Runnable listener) throws RemoteException;
 final class Stub {{ public static {name} asInterface(IBinder b) {{ return ({name})b; }} }}
}}"""

HARNESS = r"""
import android.content.*;
import android.os.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.googlebook.port.serviceability.LazyClient;
import vendor.google.desktop.serviceability.*;
public class Harness {
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 interface Run {void go() throws Exception;}
 static <T extends Throwable> T fails(Class<T> type,Run run) throws Exception {
  try {run.go();} catch(Throwable t){check(type.isInstance(t),"wrong failure "+t);return type.cast(t);}
  throw new AssertionError("missing failure "+type);
 }
 static final class Service implements IBinder,IVendorServiceabilityService,IServiceabilityService {
  String actual="genuine-value"; int calls; Throwable failure; Runnable listener;
  public String value() throws RemoteException {calls++; if(failure instanceof RemoteException)throw (RemoteException)failure;if(failure instanceof RuntimeException)throw (RuntimeException)failure;return actual;}
  public String getUbindAttribute() throws RemoteException {return value();}
  public IBinder asBinder(){return this;}
  public void register(Runnable r){listener=r;}
 }
 static final class Fake extends Context {
  final List<ServiceConnection> connections=new CopyOnWriteArrayList<>();
  final List<ServiceConnection> released=new CopyOnWriteArrayList<>();
  final Service vendor=new Service(), system=new Service();
  int binds; String mode="ok", pkg="com.google.android.desktop.tips"; boolean failUnbind;
  public String getPackageName(){return pkg;}
  public synchronized boolean bindService(Intent intent,int flags,Executor executor,ServiceConnection c){
   check(flags==BIND_AUTO_CREATE,"flags changed");
   check(intent.component.pkg.equals(binds%2==0?"vendor.google.desktop.serviceability":"com.android.desktop.serviceability"),"ordering");
   check(intent.component.cls.endsWith(binds%2==0?"VendorServiceabilityService":"ServiceabilityService"),"target");
   connections.add(c); int index=binds++; Service target=index%2==0?vendor:system;
   if(mode.equals("security"))throw new SecurityException("denied");
   if(mode.equals("false") || (mode.equals("systemfalse")&&index%2==1))return false;
   if(mode.equals("timeout") || (mode.equals("systemtimeout")&&index%2==1))return true;
   if(mode.equals("null")){executor.execute(()->c.onNullBinding(intent.component));return true;}
   executor.execute(()->c.onServiceConnected(intent.component,target));return true;
  }
  public void unbindService(ServiceConnection c){check(!released.contains(c),"duplicate unbind");released.add(c);if(failUnbind)throw new IllegalStateException("unbind failed");}
 }
 static IServiceabilityService system(Object[] p){return (IServiceabilityService)p[1];}
 public static void main(String[] args) throws Exception {
  String scenario=args[0]; Fake f=new Fake();
  if(scenario.equals("scope")){
   f.pkg="genuine.other.client";check(!LazyClient.isTips(f),"other client matched");fails(IllegalArgumentException.class,()->LazyClient.create(f));check(f.binds==0,"other bind");
  } else if(scenario.equals("lazy-success")){
   Object[] p=LazyClient.create(f);check(f.binds==0,"eager bind");
   check(system(p).value().equals(f.system.actual),"fabricated identity");check(f.binds==2&&f.released.size()==0,"lifetime");
   check(system(p).getUbindAttribute().equals(f.system.actual),"registration forwarding");
   check(system(p).asBinder()==f.system,"binder substitution");
   f.system.actual=null;check(system(p).value()==null,"real null changed");f.system.actual="";check(system(p).value().equals(""),"real empty changed");f.system.actual="genuine-value";
   Looper.markMain();try{check(system(p).value().equals(f.system.actual),"ready main result");}finally{Looper.clear();}
   AtomicInteger events=new AtomicInteger();system(p).register(()->events.incrementAndGet());f.system.listener.run();check(events.get()==1,"listener lost");
   check(((IVendorServiceabilityService)p[0]).value().equals(f.vendor.actual)&&f.binds==2,"reuse");
  } else if(scenario.equals("main")){
   Object[] p=LazyClient.create(f);Looper.markMain();try{fails(IllegalStateException.class,()->system(p).value());}finally{Looper.clear();}check(f.binds==0,"main bind");
  } else if(scenario.equals("false")||scenario.equals("systemfalse")||scenario.equals("null")||scenario.equals("security")){
   f.mode=scenario;Object[]p=LazyClient.create(f);
   if(scenario.equals("security"))fails(SecurityException.class,()->system(p).value());
   else fails(IllegalStateException.class,()->system(p).value());
   check(f.released.size()==f.binds,"failed binding retained");check(f.system.calls==0&&f.vendor.calls==0,"failed operation ran");
  } else if(scenario.equals("timeout-late") || scenario.equals("systemtimeout")){
   f.mode=scenario.equals("systemtimeout")?"systemtimeout":"timeout";Object[]p=LazyClient.create(f);long start=System.nanoTime();
   fails(IllegalStateException.class,()->system(p).value());long ms=(System.nanoTime()-start)/1000000;
   check(ms>=800&&ms<1800,"unbounded timeout "+ms);int expected=scenario.equals("systemtimeout")?2:1;check(f.binds==expected&&f.released.size()==expected,"timeout cleanup");
   f.connections.get(0).onServiceConnected(null,f.vendor);f.mode="ok";f.binds=0;
   check(system(p).value().equals(f.system.actual)&&f.binds==2,"late callback resurrected");
  } else if(scenario.equals("remote-security")){
   Object[]p=LazyClient.create(f);SecurityException denied=new SecurityException("real server denied");f.system.failure=denied;
   check(fails(SecurityException.class,()->system(p).value())==denied,"security wrapped");check(f.system.calls==1&&f.binds==2,"security replay");
   RemoteException remote=new RemoteException("real transport failure");f.system.failure=remote;
   check(fails(RemoteException.class,()->system(p).value())==remote,"remote wrapped");check(f.system.calls==2,"remote replay");
  } else if(scenario.equals("dead-reconnect")){
   Object[]p=LazyClient.create(f);f.system.failure=new DeadObjectException();fails(DeadObjectException.class,()->system(p).value());
   check(f.system.calls==1&&f.released.size()==2,"dead replay/cleanup");f.system.failure=null;
   check(system(p).value().equals(f.system.actual)&&f.binds==4,"dead did not reconnect");
  } else if(scenario.equals("dead-cleanup-failure")){
   Object[]p=LazyClient.create(f);f.system.failure=new DeadObjectException();f.failUnbind=true;
   DeadObjectException e=fails(DeadObjectException.class,()->system(p).value());
   check(f.system.calls==1&&f.released.size()==2&&e.getSuppressed().length==1,"dead error masked or cleanup skipped");
  } else if(scenario.equals("disconnect")){
   Object[]p=LazyClient.create(f);system(p).value();f.connections.get(0).onServiceDisconnected(null);
   check(f.released.size()==2,"disconnect cleanup");system(p).value();check(f.binds==4,"disconnect reconnect");
  } else if(scenario.equals("cleanup-failure")){
   f.mode="systemfalse";f.failUnbind=true;Object[]p=LazyClient.create(f);
   IllegalStateException e=fails(IllegalStateException.class,()->system(p).value());
   check(e.getMessage().contains("binding rejected"),"failure masked");check(f.released.size()==2,"cleanup skipped second");check(e.getSuppressed().length==1,"cleanup failure hidden");
  } else if(scenario.equals("interrupt")){
   f.mode="timeout";Object[]p=LazyClient.create(f);AtomicReference<Throwable>failure=new AtomicReference<>();AtomicBoolean preserved=new AtomicBoolean();
   Thread t=new Thread(()->{try{system(p).value();}catch(Throwable e){failure.set(e);preserved.set(Thread.currentThread().isInterrupted());}});t.start();Thread.sleep(40);t.interrupt();t.join(1000);
   check(!t.isAlive()&&failure.get() instanceof IllegalStateException&&preserved.get(),"interrupt lost");check(f.released.size()==1,"interrupt binding leak");
  } else if(scenario.equals("concurrent")){
   Object[]p=LazyClient.create(f);CountDownLatch start=new CountDownLatch(1);AtomicReference<Throwable>failure=new AtomicReference<>();List<Thread>threads=new ArrayList<>();
   for(int i=0;i<16;i++){Thread t=new Thread(()->{try{start.await();check(system(p).value().equals(f.system.actual),"result");}catch(Throwable e){failure.set(e);}});threads.add(t);t.start();}
   start.countDown();for(Thread t:threads){t.join(1500);check(!t.isAlive(),"deadlock");}check(failure.get()==null&&f.binds==2,"duplicate acquisition "+failure.get());
  } else throw new AssertionError("unknown scenario");
  System.out.println("PASS "+scenario);
 }
}
"""


class LazyClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="gb-serviceability-host-")
        cls.root = pathlib.Path(cls.temporary.name)
        for name, text in STUBS.items():
            path = cls.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        helper = cls.root / "org/googlebook/port/serviceability/LazyClient.java"
        helper.parent.mkdir(parents=True)
        helper.write_bytes((ROOT / "LazyClient.java").read_bytes())
        (cls.root / "Harness.java").write_text(HARNESS)
        sources = sorted(str(p) for p in cls.root.rglob("*.java"))
        compile_result = subprocess.run(["javac", "-proc:none", "-d", str(cls.root / "classes"), *sources],
                                        capture_output=True, text=True, timeout=20)
        if compile_result.returncode:
            raise AssertionError(compile_result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_actual_owned_helper_scenarios(self):
        scenarios = ("scope", "lazy-success", "main", "false", "systemfalse", "null", "security",
                     "timeout-late", "systemtimeout", "remote-security", "dead-reconnect", "dead-cleanup-failure", "disconnect",
                     "cleanup-failure", "interrupt", "concurrent")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                result = subprocess.run(["java", "-Xmx128m", "-cp", str(self.root / "classes"),
                                         "Harness", scenario], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"PASS {scenario}\n")


if __name__ == "__main__":
    unittest.main()
