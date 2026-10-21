#!/usr/bin/env python3
"""Host-only public-API stubs for the owned scalar Terminal UI observer.

No ADB, accessibility connection, private output or Android code is executed.
Pass an existing pinned hardware BuildRequest to select its verified host JDK.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
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
"android/os/Bundle.java": '''package android.os;import java.util.*;public class Bundle {public final Map<String,String> values=new HashMap<>();public String getString(String key){return values.get(key);}public void putString(String key,String value){values.put(key,value);}}''',
"android/os/Process.java": '''package android.os;public class Process {public static int uid=1110001;public static int myUid(){return uid;}}''',
"android/os/SystemClock.java": '''package android.os;public class SystemClock {public static long elapsedRealtime(){return System.nanoTime()/1000000;}}''',
"android/os/UserManager.java": '''package android.os;public class UserManager {public boolean unlocked=true;public boolean isUserUnlocked(){return unlocked;}}''',
"android/graphics/Rect.java": '''package android.graphics;public class Rect {public int left,top,right,bottom;public int width(){return right-left;}}''',
"android/view/accessibility/AccessibilityManager.java": '''package android.view.accessibility;public class AccessibilityManager {public boolean enabled,touch;public boolean isEnabled(){return enabled;}public boolean isTouchExplorationEnabled(){return touch;}}''',
"android/content/Context.java": '''package android.content;
import android.os.*;import android.view.accessibility.*;
public class Context {
 public String name="org.googlebook.port.terminaluiobserver";
 public UserManager users=new UserManager();public AccessibilityManager accessibility=new AccessibilityManager();
 public String getPackageName(){return name;}
 public <T>T getSystemService(Class<T> cls){if(cls==UserManager.class)return cls.cast(users);if(cls==AccessibilityManager.class)return cls.cast(accessibility);throw new AssertionError("unapproved service");}
}''',
"android/view/accessibility/AccessibilityNodeInfo.java": '''package android.view.accessibility;
import java.util.*;import android.graphics.*;
public class AccessibilityNodeInfo {
 public String pkg="com.android.virtualization.terminal",cls="android.view.View";
 public CharSequence text;public int width=100,recycles,textReads,childReads;public boolean failText,failRecycle;
 public final List<AccessibilityNodeInfo> children=new ArrayList<>();
 public CharSequence getPackageName(){return pkg;}public CharSequence getClassName(){return cls;}
 public void getBoundsInScreen(Rect out){out.left=0;out.top=0;out.right=width;out.bottom=20;}
 public CharSequence getText(){textReads++;if(failText)throw new IllegalStateException();return text;}
 public int getChildCount(){return children.size();}public AccessibilityNodeInfo getChild(int i){childReads++;return children.get(i);}
 public void recycle(){recycles++;if(recycles>1)throw new AssertionError("double recycle");if(failRecycle)throw new IllegalStateException();}
}''',
"android/app/UiAutomation.java": '''package android.app;import android.view.accessibility.*;
public class UiAutomation {
 public static final int FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES=1;
 public AccessibilityNodeInfo template,cached;public int roots,clears;public boolean failRoot,failClear,clearResult=true;
 private AccessibilityNodeInfo copy(AccessibilityNodeInfo n){if(n==null)return null;AccessibilityNodeInfo c=new AccessibilityNodeInfo();c.pkg=n.pkg;c.cls=n.cls;c.text=n.text;c.width=n.width;c.failText=n.failText;for(AccessibilityNodeInfo a:n.children)c.children.add(copy(a));return c;}
 public boolean clearCache(){clears++;if(failClear)throw new IllegalStateException();if(!clearResult)return false;cached=null;return true;}
 public AccessibilityNodeInfo getRootInActiveWindow(){roots++;if(failRoot)throw new IllegalStateException();if(cached==null)cached=copy(template);return copy(cached);}
}''',
"org/json/JSONArray.java": '''package org.json;import java.util.*;public class JSONArray {public final List<Object> values=new ArrayList<>();public JSONArray put(Object v){values.add(v);return this;}public int length(){return values.size();}public String toString(){StringJoiner out=new StringJoiner(",","[","]");for(Object v:values)out.add(JSONObject.encode(v));return out.toString();}}''',
"org/json/JSONObject.java": r'''package org.json;import java.util.*;public class JSONObject {
 public static JSONObject last;public final Map<String,Object> values=new LinkedHashMap<>();
 public JSONObject put(String k,Object v){values.put(k,v);return this;}public Object get(String k){return values.get(k);}
 public static String encode(Object value){if(value==null)return "null";if(value instanceof String)return "\""+((String)value).replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r")+"\"";return value.toString();}
 public String toString(){StringJoiner out=new StringJoiner(",","{","}");for(Map.Entry<String,Object> v:values.entrySet())out.add(encode(v.getKey())+":"+encode(v.getValue()));last=this;return out.toString();}
}''',
"android/app/Instrumentation.java": '''package android.app;
import android.content.*;import android.os.*;import java.util.*;import org.json.*;
public class Instrumentation {
 public static Context context;public static Context target;public static UiAutomation automation;
 public static boolean failFinish,failStatus;public static int finishes,starts,automationCalls,finishCode;
 public static Bundle result;public static JSONObject resultObject;public static final List<JSONObject> statuses=new ArrayList<>();
 public void onCreate(Bundle args){}public void onStart(){}
 public void start(){starts++;}public Context getContext(){return context;}public Context getTargetContext(){return target;}
 public UiAutomation getUiAutomation(int flags){if(flags!=UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES)throw new AssertionError();automationCalls++;if(automation!=null)target.accessibility.enabled=true;return automation;}
 public void sendStatus(int code,Bundle data){if(failStatus)throw new IllegalStateException();statuses.add(JSONObject.last);}
 public void finish(int code,Bundle data){finishes++;finishCode=code;result=data;resultObject=JSONObject.last;if(failFinish)throw new IllegalStateException();}
 public static void reset(){context=new Context();target=context;automation=new UiAutomation();failFinish=false;failStatus=false;finishes=starts=automationCalls=0;result=null;resultObject=null;statuses.clear();android.os.Process.uid=1110001;}
}''',
"org/googlebook/port/terminaluiobserver/ObserverSelfTest.java": '''package org.googlebook.port.terminaluiobserver;
import android.app.*;import android.content.*;import android.os.*;import android.view.accessibility.*;import org.json.*;
public class ObserverSelfTest {
 static final String MARKER="GB_UI_EXEC_0123456789abcdef0123456789abcdef";
 static int cases;
 static void check(boolean value){if(!value)throw new AssertionError("owned observer scalar fixture");}
 static AccessibilityNodeInfo node(String text){AccessibilityNodeInfo n=new AccessibilityNodeInfo();n.text=text;return n;}
 static AccessibilityNodeInfo web(AccessibilityNodeInfo... children){AccessibilityNodeInfo n=node(null);n.cls="android.webkit.WebView";for(AccessibilityNodeInfo c:children)n.children.add(c);return n;}
 static TerminalUiObserver.Observation reduce(AccessibilityNodeInfo n){return TerminalUiObserver.reduce(n,MARKER,Long.MAX_VALUE);}
 static Bundle args(String user,String marker,String duration){Bundle b=new Bundle();b.putString("expected_user",user);b.putString("marker",marker);b.putString("duration_ms",duration);return b;}
 static JSONObject run(){TerminalUiObserver helper=new TerminalUiObserver();helper.onCreate(args("11",MARKER,"1000"));check(Instrumentation.starts==1);helper.onStart();check(Instrumentation.finishes==1);return Instrumentation.resultObject;}
 static boolean yes(JSONObject o,String k){return Boolean.TRUE.equals(o.get(k));}
 static int number(JSONObject o,String k){return ((Number)o.get(k)).intValue();}
 static void safe(JSONObject o){String s=o.toString();check(!s.contains(MARKER)&&!s.contains("diagnostic body")&&!s.contains("fixture.foreign")&&!s.contains("http:"));check(!yes(o,"command_execution_verified")&&!yes(o,"output_proof_claimed")&&!yes(o,"framework_cleanup_verified"));}
 public static void main(String[]ignored)throws Exception {
  AccessibilityNodeInfo leaf=node(MARKER),foreign=web(leaf);foreign.pkg="fixture.foreign";
  TerminalUiObserver.Observation r=reduce(foreign);check(r.status==TerminalUiObserver.Trace.FOREIGN_ACTIVE_WINDOW&&r.whole==0&&r.visited==1&&foreign.recycles==1&&foreign.childReads==0&&leaf.textReads==0);cases++;
  AccessibilityNodeInfo nativeTitle=node(MARKER),body=node(MARKER),view=web(body),root=node(null);root.children.add(nativeTitle);root.children.add(view);view.text=MARKER;
  r=reduce(root);check(r.complete&&r.webviews==1&&r.whole==1&&nativeTitle.textReads==0&&view.textReads==0&&body.textReads==1);cases++;
  AccessibilityNodeInfo nestedBody=node(MARKER),nested=web(nestedBody),outer=web(nested);nested.text=MARKER;outer.text=MARKER;
  r=reduce(outer);check(r.complete&&r.webviews==2&&r.whole==1&&r.contains==1&&r.textNodes==1&&outer.textReads==0&&nested.textReads==0&&nestedBody.textReads==1);cases++;
  AccessibilityNodeInfo spoofLeaf=node(MARKER),spoof=web(spoofLeaf),owned=node(null);spoof.pkg="fixture.foreign";owned.children.add(spoof);
  r=reduce(owned);check(r.complete&&r.webviews==0&&r.whole==0&&spoof.childReads==0&&spoofLeaf.textReads==0);cases++;
  r=reduce(web(node("echo "+MARKER+" suffix")));check(r.contains==1&&r.whole==0);cases++;
  r=reduce(web(node(MARKER+"\\r\\n"+MARKER+"\\n"),node(MARKER)));check(r.contains==3&&r.whole==3&&r.textNodes==2);cases++;
  leaf=node(MARKER);leaf.width=0;r=reduce(web(leaf));check(r.complete&&r.whole==0&&r.textNodes==0&&leaf.textReads==0);cases++;
  r=reduce(web(node("x".repeat(4096))));check(r.complete&&r.chars==4096);cases++;
  leaf=node(null);leaf.text=new CharSequence(){public int length(){return 4097;}public char charAt(int i){throw new AssertionError("oversized text examined");}public CharSequence subSequence(int a,int b){throw new AssertionError();}};
  r=reduce(web(leaf));check(!r.complete&&r.textLimit&&r.chars==0);cases++;
  view=web();for(int i=0;i<64;i++)view.children.add(node("x".repeat(4096)));r=reduce(view);check(r.complete&&r.chars==262144);cases++;
  view=web();for(int i=0;i<65;i++)view.children.add(node("x".repeat(4096)));r=reduce(view);check(!r.complete&&r.textLimit&&r.chars==262144);cases++;
  root=node(null);for(int i=0;i<4095;i++)root.children.add(node(null));r=reduce(root);check(r.complete&&r.visited==4096);cases++;
  root=node(null);for(int i=0;i<4096;i++)root.children.add(node(null));r=reduce(root);check(!r.complete&&r.nodeLimit&&r.visited<=4096);cases++;
  root=web();AccessibilityNodeInfo cur=root;for(int i=0;i<64;i++){AccessibilityNodeInfo n=node(null);cur.children.add(n);cur=n;}cur.text=MARKER;r=reduce(root);check(r.complete&&r.whole==1);cases++;
  root=web();cur=root;for(int i=0;i<65;i++){AccessibilityNodeInfo n=node(null);cur.children.add(n);cur=n;}cur.text=MARKER;r=reduce(root);check(!r.complete&&r.depthLimit&&r.whole==0);cases++;
  view=web();view.children.add(null);r=reduce(view);check(!r.complete&&r.nullChildren==1&&r.status==TerminalUiObserver.Trace.NODE_UNAVAILABLE);cases++;
  leaf=node(MARKER);leaf.failText=true;view=web(leaf);r=reduce(view);check(!r.complete&&r.queryFailed&&view.recycles==1&&leaf.recycles==1);cases++;
  leaf=node(MARKER);leaf.failRecycle=true;view=web(leaf);r=reduce(view);check(!r.complete&&r.recycleFailed&&view.recycles==1&&leaf.recycles==1);cases++;
  view=web(node(MARKER));r=TerminalUiObserver.reduce(view,MARKER,0);check(!r.complete&&r.timeLimit&&view.recycles==1&&r.whole==0);cases++;
  view=web();for(int i=0;i<45;i++)view.children.add(node((MARKER+"\\n").repeat(93)));r=reduce(view);check(!r.complete&&r.matchLimit&&r.contains==4096&&r.whole<=r.contains&&r.chars<=262144);cases++;
  for(Bundle bad:new Bundle[]{null,args("215",MARKER,"1000"),args("11",MARKER.toUpperCase(),"1000"),args("11",MARKER,"999"),args("11",MARKER,"90001")}){
   Instrumentation.reset();new TerminalUiObserver().onCreate(bad);check(Instrumentation.starts==0&&Instrumentation.finishes==1&&Instrumentation.automationCalls==0);check(Instrumentation.resultObject.get("status").equals("arguments_refused"));cases++;
  }
  Instrumentation.reset();Instrumentation.target.name="com.android.virtualization.terminal";JSONObject out=run();check(out.get("status").equals("owner_refused")&&Instrumentation.automationCalls==0);safe(out);cases++;
  Instrumentation.reset();android.os.Process.uid=1010001;out=run();check(out.get("status").equals("owner_refused")&&Instrumentation.automationCalls==0);cases++;
  Instrumentation.reset();Instrumentation.target.users.unlocked=false;out=run();check(out.get("status").equals("user_locked")&&Instrumentation.automationCalls==0);cases++;
  Instrumentation.reset();Instrumentation.target.accessibility=null;out=run();check(out.get("status").equals("accessibility_unavailable")&&Instrumentation.automationCalls==0);cases++;
  Instrumentation.reset();Instrumentation.automation=null;out=run();check(out.get("status").equals("automation_unavailable"));cases++;
  Instrumentation.reset();Instrumentation.context.accessibility.touch=true;Instrumentation.automation.template=web(node("diagnostic body"));out=run();
  check(out.get("status").equals("completed")&&yes(out,"ready_sent")&&yes(out,"ui_automation_acquired"));
  check(!yes(out,"accessibility_enabled_before_connection")&&yes(out,"accessibility_enabled_after_connection")&&yes(out,"accessibility_enabled_before_finish"));
  check(yes(out,"touch_exploration_before_connection")&&yes(out,"touch_exploration_after_connection")&&yes(out,"touch_exploration_before_finish"));
  check(number(out,"polls")>=3&&number(out,"complete_polls")>=3&&((JSONArray)out.get("samples")).length()<=32);safe(out);cases++;
  check(Instrumentation.automation.clears==number(out,"polls")&&Instrumentation.automation.roots==number(out,"polls"));
  check(out.get("accessibility_cache_policy").equals("clear_before_each_poll"));
  Instrumentation.reset();Instrumentation.automation.cached=web(node("cached old row"));Instrumentation.automation.template=web(node(MARKER));out=run();
  check(number(out,"maximum_whole_line_marker_matches")==1&&number(out,"complete_polls")>=3&&Instrumentation.automation.clears==number(out,"polls"));safe(out);cases++;
  for(boolean throwsFailure:new boolean[]{false,true}) {
   Instrumentation.reset();Instrumentation.automation.template=web(node(MARKER));Instrumentation.automation.clearResult=false;Instrumentation.automation.failClear=throwsFailure;out=run();
   check(number(out,"complete_polls")==0&&number(out,"maximum_contains_marker_matches")==0&&Instrumentation.automation.roots==0&&Instrumentation.automation.clears==number(out,"polls"));
   JSONObject failure=(JSONObject)((JSONArray)out.get("samples")).values.get(0);check(yes(failure,"query_failed")&&!yes(failure,"poll_complete"));safe(out);cases++;
  }
  Instrumentation.reset();Instrumentation.failStatus=true;out=run();check(!yes(out,"ready_sent")&&Instrumentation.finishes==1);cases++;
  Instrumentation.reset();Instrumentation.automation.template=web(node(MARKER));Thread.currentThread().interrupt();out=run();check(out.get("status").equals("interrupted")&&Thread.interrupted());safe(out);cases++;
  Instrumentation.reset();Instrumentation.failFinish=true;Instrumentation.automation.template=web();out=run();
  JSONObject failure=Instrumentation.statuses.get(Instrumentation.statuses.size()-1);check(failure.get("status").equals("finish_failed")&&yes(failure,"finish_failed")&&!yes(failure,"framework_cleanup_verified"));cases++;
  System.out.println("PASS:"+cases+" owned observer cases; scope, caps, matching, identity, accessibility scalars and finish failures; no Android/runtime output proof");
 }
}''',
}

with tempfile.TemporaryDirectory(prefix="gb-terminal-ui-observer-host-") as temporary:
    base = Path(temporary)
    paths = []
    for relative, source in SOURCES.items():
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        paths.append(str(path))
    paths.append(str(ROOT / "crates/gb-framework/src/hardware_probe/TerminalUiObserver.java"))
    env = {key: value for key, value in os.environ.items() if key not in
           ("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")}
    subprocess.run([tools["javac"]["path"], "-d", str(base), *paths], env=env,
                   check=True, timeout=30)
    subprocess.run([tools["java"]["path"], "-cp", str(base),
                    "org.googlebook.port.terminaluiobserver.ObserverSelfTest"], env=env,
                   check=True, timeout=30)
