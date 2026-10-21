#!/usr/bin/env python3
"""Actual owned Java onStart heartbeat-policy tests using public-API host stubs.
No Android/device, guest programs, accessibility connection or raw console reads.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('build_request',type=Path);args=parser.parse_args()
tools=json.loads(args.build_request.read_text())['java']['tools']
for name in ('java','javac'):
    path=Path(tools[name]['path'])
    if not path.is_absolute():path=args.build_request.parent/path
    assert path.is_file() and not path.is_symlink()
    with path.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==tools[name]['sha256']
    tools[name]['path']=str(path.resolve())
# Reuse owned stub definitions as inert AST literals; do not import/run the older
# driver or its tests. Compile this actual tracked helper, never a copied model.
tree=ast.parse((ROOT/'tests/android_terminal_ui_observer.py').read_text())
node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCES' for t in n.targets))
sources=ast.literal_eval(node.value)
del sources['org/googlebook/port/terminaluiobserver/ObserverSelfTest.java']
sources['org/googlebook/port/terminaluiobserver/HeartbeatSelfTest.java']=r'''package org.googlebook.port.terminaluiobserver;
import android.app.*;import android.os.*;import android.view.accessibility.*;import org.json.*;
public class HeartbeatSelfTest {
 static int cases;
 static final String MARKER="GB_UI_EXEC_0123456789abcdef0123456789abcdef";
 static void check(boolean v){if(!v)throw new AssertionError("owned heartbeat policy");}
 static Bundle args(String interval,String window,String duration){Bundle b=new Bundle();b.putString("expected_user","11");b.putString("marker",MARKER);b.putString("duration_ms",duration);if(interval!=null)b.putString("readiness_heartbeat_ms",interval);if(window!=null)b.putString("readiness_heartbeat_window_ms",window);return b;}
 static AccessibilityNodeInfo tree(){AccessibilityNodeInfo n=new AccessibilityNodeInfo();n.cls="android.webkit.WebView";AccessibilityNodeInfo row=new AccessibilityNodeInfo();row.text="owned stable row";n.children.add(row);return n;}
 static int number(JSONObject r,String k){return ((Number)r.get(k)).intValue();}
 static boolean yes(JSONObject r,String k){return Boolean.TRUE.equals(r.get(k));}
 static JSONObject run(String interval,String window,String duration){TerminalUiObserver o=new TerminalUiObserver();o.onCreate(args(interval,window,duration));check(Instrumentation.starts==1);o.onStart();check(Instrumentation.finishes==1);return Instrumentation.resultObject;}
 static int emitted(){int n=0;for(JSONObject r:Instrumentation.statuses)if("sample".equals(r.get("record_kind")))n++;return n;}
 public static void main(String[]ignored){
  // Real unchanged polls for >1second prove the historical change-only trap.
  Instrumentation.reset();Instrumentation.automation.template=tree();JSONObject r=run(null,null,"2250");
  check(r.get("status").equals("completed")&&number(r,"polls")>=6&&number(r,"complete_polls")==number(r,"polls"));
  check(emitted()==1&&Instrumentation.automation.clears==number(r,"polls"));cases++;
  // The optional policy emits actual new offsets for identical observations,
  // then reverts to change-only after the bounded window.
  Instrumentation.reset();Instrumentation.automation.template=tree();r=run("500","1500","2250");
  check(r.get("status").equals("completed")&&emitted()>=2&&emitted()<=4);long previous=-1;int repeats=0;
  for(JSONObject record:Instrumentation.statuses)if("sample".equals(record.get("record_kind"))){
   JSONObject sample=(JSONObject)record.get("sample");long offset=((Number)sample.get("offset_ms")).longValue();
   check(yes(sample,"poll_complete")&&number(sample,"nonempty_positive_width_text_nodes")==1&&number(sample,"whole_line_marker_matches")==0);
   if(previous>=0){check(offset-previous>=500&&offset<=1500);repeats++;}previous=offset;
  }
  check(repeats>=1&&Instrumentation.automation.clears==number(r,"polls")&&Instrumentation.automation.roots==number(r,"polls"));cases++;
  for(String[] bad:new String[][]{{"500",null},{null,"8000"},{"0","0"},{"250","1000"},{"500","0499"},{"500","499"},{"500","8001"},{"500","9000"},{"500","1001x"},{"500","+500"},{"500","2000"}}){
   Instrumentation.reset();new TerminalUiObserver().onCreate(args(bad[0],bad[1],"1000"));check(Instrumentation.starts==0&&Instrumentation.finishes==1&&Instrumentation.automationCalls==0&&Instrumentation.resultObject.get("status").equals("arguments_refused"));cases++;
  }
  int beats=0;long last=0;
  for(long offset=250;offset<=10000;offset+=250)if(TerminalUiObserver.heartbeatDue(500,8000,offset,last)){last=offset;beats++;}
  check(beats==16&&last==8000);cases++;
  check(!TerminalUiObserver.heartbeatDue(0,0,500,0)&&!TerminalUiObserver.heartbeatDue(500,8001,500,0)&&!TerminalUiObserver.heartbeatDue(500,8000,499,0)&&!TerminalUiObserver.heartbeatDue(500,8000,8001,0)&&!TerminalUiObserver.heartbeatDue(500,8000,500,-1)&&!TerminalUiObserver.heartbeatDue(500,8000,500,501));cases++;
  // Real changing polls still share the original32record budget. Overflow stays
  // explicit/fail-closed; optional repeated observations do not bypass it.
  Instrumentation.reset();Instrumentation.automation=new UiAutomation(){@Override public AccessibilityNodeInfo getRootInActiveWindow(){AccessibilityNodeInfo n=super.getRootInActiveWindow();n.children.get(0).text=roots%2==0?"x":"xx";return n;}};
  Instrumentation.automation.template=tree();r=run("500","8000","9000");
  check(number(r,"polls")>32&&number(r,"samples_dropped")>0&&yes(r,"sample_budget_exceeded")&&((JSONArray)r.get("samples")).length()==32&&emitted()==32);cases++;
  check(!yes(r,"command_execution_verified")&&!yes(r,"input_performed")&&!yes(r,"raw_content_exported")&&!r.toString().contains(MARKER));cases++;
  System.out.println("PASS:"+cases+" actual observer heartbeat cases; stable/default/opt-in/window/args/budget/privacy; host stubs only");
 }
}'''
with tempfile.TemporaryDirectory(prefix='gb-terminal-heartbeat-host-') as tmp:
    base=Path(tmp);paths=[]
    for relative,source in sources.items():
        path=base/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(source);paths.append(str(path))
    paths.append(str(ROOT/'crates/gb-framework/src/hardware_probe/TerminalUiObserver.java'))
    env={k:v for k,v in os.environ.items() if k not in ('CLASSPATH','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS')}
    subprocess.run([tools['javac']['path'],'-d',str(base),*paths],env=env,check=True,timeout=30)
    subprocess.run([tools['java']['path'],'-cp',str(base),'org.googlebook.port.terminaluiobserver.HeartbeatSelfTest'],env=env,check=True,timeout=30)
