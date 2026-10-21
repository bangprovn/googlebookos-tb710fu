#!/usr/bin/env python3
"""Actual owned Java collector tests against tracked public-API host stubs.
No Android/device/Google application code runs. Optional --inspect-runner checks
actual Java-produced scalar JSON through the newly built strict Rust parser.
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
p=argparse.ArgumentParser();p.add_argument('build_request',type=Path);p.add_argument('--inspect-runner',type=Path);args=p.parse_args()
tools=json.loads(args.build_request.read_text())['java']['tools']
for name in ('java','javac'):
    path=Path(tools[name]['path'])
    if not path.is_absolute():path=args.build_request.parent/path
    assert path.is_file() and not path.is_symlink()
    with path.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==tools[name]['sha256']
    tools[name]['path']=str(path.resolve())
# Inert literal AST reuse of tracked public Android API stubs. Never imports or
# executes the older collector/test driver; this test compiles the current source.
tree=ast.parse((ROOT/'tests/android_terminal_ui_observer.py').read_text())
node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCES' for t in n.targets))
sources=ast.literal_eval(node.value)
sources.pop('org/googlebook/port/terminaluiobserver/ObserverSelfTest.java')
sources['android/content/Context.java']=sources['android/content/Context.java'].replace('org.googlebook.port.terminaluiobserver','org.googlebook.port.phonelinkui')
sources['android/graphics/Rect.java']=sources['android/graphics/Rect.java'].replace('public int width(){return right-left;}','public int width(){return right-left;}public int height(){return bottom-top;}')
sources['android/view/accessibility/AccessibilityNodeInfo.java']=sources['android/view/accessibility/AccessibilityNodeInfo.java'].replace('com.android.virtualization.terminal','com.google.ambient.streaming').replace('public CharSequence text;','public CharSequence text,description;public boolean visible=true;public int height=20,descriptionReads;').replace('out.bottom=20','out.bottom=height').replace('public int getChildCount()', 'public CharSequence getContentDescription(){descriptionReads++;return description;}public boolean isVisibleToUser(){return visible;}public int getChildCount()')
sources['android/app/UiAutomation.java']=sources['android/app/UiAutomation.java'].replace('c.text=n.text;','c.text=n.text;c.description=n.description;c.visible=n.visible;c.height=n.height;')
sources['org/googlebook/port/phonelinkui/ProbeSelfTest.java']=r'''package org.googlebook.port.phonelinkui;
import android.app.*;import android.os.*;import android.view.accessibility.*;import org.json.*;
public class ProbeSelfTest {
 static int cases;static void check(boolean v){if(!v)throw new AssertionError("PhoneLink scalar fixture");}
 static AccessibilityNodeInfo node(String text){AccessibilityNodeInfo n=new AccessibilityNodeInfo();n.text=text;return n;}
 static PhoneLinkUiProbe.Sample reduce(AccessibilityNodeInfo n){return PhoneLinkUiProbe.reduce(n,Long.MAX_VALUE);}
 static Bundle args(String user){Bundle b=new Bundle();if(user!=null)b.putString("expected_user",user);return b;}
 static int number(JSONObject r,String key){return ((Number)r.get(key)).intValue();}
 static boolean yes(JSONObject r,String key){return Boolean.TRUE.equals(r.get(key));}
 public static void main(String[]unused)throws Exception {
  AccessibilityNodeInfo leaf=node(PhoneLinkUiProbe.LITERALS[0]);PhoneLinkUiProbe.Sample s=reduce(leaf);
  check(s.complete&&s.text[0]==1&&s.recycled==1&&leaf.textReads==1&&leaf.descriptionReads==1);cases++;
  for(int i=0;i<11;i++){AccessibilityNodeInfo n=node(PhoneLinkUiProbe.LITERALS[i]);n.description=PhoneLinkUiProbe.LITERALS[i];s=reduce(n);check(s.complete&&s.text[i]==1&&s.description[i]==1);}cases++;
  s=reduce(node("prefix "+PhoneLinkUiProbe.LITERALS[0]));check(s.complete&&s.text[0]==0);cases++;
  leaf=node("PRIVATE_ACCOUNT_AND_PEER");leaf.description="PRIVATE_UNKNOWN_BODY";s=reduce(leaf);String serialized=s.json().toString();check(s.complete&&!serialized.contains("PRIVATE")&&s.text[0]==0);cases++;
  leaf=node(PhoneLinkUiProbe.LITERALS[0]);AccessibilityNodeInfo foreign=node(PhoneLinkUiProbe.LITERALS[0]);foreign.pkg="foreign.private";foreign.children.add(leaf);s=reduce(foreign);check(!s.complete&&!s.target&&s.foreign==1&&foreign.textReads==0&&foreign.childReads==0&&leaf.textReads==0&&foreign.recycles==1);cases++;
  leaf=node(PhoneLinkUiProbe.LITERALS[0]);AccessibilityNodeInfo web=node(PhoneLinkUiProbe.LITERALS[0]);web.cls="android.webkit.WebView";web.children.add(leaf);s=reduce(web);check(!s.complete&&s.webviews==1&&web.textReads==0&&web.childReads==0&&leaf.textReads==0&&web.recycles==1);cases++;
  web=node(null);web.cls="android.webkit.WebView";web.children.add(node(PhoneLinkUiProbe.LITERALS[0]));AccessibilityNodeInfo root=node(null);root.children.add(web);s=reduce(root);check(s.complete&&s.webviews==1&&s.text[0]==0&&web.childReads==0);cases++;
  for(int mode=0;mode<3;mode++){leaf=node(PhoneLinkUiProbe.LITERALS[0]);if(mode==0)leaf.width=0;if(mode==1)leaf.height=0;if(mode==2)leaf.visible=false;s=reduce(leaf);check(s.complete&&s.text[0]==0&&leaf.textReads==0&&leaf.descriptionReads==0);}cases++;
  root=node(null);for(int i=0;i<512;i++)root.children.add(node(PhoneLinkUiProbe.LITERALS[0]));s=reduce(root);check(!s.complete&&s.nodeLimit&&s.visited==1&&root.childReads==0&&root.recycles==1);cases++;
  root=node(null);AccessibilityNodeInfo tail=root;for(int i=0;i<33;i++){AccessibilityNodeInfo child=node(null);tail.children.add(child);tail=child;}s=reduce(root);check(!s.complete&&s.depthLimit&&s.visited==33&&s.recycled==33);cases++;
  s=reduce(node("x".repeat(2049)));check(!s.complete&&s.textLimit&&s.chars==0);cases++;
  root=node(null);root.children.add(null);s=reduce(root);check(!s.complete&&s.nullChildren==1&&s.recycled==1);cases++;
  root=node(null);root.failText=true;s=reduce(root);check(!s.complete&&s.queryFailed&&root.recycles==1);cases++;
  root=node(null);root.failRecycle=true;s=reduce(root);check(!s.complete&&s.recycleFailed&&s.recycled==0);cases++;
  check(!reduce(null).complete);root=node(null);s=PhoneLinkUiProbe.reduce(root,0);check(!s.complete&&s.timeLimit&&root.recycles==1);cases++;
  for(String bad:new String[]{null,"0","011","11x","12"}){Instrumentation.reset();new PhoneLinkUiProbe().onCreate(args(bad));check(Instrumentation.starts==0&&Instrumentation.finishes==1&&Instrumentation.automationCalls==0);}cases++;
  Instrumentation.reset();Instrumentation.target.name="foreign";PhoneLinkUiProbe q=new PhoneLinkUiProbe();q.onCreate(args("11"));q.onStart();check(Instrumentation.automationCalls==0&&Instrumentation.finishes==1&&Instrumentation.resultObject.get("status").equals("owner_refused"));cases++;
  // Actual unchanged native tree: two fresh cache-cleared queries with a >5s
  // separation. This is a finite observation interval, never continuous proof.
  Instrumentation.reset();Instrumentation.automation.template=node(PhoneLinkUiProbe.LITERALS[0]);q=new PhoneLinkUiProbe();q.onCreate(args("11"));q.onStart();JSONObject r=Instrumentation.resultObject;
  check(Instrumentation.starts==1&&Instrumentation.finishes==1&&Instrumentation.finishCode==0&&r.get("status").equals("completed")&&number(r,"cache_clear_attempts")==2&&number(r,"cache_clear_successes")==2&&number(r,"root_queries")==2&&Instrumentation.automation.clears==2&&Instrumentation.automation.roots==2);
  JSONArray rows=(JSONArray)r.get("samples");check(rows.length()==2);JSONObject second=(JSONObject)rows.values.get(1);check(((Number)second.get("offset_ms")).longValue()>=5500&&yes(second,"poll_complete"));
  check(!yes(r,"input_performed")&&!yes(r,"raw_content_exported")&&!yes(r,"registration_verified")&&!yes(r,"active_rf_scan_verified")&&!yes(r,"framework_cleanup_verified")&&!r.toString().contains(PhoneLinkUiProbe.LITERALS[0]));cases++;
  System.out.println("PASS:"+cases+" actual PhoneLink collector cases; host API stubs only");System.out.println(r.toString());
 }
}'''
with tempfile.TemporaryDirectory(prefix='gb-phone-ui-host-') as tmp:
    base=Path(tmp);paths=[]
    for relative,source in sources.items():
        path=base/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(source);paths.append(str(path))
    paths.append(str(ROOT/'crates/gb-framework/src/phone_link_ui_probe/PhoneLinkUiProbe.java'))
    env={k:v for k,v in os.environ.items() if k not in ('CLASSPATH','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS')}
    subprocess.run([tools['javac']['path'],'-d',str(base),*paths],env=env,check=True,timeout=30)
    r=subprocess.run([tools['java']['path'],'-cp',str(base),'org.googlebook.port.phonelinkui.ProbeSelfTest'],env=env,check=False,capture_output=True,text=True,timeout=20)
    if r.returncode:raise RuntimeError(r.stderr[:4096])
    assert len(r.stdout)<16384 and not r.stderr
    lines=r.stdout.splitlines();assert len(lines)==2 and lines[0].startswith('PASS:');value=json.loads(lines[1]);assert value['status']=='completed'
    if args.inspect_runner:
        source=base/'report.json';source.write_text(lines[1]);target=base/'inspected.json'
        subprocess.run([str(args.inspect_runner.resolve()),'inspect',str(source),str(target)],check=True,capture_output=True,timeout=10)
        assert json.loads(target.read_text())['receipt']==value
    print(lines[0]);print('PASS: actual Java scalar report privacy/schema'+(' and strict Rust parser' if args.inspect_runner else ''))
