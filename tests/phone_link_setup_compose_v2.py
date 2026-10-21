#!/usr/bin/env python3
"""Actual separately-versioned shell classifier/Compose reducer tests, no device.
Old reducer/guard fixtures remain immutable. Optional new Rust guard crosscheck.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from xml.sax.saxutils import quoteattr
ROOT=Path(__file__).resolve().parents[1]
REDUCER=ROOT/'crates/gb-tools/src/phone_link_setup/reduce-setup-v2.sh'
ARGS=argparse.Namespace(guard_runner=None)
FOCUS='mCurrentFocus=Window{123abc u11 com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity}'
def node(text='',kids='',**extra):
    a={'package':'com.google.ambient.streaming','class':'android.view.View','bounds':'[0,0][600,600]','enabled':'true','clickable':'false','text':text,'content-desc':''};a.update(extra)
    return '<node '+' '.join(k+'='+quoteattr(v) for k,v in a.items())+'>'+kids+'</node>'
def fixture(classname='androidx.compose.ui.platform.ComposeView'):
    title=node('Cast your phone’s apps',**{'class':'android.widget.TextView','bounds':'[100,100][400,140]'})
    body=node('Use your Android phone’s apps on your Googlebook with no installs needed',**{'class':'android.widget.TextView','bounds':'[100,180][400,240]'})
    label=node('Get started',**{'class':'android.widget.TextView','bounds':'[120,400][280,440]'})
    button=node(kids=label,clickable='true',bounds='[100,380][300,460]')
    return '<hierarchy>'+node(kids=node(kids=title+body+button,**{'class':classname}),**{'class':'android.widget.FrameLayout'})+'</hierarchy>'
def run(raw,classify=False):
    with tempfile.TemporaryDirectory(prefix='gb-phone-compose-') as tmp:
        p=Path(tmp)/'private.xml';p.write_text(raw)
        return subprocess.run(['sh',str(REDUCER),*(['--classify'] if classify else []),str(p)],capture_output=True,text=True,timeout=3)
class Tests(unittest.TestCase):
    def test_only_exact_source_compose_gains_native_label_visibility(self):
        r=run(fixture());self.assertEqual(r.returncode,0,r.stderr);doc=ET.fromstring(r.stdout)
        self.assertEqual(sum(n.attrib['text']=='Get started' for n in doc.findall('.//node')),1)
        self.assertEqual(sum(n.attrib['class']=='androidx.compose.ui.platform.ComposeView' for n in doc.findall('.//node')),1)
        if ARGS.guard_runner:
            p=subprocess.run([str(ARGS.guard_runner.resolve())],input=json.dumps({'owner':11,'focus':FOCUS,'xml':r.stdout}),capture_output=True,text=True,timeout=3)
            self.assertEqual(p.returncode,0,p.stderr);plan=json.loads(p.stdout);self.assertEqual((plan['x'],plan['y']),(200,420));self.assertFalse(plan['input_authorized']);self.assertFalse(plan['visibility_verified'])
    def test_other_candidates_remain_pruned_not_promoted(self):
        for name in ['androidx.compose.ui.platform.AndroidComposeView','androidx.compose.ui.platform.AbstractComposeView','PRIVATE_CLASS','android.webkit.WebView']:
            r=run(fixture(name));self.assertEqual(r.returncode,0,r.stderr);doc=ET.fromstring(r.stdout)
            self.assertTrue(all(not n.attrib['text'] and not n.attrib['content-desc'] for n in doc.findall('.//node')))
            self.assertNotIn('PRIVATE',r.stdout)
    def test_classification_is_only_fixed_counts_never_labels_or_names(self):
        nodes=''.join(node('PRIVATE_PEER',**{'class':c,'content-desc':'Get started'}) for c in ['androidx.compose.ui.platform.ComposeView','androidx.compose.ui.platform.AndroidComposeView','androidx.compose.ui.platform.AbstractComposeView','android.widget.ProgressBar','android.webkit.WebView','PRIVATE_CLASS','android.view.View'])
        r=run('<hierarchy>'+node(kids=nodes)+'</hierarchy>',True);self.assertEqual(r.returncode,0,r.stderr);v=json.loads(r.stdout)
        self.assertEqual(v['class_counts'],{'compose_view':1,'android_compose_view':1,'abstract_compose_view':1,'progress_bar':1,'webview':1,'known_native':2,'unknown_other':1})
        self.assertEqual(v['nodes'],8);self.assertFalse(v['class_names_exported']);self.assertFalse(v['raw_content_exported']);self.assertFalse(v['target_identity_verified'])
        for forbidden in ['PRIVATE','Get started','ComposeView','android.view.View','<node']:self.assertNotIn(forbidden,r.stdout)
    def test_malformed_classification_and_foreign_scope_fail_safe(self):
        r=run(fixture().replace('com.google.ambient.streaming','PRIVATE_FOREIGN'),True);self.assertEqual(r.returncode,0);v=json.loads(r.stdout);self.assertEqual(v['foreign_nodes'],6);self.assertTrue(all(n==0 for n in v['class_counts'].values()))
        for raw in [fixture().replace('</hierarchy>',''),fixture().replace('enabled="true"','enabled="bad"',1),'x'*65537]:
            self.assertEqual(run(raw,True).returncode,2)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--guard-runner',type=Path);ARGS,rest=p.parse_known_args();unittest.main(argv=[__file__,*rest])
