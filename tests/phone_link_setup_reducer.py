#!/usr/bin/env python3
"""Self-contained actual shell reducer tests; no device or private UI input.
Optional --guard-runner validates the real reduced synthetic shape through Rust.
"""
import argparse
from pathlib import Path
import json
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
ARGS=argparse.Namespace(guard_runner=None)
ROOT=Path(__file__).resolve().parents[1]
REDUCER=ROOT/'crates/gb-tools/src/phone_link_setup/reduce-setup.sh'
FOCUS='mCurrentFocus=Window{abc123 u11 com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity}'
TITLE='Cast your phone’s apps';BODY='Use your Android phone’s apps on your Googlebook with no installs needed'
def node(text='',kids='',**kw):
    attrs={'package':'com.google.ambient.streaming','class':'android.view.View','bounds':'[0,0][600,600]',
        'enabled':'true','clickable':'false','text':text,'content-desc':'','resource-id':'PRIVATE_ID'}
    attrs.update(kw)
    from xml.sax.saxutils import quoteattr
    a=' '.join(f'{k}={quoteattr(v)}' for k,v in attrs.items())
    return f'<node {a}>{kids}</node>'
def fixture(extra=''):
    title=node(TITLE,**{'class':'android.widget.TextView','bounds':'[100,100][500,140]'})
    body=node(BODY,**{'class':'android.widget.TextView','bounds':'[100,180][500,240]'})
    label=node('Get started',**{'class':'android.widget.TextView','bounds':'[220,400][380,440]'})
    button=node(kids=label,clickable='true',bounds='[100,380][500,460]')
    return '<hierarchy rotation="0">'+node(kids=title+body+button+extra)+'</hierarchy>'
def reduce(raw):
    with tempfile.TemporaryDirectory(prefix='gb-phone-redact-') as tmp:
        source=Path(tmp)/'private-fixture.xml';source.write_text(raw)
        return subprocess.run(['sh',str(REDUCER),str(source)],capture_output=True,text=True,timeout=3)
class Tests(unittest.TestCase):
    def test_positive_unknown_visibility_and_no_private_metadata(self):
        r=reduce(fixture());self.assertEqual(r.returncode,0,r.stderr);doc=ET.fromstring(r.stdout)
        self.assertNotIn('PRIVATE',r.stdout);self.assertNotIn('com.google.ambient.streaming',r.stdout)
        nodes=doc.findall('.//node');self.assertEqual(len(nodes),5)
        self.assertTrue(all(set(n.attrib)=={'package_scope','class','bounds','enabled','clickable','visibility','text','content-desc'} for n in nodes))
        self.assertTrue(all(n.attrib['visibility']=='unknown' for n in nodes))
        self.assertEqual(doc.find('gb-meta').attrib['visibility_attributes'],'0')
        if ARGS.guard_runner:
            p=subprocess.run([str(ARGS.guard_runner.resolve())],input=json.dumps({'owner':11,'focus':FOCUS,'xml':r.stdout}),capture_output=True,text=True,timeout=3)
            self.assertEqual(p.returncode,0,p.stderr);plan=json.loads(p.stdout);self.assertEqual((plan['x'],plan['y']),(300,420))
            self.assertFalse(plan['input_authorized']);self.assertFalse(plan['visibility_verified'])
    def test_foreign_webview_and_private_strings_never_export(self):
        for wrapper in [{'package':'PRIVATE_FOREIGN'},{'class':'android.webkit.WebView'},{'class':'PRIVATE_CLASS'}]:
            child=node('Get started',**{'content-desc':'Onboarding illustration'})
            r=reduce('<hierarchy>'+node('PRIVATE_BODY',child,**wrapper)+'</hierarchy>')
            self.assertEqual(r.returncode,0,r.stderr);doc=ET.fromstring(r.stdout)
            self.assertNotIn('PRIVATE',r.stdout);self.assertTrue(all(n.attrib['text']==n.attrib['content-desc']=='' for n in doc.findall('.//node')))
        r=reduce(fixture(node('private@example.invalid',**{'content-desc':'https://PRIVATE_SECRET','class':'PRIVATE_CLASS'})))
        self.assertEqual(r.returncode,0);self.assertNotIn('PRIVATE',r.stdout);self.assertNotIn('private@',r.stdout)
    def test_exact_literals_only_no_substrings_or_encoded_guess(self):
        for text in ['Get started suffix','prefix Get started','Get&#32;started','private peer','Get started\n']:
            r=reduce('<hierarchy>'+node(text)+'</hierarchy>');self.assertEqual(r.returncode,0)
            self.assertEqual(ET.fromstring(r.stdout).find('.//node').attrib['text'],'')
        for text in ['Get started','Searching for nearby devices','Scan the QR code using your phone to start setup']:
            r=reduce('<hierarchy>'+node(text)+'</hierarchy>');self.assertEqual(r.returncode,0)
            self.assertEqual(ET.fromstring(r.stdout).find('.//node').attrib['text'],text)
    def test_visibility_boolean_or_unknown_is_not_invented(self):
        r=reduce('<hierarchy>'+node(**{'visible-to-user':'true','visible':'true'})+'</hierarchy>')
        self.assertEqual(r.returncode,0);doc=ET.fromstring(r.stdout);self.assertEqual(doc.find('.//node').attrib['visibility'],'true');self.assertEqual(doc.find('gb-meta').attrib['visibility_attributes'],'2')
        for kw in [{'visible-to-user':'yes'},{'visible-to-user':'true','visible':'false'}]:
            self.assertEqual(reduce('<hierarchy>'+node(**kw)+'</hierarchy>').returncode,2)
    def test_malformed_duplicate_flags_counts_and_depth_refuse(self):
        bad=[fixture().replace('enabled="true"','enabled="maybe"',1),fixture().replace('enabled="true"','enabled="true" enabled="true"',1),
            fixture().replace('</hierarchy>',''),fixture().replace('bounds="[0,0][600,600]"','bounds="PRIVATE"',1),'<hierarchy/>' ]
        for raw in bad:self.assertEqual(reduce(raw).returncode,2)
        self.assertEqual(reduce('<hierarchy>'+('<node package="" class="" bounds="[0,0][1,1]" enabled="true" clickable="false"/>'*513)+'</hierarchy>').returncode,2)
        raw=node()
        for _ in range(32):raw=node(kids=raw)
        self.assertEqual(reduce('<hierarchy>'+raw+'</hierarchy>').returncode,2)
        # Both nonselfclosing and final selfclosing depth33 must be refused.
        raw='<node package="com.google.ambient.streaming" class="android.view.View" bounds="[0,0][600,600]" enabled="true" clickable="false"/>'
        for _ in range(32):raw=node(kids=raw)
        self.assertEqual(reduce('<hierarchy>'+raw+'</hierarchy>').returncode,2)
        self.assertEqual(reduce('x'*65537).returncode,2)
    def test_shell_source_has_no_actions_or_raw_emission(self):
        text=REDUCER.read_text()
        for forbidden in ['input tap','am start','settings put','logcat','print tag','print rest','print attrs["text"]']:
            self.assertNotIn(forbidden,text)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--guard-runner',type=Path);ARGS,rest=p.parse_known_args();unittest.main(argv=[__file__,*rest])
