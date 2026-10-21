#!/usr/bin/env python3
"""Owned synthetic XML only; verifies source redaction without Android access."""
from pathlib import Path
import subprocess,tempfile,unittest,xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];REDUCER=ROOT/'crates/gb-tools/src/terminal_ui/reduce-controls.sh'
def node(text='',desc='',package='com.android.virtualization.terminal',cls='android.view.View',body='',quote='"'):
 attrs=dict(package=package,**{'class':cls},text=text,**{'content-desc':desc},bounds='[0,0][100,100]',enabled='true',clickable='false',focusable='false',focused='false',selected='false',password='false')
 return '<node '+ ' '.join(k+'='+quote+v+quote for k,v in attrs.items())+'>'+body+'</node>'
def run(xml):
 with tempfile.TemporaryDirectory() as t:
  p=Path(t)/'ui';p.write_text(xml)
  return subprocess.run(['sh',str(REDUCER),str(p)],capture_output=True,text=True,timeout=3)
class Controls(unittest.TestCase):
 def test_both_quote_styles_produce_identical_native_inventory(self):
  a=run('<hierarchy>'+node(text='PRIVATE_SENTINEL',desc='Add tab')+'</hierarchy>');b=run('<hierarchy>'+node(text='PRIVATE_SENTINEL',desc='Add tab',quote="'")+'</hierarchy>')
  self.assertEqual(a.returncode,0);self.assertEqual(b.returncode,0);self.assertEqual(a.stdout,b.stdout);self.assertNotIn('PRIVATE',a.stdout);self.assertIn('Add tab',a.stdout)
 def test_opposite_quote_inside_private_attribute_stays_private(self):
  a=run('<hierarchy>'+node(text='PRIVATE_SENTINEL "quoted"',quote="'")+'</hierarchy>');self.assertEqual(a.returncode,0,a.stderr);self.assertNotIn('PRIVATE',a.stdout)
 def test_only_known_control_descriptions_survive(self):
  a=run('<hierarchy>'+node(text='SECRET',desc='PRIVATE_DESCRIPTION')+'</hierarchy>');self.assertEqual(a.returncode,0);self.assertNotIn('SECRET',a.stdout);self.assertNotIn('PRIVATE',a.stdout)
 def test_foreign_packages_are_reduced_and_webview_ancestry_preserved(self):
  x='<hierarchy>'+node(package='private.other',body=node(cls='android.webkit.WebView',body=node(cls='android.widget.TextView',text='SECRET',desc='Add tab')))+'</hierarchy>'
  a=run(x);self.assertEqual(a.returncode,0);self.assertNotIn('private.other',a.stdout);d=ET.fromstring(a.stdout);self.assertEqual(d.find('.//node').attrib['package'],'redacted.foreign');self.assertIsNotNone(d.find('.//node[@class="android.webkit.WebView"]'));self.assertNotIn('SECRET',a.stdout)
 def test_duplicate_attribute_bad_bounds_and_missing_hierarchy_refuse(self):
  v='<hierarchy>'+node()+'</hierarchy>'
  for bad in [v.replace('enabled="true"','enabled="true" enabled="false"'),v.replace('[0,0][100,100]','[-1,0][100,100]'),v[:-12]]:
   self.assertNotEqual(run(bad).returncode,0)
 def test_mismatched_quotes_refuse(self):
  self.assertNotEqual(run('<hierarchy>'+node().replace('package="','package=\'',1)+'</hierarchy>').returncode,0)
if __name__=='__main__':unittest.main()
