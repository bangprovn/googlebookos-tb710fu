#!/usr/bin/env python3
"""Owned synthetic command/row tests. No Android contact or donor execution."""
import json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BOOT='12345678-1234-1234-1234-123456789abc'
GUEST='abcdef01-2345-6789-abcd-0123456789ab'
NONCE='9876543210abcdef0123456789abcdef'
REDUCER=ROOT/'crates/gb-tools/src/terminal_workload/reduce-metadata.sh'
PLAN=json.loads(subprocess.check_output([str(ROOT/'target/debug/examples/terminal_workload'),NONCE,BOOT],text=True))
def run_command(boot=GUEST,kernel='6.12.48-owned-test',arch='aarch64',memory=2015232,fail_hash=False):
 with tempfile.TemporaryDirectory() as tmp:
  p=Path(tmp)
  scripts={'cat':"printf '%s' '"+boot+"'",'uname':"case \"$1\" in -s) echo Linux;;-r) echo '"+kernel+"';;-m) echo '"+arch+"';;*)exit 2;;esac",'awk':f'echo {memory}'}
  if fail_hash:scripts['sha256sum']='exit 1'
  for name,script in scripts.items():
   f=p/name;f.write_text('#!/bin/sh\n'+script+'\n');f.chmod(0o700)
  env=dict(os.environ,PATH=str(p)+':/usr/bin:/bin')
  return subprocess.run(['/bin/sh','-c',PLAN['command']],capture_output=True,text=True,timeout=8,env=env)
def rows():
 r=run_command();assert r.returncode==0
 return [x for x in r.stdout.splitlines() if x.startswith(PLAN['metadata_prefix']+'|')]
def xml(lines,package='com.android.virtualization.terminal',web=True,editor=False):
 def node(cls,text='',body='',bounds='[0,0][600,50]',pkg=package):
  return '<node package="'+pkg+'" class="'+cls+'" bounds="'+bounds+'" text="'+text+'">'+body+'</node>'
 leaf=''.join(node('android.widget.TextView',s) for s in lines)
 if editor:leaf=node('android.widget.EditText',body=leaf)
 return '<hierarchy>'+node('android.webkit.WebView' if web else 'android.view.View',body=leaf)+'</hierarchy>'
def reduce(content):
 with tempfile.TemporaryDirectory() as tmp:
  p=Path(tmp);a=p/'ui.xml';a.write_text(content);a.chmod(0o600);b=p/'prefix';b.write_text(PLAN['metadata_prefix']+'\n');b.chmod(0o600)
  return subprocess.run(['sh',str(REDUCER),str(a),str(b)],capture_output=True,text=True,timeout=3)
class Protocol(unittest.TestCase):
 def test_actual_owned_shell_command_and_normalized_values(self):
  r=run_command();self.assertEqual(r.returncode,0);self.assertIn('\n'+PLAN['success_marker']+'\n',r.stdout)
  self.assertEqual(len(rows()),14);self.assertLessEqual(max(map(len,rows())),40)
  q=reduce(xml(rows()));self.assertEqual(q.returncode,0,q.stderr);d=json.loads(q.stdout)
  self.assertEqual(d['guest_boot_id'],GUEST);self.assertEqual(d['kernel_release'],'6.12.48-owned-test');self.assertEqual(d['memtotal_kib'],2015232);self.assertTrue(d['known_answer_sha256_matches']);self.assertFalse(d['command_execution_verified'])
 def test_single_quoted_attributes_are_valid_without_decoding_other_text(self):
  content=xml(rows()).replace(chr(34),chr(39))
  q=reduce(content);self.assertEqual(q.returncode,0,q.stderr)
  self.assertEqual(json.loads(q.stdout)['guest_boot_id'],GUEST)
 def test_mixed_quotes_keep_embedded_quote_private(self):
  content=xml(rows()+['PRIVATE_SENTINEL']).replace('text="PRIVATE_SENTINEL"',"text='PRIVATE_SENTINEL \"quoted\"'")
  q=reduce(content);self.assertEqual(q.returncode,0,q.stderr);self.assertNotIn('PRIVATE',q.stdout)
 def test_unclosed_or_mismatched_attribute_quote_is_rejected(self):
  content=xml(rows()).replace('text="'+rows()[0]+'"',"text='"+rows()[0]+'"')
  self.assertNotEqual(reduce(content).returncode,0)
 def test_own_success_marker_is_not_an_extra_metadata_row(self):
  self.assertIn(PLAN['metadata_prefix'],PLAN['success_marker'])
  q=reduce(xml(rows()+[PLAN['success_marker']]))
  self.assertEqual(q.returncode,0,q.stderr)
  self.assertEqual(json.loads(q.stdout)['guest_boot_id'],GUEST)
 def test_nonce_substring_without_frame_is_not_exported(self):
  q=reduce(xml(rows()+['PRIVATE_SENTINEL '+PLAN['metadata_prefix']+' trailing']))
  self.assertEqual(q.returncode,0,q.stderr);self.assertNotIn('PRIVATE',q.stdout)
 def test_maximum_kernel_uses_explicit_fragments(self):
  k='6.12.48-'+('a'*72);self.assertEqual(len(k),80)
  r=run_command(kernel=k);self.assertEqual(r.returncode,0)
  q=reduce(xml([s for s in r.stdout.splitlines() if s.startswith(PLAN['metadata_prefix']+'|')]));self.assertEqual(q.returncode,0);self.assertEqual(json.loads(q.stdout)['kernel_release'],k)
 def test_semantic_negative_cases_emit_no_success_marker(self):
  for kw in [dict(boot=BOOT),dict(arch='x86_64'),dict(kernel='6.6.1'),dict(memory=1000000),dict(memory=4000000),dict(fail_hash=True),dict(kernel='6.12.'+'a'*80)]:
   with self.subTest(kw=kw):
    r=run_command(**kw);self.assertNotIn(PLAN['success_marker'],r.stdout);self.assertNotEqual(r.returncode,0)
 def test_missing_each_fragment(self):
  good=rows()
  for i in range(14):
   with self.subTest(i=i):self.assertNotEqual(reduce(xml(good[:i]+good[i+1:])).returncode,0)
 def test_duplicate_each_fragment(self):
  good=rows()
  for i in range(14):
   with self.subTest(i=i):self.assertNotEqual(reduce(xml(good+[good[i]])).returncode,0)
 def test_split_rows_are_not_joined(self):
  good=rows();bad=good[:];v=bad.pop(0);bad.extend([v[:20],v[20:]]);self.assertNotEqual(reduce(xml(bad)).returncode,0)
 def test_combined_rows_are_not_split(self):
  good=rows();self.assertNotEqual(reduce(xml([good[0]+' '+good[1]]+good[2:])).returncode,0)
 def test_foreign_native_editor_and_root_text_not_metadata(self):
  good=rows()
  for opts in [dict(package='other.package'),dict(web=False),dict(editor=True)]:
   self.assertNotEqual(reduce(xml(good,**opts)).returncode,0)
 def test_unrelated_private_text_is_not_exported(self):
  q=reduce(xml(rows()+['PRIVATE_SENTINEL password email']));self.assertEqual(q.returncode,0);self.assertNotIn('PRIVATE',q.stdout)
 def test_unknown_index_bad_terminator_and_entity_refused(self):
  good=rows()
  for value in [good[0].replace('|b0|','|b2|'),good[0][:-1]+'END',good[0].replace('|b0|','|b&#48;|')]:
   bad=good[:];bad[0]=value;self.assertNotEqual(reduce(xml(bad)).returncode,0)
 def test_missing_kernel_middle_is_not_silently_joined(self):
  good=rows();i=next(i for i,s in enumerate(good) if '|k0|' in s);good[i]=PLAN['metadata_prefix']+'|k0||E'
  self.assertNotEqual(reduce(xml(good)).returncode,0)
 def test_order_is_explicit_not_screen_position(self):
  q=reduce(xml(list(reversed(rows()))));self.assertEqual(q.returncode,0)
if __name__=='__main__':unittest.main()
