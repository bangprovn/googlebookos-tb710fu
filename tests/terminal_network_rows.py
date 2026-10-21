#!/usr/bin/env python3
"""Network command fixtures use fake local curl/getent only, never real network/ADB."""
from pathlib import Path
import json,os,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1];TOOL=ROOT/'target/debug/examples/terminal_network'
NONCE='1234567890abcdef0123456789abcdef';GUEST='00000000-0000-4000-8000-000000000003'
PLAN=json.loads(subprocess.check_output([str(TOOL),'prepare',NONCE,GUEST],text=True))
REDUCER=ROOT/'crates/gb-tools/src/terminal_network/reduce-network.sh'
def execute(metrics='200|1234|0',curl_exit=0,dns_exit=0,curl=True,getent=True,boot=GUEST):
 with tempfile.TemporaryDirectory() as t:
  p=Path(t);scripts={'cat':"printf '%s' '"+boot+"'"}
  if curl:scripts['curl']='printf \'%s\\n\' "$@" > "$OWNED_ARGS_FILE";printf \'%s\' "$OWNED_METRICS";exit "$OWNED_CURL_EXIT"'
  if getent:scripts['getent']='[ "$1" = ahosts ] && [ "$2" = deb.debian.org ] || exit 99;exit "$OWNED_DNS_EXIT"'
  for name,body in scripts.items():
   f=p/name;f.write_text('#!/bin/sh\n'+body+'\n');f.chmod(0o700)
  (p/'timeout').symlink_to('/usr/bin/timeout')
  env=dict(os.environ,PATH=str(p),OWNED_ARGS_FILE=str(p/'args'),OWNED_METRICS=metrics,OWNED_CURL_EXIT=str(curl_exit),OWNED_DNS_EXIT=str(dns_exit))
  r=subprocess.run(['/bin/sh','-c',PLAN['command']],env=env,capture_output=True,text=True,timeout=3)
  return r,(p/'args').read_text().splitlines() if (p/'args').exists() else []
def rows(**kw):return [s for s in execute(**kw)[0].stdout.splitlines() if s.startswith(PLAN['metadata_prefix']+'|')]
def xml(lines,own=True,web=True,editor=False,quotes='double'):
 pkg='com.android.virtualization.terminal' if own else 'other.package'
 def n(cls,text='',body=''):return f'<node package="{pkg}" class="{cls}" bounds="[0,0][600,50]" text="{text}">{body}</node>'
 body=''.join(n('android.widget.TextView',s) for s in lines)
 if editor:body=n('android.widget.EditText',body=body)
 text='<hierarchy>'+n('android.webkit.WebView' if web else 'android.view.View',body=body)+'</hierarchy>'
 return text if quotes=='double' else text.replace('"',"'")
def reduce(lines=None,content=None):
 with tempfile.TemporaryDirectory() as t:
  p=Path(t);a=p/'ui';a.write_text(content if content is not None else xml(rows() if lines is None else lines));a.chmod(0o600);b=p/'prefix';b.write_text(PLAN['metadata_prefix']+'\n');b.chmod(0o600)
  return subprocess.run(['sh',str(REDUCER),str(a),str(b)],capture_output=True,text=True,timeout=3)
def validate(d):return subprocess.run([str(TOOL),'validate'],input=json.dumps(d),capture_output=True,text=True,timeout=3)
class Network(unittest.TestCase):
 def test_success_is_bound_to_guest_and_all_network_predicates(self):
  r,args=execute();self.assertEqual(r.returncode,0);self.assertIn('\n'+PLAN['success_marker']+'\n',r.stdout)
  self.assertEqual(args[0],'-q');self.assertIn('--noproxy',args);self.assertIn('--max-filesize',args);self.assertIn('65536',args);self.assertIn('--max-time',args);self.assertIn('--proto',args);self.assertNotIn('--insecure',args);self.assertEqual(args[-1],PLAN['endpoint'])
  self.assertEqual(len(rows()),8);self.assertLessEqual(max(map(len,rows())),PLAN['maximum_output_row_chars'])
  q=reduce(rows()+[PLAN['success_marker']]);self.assertEqual(q.returncode,0,q.stderr);d=json.loads(q.stdout);self.assertEqual(d['downloaded_bytes'],1234)
  v=validate(d);self.assertEqual(v.returncode,0,v.stderr);self.assertTrue(json.loads(v.stdout)['requested_semantics_match']);self.assertFalse(json.loads(v.stdout)['command_execution_verified'])
 def test_foreign_guest_never_invokes_network(self):
  r,args=execute(boot='abcdef01-2345-6789-abcd-0123456789ab');self.assertNotEqual(r.returncode,0);self.assertEqual(args,[]);self.assertEqual(r.stdout,'')
 def test_failures_have_exact_numeric_rows_and_no_success_marker(self):
  for kw in [dict(curl=False),dict(getent=False),dict(dns_exit=2),dict(curl_exit=6,metrics='000|0|0'),dict(curl_exit=60,metrics='000|0|20'),dict(metrics='503|10|0'),dict(metrics='200|1234|20'),dict(metrics='200|0|0'),dict(metrics='')]:
   with self.subTest(kw=kw):
    r,_=execute(**kw);self.assertNotEqual(r.returncode,0);self.assertNotIn(PLAN['success_marker'],r.stdout)
    q=reduce(rows(**kw));self.assertEqual(q.returncode,0,q.stderr);v=validate(json.loads(q.stdout));self.assertEqual(v.returncode,0,v.stderr);self.assertFalse(json.loads(v.stdout)['requested_semantics_match'])
 def test_exact_failure_codes_are_preserved(self):
  d=json.loads(reduce(rows(curl_exit=60,metrics='000|0|20')).stdout);self.assertEqual(d['curl_exit'],60);self.assertEqual(d['tls_verify_result'],20)
  d=json.loads(reduce(rows(dns_exit=124)).stdout);self.assertEqual(d['resolver_exit'],124)
 def test_missing_duplicate_and_split_rows_refuse(self):
  good=rows()
  for i in range(8):
   with self.subTest(i=i):
    self.assertNotEqual(reduce(good[:i]+good[i+1:]).returncode,0)
    self.assertNotEqual(reduce(good+[good[i]]).returncode,0)
  self.assertNotEqual(reduce([good[0][:20],good[0][20:]]+good[1:]).returncode,0)
 def test_foreign_native_editor_metadata_refused(self):
  for kw in [dict(own=False),dict(web=False),dict(editor=True)]:self.assertNotEqual(reduce(content=xml(rows(),**kw)).returncode,0)
 def test_single_quotes_and_private_text_do_not_leak(self):
  q=reduce(content=xml(rows()+['PRIVATE_SENTINEL'],quotes='single'));self.assertEqual(q.returncode,0);self.assertNotIn('PRIVATE',q.stdout)
 def test_metrics_schema_budget_and_scope_refused(self):
  good=json.loads(reduce().stdout)
  for k,v in [('http_status',99),('downloaded_bytes',65537),('curl_exit',256),('curl_present',True),('schema_version',True),('command_execution_verified',True),('raw_other_content_exported',True),('extra','secret')]:
   with self.subTest(k=k):self.assertNotEqual(validate(dict(good,**{k:v})).returncode,0)
 def test_duplicate_json_key_is_refused(self):
  good=json.loads(reduce().stdout);s=json.dumps(good)[:-1]+',"curl_exit":0}'
  r=subprocess.run([str(TOOL),'validate'],input=s,capture_output=True,text=True,timeout=3);self.assertNotEqual(r.returncode,0)
 def test_malformed_curl_writeout_cannot_pass(self):
  for value in ['200','200|1','200|1|0|0','200|1|0:0','PRIVATE_SENTINEL','200|1|']:
   r,_=execute(metrics=value);self.assertNotIn(PLAN['success_marker'],r.stdout);self.assertNotEqual(r.returncode,0)
if __name__=='__main__':unittest.main()
