#!/usr/bin/env python3
"""Bounded, opt-in native GPU diagnostics. Never launches/resets a VM.

Start empty-prearmed before the original Activity resumes. Wait for ready.json.
Explicit-current collects future messages only; it does not retrieve old logs.
Only fixed-prefix records leave the device. CPU uses /proc ticks, not trace walltime.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import selectors
import signal
import subprocess
import threading
import time

PREFIX = 'GB-GPU-IDLE-TRACE:'
MAX_RECORD = 2048
MAX_TRACE = 40960
MAX_TASKS = 128
MAX_SAMPLES = 37
U64 = (1 << 64) - 1
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
TOKENS = {'ctrl_queue', 'cursor_queue', 'display', 'gpu_control', 'resource_bridge',
          'virtio_gpu_poll', 'flip_fence', 'sleep', 'kill', 'display_descriptor_request'}
FIELDS = {'schema_version', 'scope', 'record', 'final_record', 'elapsed_ms', 'waits',
          'empty_waits', 'quick_waits_le_100us', 'wait_ns', 'work_ns', 'readable_tokens',
          'queue_progress_batches', 'flip_pending_peak', 'flip_retired', 'cpu_usage_measured'}

class CaptureError(Exception):
    """Fixed diagnostic code only; never includes raw log/stdout/stderr."""

def require(ok, code):
    if not ok:
        raise CaptureError(code)

def integer(value, lo=0, hi=U64):
    require(type(value) is int and lo <= value <= hi, 'invalid_integer')
    return value

def decimal(text):
    require(bool(re.fullmatch(r'[0-9]{1,12}(?:\.[0-9]{1,9})?', text)), 'invalid_time')
    whole, _, fraction = text.partition('.')
    return int(whole) * 1_000_000_000 + int(fraction.ljust(9, '0') or '0')

def object_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate_json_key')
        value[key] = item
    return value

def parse_record(text):
    require(type(text) is str and text.isascii() and len((PREFIX + text).encode()) <= MAX_RECORD,
            'record_size_or_encoding')
    try:
        value = json.loads(text, object_pairs_hook=object_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(CaptureError('nonfinite_json')))
    except (ValueError, TypeError, RecursionError):
        raise CaptureError('invalid_json') from None
    require(type(value) is dict and set(value) == FIELDS, 'record_schema')
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and
            value['scope'] == 'worker_event_counters', 'record_schema')
    require(type(value['final_record']) is bool and value['cpu_usage_measured'] is False,
            'record_scope')
    integer(value['record'], 1, 16)
    for key in FIELDS - {'schema_version', 'scope', 'record', 'final_record',
                         'readable_tokens', 'queue_progress_batches', 'cpu_usage_measured'}:
        integer(value[key])
    require(value['elapsed_ms'] <= U64 // 1_000_000, 'elapsed_overflow')
    require(type(value['readable_tokens']) is dict and set(value['readable_tokens']) == TOKENS,
            'token_schema')
    require(type(value['queue_progress_batches']) is dict and
            set(value['queue_progress_batches']) == {'ctrl', 'cursor'}, 'queue_schema')
    for item in list(value['readable_tokens'].values()) + list(value['queue_progress_batches'].values()):
        integer(item)
    require(value['empty_waits'] <= value['waits'] and value['quick_waits_le_100us'] <= value['waits'],
            'wait_consistency')
    return value

# No arbitrary path, identifier, command line, environment or map inspection.
COMMON = r'''
boot=$(cat /proc/sys/kernel/random/boot_id) || exit 2
hz=$(getconf CLK_TCK) || exit 2
up=$(cut -d' ' -f1 /proc/uptime) || exit 2
statnums() {
 awk -v expected="$2" 'BEGIN {ok=0} {s=$0; if ($1!=expected) exit 2; sub(/^.*\) /,"",s); n=split(s,a," "); if(n<20)exit 2; if(a[12]!~/^[0-9]+$/ || a[13]!~/^[0-9]+$/ || a[20]!~/^[0-9]+$/)exit 2; print a[20],a[12],a[13];ok=1} END {if(!ok)exit 2}' "$1" 2>/dev/null
}
uidof() { awk '/^Uid:/ {if(NF!=5)exit 2; if($2!=$3 || $2!=$4 || $2!=$5)exit 2; print $2;ok=1} END{if(!ok)exit 2}' "/proc/$1/status" 2>/dev/null; }
'''

def probe_script():
    return '# GB_GPU_CAPTURE_PROBE_V1\nfor tool in awk timeout getconf cut head date logcat; do command -v "$tool" >/dev/null 2>&1 || exit 2; done\n' + COMMON + r'''
printf 'BASE\t%s\t%s\t%s\n' "$boot" "$hz" "$up"
n=0; seen=0
for p in /proc/[0-9]*; do
 seen=$((seen+1)); [ "$seen" -le 4096 ] || exit 2
 read -r name 2>/dev/null < "$p/comm" || continue
 [ "$name" = crosvm_debian ] || continue
 pid=${p##*/}; values=$(statnums "$p/stat" "$pid") || exit 2
 uid=$(uidof "$pid") || exit 2
 set -- $values
 printf 'IDENT\t%s\t%s\t%s\n' "$pid" "$uid" "$1"
 n=$((n+1)); [ "$n" -le 2 ] || exit 2
done
'''

# Reduce framework output on device: no window/service names or dump contents leave.
# A status sentinel distinguishes unavailable/timeout from a negative observation.
# Three dumps each have a two-second timeout plus one-second kill grace.
def state_script():
    return r'''
state_start=$(cut -d' ' -f1 /proc/uptime) || exit 2
wake=$({ timeout -k 1 2 dumpsys power 2>/dev/null; printf '\nGB_CAPTURE_DUMP_STATUS %s\n' "$?"; } | awk '
 /^GB_CAPTURE_DUMP_STATUS / {ok=($2==0);done=1;next}
 {for(i=1;i<=NF;i++) if($i ~ /^mWakefulness=(Awake|Asleep|Dozing|Dreaming)$/){split($i,a,"=");value=a[2];n++}}
 END {if(done && ok && n==1)print value;else print "unknown"}')
keyguard=$({ timeout -k 1 2 dumpsys window policy 2>/dev/null; printf '\nGB_CAPTURE_DUMP_STATUS %s\n' "$?"; } | awk '
 /^GB_CAPTURE_DUMP_STATUS / {ok=($2==0);done=1;next}
 /KeyguardServiceDelegate/ {section=1;lines=0;next}
 section {lines++;if(lines>64)section=0; if(section && $1 ~ /^showing=(true|false)$/ && !n){split($1,a,"=");value=a[2];n=1}}
 END {if(done && ok && n==1)print value;else print "unknown"}')
fgs=$({ timeout -k 1 2 dumpsys activity services --user "$((uid / 100000))" com.android.virtualization.terminal 2>/dev/null; printf '\nGB_CAPTURE_DUMP_STATUS %s\n' "$?"; } | awk '
 /^GB_CAPTURE_DUMP_STATUS / {ok=($2==0);done=1;next}
 {for(i=1;i<=NF;i++){if($i=="isForeground=true"){yes=1;seen=1} else if($i=="isForeground=false")seen=1}}
 END {if(done && ok && seen)print yes ? "true" : "false";else print "unknown"}')
state_end=$(cut -d' ' -f1 /proc/uptime) || exit 2
printf 'STATE\t%s\t%s\t%s\t%s\t%s\n' "$state_start" "$state_end" "$wake" "$keyguard" "$fgs"
'''

def snapshot_script(pid):
    integer(pid, 1, 1 << 22)
    return '# GB_GPU_CAPTURE_SAMPLE_V2\npid=' + str(pid) + '\n' + COMMON + r'''
read -r name 2>/dev/null < "/proc/$pid/comm" || exit 2
[ "$name" = crosvm_debian ] || exit 2
uid=$(uidof "$pid") || exit 2
before=$(statnums "/proc/$pid/stat" "$pid") || exit 2
set -- $before
printf 'SAMPLE\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$boot" "$pid" "$uid" "$1" "$hz" "$up" "$2" "$3"
n=0; raced=0
for path in /proc/$pid/task/[0-9]*; do
 n=$((n+1)); [ "$n" -le 128 ] || exit 2
 tid=${path##*/}; values=$(statnums "$path/stat" "$tid") || { raced=$((raced+1)); continue; }
 read -r role 2>/dev/null < "$path/comm" || { raced=$((raced+1)); continue; }
 gpu=0; [ "$role" != v_gpu ] || gpu=1
 set -- $values
 printf 'TASK\t%s\t%s\t%s\t%s\t%s\n' "$tid" "$1" "$2" "$3" "$gpu"
done
''' + state_script() + r'''
after=$(statnums "/proc/$pid/stat" "$pid") || exit 2
set -- $before; first=$1
set -- $after; [ "$first" = "$1" ] || exit 2
[ "$boot" = "$(cat /proc/sys/kernel/random/boot_id)" ] || exit 2
[ "$uid" = "$(uidof "$pid")" ] || exit 2
printf 'END\t%s\n' "$raced"
'''

def trace_script(uid, seconds):
    integer(uid, 10000, (1 << 31) - 1)
    integer(seconds, 10, 180)
    # Logcat bounds regex matches before transport. awk strips tags/source paths and
    # enforces payload bytes. head is a second independent on-device transport cap.
    pipeline = r'''logcat -b main -b system -v threadtime -v epoch -v usec --uid=UID --regex='GB-GPU-IDLE-TRACE:' --max-count=16 -T "$since" 2>/dev/null | awk '
BEGIN {p="GB-GPU-IDLE-TRACE:"; n=0}
{ i=index($0,p); if(!i)next; payload=substr($0,i+length(p)); if(length(payload)+length(p)>2048){print "ERROR\trecord_size";exit 2} if($1!~/^[0-9]+\.[0-9]+$/ || $2!~/^[0-9]+$/ || $3!~/^[0-9]+$/){print "ERROR\tlog_header";exit 2} n++;if(n>16){print "ERROR\ttransport_cap";exit 2} printf "TRACE\t%s\t%s\t%s\t%s\n",$1,$2,$3,payload;fflush()}' | head -c 40960'''.replace('UID', str(uid))
    # since is exported for the nested timeout shell. No old ring-buffer retrieval.
    return ('# GB_GPU_CAPTURE_TRACE_V1\nexport LC_ALL=C\n'
            'boot=$(cat /proc/sys/kernel/random/boot_id) || exit 2\n'
            'since=$(date +%s.%N) || exit 2\nexport since\n'
            'printf "READY\\t%s\\t%s\\n" "$boot" "$since"\n'
            'timeout -k 2 ' + str(seconds + 75) + " sh -c '" + pipeline.replace("'", "'\"'\"'") + "'\n")

def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)

def bounded(command, script, maximum=65536, timeout=12):
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    selector = selectors.DefaultSelector()
    result = bytearray()
    try:
        process.stdin.write(script.encode()); process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            require(time.monotonic() < deadline, 'adb_timeout')
            for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                data = os.read(key.fd, 4096)
                if not data:
                    selector.unregister(key.fileobj); continue
                result.extend(data); require(len(result) <= maximum, 'adb_output_cap')
        require(process.wait(timeout=1) == 0, 'device_command_failed')
        return bytes(result)
    finally:
        selector.close(); stop(process); process.stdout.close()

class TraceStream:
    def __init__(self, command, script):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            self.process.stdin.write(script.encode()); self.process.stdin.close()
            self.events = queue.Queue(maxsize=20)
            self.error = None
            self.total = 0
            def read():
                try:
                    while True:
                        data = self.process.stdout.readline(MAX_RECORD + 256)
                        if not data: break
                        self.total += len(data)
                        require(self.total <= MAX_TRACE and len(data) < MAX_RECORD + 256 and data.endswith(b'\n'),
                                'trace_transport_cap')
                        try: self.events.put_nowait(data.decode('ascii').rstrip('\n'))
                        except (queue.Full, UnicodeDecodeError): raise CaptureError('trace_transport_schema')
                except CaptureError as error: self.error = str(error)
                except (OSError, ValueError): self.error = 'trace_stream_io'
                finally: self.process.stdout.close()
            self.reader = threading.Thread(target=read, daemon=True); self.reader.start()
        except BaseException:
            try:
                self.process.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                stop(self.process)
            except (OSError, subprocess.SubprocessError):
                raise CaptureError('trace_constructor_cleanup_failed') from None
            finally:
                self.process.stdout.close()
            raise
    def lines(self):
        require(self.error is None, self.error or 'trace_transport_error')
        lines = []
        while True:
            try: lines.append(self.events.get_nowait())
            except queue.Empty: return lines
    def close(self):
        prior = self.process.poll()
        stop(self.process); self.reader.join(timeout=5)
        require(not self.reader.is_alive(), 'trace_reader_not_reaped')
        require(self.error is None, self.error or 'trace_stream_io')
        require(prior is None or prior == 0, 'trace_command_failed')

class ADB:
    def __init__(self, executable, serial): self.command = [executable, '-s', serial, 'shell', '-T', 'sh']
    def probe(self): return bounded(self.command, probe_script(), 4096)
    def sample(self, pid): return bounded(self.command, snapshot_script(pid), 32768)
    def stream(self, uid, seconds): return TraceStream(self.command, trace_script(uid, seconds))

def words(data):
    require(len(data) <= 32768, 'sample_output_cap')
    try: return [line.split('\t') for line in data.decode('ascii').splitlines()]
    except UnicodeDecodeError: raise CaptureError('sample_encoding') from None

def number(text, lo=0, hi=U64):
    require(bool(re.fullmatch(r'[0-9]{1,20}', text)), 'numeric_field')
    return integer(int(text), lo, hi)

def parse_probe(data, boot, uid):
    rows = words(data); require(1 <= len(rows) <= 3 and len(rows[0]) == 4 and rows[0][0] == 'BASE', 'probe_schema')
    require(rows[0][1] == boot, 'boot_changed')
    hz = number(rows[0][2], 1, 10000); uptime = decimal(rows[0][3]); identities = []
    for row in rows[1:]:
        require(len(row) == 4 and row[0] == 'IDENT', 'probe_schema')
        identity = dict(pid=number(row[1], 1, 1 << 22), uid=number(row[2], 10000, (1 << 31)-1), startticks=number(row[3], 1))
        require(identity['uid'] == uid, 'native_uid_mismatch'); identities.append(identity)
    require(len(identities) <= 1, 'ambiguous_native')
    return hz, uptime, identities

def parse_sample(data, boot, identity, hz):
    rows = words(data); require(2 <= len(rows) <= MAX_TASKS + 3, 'sample_schema')
    head, end = rows[0], rows[-1]
    require(len(head) == 9 and head[0] == 'SAMPLE' and head[1] == boot, 'sample_binding')
    actual = dict(pid=number(head[2], 1, 1 << 22), uid=number(head[3], 10000, (1 << 31)-1), startticks=number(head[4], 1))
    require(actual == identity and number(head[5], 1, 10000) == hz, 'process_lifetime_changed')
    require(len(end) == 2 and end[0] == 'END', 'sample_incomplete')
    tasks = []
    state = dict(observed=False, framework_wakefulness='unknown', keyguard_showing=None, terminal_package_foreground_service_observed=None)
    body = rows[1:-1]
    if body and body[-1][0] == 'STATE':
        row = body[-1]; body = body[:-1]
        require(len(row)==6 and row[3] in {'Awake','Asleep','Dozing','Dreaming','unknown'} and
                row[4] in {'true','false','unknown'} and row[5] in {'true','false','unknown'}, 'state_schema')
        start, finish = decimal(row[1]), decimal(row[2])
        require(decimal(head[6]) <= start <= finish and finish-start <= 12_000_000_000, 'state_timing')
        state = dict(observed=True, start_uptime_ns=start, end_uptime_ns=finish, framework_wakefulness=row[3],
                     keyguard_showing={'true':True,'false':False,'unknown':None}[row[4]],
                     terminal_package_foreground_service_observed={'true':True,'false':False,'unknown':None}[row[5]])
    require(len(body) <= MAX_TASKS, 'task_count_cap')
    for row in body:
        require(len(row) == 6 and row[0] == 'TASK', 'task_schema')
        task = dict(tid=number(row[1],1,1<<22), startticks=number(row[2],1), utime=number(row[3]), stime=number(row[4]), gpu_worker=bool(number(row[5],0,1)))
        require(task['tid'] not in {t['tid'] for t in tasks}, 'duplicate_task'); tasks.append(task)
    return dict(uptime_ns=decimal(head[6]), utime=number(head[7]), stime=number(head[8]), tasks=tasks, tasks_raced=number(end[1],0,MAX_TASKS), framework_state=state)

def cpu_intervals(samples, hz):
    values = []
    for before, after in zip(samples, samples[1:]):
        elapsed = after['uptime_ns'] - before['uptime_ns']
        ticks = after['utime'] + after['stime'] - before['utime'] - before['stime']
        require(elapsed > 0 and ticks >= 0, 'cpu_counter_regressed')
        tasks = []
        old = {t['tid']:t for t in before['tasks']}
        for task in after['tasks']:
            previous = old.get(task['tid'])
            if previous is None or task['startticks'] != previous['startticks']: continue
            dt = task['utime']+task['stime']-previous['utime']-previous['stime']
            require(dt >= 0, 'task_cpu_regressed')
            tasks.append(dict(tid=task['tid'], startticks=task['startticks'], gpu_worker=task['gpu_worker'] and previous['gpu_worker'], cpu_ticks=dt, percent_one_core=round(dt/hz/(elapsed/1e9)*100,3)))
        values.append(dict(elapsed_uptime_ns=elapsed, process_cpu_ticks=ticks, percent_one_core=round(ticks/hz/(elapsed/1e9)*100,3), tasks=tasks, framework_state_before=before.get('framework_state'), framework_state_after=after.get('framework_state'), framework_state_continuous=False))
    return values

@dataclass
class Config:
    boot: str
    uid: int
    seconds: int
    output: Path
    identity: dict | None = None

class Clock:
    now = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)

def write(path, value):
    temporary = path.with_name('.' + path.name + '.tmp')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.link(temporary, path); temporary.unlink()

def collect(config, adb, clock=Clock(), sample_period=5.0, discovery_period=0.5):
    config.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    records=[]; samples=[]; stream=None; identity=config.identity; ready=None; error=None; cleaned=False
    started=clock.now(); hz=None; backlog=[]; bound_at=None
    try:
        hz, armed_uptime, initial = parse_probe(adb.probe(), config.boot, config.uid)
        if identity is None: require(not initial, 'native_exists_requires_explicit_current')
        else: require(initial == [identity], 'explicit_current_identity_mismatch')
        stream=adb.stream(config.uid, config.seconds)
        while ready is None:
            require(clock.now()-started < 12, 'trace_ready_timeout')
            lines=stream.lines()
            for line in lines:
                if ready is None:
                    parts=line.split('\t'); require(len(parts)==3 and parts[0]=='READY' and parts[1]==config.boot,'trace_ready_schema')
                    ready=decimal(parts[2])
                else: backlog.append(line)
            if ready is None: clock.sleep(0.02)
        write(config.output/'ready.json',dict(schema_version=1,state='capture_armed',mode='explicit_current_future_only' if identity else 'empty_prearmed',boot_id=config.boot,uid=config.uid,identity=identity,device_capture_epoch_ns=ready,launch_or_reset_performed=False))
        pending=[]; next_sample=clock.now(); last_probe=-1000000; armed_at=clock.now()
        if identity is not None: bound_at=armed_at
        while bound_at is None or clock.now()-bound_at < config.seconds:
            require(bound_at is not None or clock.now()-armed_at<60, 'native_discovery_timeout')
            incoming=backlog+stream.lines(); backlog=[]
            for line in incoming:
                parts=line.split('\t',4); require(len(parts)==5 and parts[0]=='TRACE','trace_frame_schema')
                timestamp=decimal(parts[1]); require(timestamp>=ready,'trace_before_capture')
                value=parse_record(parts[4]); row=dict(device_epoch_ns=timestamp,pid=number(parts[2],1,1<<22),tid=number(parts[3],1,1<<22),counters=value)
                require(len(pending)+len(records)<16,'trace_record_cap'); pending.append(row)
            if identity is None and clock.now()-last_probe>=discovery_period:
                current_hz,_,found=parse_probe(adb.probe(),config.boot,config.uid);require(current_hz==hz,'clock_tick_rate_changed');last_probe=clock.now()
                if found:
                    identity=found[0];bound_at=clock.now();require(identity['startticks']*1_000_000_000//hz>=armed_uptime-1_000_000_000,'native_not_fresh')
            if identity is not None:
                for row in pending:
                    require(row['pid']==identity['pid'],'trace_pid_mismatch');require(row['counters']['record'] not in {r['counters']['record'] for r in records},'duplicate_record_ordinal');records.append(row)
                pending=[]
                if clock.now()>=next_sample:
                    require(len(samples)<MAX_SAMPLES,'cpu_sample_cap');samples.append(parse_sample(adb.sample(identity['pid']),config.boot,identity,hz));next_sample=clock.now()+sample_period
            clock.sleep(0.05)
        require(identity is not None,'native_not_observed');require(not pending,'unbound_records')
        # Final sample ensures exit/identity/boot changes are not silently missed.
        require(len(samples)<MAX_SAMPLES,'cpu_sample_cap');samples.append(parse_sample(adb.sample(identity['pid']),config.boot,identity,hz))
        require(len(samples)>=2,'missing_cpu_samples')
        intervals=cpu_intervals(samples,hz)
    except CaptureError as e: error=str(e);intervals=[]
    except (OSError,ValueError,subprocess.SubprocessError): error='host_or_transport_failure';intervals=[]
    finally:
        if stream is not None:
            try: stream.close();cleaned=True
            except (OSError,ValueError,subprocess.SubprocessError,CaptureError): error=error or 'trace_cleanup_failed'
        else: cleaned=error != 'trace_constructor_cleanup_failed'
    ordinals=sorted(row['counters']['record'] for row in records)
    completed = error is None and cleaned
    status = ('observed_diagnostic_capture' if records else 'observed_cpu_capture_trace_unknown') if completed else 'incomplete'
    result=dict(schema_version=2,status=status,error_code=error,boot_id=config.boot,identity=identity,hz=hz,record_count=len(records),ordinals=ordinals,all16_ordinals_observed=ordinals==list(range(1,17)),early_coverage='ordinal1_observed' if 1 in ordinals else 'unknown',trace_coverage='new_records_observed' if records else 'unknown_no_new_records',cpu_measured_from_proc_ticks=True if intervals else False,cpu_percent_scale='one logical CPU =100 percent; may exceed100',host_adb_children_reaped=cleaned,remote_cleanup_observed=False,remote_producer_timeout_seconds=config.seconds+75,vm_launched_or_reset=False,device_modified=False,sampled_framework_state_continuous=False,scope='Sampled framework states are endpoints, not continuous coverage or VM lease proof. Trace waits/work are wall counters, not CPU. No per-worker identity; do not difference counters across records. No CPU-fix/performance or past-culprit claim.')
    write(config.output/'records.json',records);write(config.output/'cpu.json',dict(samples=samples,intervals=intervals));write(config.output/'result.json',result)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb',required=True);parser.add_argument('--serial',required=True)
    parser.add_argument('--boot-id',required=True);parser.add_argument('--uid',type=int,required=True)
    parser.add_argument('--seconds',type=int,default=100);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--pid',type=int);parser.add_argument('--startticks',type=int)
    args=parser.parse_args()
    try:
        require(bool(UUID.fullmatch(args.boot_id)),'invalid_boot_id');integer(args.uid,10000,(1<<31)-1);integer(args.seconds,10,180)
        require(bool(re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',args.serial)),'invalid_serial')
        require((args.pid is None)==(args.startticks is None),'pid_startticks_pair_required')
        identity=None
        if args.pid is not None:identity=dict(pid=integer(args.pid,1,1<<22),uid=args.uid,startticks=integer(args.startticks,1))
        result=collect(Config(args.boot_id,args.uid,args.seconds,args.output,identity),ADB(args.adb,args.serial))
        print(json.dumps(result));return 0 if result['status'] in {'observed_diagnostic_capture','observed_cpu_capture_trace_unknown'} else 2
    except (CaptureError,OSError): print(json.dumps(dict(status='refused',error_code='invalid_configuration_or_output')));return 2
if __name__=='__main__':raise SystemExit(main())
