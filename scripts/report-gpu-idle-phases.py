#!/usr/bin/env python3
"""Offline CPU/state correlation. Never contacts a device or supplies mode events.

Optional events JSON: schema_version=1, boot_id, identity{pid,uid,startticks},
mode_events:[{transition_begin_uptime_ns,mode_observed_uptime_ns,mode}]. Modes are
only tty/desktop/unknown. Events are explicit caller observations, not proof of
continuous mode or awake state. No events means every mode remains unknown.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

U64 = (1 << 64) - 1
MODES = {'tty', 'desktop', 'unknown'}
STATES = {'Awake', 'Asleep', 'Dozing', 'Dreaming', 'unknown'}
RESULT_FIELDS = {'schema_version', 'status', 'error_code', 'boot_id', 'identity', 'hz',
                 'record_count', 'ordinals', 'all16_ordinals_observed', 'early_coverage',
                 'trace_coverage', 'cpu_measured_from_proc_ticks', 'cpu_percent_scale',
                 'host_adb_children_reaped', 'remote_cleanup_observed',
                 'remote_producer_timeout_seconds', 'vm_launched_or_reset',
                 'device_modified', 'sampled_framework_state_continuous', 'scope'}
COMPLETE = {'observed_diagnostic_capture', 'observed_cpu_capture_trace_unknown'}

class ReportError(Exception):
    """Fixed code only, never raw input or exception text."""

def need(ok, code):
    if not ok:
        raise ReportError(code)

def integer(value, lo=0, hi=U64):
    need(type(value) is int and lo <= value <= hi, 'integer_schema')
    return value

def keys(value, required, optional=frozenset()):
    need(type(value) is dict and required <= value.keys() <= required | optional, 'object_schema')

def identity(value):
    keys(value, {'pid', 'uid', 'startticks'})
    integer(value['pid'], 1, 1 << 22)
    integer(value['uid'], 10000, (1 << 31) - 1)
    integer(value['startticks'], 1)
    return value

def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result

def read_json(path, maximum):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'regular_input_required')
    with path.open('rb') as stream:
        body = stream.read(maximum + 1)
    need(len(body) <= maximum, 'input_byte_cap')
    try:
        value = json.loads(body, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ReportError('nonfinite_json')))
    except (ValueError, UnicodeError, RecursionError):
        raise ReportError('invalid_json') from None
    return value, dict(file=path.name, sha256=hashlib.sha256(body).hexdigest(), bytes=len(body))

def state(value, sample_time):
    if value is None:
        return dict(observed=False, framework_wakefulness='unknown', keyguard_showing=None,
                    terminal_package_foreground_service_observed=None)
    basic = {'observed', 'framework_wakefulness', 'keyguard_showing',
             'terminal_package_foreground_service_observed'}
    keys(value, basic, {'start_uptime_ns', 'end_uptime_ns'})
    need(type(value['observed']) is bool and type(value['framework_wakefulness']) is str and value['framework_wakefulness'] in STATES, 'state_schema')
    for name in ('keyguard_showing', 'terminal_package_foreground_service_observed'):
        need(value[name] is None or type(value[name]) is bool, 'state_schema')
    if value['observed']:
        need(set(value) == basic | {'start_uptime_ns', 'end_uptime_ns'}, 'state_schema')
        start, end = integer(value['start_uptime_ns']), integer(value['end_uptime_ns'])
        need(sample_time <= start <= end and end - start <= 12_000_000_000, 'state_time_schema')
    else:
        need(set(value) == basic and value['framework_wakefulness'] == 'unknown' and
             value['keyguard_showing'] is None and
             value['terminal_package_foreground_service_observed'] is None, 'unobserved_state_schema')
    return dict(value)

def samples(value):
    keys(value, {'samples', 'intervals'})
    rows = value['samples']
    need(type(rows) is list and 2 <= len(rows) <= 37, 'sample_count_cap')
    # Stored summaries are not authoritative; CPU is recomputed from raw ticks.
    need(type(value['intervals']) is list and len(value['intervals']) <= 36, 'stored_interval_cap')
    result = []
    for row in rows:
        keys(row, {'uptime_ns', 'utime', 'stime', 'tasks', 'tasks_raced'}, {'framework_state'})
        time = integer(row['uptime_ns'])
        integer(row['utime']); integer(row['stime']); integer(row['tasks_raced'], 0, 128)
        need(type(row['tasks']) is list and len(row['tasks']) <= 128, 'task_count_cap')
        seen = set()
        for task in row['tasks']:
            keys(task, {'tid', 'startticks', 'utime', 'stime', 'gpu_worker'})
            tid = integer(task['tid'], 1, 1 << 22)
            need(tid not in seen and type(task['gpu_worker']) is bool, 'task_schema')
            seen.add(tid)
            integer(task['startticks'], 1); integer(task['utime']); integer(task['stime'])
        result.append(dict(row, framework_state=state(row.get('framework_state'), time)))
    return result

def events(value, boot, native):
    if value is None:
        return []
    keys(value, {'schema_version', 'boot_id', 'identity', 'mode_events'})
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['boot_id'] == boot and identity(value['identity']) == native, 'event_identity_binding')
    need(type(value['mode_events']) is list and len(value['mode_events']) <= 16, 'event_count_cap')
    result = []
    for event in value['mode_events']:
        keys(event, {'transition_begin_uptime_ns', 'mode_observed_uptime_ns', 'mode'})
        begin = integer(event['transition_begin_uptime_ns'])
        settled = integer(event['mode_observed_uptime_ns'])
        need(begin <= settled and type(event['mode']) is str and event['mode'] in MODES, 'event_schema')
        if result:
            previous = result[-1]
            need(previous['transition_begin_uptime_ns'] < begin and
                 previous['mode_observed_uptime_ns'] <= begin, 'events_overlap_or_unordered')
        result.append(dict(event))
    return result

def mode_at_window(begin, end, mode_events):
    for index, event in enumerate(mode_events):
        following = mode_events[index + 1]['transition_begin_uptime_ns'] if index + 1 < len(mode_events) else None
        if begin >= event['mode_observed_uptime_ns'] and (following is None or end < following):
            return event['mode']
    return 'unknown'

def summarize(ticks, nanoseconds, hz, count):
    return dict(interval_count=count, elapsed_uptime_ns=nanoseconds, process_cpu_ticks=ticks,
                process_cpu_seconds=ticks / hz,
                percent_one_core=round(ticks / hz / (nanoseconds / 1e9) * 100, 6) if nanoseconds else None)

def report(capture, transition_path=None):
    capture = Path(capture)
    result, result_pin = read_json(capture / 'result.json', 65536)
    required = {'schema_version', 'status', 'error_code', 'boot_id', 'identity', 'hz',
                'record_count', 'host_adb_children_reaped'}
    keys(result, required, RESULT_FIELDS - required)
    need(type(result['schema_version']) is int and result['schema_version'] in (1, 2), 'result_schema')
    need(type(result['status']) is str and result['status'] in COMPLETE | {'incomplete'} and type(result['host_adb_children_reaped']) is bool,
         'result_schema')
    need(type(result['boot_id']) is str and re.fullmatch(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', result['boot_id']), 'boot_schema')
    native = identity(result['identity'])
    hz = integer(result['hz'], 1, 10000)
    record_count = integer(result['record_count'], 0, 16)
    need(result['error_code'] is None or (type(result['error_code']) is str and
         re.fullmatch('[a-z_]{1,80}', result['error_code'])), 'error_schema')
    complete = result['status'] in COMPLETE and result['error_code'] is None and result['host_adb_children_reaped']
    raw_cpu, cpu_pin = read_json(capture / 'cpu.json', 2 * 1024 * 1024)
    rows = samples(raw_cpu)
    raw_records, records_pin = read_json(capture / 'records.json', 65536)
    need(type(raw_records) is list and len(raw_records) == record_count, 'record_count_mismatch')
    source_pins = [result_pin, cpu_pin, records_pin]
    supplied = None
    if transition_path is not None:
        supplied, transition_pin = read_json(transition_path, 32768)
        source_pins.append(dict(transition_pin, role='explicit_mode_events'))
    mode_events = events(supplied, result['boot_id'], native)
    intervals = []
    groups = {name: dict(ticks=0, ns=0, count=0) for name in ('tty', 'desktop')}
    total_ticks = total_ns = 0
    for before, after in zip(rows, rows[1:]):
        begin, end = before['uptime_ns'], after['uptime_ns']
        ticks = after['utime'] + after['stime'] - before['utime'] - before['stime']
        need(end > begin and after['utime'] >= before['utime'] and
             after['stime'] >= before['stime'] and ticks >= 0, 'cpu_counter_regressed')
        total_ticks += ticks; total_ns += end - begin
        left, right = before['framework_state'], after['framework_state']
        reasons = []
        if not complete: reasons.append('capture_incomplete_or_cleanup_unverified')
        if not left['observed'] or not right['observed']:
            reasons.append('framework_state_unobserved')
        else:
            if left['end_uptime_ns'] > end or left['end_uptime_ns'] > right['start_uptime_ns']:
                reasons.append('state_windows_overlap_cpu_boundary')
            if left['framework_wakefulness'] != 'Awake' or right['framework_wakefulness'] != 'Awake':
                reasons.append('sampled_wakefulness_not_both_awake')
            if left['keyguard_showing'] is not False or right['keyguard_showing'] is not False:
                reasons.append('sampled_keyguard_not_both_false')
            if (left['terminal_package_foreground_service_observed'] is not True or
                    right['terminal_package_foreground_service_observed'] is not True):
                reasons.append('sampled_package_fgs_not_both_true')
        extent_end = max(end, right.get('end_uptime_ns', end))
        mode = mode_at_window(begin, extent_end, mode_events)
        if mode == 'unknown': reasons.append('no_explicit_stable_mode_covering_cpu_and_state_window')
        if not reasons:
            groups[mode]['ticks'] += ticks; groups[mode]['ns'] += end - begin; groups[mode]['count'] += 1
        intervals.append(dict(start_uptime_ns=begin, end_uptime_ns=end, process_cpu_ticks=ticks,
                              process_cpu_seconds=ticks / hz,
                              percent_one_core=round(ticks / hz / ((end - begin) / 1e9) * 100, 6),
                              declared_mode=mode, endpoint_correlation_candidate=not reasons,
                              excluded_reasons=reasons, framework_state_before=left, framework_state_after=right,
                              continuous_awake_or_mode_verified=False))
    return dict(schema_version=1, status='offline_cpu_state_correlation_observed',
                boot_id=result['boot_id'], identity=native, hz=hz, source_pins=source_pins,
                source_capture_complete=complete, stored_interval_summaries_used=False,
                trace=dict(source_record_count=record_count, record_schema_revalidated=False,
                           coverage='source_reports_new_records' if record_count else 'unknown_no_new_records'),
                cpu=summarize(total_ticks, total_ns, hz, len(intervals)),
                explicit_mode_events_supplied=transition_path is not None, mode_events=mode_events,
                endpoint_samples=[dict(cpu_uptime_ns=row['uptime_ns'], framework_state=row['framework_state']) for row in rows],
                intervals=intervals,
                declared_mode_endpoint_groups={name:summarize(g['ticks'], g['ns'], hz, g['count']) for name,g in groups.items()},
                continuous_awake_idle_qualified=False, continuous_phase_mode_qualified=False,
                natural_idle_qualified=False, power_conditions='not_inferred_from_capture_or_directory',
                causal_cpu_or_performance_claim=False, device_contacted=False,
                limitations=['Mode history comes only from caller-supplied bound events; no events means unknown mode.',
                             'Matching state endpoints and explicit events do not prove continuous awake state, screen mode or VM lease.',
                             'Phase candidate groups exclude incomplete captures, unknown/locked/asleep endpoints, overlapping state windows and transition boundaries.',
                             'All valid process CPU intervals remain in the CPU summary even when trace is absent or phase correlation is excluded.',
                             'CPU uses process ticks and device uptime; trace wall counters and cached interval summaries are not CPU inputs.',
                             'Power conditions are not inferred; independent setting journals must distinguish forced-awake tests from natural conditions.',
                             'Source identity/cleanup bindings are collector assertions, not an independent device observation.'])

def publish(path, value):
    # Exclusive output preserves every prior report and all input artifacts.
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--transitions', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        value = report(args.capture, args.transitions)
        publish(args.output, value)
        print(json.dumps(dict(status=value['status'], device_contacted=False)))
        return 0
    except (ReportError, OSError, ValueError, TypeError, RecursionError):
        print(json.dumps(dict(status='refused', error_code='invalid_bounded_inputs_or_output')))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
