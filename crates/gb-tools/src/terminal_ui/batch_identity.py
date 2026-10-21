"""Batch the unchanged read-only UI-test identity checks into one ADB invocation.

No device input, VM argv, maps or credentials. Caller supplies a pinned context
and the bounded shell transport; this module never selects another USB device.
"""
from pathlib import Path

def verify(controller,p,native=True,unlocked=True):
    if Path(p['usb_serial_path']).read_text().strip()!=p['serial']:
        raise RuntimeError('physical serial refused')
    user=p['android_user']
    if type(user) is not int or not 0<=user<=1000:raise RuntimeError('user refused')
    commands=['getprop ro.serialno','id -u','getenforce','am get-current-user',
              'cat /proc/sys/kernel/random/boot_id','getprop ro.build.fingerprint',
              'getprop ro.vendor.build.fingerprint','am get-started-user-state '+str(user)]
    expected=[p['serial'],'2000','Enforcing',str(user),p['android_boot_id'],p['fingerprint'],p['vendor_fingerprint']]
    if native:
        for pid,birth in [(p['main_pid'],p['main_start_ticks']),(p['native_pid'],p['native_start_ticks'])]:
            if type(pid) is not int or not 0<pid<=4194304:raise RuntimeError('PID refused')
            commands.extend(["awk '{print $22}' /proc/%d/stat"%pid,"awk '/^Uid:/{print $2}' /proc/%d/status"%pid])
            expected.extend([str(birth),str(p['uid'])])
        commands.append("ps -A -o PID,NAME | awk '$2==\"crosvm_debian\"{print $1}'")
        expected.append(str(p['native_pid']))
    values=controller.shell(';'.join(commands),limit=4096).splitlines()
    if len(values)!=len(expected)+1:raise RuntimeError('identity field count refused')
    state=values.pop(7)
    allowed=['RUNNING_UNLOCKED'] if unlocked else ['RUNNING_UNLOCKED','RUNNING_LOCKED']
    if state not in allowed or values!=expected:raise RuntimeError('identity witness refused')
