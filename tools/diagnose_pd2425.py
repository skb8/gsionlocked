"""Read-only ADB collector; never installs, launches or prepares a guest."""
import argparse,json,shlex,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb',default='adb');p.add_argument('--serial')
    p.add_argument('--root',action='store_true',help='Use already-authorized su for additional read-only checks')
    p.add_argument('--output',type=Path);a=p.parse_args()
    base=[a.adb]+(['-s',a.serial] if a.serial else [])
    def read(command,root=False):
        if root:command='su -c '+shlex.quote(command)
        try:
            r=subprocess.run(base+['shell',command],capture_output=True,text=True,timeout=20)
            return {'exit':r.returncode,'stdout':r.stdout[:65536].strip(),'stderr':r.stderr[:4096].strip()}
        except (OSError,subprocess.TimeoutExpired) as error:
            return {'exit':-1,'stdout':'','stderr':str(error)}
    profile=json.loads((ROOT/'profiles/pd2425-originos6.json').read_text())
    keys=['ro.product.device','ro.product.model','ro.product.cpu.abi','ro.build.version.sdk','ro.build.fingerprint','ro.boot.flash.locked','ro.boot.verifiedbootstate','ro.soc.model','ro.vendor.build.version.sdk','ro.vivo.os.build.display.id']
    props={key:read('getprop '+key) for key in keys}
    def value(key):return props[key]['stdout'] if props[key]['exit']==0 else ''
    matched=value('ro.product.device')==profile['device'] and value('ro.build.version.sdk')=='36' and value('ro.product.cpu.abi')=='arm64-v8a' and value('ro.build.fingerprint') in profile.get('accepted_host_fingerprints',[profile['fingerprint']])
    commands={'identity':'id','kernel':'uname -r','selinux':'getenforce','cgroup':'cat /sys/fs/cgroup/cgroup.controllers',
        'input_names':'for f in /sys/class/input/event*/device/name; do echo "$f"; cat "$f"; done',
        'watchdog_metadata':'for f in identity timeout nowayout state; do echo "$f"; cat /sys/class/watchdog/watchdog0/$f; done'}
    checks={name:read(command,root=a.root) for name,command in commands.items()}
    checks['services']={s['name']:read('getprop init.svc.'+s['name']) for s in profile['services']}
    if a.root:
        checks['kernel_modules']=read('cat /proc/modules',root=True)
        checks['live_selinux_policy_hash']=read('sha256sum /sys/fs/selinux/policy',root=True)
    report={'host_profile_match':matched,'ota_identity_match':matched and value('ro.build.fingerprint')==profile['fingerprint'],'runtime_ready':False,'tested_combination':False,'properties':props,'checks':checks,'no_device_changes':True,
        'limitations':'Observations do not validate HAL handoff, watchdog adoption, root implementation or restoration.'}
    text=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    else:print(text,end='')
    return 4 if matched else 2
if __name__=='__main__':raise SystemExit(main())
