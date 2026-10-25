"""Build public Android arm64 components; this is NOT a runtime installer."""
import argparse, hashlib, json, subprocess, zipfile
from pathlib import Path
from pd2425_build import generate_services
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sdk',required=True,type=Path)
    p.add_argument('--java-home',required=True,type=Path)
    p.add_argument('--ndk',type=Path)
    a=p.parse_args();sdk=a.sdk.resolve();java=a.java_home.resolve()/'bin'
    ndk=a.ndk.resolve() if a.ndk else sdk/'ndk/25.2.9519653'
    cc=ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin/clang'
    out=ROOT/'dist/runtime';out.mkdir(parents=True,exist_ok=True)
    build=ROOT/'build/runtime';build.mkdir(parents=True,exist_ok=True)
    probe_include=generate_services(build/'probe-include')
    src=ROOT/'runtime/dm1q/src';inc=ROOT/'runtime/dm1q/include'
    common=[str(cc),'--target=aarch64-linux-android33','-O2','-Wall','-Wextra','-Werror']
    jobs=[]
    for name in ['loader198','guardian198']:
        jobs.append((name+'-dm1q',common+['-static','-I',str(inc)]+(['-DTEMPGSI_HAL_PROFILE151'] if name=='loader198' else [])+[str(src/(name+'.c'))]))
    for component in ['loader','guardian']:
        jobs.append((component+'-pd2425-preflight',common+['-static','-I',str(probe_include),'-I',str(ROOT/'runtime/pd2425/include'),'-DCOMPONENT="'+component+'"',str(ROOT/'runtime/pd2425/src/preflight.c')]))
    jobs.append(('pd2425-gsi-preview',common+['-static','-I',str(probe_include),'-I',str(ROOT/'runtime/pd2425/include'),str(ROOT/'runtime/pd2425/src/gsi_preview.c')]))
    for name in ['artd_session','private_selinux_mount']:
        jobs.append((name.replace('_','-')+'.so',common+['-shared','-fPIC',str(src/(name+'.c')),'-ldl']))
    jobs.append(('userspace-property-seed',common+['-static',str(src/'userspace_property_seed.c'),'-ldl']))
    jobs.append(('soft-keymint-service',common+['-x','c++','-std=c++17',str(src/'soft_keymint_service.cpp'),'-lc++_shared','-lbinder_ndk','-ldl']))
    for name in ['storage_propagation_test','uid_lease_test']:
        # Unit-only: this header also defines intentionally unused group helpers.
        flags=['-Wno-unused-function'] if name=='uid_lease_test' else []
        jobs.append((name,common+flags+['-static','-I',str(inc),str(ROOT/'runtime/dm1q/tests'/(name+'.c'))]))
    results=[]
    for name,command in jobs:
        output=out/name;output.unlink(missing_ok=True)
        r=subprocess.run(command+['-o',str(output)],capture_output=True,text=True,timeout=180)
        (build/(name+'.log')).write_text(r.stdout+r.stderr)
        item={'file':name,'built':r.returncode==0,'log':'build/runtime/'+name+'.log'}
        if r.returncode==0:item['sha256']=hashlib.sha256(output.read_bytes()).hexdigest()
        else:item['error']=r.stderr[-4000:];output.unlink(missing_ok=True)
        results.append(item);print(name,'PASS' if item['built'] else 'FAIL',flush=True)
    classes=build/'classes';classes.mkdir(exist_ok=True)
    android=sdk/'platforms/android-35/android.jar';dex=build/'dex';dex.mkdir(exist_ok=True)
    commands=[[str(java/'javac'),'-encoding','UTF-8','-source','8','-target','8','-cp',str(android),'-d',str(classes)]+[str(x) for x in sorted(src.glob('*.java'))],
        [str(java/'java'),'-cp',str(sdk/'build-tools/35.0.0/lib/d8.jar'),'com.android.tools.r8.D8','--min-api','33','--lib',str(android),'--output',str(dex)]]
    logs=[];ok=True
    for i,cmd in enumerate(commands):
        if i:cmd += [str(x) for x in sorted(classes.rglob('*.class'))]
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=180);logs.append(r.stdout+r.stderr)
        if r.returncode:ok=False;break
    (build/'java.log').write_text('\n'.join(logs))
    jar=out/'work198-dm1q.jar';jar.unlink(missing_ok=True)
    item={'file':jar.name,'built':ok,'log':'build/runtime/java.log'}
    if ok:
        with zipfile.ZipFile(jar,'w',zipfile.ZIP_DEFLATED) as z:z.write(dex/'classes.dex','classes.dex')
        item['sha256']=hashlib.sha256(jar.read_bytes()).hexdigest()
    else:item['error']='\n'.join(logs)[-4000:]
    results.append(item)
    (out/'build.json').write_text(json.dumps({'complete_runtime':False,'pd2425_handoff':False,'components':results},indent=2)+'\n')
    return 0 if all(x['built'] for x in results) else 1
if __name__=='__main__':raise SystemExit(main())
