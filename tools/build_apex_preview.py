"""Build the bounded PD2425 APEX/classpath/ART CLI; payloads are separate inputs."""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, zipfile
from pathlib import Path
from pd2425_build import generate_services
ROOT=Path(__file__).resolve().parents[1]
def generate_pins(catalog, output):
    if catalog.get('image_sha256')!=json.loads((ROOT/'profiles/pd2425-evox-preview.json').read_text())['image_sha256']:raise ValueError('Catalog image mismatch')
    rows=[];xml=['<?xml version="1.0" encoding="utf-8"?>','<apex-info-list>'];seen=set();total=0
    if catalog.get('module_count')!=36 or len(catalog.get('modules',[]))!=36:raise ValueError('Expected pinned 36-module catalog')
    for m in catalog['modules']:
        name=m['manifest_identity']['name'];version=m['manifest_identity']['version'];size=m['payload']['bytes'];sha=m['payload']['sha256'];source=m['source_name']
        if not re.fullmatch(r'com(?:\.[A-Za-z0-9_]+)+',name) or name in seen:raise ValueError('Invalid module name')
        if source not in (name+'.apex',name+'.capex') or type(version) is not int or not 0<version<2**63:raise ValueError('Invalid module identity')
        if type(size) is not int or not 0<size<=512*1024*1024 or not re.fullmatch(r'[0-9a-f]{64}',sha):raise ValueError('Invalid payload pin')
        if m['payload']['filesystem']!='ext4' or not m['manifest_identity_verified'] or not m['payload_manifest_verified']:raise ValueError('Unverified payload')
        seen.add(name);total+=size;rows.append('{'+json.dumps(name)+','+str(size)+','+json.dumps(sha)+'},')
        path='/system/apex/'+source
        xml.append(f'<apex-info moduleName="{name}" modulePath="{path}" preinstalledModulePath="{path}" versionCode="{version}" versionName="" isFactory="true" isActive="true" lastUpdateMillis="0" provideSharedApexLibs="false" partition="SYSTEM"/>')
    if total>2*1024**3 or not {'com.android.runtime','com.android.art','com.android.sdkext'}<=seen:raise ValueError('Invalid APEX set')
    xml.append('</apex-info-list>')
    Path(output).write_text('/* Generated from pinned source metadata; not boot authorization. */\nstruct apex_pin {const char *name;uint64_t bytes;const char *sha;};\nstatic const struct apex_pin apex_pins[]={\n'+'\n'.join(rows)+'\n};\nstatic const char apex_xml[]='+json.dumps('\n'.join(xml))+';\n',encoding='utf-8')
def run(*args):subprocess.run([str(x) for x in args],check=True,timeout=180)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sdk',default=os.getenv('ANDROID_SDK_ROOT') or os.getenv('ANDROID_HOME'));p.add_argument('--ndk',default=os.getenv('ANDROID_NDK_HOME'));p.add_argument('--java-home',default=os.getenv('JAVA_HOME'));p.add_argument('--output',type=Path,default=ROOT/'dist/pd2425-apex-preview');a=p.parse_args()
    if not a.sdk or not a.java_home:p.error('Set SDK and Java paths')
    sdk=Path(a.sdk).resolve();java=Path(a.java_home).resolve()/'bin';ndk=Path(a.ndk).resolve() if a.ndk else sdk/'ndk/25.2.9519653'
    host='windows-x86_64' if os.name=='nt' else ('darwin-x86_64' if sys.platform=='darwin' else 'linux-x86_64');suffix='.exe' if os.name=='nt' else '';clang=ndk/f'toolchains/llvm/prebuilt/{host}/bin/clang{suffix}'
    tools=sorted((sdk/'build-tools').iterdir(),key=lambda x:x.name);d8=next((x/'lib/d8.jar' for x in reversed(tools) if (x/'lib/d8.jar').is_file()),None);android=sdk/'platforms/android-35/android.jar'
    if not clang.is_file() or not android.is_file() or d8 is None:p.error('Missing NDK, SDK 35 or D8')
    build=ROOT/'build/apex-preview';classes=build/'classes';dex=build/'dex'
    for directory in (build,classes,dex,a.output):directory.mkdir(parents=True,exist_ok=True)
    include=generate_services(build/'include');generate_pins(json.loads((ROOT/'profiles/pd2425-evox-apex.json').read_text()),include/'apex_pins.generated.h')
    src=ROOT/'runtime/pd2425/src';headers=ROOT/'runtime/pd2425/include'
    helper=a.output/'selinux-check.so';run(clang,'--target=aarch64-linux-android33','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',src/'apex_selinux.c','-ldl','-o',helper)
    run(java/('javac'+suffix),'--release','8','-d',classes,ROOT/'runtime/pd2425/tests/ArtProbe.java')
    run(java/('java'+suffix),'-cp',d8,'com.android.tools.r8.D8','--min-api','33','--lib',android,'--output',dex,*sorted(classes.rglob('*.class')))
    jar=a.output/'art-probe.jar'
    with zipfile.ZipFile(jar,'w',zipfile.ZIP_DEFLATED) as z:z.write(dex/'classes.dex','classes.dex')
    pins=include/'apex_binary_pins.generated.h'
    pins.write_text('\n'.join('#define '+prefix+'_BYTES '+str(path.stat().st_size)+'\n#define '+prefix+'_SHA "'+hashlib.sha256(path.read_bytes()).hexdigest()+'"' for prefix,path in [('AP_JAR',jar),('AP_SELINUX',helper)])+'\n',encoding='utf-8')
    run(clang,'--target=aarch64-linux-android33','-static','-O2','-Wall','-Wextra','-Werror','-include',pins,'-I',include,'-I',headers,'-I',src,src/'apex_preview.c','-o',a.output/'apex-preview')
    report={'schema':1,'runtime_ready':False,'guest_boot_complete':False,'image_sha256':json.loads((ROOT/'profiles/pd2425-evox-preview.json').read_text())['image_sha256'],'files':{path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in (a.output/'apex-preview',jar,helper)}}
    (a.output/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(a.output)
if __name__=='__main__':main()
