"""Host-side identity and CLI refusal tests; no device or root required."""
from pathlib import Path
import os, subprocess, tempfile, json
ROOT=Path(__file__).resolve().parents[1]
def run(args,**kw):return subprocess.run([str(x) for x in args],check=True,**kw)
with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp);cc=os.environ.get('CC','cc')
    run([cc,'-Wall','-Wextra','-Werror','-I',ROOT/'runtime/pd2425/include',ROOT/'runtime/pd2425/tests/profile_test.c','-o',d/'profile'])
    run([d/'profile'])
    (d/'sys').mkdir()
    (d/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char *,char *);\n')
    (d/'mock.c').write_text(r'''#include <string.h>
#include <stdlib.h>
#include "profile.h"
int __system_property_get(const char *k,char *v){
 const char *x="";
 if(!strcmp(k,"ro.product.device"))x=getenv("BAD_DEVICE")?"other":"PD2425";
 if(!strcmp(k,"ro.build.version.sdk"))x="36";
 if(!strcmp(k,"ro.product.cpu.abi"))x="arm64-v8a";
 if(!strcmp(k,"ro.build.fingerprint"))x=PD2425_FINGERPRINT;
 strcpy(v,x);return (int)strlen(v);
}
''')
    run([cc,'-Wall','-Wextra','-Werror','-I',d,'-I',ROOT/'runtime/pd2425/include',ROOT/'runtime/pd2425/src/preflight.c',d/'mock.c','-o',d/'preflight'])
    for arg in ['--check-host','--diagnose']:
        r=run([d/'preflight',arg],capture_output=True,text=True)
        assert 'runtime_ready=0' in r.stdout and 'no_changes=1' in r.stdout
    assert subprocess.run([d/'preflight','--run'],capture_output=True).returncode==78
    assert subprocess.run([d/'preflight','--check-host'],env={**os.environ,'BAD_DEVICE':'1'},capture_output=True).returncode==31
    (d/'guard.c').write_text(r'''#include <string.h>
#include <assert.h>
#include "host_guard.h"
static int bad=0;
int __system_property_get(const char *k,char *v){
 const char *x="";
 if(!strcmp(k,"ro.product.model"))x=bad==1?"V2425A":"SM-S911B";
 if(!strcmp(k,"ro.product.device"))x=bad==2?"PD2425":"dm1q";
 if(!strcmp(k,"ro.build.version.sdk"))x=bad==3?"35":"36";
 if(!strcmp(k,"ro.bootloader"))x=bad==4?"new":"S911BXXSAFZG1";
 strcpy(v,x);return (int)strlen(v);
}
int main(void){assert(!require_dm1q_host());for(bad=1;bad<=4;bad++)assert(require_dm1q_host()==31);}
''')
    run([cc,'-Wall','-Wextra','-Werror','-I',d,'-I',ROOT/'runtime/common',d/'guard.c','-o',d/'guard'])
    run([d/'guard'])
    for name in ['loader198','guardian198']:
        s=(ROOT/'runtime/dm1q/src'/(name+'.c')).read_text().split('int main(int argc,char **argv){',1)[1]
        assert s.lstrip().startswith('if(require_dm1q_host())return 31;')
    p=json.loads((ROOT/'profiles/pd2425-originos6.json').read_text())
    assert p['launch_enabled'] is False and p['host_sdk']==36
print('PASS: CLI refusal, readiness separation and native entry gates')

from analyze_pd2425 import inventory
with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp);v=d/'fs/vendor/etc';(v/'init').mkdir(parents=True);(v/'vintf').mkdir();s=d/'selected';s.mkdir()
    (v/'init/test.rc').write_text('service sample /vendor/bin/sample \\\n --flag\n    user system\n    onrestart restart surfaceflinger\non boot\n    start sample\n')
    (v/'vintf/manifest.xml').write_text('<manifest type="device" target-level="8"><hal format="aidl"><name>test.hal</name><version>3</version><fqname>ITest/default</fqname></hal></manifest>')
    j=inventory(d/'fs',s)
    assert len(j['services'])==1 and j['services'][0]['argv']==['/vendor/bin/sample','--flag']
    assert j['services'][0]['options']==['user system','onrestart restart surfaceflinger']
    assert j['manifests'][0]['target_level']=='8' and j['manifests'][0]['hals'][0]['versions']==['3']
print('PASS: continued init declarations and VINTF inventory')
