"""Exercise live evidence using a fake proc/sys/dev tree, never phone state."""
import copy,json,os,subprocess,tempfile
from pathlib import Path
from pd2425_build import generate_services
from review_pd2425 import review
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    d=Path(temp);generate_services(d);(d/'sys').mkdir()
    (d/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char *,char *);\n')
    harness=r'''
#define PD2425_TESTING
#define open pd_test_open
#define openat pd_test_openat
#define mkdirat pd_test_mkdirat
#define unlinkat pd_test_unlinkat
#define ioctl pd_test_ioctl
#define main probe_cli
#include "preflight.c"
#undef main
#undef open
#undef openat
#undef mkdirat
#undef unlinkat
#undef ioctl
#include <assert.h>
#include <stdarg.h>
#include <sys/syscall.h>
int pd_test_open(const char *path,int flags,...){
 assert(!(flags&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)));
 assert(!strstr(path,"/dev/watchdog"));
 return syscall(SYS_openat,AT_FDCWD,path,flags,0);
}
int pd_test_openat(int dir,const char *path,int flags,...){
 assert(!(flags&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)));
 return syscall(SYS_openat,dir,path,flags,0);
}
int pd_test_mkdirat(int dir,const char *path,mode_t mode){(void)dir;(void)path;(void)mode;assert(0&&"readonly probe attempted mkdir");return -1;}
int pd_test_unlinkat(int dir,const char *path,int flags){(void)dir;(void)path;(void)flags;assert(0&&"readonly probe attempted unlink");return -1;}
int pd_test_ioctl(int fd,unsigned long request,...){
 assert(_IOC_DIR(request)==_IOC_READ);
 va_list args;va_start(args,request);void *arg=va_arg(args,void*);va_end(args);
 return syscall(SYS_ioctl,fd,request,arg);
}
static int pid_reads,state_reads;
int __system_property_get(const char *key,char *value){
 const char *s="";
 if(!strcmp(key,"ro.product.device"))s=getenv("BAD_DEVICE")?"other":"PD2425";
 if(!strcmp(key,"ro.build.version.sdk"))s="36";
 if(!strcmp(key,"ro.product.cpu.abi"))s="arm64-v8a";
 if(!strcmp(key,"ro.build.fingerprint"))s=getenv("FP_ALIAS")?PD2425_FINGERPRINT_V000L1:PD2425_FINGERPRINT;
 if(!strncmp(key,"init.svc.",9))s="stopped";
 if(!strcmp(key,"init.svc.vendor.audio-hal")){
  s=(getenv("CHANGED_STATE")&&state_reads++)?"restarting":"running";
 }
 if(!strcmp(key,"init.svc_debug_pid.vendor.audio-hal")&&!getenv("MISSING_PID")){
  s=(getenv("CHANGED_PID")&&pid_reads++)?"322":"321";
 }
 strcpy(value,s);return (int)strlen(s);
}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--parser-test")){
  assert(parse_pid("123")==123 && parse_pid("12junk")==-1 && parse_pid("1")==-1 && parse_pid("9999999999999999999999")==-1);
  assert(!process_start("123 (broken)"));
  assert(process_start("321 (audio ) tricky) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0")==12345);
  assert(!process_start("321 (x) S 0 0 0"));
  return 0;
 }
 return probe_cli(argc,argv);
}
'''
    (d/'harness.c').write_text(harness)
    cc=os.getenv('CC','cc');binary=d/'probe'
    subprocess.run([cc,'-Wall','-Wextra','-Werror','-I',str(d),'-I',str(ROOT/'runtime/pd2425/include'),'-I',str(ROOT/'runtime/pd2425/src'),str(d/'harness.c'),'-o',str(binary)],check=True)
    subprocess.run([binary,'--parser-test'],check=True)
    fixture=d/'fixture'
    def put(path,text):
        p=fixture/path.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p
    stat='321 (audio ) tricky) S '+'0 '*18+'12345 0\n'
    put('/proc/321/stat',stat)
    put('/proc/321/status','Name:\taudio\nUid:\t1041\t1041\t1041\t1041\nGid:\t1041\t1041\t1041\t1041\nGroups:\t1005 1006\nCapEff:\t0000000000800000\n')
    label=put('/proc/321/attr/current','u:r:hal_audio_default:s0')
    put('/proc/321/comm','audiohal\n')
    (fixture/'proc/321/exe').symlink_to('/vendor/bin/hw/android.hardware.audio.service_64')
    put('/proc/777/comm','system_server\n');(fixture/'proc/777/fd').mkdir()
    (fixture/'proc/777/fd/9').symlink_to('/dev/watchdog0')
    put('/proc/sys/kernel/osrelease','6.1-test\n');put('/sys/fs/selinux/enforce','1\n')
    put('/sys/class/power_supply/battery/temp','379\n');put('/sys/fs/cgroup/cgroup.controllers','cpu memory\n')
    for key,value in {'identity':'OEM watchdog','timeout':'45','nowayout':'1','state':'active'}.items():put('/sys/class/watchdog/watchdog0/'+key,value+'\n')
    put('/dev/input/event0','ordinary fixture file, not an input device')
    def collect(**extra):
        env={**os.environ,'PD2425_FIXTURE_ROOT':str(fixture),**extra}
        r=subprocess.run([binary,'--diagnose-json'],env=env,capture_output=True,text=True)
        assert r.returncode==(31 if extra.get('BAD_DEVICE') else 0),r.stderr
        j=json.loads(r.stdout);assert j['schema']==3 and j['runtime_ready'] is False and j['no_device_changes'] is True
        return j
    j=collect();audio=next(s for s in j['services'] if s['name']=='vendor.audio-hal')
    assert audio['snapshot_stable'] and audio['pid_source']=='init_property' and audio['executable_matches']
    assert audio['uid']=='1041\t1041\t1041\t1041' and audio['groups']=='1005 1006' and audio['start_ticks']==12345
    assert j['watchdog']['system_server_fds']==[{'pid':777,'fd':'9','target':'/dev/watchdog0'}]
    assert j['watchdog']['fd_adoption_tested'] is False
    assert j['inputs']['devices'][0]['keys_errno']!=0 and not j['inputs']['devices'][0]['volume_up']
    profile=json.loads((ROOT/'profiles/pd2425-originos6.json').read_text())
    for expected in profile['services']+profile.get('host_services',[]):expected.pop('observed_identity',None)
    profile['service_alternatives']=[]
    reviewed=review(j,profile)
    assert reviewed['runtime_ready'] is False and not reviewed['observation_checks_passed']
    assert any(x['code']=='physical_return_keys_unknown' for x in reviewed['issues'])
    clean=copy.deepcopy(j);clean['uid']=0;clean['cgroup_filesystem']={'errno':0,'is_cgroup2':True}
    clean['inputs']['devices']=[{'path':'/dev/input/event9','name':'gpio-keys','name_errno':0,'keys_errno':0,'touch':False,'volume_up':True,'volume_down':False},{'path':'/dev/input/event12','name':'pmic_resin','name_errno':0,'keys_errno':0,'touch':False,'volume_up':False,'volume_down':True}]
    for expected in profile.get('host_services',[]):
        if expected.get('required_running'):
            entry=next(x for x in clean['services'] if x['name']==expected['name'])
            entry.update(copy.deepcopy(audio));entry['name']=expected['name']
            entry['executable']=entry['expected_executable']=expected['executable']
    reviewed=review(clean,profile)
    assert reviewed['observation_checks_passed'] and reviewed['runtime_ready'] is False
    assert reviewed['remaining_device_tests'] and reviewed['observed_process_credentials']
    for field,value,code in [('fingerprint','drift','host_profile_mismatch'),('uid',2000,'root_unconfirmed'),('selinux_enforce',{'errno':0,'value':'0'},'selinux_not_enforcing'),('battery_temp',{'errno':0,'value':'420'},'temperature_high')]:
        bad=copy.deepcopy(clean);bad[field]=value;r=review(bad,profile)
        assert not r['observation_checks_passed'] and r['runtime_ready'] is False
        assert any(x['code']==code for x in r['issues'])
    assert review({'schema':1},profile)['runtime_ready'] is False
    aliased=collect(FP_ALIAS='1');assert aliased['host_profile_match'] and not aliased['ota_identity_match']

    assert not collect(BAD_DEVICE='1')['ota_identity_match']
    for env in [{'CHANGED_PID':'1'},{'CHANGED_STATE':'1'}]:
        a=next(s for s in collect(**env)['services'] if s['name']=='vendor.audio-hal');assert not a['snapshot_stable']
    candidate=next(s for s in collect(MISSING_PID='1')['services'] if s['name']=='vendor.audio-hal')
    assert candidate['pid_source']=='exe_candidate' and candidate['candidate_count']==1
    candidate_report=collect(MISSING_PID='1');candidate_report['uid']=0
    assert any(x['code']=='init_pid_unconfirmed' for x in review(candidate_report,profile)['issues'])

    (fixture/'proc/322').mkdir();(fixture/'proc/322/exe').symlink_to('/vendor/bin/hw/android.hardware.audio.service_64')
    ambiguous=next(s for s in collect(MISSING_PID='1')['services'] if s['name']=='vendor.audio-hal')
    assert ambiguous['pid']==-1 and ambiguous['candidate_count']==2 and not ambiguous['snapshot_stable']
    label.unlink();missing=next(s for s in collect()['services'] if s['name']=='vendor.audio-hal')
    assert missing['selinux_errno']!=0 and not missing['snapshot_stable']
    label.write_text('u:r:quoted"\\context:s0\n');escaped=next(s for s in collect()['services'] if s['name']=='vendor.audio-hal')
    assert escaped['selinux_context']==label.read_text()
print('PASS: native JSON, process races, credentials, ambiguous candidates, input query errors, watchdog metadata; no write opens/setter ioctls')
